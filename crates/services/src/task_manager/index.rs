/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::task_manager::{Task, TaskDetails, TaskFailureType, TaskResult};
use common::Server;
use email::{
    cache::MessageCacheFetch,
    message::metadata::{MESSAGE_RECEIVED_MASK, MessageMetadata},
};
use inbuxa_features::undelete;
use types::blob_hash::BlobHash;
use groupware::{cache::GroupwareCache, calendar::CalendarEvent, contact::ContactCard};
use registry::{
    schema::{
        enums::IndexDocumentType,
        structs::{TaskIndexDocument, TaskIndexTrace, TaskStatus},
    },
    types::EnumImpl,
};
use std::cmp::Ordering;
use store::{
    IterateParams, ValueKey,
    ahash::AHashMap,
    rand::{self, RngExt},
    search::{IndexDocument, SearchField, SearchFilter, SearchQuery},
    write::{
        AlignedBytes, Archive, BatchBuilder, SearchIndex, TelemetryClass, ValueClass,
        key::DeserializeBigEndian, now,
    },
};
use trc::{AddContext, TaskManagerEvent};
use types::{
    collection::{Collection, SyncCollection},
    field::EmailField,
};

pub(crate) trait SearchIndexTask: Sync + Send {
    fn index(&self, tasks: &[TaskDetails]) -> impl Future<Output = Vec<IndexTaskResult>> + Send;
}

const NUM_INDEXES: usize = 5;
const MISSING_DOCUMENT_MAX_ATTEMPTS: u64 = 3;
const MISSING_DOCUMENT_RETRY_DELAY: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskType {
    Insert,
    Delete,
}

enum BuildResult {
    Document(IndexDocument),
    NotIndexed,
    NotFound,
}

#[derive(Debug)]
pub(crate) struct IndexTaskResult {
    index: IndexDocumentType,
    task_type: TaskType,
    pub result: TaskResult,
}

impl SearchIndexTask for Server {
    async fn index(&self, tasks: &[TaskDetails]) -> Vec<IndexTaskResult> {
        let mut results: Vec<IndexTaskResult> = Vec::with_capacity(tasks.len());
        let mut batch = BatchBuilder::new();
        let mut document_insertions = Vec::new();
        let mut document_deletions: [AHashMap<u32, Vec<u32>>; NUM_INDEXES] =
            std::array::from_fn(|_| AHashMap::new());

        for task in tasks {
            match &task.task {
                Task::IndexDocument(task) => {
                    let account_id = task.account_id.document_id();
                    let document_id = task.document_id.document_id();

                    let document = match task.document_type {
                        IndexDocumentType::Email => {
                            build_email_document(self, account_id, document_id).await
                        }
                        IndexDocumentType::Calendar => {
                            build_calendar_document(self, account_id, document_id).await
                        }
                        IndexDocumentType::Contacts => {
                            build_contact_document(self, account_id, document_id).await
                        }
                        IndexDocumentType::File => {
                            // File indexing not implemented yet
                            continue;
                        }
                    };

                    // Retry non found errors in case they are due to SQL read replication lag
                    let result = match document {
                        Ok(BuildResult::Document(doc)) if !doc.is_empty() => {
                            document_insertions.push(doc);
                            TaskResult::Success(vec![])
                        }
                        Err(err) => {
                            let result = TaskResult::temporary(err.to_string());
                            trc::error!(
                                err.account_id(account_id)
                                    .document_id(document_id)
                                    .caused_by(trc::location!())
                                    .ctx(trc::Key::Collection, task.document_type.as_str())
                                    .details("Failed to build document for indexing")
                            );
                            result
                        }
                        Ok(BuildResult::NotFound)
                            if attempt_number(&task.status) < MISSING_DOCUMENT_MAX_ATTEMPTS =>
                        {
                            TaskResult::Failure {
                                typ: TaskFailureType::Retry(
                                    now().saturating_add(MISSING_DOCUMENT_RETRY_DELAY),
                                ),
                                message: "Document not found in data store".into(),
                                max_attempts: Some(MISSING_DOCUMENT_MAX_ATTEMPTS),
                            }
                        }
                        Ok(BuildResult::NotFound) => {
                            trc::event!(
                                TaskManager(TaskManagerEvent::TaskIgnored),
                                Collection = task.document_type.as_str(),
                                Reason = "Document no longer exists",
                                AccountId = account_id,
                                DocumentId = document_id,
                            );
                            TaskResult::Ignored
                        }
                        _ => {
                            trc::event!(
                                TaskManager(TaskManagerEvent::TaskIgnored),
                                Collection = task.document_type.as_str(),
                                Reason = "Nothing to index",
                                AccountId = account_id,
                                DocumentId = document_id,
                            );
                            TaskResult::Ignored
                        }
                    };

                    results.push(IndexTaskResult {
                        task_type: TaskType::Insert,
                        index: task.document_type,
                        result,
                    });
                }
                Task::IndexTrace(task) => {
                    let result = match build_tracing_span_document(self, task.trace_id.id()).await {
                        Ok(Some(doc)) if !doc.is_empty() => {
                            document_insertions.push(doc);
                            TaskResult::Success(vec![])
                        }
                        Err(err) => {
                            let result = TaskResult::temporary(err.to_string());
                            trc::error!(
                                err.id(task.trace_id.id())
                                    .caused_by(trc::location!())
                                    .details("Failed to build document for indexing")
                            );
                            result
                        }
                        _ => {
                            trc::event!(
                                TaskManager(TaskManagerEvent::TaskIgnored),
                                Reason = "Nothing to index",
                                Id = task.trace_id.id(),
                            );
                            TaskResult::Ignored
                        }
                    };

                    results.push(IndexTaskResult {
                        task_type: TaskType::Insert,
                        index: IndexDocumentType::File, // use File index for tracing spans to avoid creating a new index type
                        result,
                    });
                }
                Task::UnindexDocument(task) => {
                    let account_id = task.account_id.document_id();
                    let document_id = task.document_id.document_id();
                    let idx = match task.document_type {
                        IndexDocumentType::Email => {
                            if let Err(err) =
                                delete_email_metadata(self, &mut batch, account_id, document_id)
                                    .await
                            {
                                trc::error!(
                                    err.account_id(account_id)
                                        .document_id(document_id)
                                        .caused_by(trc::location!())
                                        .details("Failed to delete email metadata from index")
                                );
                                results.push(IndexTaskResult {
                                    task_type: TaskType::Delete,
                                    index: task.document_type,
                                    result: TaskResult::temporary(
                                        "Failed to delete email metadata from index",
                                    ),
                                });
                                continue;
                            }
                            0
                        }
                        IndexDocumentType::Calendar => 1,
                        IndexDocumentType::Contacts => 2,
                        IndexDocumentType::File => 3,
                    };
                    // inbuxa: UD-1: a noted file, event or contact is archived
                    if let Some(kind) = match task.document_type {
                        IndexDocumentType::Calendar => Some(undelete::groupware::Kind::CalendarEvent),
                        IndexDocumentType::Contacts => Some(undelete::groupware::Kind::ContactCard),
                        IndexDocumentType::File => Some(undelete::groupware::Kind::File),
                        IndexDocumentType::Email => None,
                    } && let Err(err) = archive_noted(self, kind, account_id, document_id).await
                    {
                        trc::error!(
                            err.account_id(account_id)
                                .document_id(document_id)
                                .details("Failed to archive a deleted item")
                        );
                    }

                    document_deletions[idx]
                        .entry(account_id)
                        .or_default()
                        .push(document_id);

                    results.push(IndexTaskResult {
                        task_type: TaskType::Delete,
                        index: task.document_type,
                        result: TaskResult::Success(vec![]),
                    });
                }
                _ => unreachable!(),
            }
        }

        // Commit deletion batch to data store
        if !batch.is_empty()
            && let Err(err) = self.store().write(batch.build_all()).await
        {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to commit index deletions to data store")
            );
            for r in results.iter_mut() {
                if r.task_type == TaskType::Delete
                    && r.result.is_success()
                    && r.index == IndexDocumentType::Email
                {
                    r.result =
                        TaskResult::temporary("Failed to commit index deletions to data store");
                }
            }
            return results;
        }

        // Index documents
        if !document_insertions.is_empty()
            && let Err(err) = self.search_store().index(document_insertions).await
        {
            let retry_at = deferred_retry_time(&err);
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to index documents")
            );
            for r in results.iter_mut() {
                if r.task_type == TaskType::Insert && r.result.is_success() {
                    r.result = search_store_failure(retry_at, "Failed to index documents");
                }
            }
            return results;
        }

        // Delete documents
        for (accounts, index) in document_deletions.into_iter().zip([
            SearchIndex::Email,
            SearchIndex::Calendar,
            SearchIndex::Contacts,
        ]) {
            let multi_account = match accounts.len().cmp(&1) {
                Ordering::Greater => true,
                Ordering::Equal => false,
                Ordering::Less => continue,
            };

            let mut query = SearchQuery::new(index);
            if multi_account {
                query.add_filter(SearchFilter::Or);
            }

            for (account_id, document_ids) in accounts {
                let multi_document = document_ids.len() > 1;
                query
                    .add_filter(SearchFilter::And)
                    .add_filter(SearchFilter::eq(SearchField::AccountId, account_id));

                if multi_document {
                    query.add_filter(SearchFilter::Or);
                }

                for document_id in document_ids {
                    query.add_filter(SearchFilter::eq(SearchField::DocumentId, document_id));
                }

                if multi_document {
                    query.add_filter(SearchFilter::End);
                }
                query.add_filter(SearchFilter::End);
            }

            if multi_account {
                query.add_filter(SearchFilter::End);
            }

            if let Err(err) = self.search_store().unindex(query).await {
                let retry_at = deferred_retry_time(&err);
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to delete documents from index")
                        .ctx(trc::Key::Collection, index.name())
                );
                for r in results.iter_mut() {
                    if r.task_type == TaskType::Delete && r.result.is_success() {
                        r.result =
                            search_store_failure(retry_at, "Failed to delete documents from index");
                    }
                }
                return results;
            }
        }

        results
    }
}

pub(crate) async fn reindex_telemetry(server: &Server) -> trc::Result<()> {
    let mut spans = Vec::new();
    server
        .tracing_store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(0))),
                ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(u64::MAX))),
            )
            .no_values(),
            |key, _| {
                spans.push(key.deserialize_be_u64(0)?);
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let mut batch = BatchBuilder::new();
    let now = now() as i64;
    for span_id in spans {
        batch.schedule_task(Task::IndexTrace(TaskIndexTrace {
            trace_id: span_id.into(),
            status: TaskStatus::at(now + rand::rng().random_range(0..=300)),
        }));
        if batch.is_large_batch() {
            server.core.storage.data.write(batch.build_all()).await?;
            batch = BatchBuilder::new();
        }
    }

    if !batch.is_empty() {
        server.core.storage.data.write(batch.build_all()).await?;
    }
    Ok(())
}

pub(crate) async fn reindex_account(server: &Server, account_id: u32) -> trc::Result<()> {
    let now = now() as i64;

    let mut batch = BatchBuilder::new();

    for document_id in server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?
        .emails
        .items
        .iter()
        .map(|v| v.document_id)
    {
        batch.schedule_task(Task::IndexDocument(TaskIndexDocument {
            account_id: account_id.into(),
            document_id: document_id.into(),
            document_type: IndexDocumentType::Email,
            status: TaskStatus::at(now + rand::rng().random_range(0..=300)),
        }));

        if batch.is_large_batch() {
            server.core.storage.data.write(batch.build_all()).await?;
            batch = BatchBuilder::new();
        }
    }

    for document_type in [IndexDocumentType::Calendar, IndexDocumentType::Contacts] {
        let cache = server
            .fetch_dav_resources(
                account_id,
                account_id,
                if document_type == IndexDocumentType::Calendar {
                    SyncCollection::Calendar
                } else {
                    SyncCollection::AddressBook
                },
            )
            .await
            .caused_by(trc::location!())?;

        for document_id in cache.document_ids(false) {
            batch.schedule_task(Task::IndexDocument(TaskIndexDocument {
                account_id: account_id.into(),
                document_id: document_id.into(),
                document_type,
                status: TaskStatus::at(now + rand::rng().random_range(0..=300)),
            }));

            if batch.is_large_batch() {
                server.core.storage.data.write(batch.build_all()).await?;
                batch = BatchBuilder::new();
            }
        }
    }

    if !batch.is_empty() {
        server.core.storage.data.write(batch.build_all()).await?;
    }

    // Request indexing
    server.notify_task_queue();

    Ok(())
}

fn deferred_retry_time(err: &trc::Error) -> Option<u64> {
    err.value(trc::Key::NextRetry)
        .and_then(|value| value.to_uint())
}

fn search_store_failure(retry_at: Option<u64>, message: &'static str) -> TaskResult {
    match retry_at {
        Some(retry_at) => TaskResult::Failure {
            typ: TaskFailureType::Retry(retry_at),
            message: message.into(),
            max_attempts: None,
        },
        None => TaskResult::temporary(message),
    }
}

fn attempt_number(status: &TaskStatus) -> u64 {
    match status {
        TaskStatus::Pending(_) => 0,
        TaskStatus::Retry(status) => status.attempt_number,
        TaskStatus::Failed(status) => status.failed_attempt_number,
    }
}

async fn build_email_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<BuildResult> {
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Email) else {
        return Ok(BuildResult::NotIndexed);
    };

    match server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await?
    {
        Some(metadata_) => {
            let metadata = metadata_
                .unarchive::<MessageMetadata>()
                .caused_by(trc::location!())?;

            let raw_message = server
                .blob_store()
                .get_blob(metadata.blob_hash.0.as_slice(), 0..usize::MAX)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| {
                    trc::StoreEvent::NotFound
                        .into_err()
                        .details("Blob not found")
                })?;

            Ok(BuildResult::Document(metadata.index_document(
                account_id,
                document_id,
                &raw_message,
                index_fields,
                server.core.email.default_language,
            )))
        }
        None => Ok(BuildResult::NotFound),
    }
}

async fn build_calendar_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<BuildResult> {
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Calendar) else {
        return Ok(BuildResult::NotIndexed);
    };

    match server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::CalendarEvent,
            document_id,
        ))
        .await?
    {
        Some(metadata_) => Ok(BuildResult::Document(
            metadata_
                .unarchive::<CalendarEvent>()
                .caused_by(trc::location!())?
                .index_document(
                    account_id,
                    document_id,
                    index_fields,
                    server.core.email.default_language,
                ),
        )),
        None => Ok(BuildResult::NotFound),
    }
}

async fn build_contact_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<BuildResult> {
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Contacts) else {
        return Ok(BuildResult::NotIndexed);
    };

    match server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
            account_id,
            Collection::ContactCard,
            document_id,
        ))
        .await?
    {
        Some(metadata_) => Ok(BuildResult::Document(
            metadata_
                .unarchive::<ContactCard>()
                .caused_by(trc::location!())?
                .index_document(
                    account_id,
                    document_id,
                    index_fields,
                    server.core.email.default_language,
                ),
        )),
        None => Ok(BuildResult::NotFound),
    }
}


// inbuxa: MON-16: a trace's search document, when trace search is on:
// its event types, queue ids, and addresses, their domains, hosts, IPs,
// message ids and account names as keywords
async fn build_tracing_span_document(
    server: &Server,
    span_id: u64,
) -> trc::Result<Option<IndexDocument>> {
    use common::telemetry::tracers::store::MaybeTrace;
    use registry::schema::{enums::SearchTracingField, structs::Search};
    use store::{
        search::TracingSearchField,
        write::{TelemetryClass, ValueClass},
    };
    use trc::Key;

    let settings = server
        .registry()
        .object::<Search>(types::id::Id::singleton())
        .await?
        .unwrap_or_default();
    if !settings.index_telemetry {
        return Ok(None);
    }
    let wants = |field: SearchTracingField| settings.index_tracing_fields.iter().any(|f| *f == field);
    let Some(MaybeTrace(Some(trace))) = server
        .tracing_store()
        .get_value::<MaybeTrace>(ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(
            span_id,
        ))))
        .await?
    else {
        return Ok(None);
    };

    let mut document = IndexDocument::new(SearchIndex::Tracing).with_id(span_id);
    let mut seen = store::ahash::AHashSet::new();
    for event in trace.events.iter() {
        if wants(SearchTracingField::EventType) && seen.insert(event.event.as_str().to_string()) {
            document.index_keyword(TracingSearchField::EventType, event.event.as_str());
        }
        for kv in event.key_values.iter() {
            let text = match &kv.value {
                registry::schema::structs::TraceValue::String(v) => v.value.clone(),
                registry::schema::structs::TraceValue::UnsignedInt(v) => v.value.to_string(),
                registry::schema::structs::TraceValue::IpAddr(v) => v.value.to_string(),
                _ => continue,
            };
            match kv.key {
                Key::QueueId if wants(SearchTracingField::QueueId) => {
                    if seen.insert(format!("q:{text}")) {
                        document.index_keyword(TracingSearchField::QueueId, &text);
                    }
                }
                Key::From
                | Key::To
                | Key::Domain
                | Key::Hostname
                | Key::RemoteIp
                | Key::MessageId
                | Key::AccountName
                    if wants(SearchTracingField::Keywords) =>
                {
                    let text = text.to_lowercase();
                    if seen.insert(format!("k:{text}")) {
                        document.index_text(TracingSearchField::Keywords, &text, nlp::language::Language::None);
                        // An address's domain, so a domain search finds it
                        if let Some((_, domain)) = text.rsplit_once('@')
                            && seen.insert(format!("k:{domain}"))
                        {
                            document.index_text(
                                TracingSearchField::Keywords,
                                domain,
                                nlp::language::Language::None,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(Some(document))
}

// inbuxa: UD-1, UD-4: archives a deleted file, event or contact noted at
// deletion, when archiving is on; otherwise its note is dropped
async fn archive_noted(
    server: &Server,
    kind: undelete::groupware::Kind,
    account_id: u32,
    document_id: u32,
) -> trc::Result<()> {
    let data = &server.core.storage.data;
    let Some(note) = undelete::groupware::take(data, kind, account_id, document_id).await? else {
        return Ok(());
    };
    let Some(retention) = undelete::settings::retention(server.registry()).await?.items else {
        return Ok(());
    };
    let blob_hash = match (&note.content, &note.blob_hash) {
        (Some(text), _) => {
            server
                .put_temporary_blob(account_id, text.as_bytes(), 600)
                .await?
                .0
        }
        (None, Some(hash)) => BlobHash::try_from_hash_slice(hash).map_err(|_| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid blob hash in undelete note")
        })?,
        (None, None) => return Ok(()),
    };
    undelete::groupware::archive(data, server.registry(), account_id, note, blob_hash, retention)
        .await
        .map(|_| ())
}

async fn delete_email_metadata(
    server: &Server,
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
) -> trc::Result<()> {
    match server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await?
    {
        Some(metadata_) => {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .with_document(document_id);
            let metadata = metadata_
                .unarchive::<MessageMetadata>()
                .caused_by(trc::location!())?;
            metadata.unindex(batch);

            // inbuxa: UD-1, UD-4: a message noted at deletion is archived
            let root = metadata.contents.first().and_then(|c| c.parts.first());
            inbuxa_features::undelete::email::archive(
                &server.core.storage.data,
                server.registry(),
                account_id,
                document_id,
                inbuxa_features::undelete::email::Summary {
                    blob_hash: BlobHash::from(&metadata.blob_hash),
                    from: root.and_then(|part| part.from()),
                    subject: root.and_then(|part| part.subject()),
                    received_at: metadata.rcvd_attach.to_native() & MESSAGE_RECEIVED_MASK,
                },
            )
            .await
            .caused_by(trc::location!())?;
        }
        None => {
            trc::event!(
                TaskManager(TaskManagerEvent::MetadataNotFound),
                Details = "E-mail metadata not found",
                AccountId = account_id,
                DocumentId = document_id,
            );
        }
    }

    Ok(())
}
