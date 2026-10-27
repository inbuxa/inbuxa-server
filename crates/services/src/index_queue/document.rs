/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use common::{Core, Server};
use email::message::metadata::MetadataRow;
use groupware::{calendar::CalendarEventContent, contact::ContactCardContent};
use store::{
    ValueKey,
    search::{IndexDocument, TracingSearchField},
    write::{Archive, ArchiveBytes, SearchIndex},
};
use trc::AddContext;
use types::{
    collection::Collection,
    field::{CalendarEventField, ContactField},
};

pub(crate) fn is_email_indexed(server: &Server) -> bool {
    server
        .core
        .email
        .index_fields
        .contains_key(&SearchIndex::Email)
}

pub(crate) async fn build_email_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
    row: MetadataRow,
) -> trc::Result<IndexDocument> {
    let metadata = row.unarchive().caused_by(trc::location!())?;
    let raw_message = server
        .get_message_blob(metadata.blob_hash().as_slice(), 0..usize::MAX)
        .await
        .caused_by(trc::location!())?
        .ok_or_else(|| {
            trc::StoreEvent::NotFound
                .into_err()
                .details("Blob not found")
        })?;

    if !metadata.has_extractable_attachments() {
        return email_document(&server.core, &row, account_id, document_id, &raw_message);
    }

    let core = server.core.clone();
    tokio::task::spawn_blocking(move || {
        email_document(&core, &row, account_id, document_id, &raw_message)
    })
    .await
    .map_err(|err| {
        trc::EventType::Server(trc::ServerEvent::ThreadError)
            .reason(err)
            .details("Email indexing task failed")
            .caused_by(trc::location!())
    })?
}

fn email_document(
    core: &Core,
    row: &MetadataRow,
    account_id: u32,
    document_id: u32,
    raw_message: &[u8],
) -> trc::Result<IndexDocument> {
    let index_fields = core
        .email
        .index_fields
        .get(&SearchIndex::Email)
        .ok_or_else(|| trc::StoreEvent::UnexpectedError.into_err())?;
    let headers = row.raw_headers().caused_by(trc::location!())?;
    Ok(row.unarchive().caused_by(trc::location!())?.index_document(
        account_id,
        document_id,
        &headers,
        raw_message,
        index_fields,
        core.email.default_language,
        &core.email.extract_limits,
    ))
}

pub(crate) async fn build_calendar_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Calendar) else {
        return Ok(None);
    };

    match server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
            account_id,
            Collection::CalendarEvent,
            document_id,
            CalendarEventField::Content,
        ))
        .await?
    {
        Some(metadata_) => Ok(Some(
            metadata_
                .unarchive::<CalendarEventContent>()
                .caused_by(trc::location!())?
                .index_document(
                    account_id,
                    document_id,
                    index_fields,
                    server.core.email.default_language,
                ),
        )),
        None => Ok(None),
    }
}

pub(crate) async fn build_contact_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Contacts) else {
        return Ok(None);
    };

    match server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
            account_id,
            Collection::ContactCard,
            document_id,
            ContactField::Content,
        ))
        .await?
    {
        Some(metadata_) => Ok(Some(
            metadata_
                .unarchive::<ContactCardContent>()
                .caused_by(trc::location!())?
                .index_document(
                    account_id,
                    document_id,
                    index_fields,
                    server.core.email.default_language,
                ),
        )),
        None => Ok(None),
    }
}


// inbuxa: MON-16: a trace's search document, when trace search is on
pub(crate) async fn build_tracing_span_document(
    server: &Server,
    span_id: u64,
) -> trc::Result<Option<IndexDocument>> {
    use common::telemetry::tracers::store::MaybeTrace;
    use registry::schema::structs::Search;
    use store::write::{TelemetryClass, ValueClass};

    let settings = server
        .registry()
        .object::<Search>(types::id::Id::singleton())
        .await?
        .unwrap_or_default();
    if !settings.index_telemetry {
        return Ok(None);
    }
    let Some(MaybeTrace(Some(trace))) = server
        .tracing_store()
        .get_value::<MaybeTrace>(ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(
            span_id,
        ))))
        .await?
    else {
        return Ok(None);
    };

    // inbuxa: 1.0 dropped the choice of fields; 0.16's default was all three
    Ok(Some(trace_search_document(
        span_id,
        &trace,
        &[
            TracingSearchField::EventType,
            TracingSearchField::QueueId,
            TracingSearchField::Keywords,
        ],
    )))
}

/// inbuxa: MON-16: the search document for a stored trace.
///
/// The event type and queue id columns are integers on every search backend
/// (BIGINT on PostgreSQL and MySQL, long on Elasticsearch), and each holds a
/// single value per trace: the event type is the trace's opening event, the
/// one `x:Trace/query` filters on, and the queue id is the first queue id the
/// trace mentions. Every queue id also goes into the keywords, so a session
/// that queued several messages is found by any of them.
pub fn trace_search_document(
    span_id: u64,
    trace: &registry::schema::structs::Trace,
    fields: &[TracingSearchField],
) -> IndexDocument {
    use registry::schema::structs::TraceValue;
    use trc::Key;

    let wants = |field: TracingSearchField| fields.contains(&field);
    let mut document = IndexDocument::new(SearchIndex::Tracing).with_id(span_id);
    if wants(TracingSearchField::EventType)
        && let Some(first) = trace.events.iter().next()
    {
        document.index_unsigned(TracingSearchField::EventType, first.event.to_id() as u64);
    }

    let mut seen = store::ahash::AHashSet::new();
    let mut queue_id_indexed = false;
    for event in trace.events.iter() {
        for kv in event.key_values.iter() {
            // inbuxa: 1.0 events list their addresses (to = [...]), so a
            // list's strings are indexed like single values
            let texts = match &kv.value {
                TraceValue::String(v) => vec![v.value.clone()],
                TraceValue::UnsignedInt(v) => vec![v.value.to_string()],
                TraceValue::IpAddr(v) => vec![v.value.to_string()],
                TraceValue::List(list) => list
                    .value
                    .iter()
                    .filter_map(|item| match item {
                        TraceValue::String(v) => Some(v.value.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => continue,
            };
            for text in texts {
                match kv.key {
                    Key::QueueId => {
                        let Ok(queue_id) = text.parse::<u64>() else {
                            continue;
                        };
                        if wants(TracingSearchField::QueueId) && !queue_id_indexed {
                            document.index_unsigned(TracingSearchField::QueueId, queue_id);
                            queue_id_indexed = true;
                        }
                        if wants(TracingSearchField::Keywords) && seen.insert(format!("k:{text}")) {
                            document.index_text(
                                TracingSearchField::Keywords,
                                &text,
                                nlp::language::Language::None,
                            );
                        }
                    }
                    Key::From
                    | Key::To
                    | Key::Domain
                    | Key::Hostname
                    | Key::RemoteIp
                    | Key::MessageId
                    | Key::AccountName
                        if wants(TracingSearchField::Keywords) =>
                    {
                        let text = text.to_lowercase();
                        if seen.insert(format!("k:{text}")) {
                            document.index_text(
                                TracingSearchField::Keywords,
                                &text,
                                nlp::language::Language::None,
                            );
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
    }
    document
}
