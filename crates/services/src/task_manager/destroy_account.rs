/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::task_manager::{TaskResult, deferred_retry_time};
use common::Server;
use email::{message::metadata::MessageMetadata, sieve::SieveScript};
use groupware::file::FileNode;
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{ArchivedItem, SpamTrainingSample, Task, TaskDestroyAccount},
    },
    types::EnumImpl,
};
use store::{
    Deserialize, IterateParams, SerializeInfallible, U64_LEN, ValueKey,
    registry::RegistryQuery,
    search::SearchQuery,
    write::{
        BatchBuilder, BlobLink, BlobOp, RegistryClass, SearchIndex, TaskQueueClass, ValueClass,
        key::DeserializeBigEndian,
    },
};
use trc::AddContext;
use types::{
    blob_hash::BlobHash,
    collection::Collection,
    field::{EmailField, Field},
    id::Id,
};

pub(crate) trait DestroyAccountTask: Sync + Send {
    fn destroy_account(&self, task: &TaskDestroyAccount)
    -> impl Future<Output = TaskResult> + Send;
}

impl DestroyAccountTask for Server {
    async fn destroy_account(&self, task: &TaskDestroyAccount) -> TaskResult {
        match destroy_account(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::deferred(deferred_retry_time(&err), err.to_string());
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .details("Failed to destroy account")
                );
                result
            }
        }
    }
}

async fn destroy_account(server: &Server, task: &TaskDestroyAccount) -> trc::Result<TaskResult> {
    let account_id = task.account_id.document_id();

    // inbuxa: LH-8, LH-10: a kept account waits for its time, and a held one
    // for its release; "destroy now" clears the kept record first
    let kept = inbuxa_features::undelete::data::kept_account(&server.core.storage.data, account_id)
        .await?;
    if let Some(kept) = &kept {
        let now = store::write::now();
        let held = inbuxa_features::hold::is_held_until(kept.kept_until)
            || server.is_kept_held(account_id, kept).await?;
        if held || kept.kept_until > now {
            let retry = if held { now + 86_400 } else { kept.kept_until };
            return Ok(TaskResult::deferred(
                Some(retry),
                "The account is still kept: a legal hold applies, or its time hasn't come.",
            ));
        }
    }

    // Destroy public keys and masked emails
    for object in [ObjectType::PublicKey, ObjectType::MaskedEmail] {
        let mut batch = BatchBuilder::new();
        let ids = server
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(object).with_account(account_id))
            .await?;
        let object_id = object.to_id();

        for id in ids {
            batch
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id: id.id(),
                }))
                .clear(ValueClass::Registry(RegistryClass::IndexId {
                    object_id,
                    item_id: id.id(),
                }))
                .clear(ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId as u16,
                    object_id,
                    item_id: id.id(),
                    key: (account_id as u64).serialize(),
                }))
                .clear(ValueClass::Registry(RegistryClass::Reference {
                    to_object_id: ObjectType::Account as u16,
                    to_item_id: account_id as u64,
                    from_object_id: object_id,
                    from_item_id: id.id(),
                }));
        }

        if !batch.is_empty() {
            server.store().write(batch.build_all()).await?;
        }
    }

    // inbuxa: UD-15: the account's hold and undelete's own records go first
    inbuxa_features::undelete::accounts::forget(
        &server.core.storage.data,
        server.registry(),
        account_id,
    )
    .await?;

    // inbuxa: passkeys spec, PK-16: its passkeys and user handle go too
    inbuxa_features::passkey::forget_account(&server.core.storage.data, account_id).await?;

    // Remove archived items
    let mut batch = BatchBuilder::new();
    let ids = server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::ArchivedItem).with_account(account_id))
        .await?;
    for id in ids {
        let object_id = ObjectType::ArchivedItem.to_id();
        let item_id = id.id();

        if let Some(item) = server
            .store()
            .get_value::<ArchivedItem>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id,
            })))
            .await?
        {
            let until = item.archived_until().timestamp() as u64;
            let blob_hash = item.into_blob_id().hash;

            batch
                .with_account_id(account_id)
                .clear(BlobOp::Link {
                    hash: blob_hash,
                    to: BlobLink::Temporary { until },
                })
                .clear(ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId.to_id(),
                    object_id,
                    item_id,
                    key: (account_id as u64).serialize(),
                }))
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id,
                }));
        }
    }
    if !batch.is_empty() {
        server.store().write(batch.build_all()).await?;
    }

    // inbuxa: its spam training samples go too, with the links that kept
    // their messages; otherwise both stayed until the sample's hold ended
    // (holdSamplesFor, 90 days by default), and the notes that would have
    // ended a hold early went with undelete's records above
    let mut batch = BatchBuilder::new();
    let object_id = ObjectType::SpamTrainingSample.to_id();
    let ids = server
        .registry()
        .query::<Vec<Id>>(
            RegistryQuery::new(ObjectType::SpamTrainingSample).with_account(account_id),
        )
        .await?;
    for id in ids {
        let item_id = id.id();
        if batch.is_large_batch() {
            server
                .store()
                .write(std::mem::take(&mut batch).build_all())
                .await?;
        }
        if let Some(sample) = server
            .store()
            .get_value::<SpamTrainingSample>(ValueKey::from(ValueClass::Registry(
                RegistryClass::Item { object_id, item_id },
            )))
            .await?
        {
            batch.with_account_id(account_id).clear(BlobOp::Link {
                hash: sample.blob_id.hash,
                to: BlobLink::Temporary {
                    until: sample.expires_at.timestamp() as u64,
                },
            });
        }
        batch
            .clear(ValueClass::Registry(RegistryClass::Index {
                index_id: Property::AccountId.to_id(),
                object_id,
                item_id,
                key: (account_id as u64).serialize(),
            }))
            .clear(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id,
            }));
    }
    if !batch.is_empty() {
        server.store().write(batch.build_all()).await?;
    }

    // Unlink all accounts's blobs
    destroy_account_blobs(server, account_id).await?;

    // inbuxa: #562: its calendar alarms would still fire, and fail, later
    destroy_account_alarms(server, account_id).await?;

    // inbuxa: MT-20: what the account stored leaves its tenant's usage with
    // it. Read before the data goes and taken off after, so a retry after a
    // failed destroy (the counter still there) or a finished one (gone, so
    // zero) takes it off once.
    let tenant_id = match &kept {
        Some(kept) => kept.member_tenant_id.map(|id| id as u32),
        None => server
            .registry()
            .object::<registry::schema::structs::Domain>(task.account_domain_id)
            .await?
            .and_then(|domain| domain.member_tenant_id)
            .map(|id| id.document_id()),
    };
    let used = server.get_used_quota_account(account_id).await?.max(0);

    #[cfg(feature = "test_mode")]
    if test_hooks::take(account_id) {
        super::index::index_emails_now(server, account_id).await?;
    }

    // Destroy account data
    server
        .store()
        .danger_destroy_account(account_id)
        .await
        .caused_by(trc::location!())?;

    // Remove search index
    // inbuxa: after the data, so an index task that ran while the account
    // was being destroyed can't have written any of it back
    for index in [
        SearchIndex::Email,
        SearchIndex::Contacts,
        SearchIndex::Calendar,
    ] {
        server
            .search_store()
            .unindex(SearchQuery::new(index).with_account_id(account_id))
            .await?;
    }

    if let Some(tenant_id) = tenant_id
        && used > 0
    {
        let mut batch = BatchBuilder::new();
        batch.add(ValueClass::TenantQuota(tenant_id), -used);
        server
            .core
            .storage
            .data
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(TaskResult::Success(vec![]))
}

/// inbuxa: tests only: an index task that runs while an account is being
/// destroyed, just before its data goes.
#[cfg(feature = "test_mode")]
pub mod test_hooks {
    static INDEX_WHILE_DESTROYING: std::sync::Mutex<Vec<u32>> = std::sync::Mutex::new(Vec::new());

    /// The account's emails are indexed once more during its destruction.
    pub fn index_while_destroying(account_id: u32) {
        INDEX_WHILE_DESTROYING.lock().unwrap().push(account_id);
    }

    /// Whether that is still to happen for the account.
    pub fn is_pending(account_id: u32) -> bool {
        INDEX_WHILE_DESTROYING.lock().unwrap().contains(&account_id)
    }

    pub(super) fn take(account_id: u32) -> bool {
        let mut accounts = INDEX_WHILE_DESTROYING.lock().unwrap();
        if let Some(pos) = accounts.iter().position(|id| *id == account_id) {
            accounts.swap_remove(pos);
            true
        } else {
            false
        }
    }
}

/// inbuxa: #562: removes the account's queued calendar alarms. Each is
/// keyed by its account and event (see `CalendarAlarm::build_write_ops`), so
/// only that id range is read, and only alarm tasks of this account are taken:
/// other tasks use generated ids that could fall in the same range.
async fn destroy_account_alarms(server: &Server, account_id: u32) -> trc::Result<()> {
    let mut alarms = Vec::new();
    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task {
                    id: Id::from_parts(account_id, 0).id(),
                })),
                ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task {
                    id: Id::from_parts(account_id, u32::MAX).id(),
                })),
            )
            .ascending(),
            |key, value| {
                // a row that can't be read is left for the task manager
                let Ok(task) = Task::deserialize(value) else {
                    return Ok(true);
                };
                let task_account_id = match &task {
                    Task::CalendarAlarmEmail(task) => task.account_id,
                    Task::CalendarAlarmNotification(task) => task.account_id,
                    _ => return Ok(true),
                };
                if task_account_id.document_id() == account_id {
                    alarms.push((key.deserialize_be_u64(U64_LEN)?, task.due_timestamp()));
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let mut batch = BatchBuilder::new();
    for (id, due) in alarms {
        if batch.is_large_batch() {
            server
                .store()
                .write(std::mem::take(&mut batch).build_all())
                .await
                .caused_by(trc::location!())?;
        }
        batch
            .clear(ValueClass::TaskQueue(TaskQueueClass::Task { id }))
            .clear(ValueClass::TaskQueue(TaskQueueClass::Due { id, due }));
    }
    if !batch.is_empty() {
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(())
}

pub async fn destroy_account_blobs(server: &Server, account_id: u32) -> trc::Result<()> {
    let mut delete_keys = Vec::new();
    for (collection, field) in [
        (Collection::Email, u8::from(EmailField::Metadata)),
        (Collection::FileNode, u8::from(Field::ARCHIVE)),
        (Collection::SieveScript, u8::from(Field::ARCHIVE)),
    ] {
        server
            .all_archives(account_id, collection, field, |document_id, archive| {
                match collection {
                    Collection::Email => {
                        let message = archive.unarchive::<MessageMetadata>()?;
                        delete_keys.push((
                            collection,
                            document_id,
                            BlobHash::from(&message.blob_hash),
                        ));
                    }
                    Collection::FileNode => {
                        if let Some(file) = archive.unarchive::<FileNode>()?.file.as_ref() {
                            delete_keys.push((
                                collection,
                                document_id,
                                BlobHash::from(&file.blob_hash),
                            ));
                        }
                    }
                    Collection::SieveScript => {
                        let sieve = archive.unarchive::<SieveScript>()?;
                        delete_keys.push((
                            collection,
                            document_id,
                            BlobHash::from(&sieve.blob_hash),
                        ));
                    }
                    _ => {}
                }
                Ok(())
            })
            .await
            .caused_by(trc::location!())?;
    }

    let mut batch = BatchBuilder::new();
    batch.with_account_id(account_id);

    for (collection, document_id, hash) in delete_keys {
        if batch.is_large_batch() {
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            batch = BatchBuilder::new();
            batch.with_account_id(account_id);
        }
        batch
            .with_collection(collection)
            .with_document(document_id)
            .clear(ValueClass::Blob(BlobOp::Link {
                hash,
                to: BlobLink::Document,
            }));
    }

    if !batch.is_empty() {
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(())
}
