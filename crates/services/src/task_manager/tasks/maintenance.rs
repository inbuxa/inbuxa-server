/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    index_queue::reindex::reindex_account,
    task_manager::{outcome::Outcome, tasks::rebuild_shares::RebuildSharesTask},
};
use common::{
    KV_ACME, KV_GREYLIST, KV_LOCK_DAV, KV_LOCK_QUEUE_MESSAGE, KV_LOCK_TASK, KV_OAUTH,
    KV_OAUTH_CIMD, KV_QUOTA_BLOB, KV_RATE_LIMIT_AUTH, KV_RATE_LIMIT_CIMD, KV_RATE_LIMIT_CONTACT,
    KV_RATE_LIMIT_HTTP_ANONYMOUS, KV_RATE_LIMIT_HTTP_AUTHENTICATED, KV_RATE_LIMIT_IMAP,
    KV_RATE_LIMIT_LOITER, KV_RATE_LIMIT_RCPT, KV_RATE_LIMIT_SCAN, KV_RATE_LIMIT_SMTP, Server,
    storage::index::ObjectIndexBuilder,
};
use email::{
    cache::MessageCacheFetch,
    message::{
        delete::EmailDeletion,
        messagedata::{EmailMessageData, MessageData, PendingMessageData},
    },
    sieve::SieveScript,
};
use groupware::{
    calendar::{Calendar, CalendarEvent, CalendarEventNotification},
    contact::{AddressBook, ContactCard},
    file::FileNode,
};
use registry::{
    schema::{
        enums::{
            StorageQuota, TaskAccountMaintenanceType, TaskStoreMaintenanceType,
            TaskTenantMaintenanceType,
        },
        prelude::{Object, ObjectInner, ObjectType, Property},
        structs::{
            Task, TaskAccountMaintenance, TaskStatus, TaskStoreMaintenance, TaskTenantMaintenance,
        },
    },
    types::EnumImpl,
};
use smtp::reporting::index::ExternalReportIndex;
use std::time::Instant;
use store::{
    IterateParams, ValueKey,
    rand::{self},
    registry::{RegistryFilter, RegistryQuery},
    roaring::RoaringBitmap,
    write::{
        Archive, ArchiveBytes, BatchBuilder, RegistryClass, TelemetryClass, ValueClass,
        key::DeserializeBigEndian, now,
    },
};
use trc::{AddContext, StoreEvent};
use types::{
    collection::Collection,
    field::{EmailField, Field, MailboxField},
    id::Id,
};

pub(crate) trait MaintenanceTask: Sync + Send {
    fn store_maintenance(
        &self,
        task: &TaskStoreMaintenance,
    ) -> impl Future<Output = Outcome> + Send;
    fn account_maintenance(
        &self,
        task: &TaskAccountMaintenance,
    ) -> impl Future<Output = Outcome> + Send;
    // inbuxa: MT-21
    fn tenant_maintenance(
        &self,
        task: &TaskTenantMaintenance,
    ) -> impl Future<Output = Outcome> + Send;
}

impl MaintenanceTask for Server {
    async fn store_maintenance(&self, task: &TaskStoreMaintenance) -> Outcome {
        match store_maintenance(self, task).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let result = Outcome::error(&err);
                trc::error!(err.details("Failed to perform store maintenance task"));
                result
            }
        }
    }

    async fn account_maintenance(&self, task: &TaskAccountMaintenance) -> Outcome {
        match account_maintenance(self, task).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let result = Outcome::error(&err);
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .details("Failed to perform account maintenance task")
                );
                result
            }
        }
    }

    async fn tenant_maintenance(&self, task: &TaskTenantMaintenance) -> Outcome {
        match tenant_maintenance(self, task).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let result = Outcome::error(&err);
                trc::error!(err.details("Failed to perform tenant maintenance task"));
                result
            }
        }
    }
}

async fn store_maintenance(server: &Server, task: &TaskStoreMaintenance) -> trc::Result<Outcome> {
    match task.maintenance_type {
        TaskStoreMaintenanceType::ReindexAccounts
        | TaskStoreMaintenanceType::PurgeAccounts
        | TaskStoreMaintenanceType::ResetUserQuotas => {
            let mut batch = BatchBuilder::new();
            let now = now() as i64;
            let maintenance_type = match task.maintenance_type {
                TaskStoreMaintenanceType::ReindexAccounts => TaskAccountMaintenanceType::Reindex,
                TaskStoreMaintenanceType::PurgeAccounts => TaskAccountMaintenanceType::Purge,
                TaskStoreMaintenanceType::ResetUserQuotas => {
                    TaskAccountMaintenanceType::RecalculateQuota
                }
                _ => unreachable!(),
            };
            for account_id in server
                .registry()
                .query::<RoaringBitmap>(RegistryQuery::new(ObjectType::Account))
                .await?
            {
                #[cfg(inbuxa_tests)]
                let status = TaskStatus::at(now);

                #[cfg(not(inbuxa_tests))]
                let status =
                    TaskStatus::at(now + rand::RngExt::random_range(&mut rand::rng(), 0..=300));

                batch.schedule_task(Task::AccountMaintenance(TaskAccountMaintenance {
                    account_id: account_id.into(),
                    maintenance_type,
                    status,
                }));

                if batch.is_large_batch() {
                    server.commit_batch(batch).await?;
                    batch = BatchBuilder::new();
                }
            }

            if !batch.is_empty() {
                server.commit_batch(batch).await?;
            }
        }
        // inbuxa: MON-16: every stored trace back into the search index
        TaskStoreMaintenanceType::ReindexTelemetry => {
            reindex_telemetry(server).await?;
        }
        TaskStoreMaintenanceType::PurgeData => {
            // Delete expired external reports
            let now = now();
            let mut batch = BatchBuilder::new();
            for object in [
                ObjectType::DmarcExternalReport,
                ObjectType::TlsExternalReport,
                ObjectType::ArfExternalReport,
            ] {
                let ids = server
                    .registry()
                    .query::<Vec<Id>>(RegistryQuery::new(object).filter(RegistryFilter::less_than(
                        Property::ExpiresAt,
                        now,
                        false,
                    )))
                    .await?;
                let object_id = object.to_id();
                for id in ids {
                    let item_id = id.id();
                    if let Some(report) = server
                        .store()
                        .get_value::<Object>(ValueKey::from(ValueClass::Registry(
                            RegistryClass::Item { object_id, item_id },
                        )))
                        .await?
                    {
                        match &report.inner {
                            ObjectInner::DmarcExternalReport(report) => {
                                report.write_ops(&mut batch, item_id, false);
                            }
                            ObjectInner::TlsExternalReport(report) => {
                                report.write_ops(&mut batch, item_id, false);
                            }
                            ObjectInner::ArfExternalReport(report) => {
                                report.write_ops(&mut batch, item_id, false);
                            }
                            _ => {}
                        }

                        if batch.is_large_batch() {
                            server.store().write_batch(&mut batch).await?;
                            batch = BatchBuilder::new();
                        }
                    }
                }
            }
            if !batch.is_empty() {
                server.store().write_batch(&mut batch).await?;
            }

            let started = Instant::now();

            server
                .store()
                .purge_store()
                .await
                .caused_by(trc::location!())?;

            // inbuxa: expired keys, locks and counters kept in the data
            // store (1.0 dropped this in-memory store)
            server
                .in_memory_store()
                .purge_in_memory_store()
                .await
                .caused_by(trc::location!())?;

            server
                .registry()
                .purge_dead_nodes()
                .await
                .caused_by(trc::location!())?;

            // inbuxa: UD-13: archived items past their deadline go
            inbuxa_features::undelete::records::remove_expired(
                &server.core.storage.data,
                server.registry(),
            )
            .await
            .caused_by(trc::location!())?;

            use common::telemetry::metrics::store::MetricsStore;
            // inbuxa: MON-17, MON-38: history past its retention goes; a
            // failure leaves it for the next run
            let retention = common::telemetry::metrics::store::retention(server).await;
            if let Some(keep) = retention.hold_metrics_for
                && !server.metrics_store().is_none()
                && let Err(err) = server
                    .metrics_store()
                    .purge_metrics(keep.into_inner())
                    .await
            {
                trc::error!(err.details("Failed to purge metric history"));
            }
            if let Some(keep) = retention.hold_traces_for
                && !server.tracing_store().is_none()
            {
                use common::telemetry::tracers::store::TracingStore;
                if let Err(err) = server
                    .tracing_store()
                    .purge_spans(keep.into_inner(), Some(server.search_store()))
                    .await
                {
                    trc::error!(err.details("Failed to purge trace history"));
                }
            }

            // inbuxa: AL-7: locks' grants reach folders the server made on
            // its own (a Sieve fileinto :create)
            if let Err(err) = email::inbuxa_lock::reconcile_all(server).await {
                trc::error!(err.details("Failed to re-apply account locks"));
            }

            // inbuxa: personal-data catalog: the inventory's daily look for
            // a change, and snapshots past the audit log's retention go
            if let Err(err) = server
                .inventory_snapshot(inbuxa_features::privacy::snapshot::Trigger::Daily)
                .await
            {
                trc::error!(err.details("Failed to record an inventory snapshot"));
            }
            if let Err(err) = server.purge_inventory_snapshots().await {
                trc::error!(err.details("Failed to purge inventory snapshots"));
            }

            // inbuxa: personal-data catalog, D2: bans past their period go
            if let Err(err) = server.purge_expired_blocked_ips().await {
                trc::error!(err.details("Failed to purge expired IP bans"));
            }

            // inbuxa: DLP, §2.6: mail nobody reviewed in time goes back
            if let Err(err) = smtp::queue::held::expire(server).await {
                trc::error!(err.details("Failed to return unreviewed held mail"));
            }

            // inbuxa: journaling, JR-13: entries past their retention go,
            // except those a legal hold keeps
            if let Err(err) = purge_journal(server).await {
                trc::error!(err.details("Failed to purge journal entries"));
            }

            // inbuxa: AU-7: audit records past their retention go; a
            // failure leaves them for the next run
            if let Err(err) = server.audit_purge().await {
                trc::error!(err.details("Failed to purge audit records"));
            }

            trc::event!(
                Store(StoreEvent::DataStorePurged),
                Elapsed = started.elapsed()
            );
        }
        TaskStoreMaintenanceType::PurgeBlob => {
            if let Some(shard_index) = task.shard_index {
                server
                    .store()
                    .purge_blobs(server.blob_store().clone(), shard_index as u8)
                    .await
                    .caused_by(trc::location!())?;
            } else {
                let mut batch = BatchBuilder::new();
                let now = now() as i64;
                for shard_index in 0..=u8::MAX {
                    batch.schedule_task(Task::StoreMaintenance(TaskStoreMaintenance {
                        maintenance_type: TaskStoreMaintenanceType::PurgeBlob,
                        shard_index: Some(shard_index as u64),
                        status: TaskStatus::at(now),
                    }));

                    if batch.is_large_batch() {
                        server.commit_batch(batch).await?;
                        batch = BatchBuilder::new();
                    }
                }

                if !batch.is_empty() {
                    server.commit_batch(batch).await?;
                }
            }
        }
        TaskStoreMaintenanceType::RemoveGreylist
        | TaskStoreMaintenanceType::RemoveLockQueueMessage
        | TaskStoreMaintenanceType::RemoveLockTask
        | TaskStoreMaintenanceType::RemoveLockDav
        | TaskStoreMaintenanceType::ResetRateLimiters
        | TaskStoreMaintenanceType::ResetBlobQuotas
        | TaskStoreMaintenanceType::RemoveAuthTokens => {
            #[cfg(inbuxa_tests)]
            if let Some(test_var) = task.shard_index {
                use crate::task_manager::outcome::{Failure, RetryClass};

                return Ok(match test_var {
                    0 => Outcome::done(),
                    1 => Outcome::transient("Simulated temporary failure"),
                    2 => Outcome::fatal("Simulated permanent failure"),
                    3 => panic!("Simulated task panic"),
                    4 => Outcome::Obsolete("Simulated obsolete task"),
                    5 => {
                        Outcome::Retry(Failure::new(RetryClass::Contention, "Simulated contention"))
                    }
                    retry_at => Outcome::Retry(Failure::new(
                        RetryClass::Throttled { retry_at },
                        "Simulated throttled failure",
                    )),
                });
            }

            let prefixes = match task.maintenance_type {
                TaskStoreMaintenanceType::RemoveGreylist => &[KV_GREYLIST][..],
                TaskStoreMaintenanceType::RemoveLockQueueMessage => &[KV_LOCK_QUEUE_MESSAGE][..],
                TaskStoreMaintenanceType::RemoveLockTask => &[KV_LOCK_TASK][..],
                TaskStoreMaintenanceType::RemoveLockDav => &[KV_LOCK_DAV][..],
                TaskStoreMaintenanceType::ResetRateLimiters => &[
                    KV_RATE_LIMIT_RCPT,
                    KV_RATE_LIMIT_SCAN,
                    KV_RATE_LIMIT_LOITER,
                    KV_RATE_LIMIT_AUTH,
                    KV_RATE_LIMIT_SMTP,
                    KV_RATE_LIMIT_CONTACT,
                    KV_RATE_LIMIT_HTTP_AUTHENTICATED,
                    KV_RATE_LIMIT_HTTP_ANONYMOUS,
                    KV_RATE_LIMIT_IMAP,
                    KV_RATE_LIMIT_CIMD,
                ][..],
                TaskStoreMaintenanceType::ResetBlobQuotas => &[KV_QUOTA_BLOB][..],
                TaskStoreMaintenanceType::RemoveAuthTokens => {
                    &[KV_ACME, KV_OAUTH, KV_OAUTH_CIMD][..]
                }
                _ => unreachable!(),
            };

            for &prefix in prefixes {
                server
                    .in_memory_store()
                    .key_delete_prefix(&[prefix])
                    .await?;
            }
        }
        // inbuxa: MT-21: recompute every tenant's usage
        TaskStoreMaintenanceType::ResetTenantQuotas => {
            for tenant_id in inbuxa_features::tenancy::quota::all_tenants(server.registry()).await?
            {
                recalculate_tenant_quota(server, tenant_id).await?;
            }
        }
    }

    Ok(Outcome::done())
}

/// inbuxa: MON-16: queues every stored trace for indexing (1.0 dropped the
/// tracing store, and with it this task).
async fn reindex_telemetry(server: &Server) -> trc::Result<()> {
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
    for span_id in spans {
        batch.queue_trace_index(span_id);
        if batch.is_large_batch() {
            server.store().write_batch(&mut batch).await?;
            batch = BatchBuilder::new();
        }
    }
    if !batch.is_empty() {
        server.store().write_batch(&mut batch).await?;
    }
    Ok(())
}

/// inbuxa: journaling, JR-13: removes journal entries past their
/// retention, keeping any whose sender or recipients a legal hold covers
/// (deleted accounts a hold keeps included), and records how many went.
async fn purge_journal(server: &Server) -> trc::Result<()> {
    use inbuxa_features::audit::{Action, Actor, Outcome, Record, Target};
    let mut held = server.held_accounts().await?;
    if !held.is_empty() {
        for (account_id, kept) in
            inbuxa_features::undelete::data::kept_accounts(server.store()).await?
        {
            if server.is_kept_held(account_id, &kept).await? {
                held.insert(account_id);
            }
        }
    }
    let at = store::write::now();
    let purged = inbuxa_features::journal::entries::purge(server.store(), at, |entry| {
        entry.accounts.iter().any(|account| held.contains(account))
    })
    .await?;
    if purged.removed > 0 || purged.kept_for_hold > 0 {
        server
            .audit_note(Record {
                at: at * 1000,
                actor: Actor::system("Journal"),
                via: None,
                remote_ip: None,
                action: Action::Destroy,
                target: Target {
                    kind: "inbuxa:JournalEntry".into(),
                    id: None,
                    name: None,
                    account_id: None,
                    tenant_id: None,
                },
                changes: vec![],
                details: Some(format!(
                    "{} past their retention removed; {} kept for a legal hold",
                    purged.removed, purged.kept_for_hold
                )),
                reason: None,
                outcome: Outcome::success(),
            })
            .await;
    }
    Ok(())
}

async fn account_maintenance(
    server: &Server,
    task: &TaskAccountMaintenance,
) -> trc::Result<Outcome> {
    match task.maintenance_type {
        TaskAccountMaintenanceType::Purge => {
            server.purge_account(task.account_id.document_id()).await?;
        }
        TaskAccountMaintenanceType::Reindex => {
            reindex_account(server, task.account_id.document_id()).await?;
        }
        TaskAccountMaintenanceType::RecalculateImapUid => {
            reset_imap_uids(server, task.account_id.document_id()).await?;
        }
        TaskAccountMaintenanceType::RecalculateQuota => {
            recalculate_quota(server, task.account_id.document_id()).await?;
        }
        TaskAccountMaintenanceType::RebuildShares => {
            server.rebuild_shares(task.account_id.document_id()).await?;
        }
    }

    Ok(Outcome::done())
}

// inbuxa: MT-21
async fn tenant_maintenance(
    server: &Server,
    task: &TaskTenantMaintenance,
) -> trc::Result<Outcome> {
    match task.maintenance_type {
        TaskTenantMaintenanceType::RecalculateQuota => {
            recalculate_tenant_quota(server, task.tenant_id.document_id()).await?;
        }
    }

    Ok(Outcome::done())
}

// inbuxa: MT-21: recompute a tenant's usage from its members'
async fn recalculate_tenant_quota(server: &Server, tenant_id: u32) -> trc::Result<()> {
    inbuxa_features::tenancy::quota::recalculate(
        &server.core.storage.data,
        server.registry(),
        tenant_id,
    )
    .await
    .map(|_| ())
}

async fn recalculate_quota(server: &Server, account_id: u32) -> trc::Result<()> {
    let mut quota = 0;
    let mut emails = 0;
    let mut events = 0;
    let mut notifications = 0;
    let mut submissions = 0;

    server
        .message_datas(account_id, &(), |_, data| {
            quota += data.size as i64;
            emails += 1;
            Ok(true)
        })
        .await
        .caused_by(trc::location!())?;

    for collection in [
        Collection::Calendar,
        Collection::CalendarEvent,
        Collection::CalendarEventNotification,
        Collection::AddressBook,
        Collection::ContactCard,
        Collection::FileNode,
        Collection::SieveScript,
        Collection::EmailSubmission,
    ] {
        server
            .archives(account_id, collection, Field::ARCHIVE, &(), |_, archive| {
                match collection {
                    Collection::Calendar => {
                        quota += archive.unarchive::<Calendar>()?.size() as i64;
                    }
                    Collection::CalendarEvent => {
                        quota += archive.unarchive::<CalendarEvent>()?.size.to_native() as i64;
                        events += 1;
                    }
                    Collection::CalendarEventNotification => {
                        quota += archive
                            .unarchive::<CalendarEventNotification>()?
                            .size
                            .to_native() as i64;
                        notifications += 1;
                    }
                    Collection::EmailSubmission => {
                        submissions += 1;
                    }
                    Collection::AddressBook => {
                        quota += archive.unarchive::<AddressBook>()?.size() as i64;
                    }
                    Collection::ContactCard => {
                        quota += archive.unarchive::<ContactCard>()?.size.to_native() as i64;
                    }
                    Collection::FileNode => {
                        quota += archive.unarchive::<FileNode>()?.size() as i64;
                    }
                    Collection::SieveScript => {
                        quota += u32::from(archive.unarchive::<SieveScript>()?.size) as i64;
                    }
                    _ => {}
                }
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
    }

    quota += server
        .metadata_used_quota(account_id)
        .await
        .caused_by(trc::location!())?;

    let mut batch = BatchBuilder::new();
    batch.with_account_id(account_id);
    for (object, count) in [
        (StorageQuota::MaxEmails, emails),
        (StorageQuota::MaxEmailSubmissions, submissions),
        (StorageQuota::MaxCalendarEvents, events),
        (StorageQuota::MaxCalendarEventNotifications, notifications),
    ] {
        batch
            .clear(ValueClass::ObjectCount(object))
            .add(ValueClass::ObjectCount(object), count);
    }
    batch.clear(ValueClass::Quota).add(ValueClass::Quota, quota);
    server
        .store()
        .write_batch(&mut batch)
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}


async fn reset_imap_uids(server: &Server, account_id: u32) -> trc::Result<(u32, u32)> {
    let mut mailbox_count = 0;
    let mut email_count = 0;

    let cache = server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?;

    for &mailbox_id in cache.mailboxes.index.keys() {
        let mailbox = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::Mailbox,
                mailbox_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| trc::ImapEvent::Error.into_err().caused_by(trc::location!()))?
            .into_deserialized::<email::mailbox::Mailbox>()
            .caused_by(trc::location!())?;
        let mut new_mailbox = mailbox.inner.clone();
        new_mailbox.uid_validity = rand::random::<u32>();
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Mailbox)
            .with_document(mailbox_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(mailbox)
                    .with_changes(new_mailbox),
            )
            .caused_by(trc::location!())?
            .clear(MailboxField::UidCounter);
        server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
        mailbox_count += 1;
    }

    // Reset all UIDs
    for message_id in cache.emails.iter().map(|i| i.document_id()) {
        let Some(data) = server
            .store()
            .get_value::<MessageData>(ValueKey::archive(account_id, Collection::Email, message_id))
            .await
            .caused_by(trc::location!())?
        else {
            continue;
        };
        let mut new_data = data.clone();
        for uid_mailbox in new_data.mailboxes.iter_mut() {
            uid_mailbox.uid = 0;
        }

        // Prepare write batch
        let mut batch = BatchBuilder::new();
        let uid_slots =
            batch.reserve_uids(account_id, new_data.mailboxes.iter().map(|m| m.mailbox_id));
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email)
            .with_document(message_id)
            .assert_value(
                ValueClass::Property(EmailField::Archive.into()),
                data.change_id,
            )
            .set(
                EmailField::Archive,
                PendingMessageData {
                    data: new_data,
                    uid_slots,
                    thread_slot: None,
                    change_id: Some(data.change_id),
                },
            );
        server
            .store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
        email_count += 1;
    }

    Ok((mailbox_count, email_count))
}
