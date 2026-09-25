/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::task_manager::acme::AcmeTask;
use crate::task_manager::alarm::SendAlarmTask;
use crate::task_manager::destroy_account::DestroyAccountTask;
use crate::task_manager::dkim::DkimManagementTask;
use crate::task_manager::dns::DnsManagementTask;
use crate::task_manager::imip::SendImipTask;
use crate::task_manager::index::SearchIndexTask;
use crate::task_manager::lock::{TaskLockManager, renew_task_locks};
use crate::task_manager::maintenance::MaintenanceTask;
use crate::task_manager::merge_threads::MergeThreadsTask;
use crate::task_manager::report::{self, SubmitReportTask};
use crate::task_manager::restore_item::RestoreItemTask;
use crate::task_manager::spam_classifier::SpamFilterMaintenanceTask;
use crate::task_manager::{
    CLAIM_RECHECK_INTERVAL, Locked, QUEUE_REFRESH_INTERVAL, TaskDetails, TaskFailureType, TaskInfo,
    TaskJob, TaskManagerIpc, TaskResult,
};
use common::BuildServer;
use common::config::network::ClusterRoles;
use common::config::server::{DEFAULT_TLS_TIMEOUT, ServerProtocol};
use common::network::limiter::ConcurrencyLimiter;
use common::network::{ServerInstance, TcpAcceptor};
use common::{Inner, Server};
use registry::schema::enums::TaskType;
use registry::schema::prelude::ObjectType;
use registry::schema::structs::{
    Task, TaskManager, TaskRetryStrategy, TaskStatus, TaskStatusFailed, TaskStatusRetry,
};
use registry::types::datetime::UTCDateTime;
use registry::types::{EnumImpl, ObjectImpl};
use std::collections::hash_map::Entry;
use std::future::Future;
use std::time::Duration;
use std::{sync::Arc, time::Instant};
use store::rand::seq::SliceRandom;
use store::write::key::DeserializeBigEndian;
use store::{
    IterateParams, ValueKey,
    write::{BatchBuilder, TaskQueueClass, ValueClass, assert::AssertValue, now},
};
use store::{SerializeInfallible, U64_LEN, rand};
use tokio::sync::{mpsc, watch};
use trc::TaskManagerEvent;
use utils::snowflake::SnowflakeIdGenerator;

const TASK_QUEUE_BUFFER: usize = 10;
const PERPETUAL_RETRY_MIN_DELAY: u64 = 3600;
const PERPETUAL_RETRY_MAX_DELAY: u64 = 21600;

pub fn spawn_task_manager(inner: Arc<Inner>) {
    // inbuxa: upstream didn't start the task manager on a node whose role
    // had no task types at boot, so adding one later did nothing until a
    // restart. It now always runs and reads the role on every scan and
    // before every job (task_enabled), so a role change applies at the next
    // settings reload.
    let is_clustered = inner.build_server().core.storage.coordinator.is_enabled();

    trc::event!(TaskManager(TaskManagerEvent::ManagerStarted));

    // inbuxa: keep the leases of running tasks alive, every third of a lock
    // lifetime, until the node stops
    {
        let inner = inner.clone();
        tokio::spawn(async move {
            let mut renewed_at = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let locks = &inner.ipc.task_locks;
                if locks.is_stopping() {
                    break;
                }
                if renewed_at.elapsed() >= Duration::from_secs((locks.expiry() / 3).max(1)) {
                    renewed_at = Instant::now();
                    if locks.held() > 0 {
                        renew_task_locks(&inner.build_server()).await;
                    }
                }
            }
        });
    }

    // Create dummy server instance for alarms
    let server_instance = Arc::new(ServerInstance {
        id: "_local".to_string(),
        protocol: ServerProtocol::Smtp,
        acceptor: TcpAcceptor::Plain,
        limiter: ConcurrencyLimiter::new(100),
        tls_timeout: DEFAULT_TLS_TIMEOUT,
        shutdown_rx: watch::channel(false).1,
        proxy_networks: vec![],
        span_id_gen: Arc::new(SnowflakeIdGenerator::new()),
    });

    // Spawn workers for each task type
    let mut txs = Vec::with_capacity(TaskType::COUNT);
    for idx in 0..TaskType::COUNT {
        let task_type = TaskType::from_id(idx as u16).unwrap();
        let channel_capacity = match task_type {
            TaskType::IndexDocument | TaskType::UnindexDocument | TaskType::IndexTrace => {
                std::cmp::max(
                    inner.build_server().core.email.index_batch_size,
                    TASK_QUEUE_BUFFER,
                )
            }
            TaskType::DestroyAccount
            | TaskType::AccountMaintenance
            | TaskType::TenantMaintenance
            | TaskType::StoreMaintenance => 1,
            TaskType::SpamFilterMaintenance => 2,
            TaskType::CalendarAlarmEmail
            | TaskType::CalendarAlarmNotification
            | TaskType::CalendarItipMessage
            | TaskType::MergeThreads
            | TaskType::DmarcReport
            | TaskType::TlsReport
            | TaskType::RestoreArchivedItem
            | TaskType::AcmeRenewal
            | TaskType::DkimManagement
            | TaskType::DnsManagement => TASK_QUEUE_BUFFER,
        };

        let (tx, mut rx) = mpsc::channel::<TaskJob>(channel_capacity);
        txs.push(tx);
        let inner = inner.clone();
        let server_instance = server_instance.clone();

        if matches!(
            task_type,
            TaskType::IndexDocument | TaskType::UnindexDocument | TaskType::IndexTrace,
        ) {
            tokio::spawn(async move {
                while let Some(job) = rx.recv().await {
                    let server = inner.build_server();
                    let batch_size = server.core.email.index_batch_size;
                    let mut batch = Vec::with_capacity(batch_size);
                    if let Some(task) = fetch_enabled_task(&server, job).await {
                        batch.push(task);
                    }

                    while batch.len() < batch_size {
                        match rx.try_recv() {
                            Ok(job) => {
                                if let Some(task) = fetch_enabled_task(&server, job).await {
                                    batch.push(task);
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    if batch.is_empty() {
                        continue;
                    }

                    // Dispatch. inbuxa: on a task of its own, so a panic
                    // releases the batch's locks and leaves this worker
                    // running; a dead worker would keep claiming tasks it
                    // can never run
                    let mut refresh_queue = false;
                    let ids = batch.iter().map(|task| task.info.id).collect::<Vec<_>>();
                    let run = {
                        let server = server.clone();
                        tokio::spawn(async move {
                            let results = server.index(&batch).await;
                            (batch, results)
                        })
                    };
                    match run.await {
                        Ok((mut batch, results)) => {
                            let results = results.into_iter().map(|r| {
                                refresh_queue |= r.result.is_retry();
                                r.result
                            });
                            update_tasks(&server, &mut batch, results).await;
                        }
                        Err(err) => {
                            worker_failed(&server, &ids, err).await;
                            refresh_queue = true;
                        }
                    }

                    if refresh_queue || rx.is_empty() {
                        server.notify_task_queue();
                    }
                }
            });
        } else {
            let server_instance = server_instance.clone();
            tokio::spawn(async move {
                while let Some(job) = rx.recv().await {
                    let server = inner.build_server();
                    let mut refresh_queue = false;

                    if let Some(TaskDetails { task, info }) = fetch_enabled_task(&server, job).await
                    {
                        // inbuxa: on a task of its own, as above
                        let run = {
                            let server = server.clone();
                            let server_instance = server_instance.clone();
                            tokio::spawn(async move {
                                let result = run_task(&server, &task, server_instance).await;
                                (task, result)
                            })
                        };
                        match run.await {
                            Ok((task, result)) => {
                                refresh_queue = result.is_retry();

                                update_tasks(
                                    &server,
                                    &mut [TaskDetails { task, info }],
                                    vec![result],
                                )
                                .await;
                            }
                            Err(err) => {
                                worker_failed(&server, &[info.id], err).await;
                                refresh_queue = true;
                            }
                        }
                    }

                    if refresh_queue || rx.is_empty() {
                        server.notify_task_queue();
                    }
                }
            });
        }
    }

    const REFRESH_INTERVAL: Duration = Duration::from_secs(60);
    tokio::spawn(async move {
        let mut ipc = TaskManagerIpc {
            txs: txs.try_into().expect("Incorrect number of task channels"),
            locked: Default::default(),
            revision: 0,
        };
        let rx = inner.ipc.task_tx.clone();
        loop {
            // Index any queued tasks
            let mut sleep_for = inner.build_server().process_tasks(&mut ipc).await;
            if is_clustered && sleep_for > REFRESH_INTERVAL {
                sleep_for = REFRESH_INTERVAL;
            }

            // Wait for a signal or sleep until the next task is due
            let _ = tokio::time::timeout(sleep_for, rx.notified()).await;
        }
    });
}

pub(crate) trait TaskQueueManager: Sync + Send {
    fn process_tasks(&self, ipc: &mut TaskManagerIpc) -> impl Future<Output = Duration> + Send;
}

impl TaskQueueManager for Server {
    async fn process_tasks(&self, ipc: &mut TaskManagerIpc) -> Duration {
        // inbuxa: a node that is stopping has released its locks and claims
        // nothing new
        let task_locks = &self.inner.ipc.task_locks;
        if task_locks.is_stopping() {
            return Duration::from_secs(QUEUE_REFRESH_INTERVAL);
        }
        // inbuxa: with no task type enabled by this node's role there is
        // nothing to claim; a settings reload wakes the manager when that
        // changes
        let roles = &self.core.network.roles;
        if !(0..TaskType::COUNT as u16)
            .filter_map(TaskType::from_id)
            .any(|task_type| task_enabled(roles, task_type))
        {
            ipc.locked.clear();
            return Duration::from_secs(QUEUE_REFRESH_INTERVAL);
        }
        let lock_expiry = task_locks.expiry();
        let now_timestamp = now();
        let from_key = ValueKey::<ValueClass> {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::TaskQueue(TaskQueueClass::Due { id: 0, due: 1 }),
        };
        let to_key = ValueKey::<ValueClass> {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::TaskQueue(TaskQueueClass::Due {
                id: u64::MAX,
                due: now_timestamp + QUEUE_REFRESH_INTERVAL,
            }),
        };

        // Retrieve tasks pending to be processed
        let mut tasks = Vec::new();
        let mut unreadable = Vec::new();
        let now = Instant::now();
        let mut next_event = None;
        ipc.revision += 1;
        let _ = self
            .store()
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    if key.len() == U64_LEN * 2 {
                        let task_due = key.deserialize_be_u64(0)?;
                        let task_id = key.deserialize_be_u64(U64_LEN)?;

                        if task_due <= now_timestamp {
                            // inbuxa: a row whose task type can't be read is
                            // set aside, not allowed to end the scan: every
                            // task due after it would wait behind it
                            let Some((task_type_idx, task_type)) = value
                                .deserialize_be_u16(0)
                                .ok()
                                .and_then(|idx| TaskType::from_id(idx).map(|typ| (idx, typ)))
                            else {
                                unreadable.push(UnreadableDueRow {
                                    due: task_due,
                                    id: task_id,
                                    value: value.to_vec(),
                                });
                                return Ok(true);
                            };
                            // inbuxa: running here under a lease this node
                            // renews; don't hand it to a worker again
                            if task_locks.is_held(task_id) {
                                return Ok(true);
                            }

                            let enabled = task_enabled(roles, task_type);

                            if !enabled {
                                trc::event!(
                                    TaskManager(TaskManagerEvent::TaskIgnored),
                                    Id = task_id,
                                    Details = task_type.as_str(),
                                    Reason = "Task type is disabled by cluster roles.",
                                );
                                return Ok(true);
                            }

                            match ipc.locked.entry(task_id) {
                                Entry::Occupied(mut entry) => {
                                    let locked = entry.get_mut();
                                    if locked.expires <= now || locked.due < task_due {
                                        locked.expires = Instant::now()
                                            + std::time::Duration::from_secs(lock_expiry + 1);
                                        locked.due = task_due;
                                        tasks.push((
                                            TaskJob {
                                                id: task_id,
                                                due: task_due,
                                                typ: task_type,
                                            },
                                            task_type_idx,
                                        ));
                                    }
                                    locked.revision = ipc.revision;
                                }
                                Entry::Vacant(entry) => {
                                    entry.insert(Locked {
                                        expires: Instant::now()
                                            + std::time::Duration::from_secs(lock_expiry + 1),
                                        due: task_due,
                                        revision: ipc.revision,
                                    });
                                    tasks.push((
                                        TaskJob {
                                            id: task_id,
                                            due: task_due,
                                            typ: task_type,
                                        },
                                        task_type_idx,
                                    ));
                                }
                            }

                            Ok(true)
                        } else {
                            next_event = Some(task_due);
                            Ok(false)
                        }
                    } else {
                        Ok(true)
                    }
                },
            )
            .await
            .map_err(|err| {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to iterate over task queue.")
                );
            });

        if !unreadable.is_empty() && repair_due_rows(self, unreadable).await {
            // Look again at once for the rows that were rewritten
            self.notify_task_queue();
        }

        if !tasks.is_empty() {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskAcquired),
                Total = tasks.len(),
                Details = ipc.locked.len(),
            );
        }

        // Shuffle tasks
        if tasks.len() > 1 {
            tasks.shuffle(&mut rand::rng());
        }

        // Dispatch tasks
        for (task_job, task_type_idx) in tasks {
            let tx = &ipc.txs[task_type_idx as usize];

            if tx.capacity() > 0 {
                let id = task_job.id;
                if !self.try_lock_task(id).await {
                    // inbuxa: another node holds the task. Look again after a
                    // short while rather than a full lock lifetime from now:
                    // the holder may have claimed it after this scan began,
                    // or run on a clock ahead of this one, and waiting the
                    // whole lifetime again would leave the task stuck for
                    // another hour past its lock if that holder died
                    if let Some(locked) = ipc.locked.get_mut(&id) {
                        locked.expires =
                            Instant::now() + Duration::from_secs(claim_recheck_interval(lock_expiry));
                    }
                } else if tx.send(task_job).await.is_err() {
                    trc::event!(
                        Server(trc::ServerEvent::ThreadError),
                        Details = "Error sending task.",
                        CausedBy = trc::location!()
                    );
                    // inbuxa: nothing will run it here, so don't hold it
                    self.remove_index_lock(id).await;
                }
            } else {
                // If the channel is full, release the lock so it can be picked up in the next iteration
                ipc.locked.remove(&task_job.id);
            }
        }

        // Delete expired locks
        let now = Instant::now();
        ipc.locked
            .retain(|_, locked| locked.expires > now && locked.revision == ipc.revision);
        let sleep_for = Duration::from_secs(next_event.map_or(QUEUE_REFRESH_INTERVAL, |timestamp| {
            timestamp.saturating_sub(store::write::now())
        }));

        // inbuxa: wake up when a claim held elsewhere is due to be tried
        // again, rather than only on the next task or refresh
        ipc.locked
            .values()
            .map(|locked| locked.expires.saturating_duration_since(now))
            .min()
            .map_or(sleep_for, |recheck| sleep_for.min(recheck.max(Duration::from_secs(1))))
    }
}

/// inbuxa: whether this node's cluster role lets it run a task type. Upstream
/// checked the dedicated roles (search indexing, account and store
/// maintenance, spam training) and let every node with a task manager run
/// the rest, whatever its taskQueueProcessing setting. Every task type now
/// answers to one ClusterTaskType:
///
/// - IndexDocument, UnindexDocument, IndexTrace: searchIndexing
/// - AccountMaintenance, TenantMaintenance, DestroyAccount: accountMaintenance
/// - StoreMaintenance: storeMaintenance
/// - SpamFilterMaintenance: spamClassifierTraining
/// - DmarcReport, TlsReport: outboundMta. They build and send reports to
///   other domains (TLS reports can go straight to an HTTPS endpoint), which
///   is the outbound MTA's business.
/// - CalendarAlarmEmail, CalendarAlarmNotification, CalendarItipMessage,
///   MergeThreads, RestoreArchivedItem, AcmeRenewal, DkimManagement,
///   DnsManagement: taskQueueProcessing, the role for queue tasks with no
///   role of their own.
///
/// A node that may not run a task leaves it unclaimed, so a node that may
/// picks it up.
pub fn task_enabled(roles: &ClusterRoles, task_type: TaskType) -> bool {
    match task_type {
        TaskType::IndexDocument | TaskType::UnindexDocument | TaskType::IndexTrace => {
            roles.search_indexing
        }
        TaskType::AccountMaintenance | TaskType::TenantMaintenance | TaskType::DestroyAccount => {
            roles.account_maintenance
        }
        TaskType::StoreMaintenance => roles.store_maintenance,
        TaskType::SpamFilterMaintenance => roles.spam_training,
        TaskType::DmarcReport | TaskType::TlsReport => roles.outbound_mta,
        TaskType::CalendarAlarmEmail
        | TaskType::CalendarAlarmNotification
        | TaskType::CalendarItipMessage
        | TaskType::MergeThreads
        | TaskType::RestoreArchivedItem
        | TaskType::AcmeRenewal
        | TaskType::DkimManagement
        | TaskType::DnsManagement => roles.task_manager,
    }
}

async fn run_task(
    server: &Server,
    task: &Task,
    server_instance: Arc<ServerInstance>,
) -> TaskResult {
    match task {
        Task::CalendarAlarmEmail(task) => {
            server.send_email_alarm(task, server_instance.clone()).await
        }
        Task::CalendarAlarmNotification(task) => {
            server.send_display_alarm(task).await
        }
        Task::CalendarItipMessage(task) => {
            server.send_imip(task, server_instance.clone()).await
        }
        Task::MergeThreads(task) => server.merge_threads(task).await,
        Task::DmarcReport(task) => {
            server
                .submit_report(report::ReportId::Dmarc(task.report_id.id()))
                .await
        }
        Task::TlsReport(task) => {
            server
                .submit_report(report::ReportId::Tls(task.report_id.id()))
                .await
        }
        Task::RestoreArchivedItem(task) => server.restore_item(task).await,
        Task::DestroyAccount(task) => server.destroy_account(task).await,
        Task::AccountMaintenance(task) => {
            server.account_maintenance(task).await
        }
        Task::TenantMaintenance(task) => {
            server.tenant_maintenance(task).await
        }
        Task::StoreMaintenance(task) => {
            server.store_maintenance(task).await
        }
        Task::SpamFilterMaintenance(task) => {
            Box::pin(server.spam_filter_maintenance(task)).await
        }
        Task::AcmeRenewal(task) => server.acme_management(task).await,
        Task::DkimManagement(task_dkim_rotation) => {
            server.dkim_management(task_dkim_rotation).await
        }
        Task::DnsManagement(task_dns_management) => {
            server.dns_management(task_dns_management).await
        }
        Task::IndexDocument(_)
        | Task::UnindexDocument(_)
        | Task::IndexTrace(_) => unreachable!(),
    }
}

/// inbuxa: reads a claimed task when this node's role still allows its type.
/// The role may have changed since the task was claimed (a settings reload in
/// between); the claim is then handed back at once for a node that may run
/// it, rather than held until the lease runs out.
async fn fetch_enabled_task(server: &Server, job: TaskJob) -> Option<TaskDetails> {
    if task_enabled(&server.core.network.roles, job.typ) {
        fetch_task(server, job).await
    } else {
        trc::event!(
            TaskManager(TaskManagerEvent::TaskIgnored),
            Id = job.id,
            Details = job.typ.as_str(),
            Reason = "Task type was disabled by cluster roles after it was claimed.",
        );
        server.remove_index_lock(job.id).await;
        None
    }
}

/// Reads a claimed task. When it is gone or can't be read, the claim is
/// released: inbuxa: holding it would block the task, everywhere, until
/// the lock expired.
async fn fetch_task(server: &Server, job: TaskJob) -> Option<TaskDetails> {
    match server
        .store()
        .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task {
            id: job.id,
        })))
        .await
    {
        Ok(Some(task)) => Some(TaskDetails { task, info: job }),
        Ok(None) => {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskIgnored),
                Id = job.id,
                Reason = "Task not found in store, likely already processed.",
            );
            server.remove_index_lock(job.id).await;
            None
        }
        Err(err) => {
            trc::error!(
                err.id(job.id)
                    .details("Failed to retrieve task details.")
                    .caused_by(trc::location!())
            );
            server.remove_index_lock(job.id).await;
            None
        }
    }
}

/// inbuxa: a task panicked: its locks are released so it runs again, here or
/// on another node, and the worker carries on.
async fn worker_failed(server: &Server, ids: &[u64], err: tokio::task::JoinError) {
    trc::event!(
        Server(trc::ServerEvent::ThreadError),
        Details = "Task worker failed",
        Reason = err.to_string(),
        CausedBy = trc::location!()
    );
    for id in ids {
        server.remove_index_lock(*id).await;
    }
}

async fn update_tasks(
    server: &Server,
    tasks: &mut [TaskDetails],
    results: impl IntoIterator<Item = TaskResult>,
) {
    let mut batch = BatchBuilder::new();

    for (task, result) in tasks.iter_mut().zip(results) {
        let id = task.info.id;
        batch.clear(ValueClass::TaskQueue(TaskQueueClass::Due {
            id,
            due: task.info.due,
        }));
        match result {
            TaskResult::Success(tasks) => {
                for task in tasks {
                    batch.schedule_task(task);
                }
                batch.clear(ValueClass::TaskQueue(TaskQueueClass::Task { id }));
            }
            TaskResult::Ignored => {
                batch.clear(ValueClass::TaskQueue(TaskQueueClass::Task { id }));
            }
            TaskResult::Update(ops) => {
                for op in ops {
                    batch.any_op(op);
                }
            }
            TaskResult::Failure {
                typ,
                message,
                max_attempts,
            } => {
                let (attempt_number, retry_since) = match task.task.status() {
                    TaskStatus::Pending(_) => (0, UTCDateTime::now()),
                    TaskStatus::Retry(status) => (status.attempt_number, status.created_at),
                    TaskStatus::Failed(status) => (status.failed_attempt_number, status.failed_at),
                };
                let retry_at = match typ {
                    TaskFailureType::Retry(retry_at) => (attempt_number
                        < max_attempts.unwrap_or(server.core.network.task_manager.max_attempts)
                        && retry_at
                            <= (retry_since.timestamp() as u64).saturating_add(
                                server.core.network.task_manager.total_deadline.as_secs(),
                            ))
                    .then_some(retry_at)
                    .or_else(|| perpetual_retry_time(task.info.typ, attempt_number)),
                    TaskFailureType::Temporary => next_retry_time(
                        &server.core.network.task_manager,
                        max_attempts,
                        retry_since.timestamp() as u64,
                        attempt_number,
                        now(),
                    )
                    .or_else(|| perpetual_retry_time(task.info.typ, attempt_number)),
                    TaskFailureType::Perpetual => {
                        perpetual_retry_time(task.info.typ, attempt_number)
                    }
                    TaskFailureType::Permanent => None,
                };

                let due = if let Some(retry_at) = retry_at {
                    trc::event!(
                        TaskManager(TaskManagerEvent::TaskRetry),
                        Id = id,
                        Details = task.task.name(),
                        Reason = message.to_string(),
                        NextRetry = trc::Value::Timestamp(retry_at),
                    );

                    task.task.set_status(TaskStatus::Retry(TaskStatusRetry {
                        due: UTCDateTime::from_timestamp(retry_at as i64),
                        attempt_number: attempt_number + 1,
                        failure_reason: message,
                        created_at: retry_since,
                    }));

                    retry_at
                } else {
                    trc::event!(
                        TaskManager(TaskManagerEvent::TaskFailed),
                        Id = id,
                        Details = task.task.name(),
                        Reason = message.to_string(),
                    );

                    task.task.set_status(TaskStatus::Failed(TaskStatusFailed {
                        failed_at: UTCDateTime::now(),
                        failed_attempt_number: attempt_number,
                        failure_reason: message,
                        created_at: retry_since,
                    }));
                    u64::MAX
                };
                batch
                    .assert_value(
                        ValueClass::TaskQueue(TaskQueueClass::Task { id }),
                        AssertValue::Some,
                    )
                    .set(
                        ValueClass::TaskQueue(TaskQueueClass::Due { id, due }),
                        task.info.typ.to_id().serialize(),
                    )
                    .set(
                        ValueClass::TaskQueue(TaskQueueClass::Task { id }),
                        task.task.to_pickled_vec(),
                    );
            }
        }
    }

    if let Err(err) = server.store().write(batch.build_all()).await {
        if err.matches(trc::EventType::Store(trc::StoreEvent::AssertValueFailed)) {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskIgnored),
                Reason = "Task was deleted while being processed; skipping update.",
            );
        } else {
            trc::error!(err.details("Failed to remove task(s) from queue."));
        }
    }

    for task in tasks {
        server.remove_index_lock(task.info.id).await;
    }
}

/// inbuxa: how long to wait before trying again to claim a task another node
/// holds: a twelfth of the lock lifetime, so five minutes for the one-hour
/// lock, never more than that and never under a second.
pub(crate) fn claim_recheck_interval(lock_expiry: u64) -> u64 {
    (lock_expiry / 12).clamp(1, CLAIM_RECHECK_INTERVAL)
}

pub fn perpetual_retry_time(typ: TaskType, attempt: u64) -> Option<u64> {
    matches!(
        typ,
        TaskType::AcmeRenewal
            | TaskType::DkimManagement
            | TaskType::IndexDocument
            | TaskType::UnindexDocument
            | TaskType::DestroyAccount
    )
    .then(|| {
        now().saturating_add(
            PERPETUAL_RETRY_MIN_DELAY
                .saturating_mul(1u64 << attempt.min(4))
                .min(PERPETUAL_RETRY_MAX_DELAY),
        )
    })
}

pub fn next_retry_time(
    manager: &TaskManager,
    max_attempts_override: Option<u64>,
    retry_since: u64,
    attempt: u64,
    now: u64,
) -> Option<u64> {
    if attempt >= max_attempts_override.unwrap_or(manager.max_attempts) {
        return None;
    }

    let delay_secs: u64 = match &manager.strategy {
        TaskRetryStrategy::FixedDelay(fixed) => fixed.delay.as_secs(),
        TaskRetryStrategy::ExponentialBackoff(backoff) => {
            let delay = (backoff.initial_delay.as_secs() as f64
                * backoff.factor.into_inner().powi(attempt as i32))
            .min(backoff.max_delay.as_secs() as f64) as u64;

            if backoff.jitter {
                let jitter_factor = rand::random::<f64>() + 0.5;
                ((delay as f64 * jitter_factor) as u64).min(backoff.max_delay.as_secs())
            } else {
                delay
            }
        }
    };

    let next_time = now.saturating_add(delay_secs);
    let deadline = retry_since.saturating_add(manager.total_deadline.as_secs());
    if next_time > deadline {
        return None;
    }

    Some(next_time)
}

impl TaskResult {
    pub fn is_success(&self) -> bool {
        matches!(self, TaskResult::Success(_))
    }

    pub fn is_retry(&self) -> bool {
        matches!(
            self,
            TaskResult::Update(_)
                | TaskResult::Failure {
                    typ: TaskFailureType::Temporary
                        | TaskFailureType::Retry(_)
                        | TaskFailureType::Perpetual,
                    ..
                }
        )
    }
}

/// inbuxa: a task queue row whose task type could not be read.
struct UnreadableDueRow {
    due: u64,
    id: u64,
    value: Vec<u8>,
}

/// inbuxa: logs each unreadable queue row and repairs it from the task it
/// schedules. The task row says what the task is, so the queue row is
/// rewritten with that task's type; a row with no task behind it is removed.
///
/// Rescheduling an internal DMARC or TLS report wrote the report's object
/// type into the queue row instead of the task type. Such a row is the time
/// an administrator chose, so the task is moved to it as the reschedule
/// meant to do: the task row takes that due, and a queue row left at the
/// task's previous due is removed. Returns whether any row was repaired.
async fn repair_due_rows(server: &Server, rows: Vec<UnreadableDueRow>) -> bool {
    let mut repaired = false;
    for row in rows {
        let UnreadableDueRow { due, id, value } = row;
        trc::error!(
            trc::StoreEvent::DataCorruption
                .into_err()
                .id(id)
                .ctx(trc::Key::Due, trc::Value::Timestamp(due))
                .ctx(
                    trc::Key::Key,
                    [due.to_be_bytes(), id.to_be_bytes()].concat()
                )
                .ctx(trc::Key::Value, value.clone())
                .details("Unreadable task queue row skipped")
                .caused_by(trc::location!())
        );

        let task_key = ValueClass::TaskQueue(TaskQueueClass::Task { id });
        let due_key = ValueClass::TaskQueue(TaskQueueClass::Due { id, due });
        let task = match server
            .store()
            .get_value::<Task>(ValueKey::from(task_key.clone()))
            .await
        {
            Ok(task) => task,
            Err(err) => {
                trc::error!(
                    err.id(id)
                        .details("Failed to read the task of an unreadable queue row.")
                        .caused_by(trc::location!())
                );
                continue;
            }
        };

        let mut batch = BatchBuilder::new();
        let action = if let Some(mut task) = task {
            let task_type = task.object_type();
            batch.assert_value(task_key.clone(), AssertValue::Some);
            if rescheduled_report_type(&value) == Some(task_type) {
                let old_due = task.due_timestamp();
                if old_due != due {
                    batch.clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                        id,
                        due: old_due,
                    }));
                }
                task.set_status(TaskStatus::at(due as i64));
            }
            batch
                .set(due_key, task_type.to_id().serialize())
                .set(task_key, task.to_pickled_vec());
            "Rewrote the queue row from its task."
        } else {
            batch.clear(due_key);
            "Removed a queue row with no task."
        };

        match server.store().write(batch.build_all()).await {
            Ok(_) => {
                repaired = true;
                trc::event!(
                    TaskManager(TaskManagerEvent::TaskIgnored),
                    Id = id,
                    Due = trc::Value::Timestamp(due),
                    Reason = action,
                );
            }
            Err(err) if err.matches(trc::EventType::Store(trc::StoreEvent::AssertValueFailed)) => {
                // The task went away meanwhile; the next scan looks again
            }
            Err(err) => {
                trc::error!(
                    err.id(id)
                        .details("Failed to repair an unreadable queue row.")
                        .caused_by(trc::location!())
                );
            }
        }
    }
    repaired
}

/// inbuxa: the task type a report reschedule meant, when a queue row holds
/// an internal report's object type (the value that reschedule wrote).
fn rescheduled_report_type(value: &[u8]) -> Option<TaskType> {
    let id = u16::from_be_bytes(value.get(..2)?.try_into().ok()?);
    match ObjectType::from_id(id)? {
        ObjectType::DmarcInternalReport => Some(TaskType::DmarcReport),
        ObjectType::TlsInternalReport => Some(TaskType::TlsReport),
        _ => None,
    }
}
