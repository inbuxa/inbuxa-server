/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::{TaskInfo, TaskJob};
use common::Server;
use compact_str::CompactString;
use registry::{
    schema::structs::{
        Task, TaskManager, TaskRetryStrategy, TaskStatus, TaskStatusFailed, TaskStatusRetry,
    },
    types::{ObjectImpl, datetime::UTCDateTime},
};
use std::ops::RangeInclusive;
use store::{
    rand::{self, RngExt},
    write::{
        BatchBuilder, Operation, TaskId, TaskQueueClass, TaskTypes, ValueClass,
        assert::AssertValue, now,
    },
};
use trc::{EventType, Key, SecurityEvent, StoreEvent, TaskManagerEvent};

const MAX_REASON_LEN: usize = 1024;
const CONTENTION_DELAY: RangeInclusive<u64> = 1..=10;
const CONTENTION_FAST_RETRIES: u64 = 3;
const ITIP_EXPIRY: u64 = 3 * 86400;
const FDB_TRANSACTION_TOO_OLD: u64 = 1007;
const FDB_NOT_COMMITTED: u64 = 1020;
const FDB_PAYLOAD_TOO_LARGE: RangeInclusive<u64> = 2101..=2103;

#[derive(Debug)]
pub(crate) enum Outcome {
    Done(Vec<Task>),
    Replace([Operation; 2]),
    Partial {
        remaining: Box<Task>,
        failure: Failure,
    },
    Retry(Failure),
    Fatal(String),
    Obsolete(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryClass {
    Transient,
    Throttled { retry_at: u64 },
    Contention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorClass {
    Retry(RetryClass),
    Fatal,
}

#[derive(Debug)]
pub(crate) struct Failure {
    class: RetryClass,
    reason: String,
}

#[derive(Debug)]
pub(crate) enum Commit {
    Committed(TaskTypes),
    Conflict,
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NextAttempt {
    Retry {
        retry: TaskStatusRetry,
        is_stalled: bool,
    },
    Expired(String),
}

impl Outcome {
    pub(crate) fn done() -> Self {
        Outcome::Done(Vec::new())
    }

    pub(crate) fn transient(reason: impl Into<String>) -> Self {
        Outcome::Retry(Failure::new(RetryClass::Transient, reason))
    }

    pub(crate) fn fatal(reason: impl Into<String>) -> Self {
        Outcome::Fatal(reason.into())
    }

    pub(crate) fn error(err: &trc::Error) -> Self {
        match ErrorClass::of(err) {
            ErrorClass::Retry(class) => Outcome::Retry(Failure::new(class, err.to_string())),
            ErrorClass::Fatal => Outcome::Fatal(err.to_string()),
        }
    }
}

impl Failure {
    pub(crate) fn new(class: RetryClass, reason: impl Into<String>) -> Self {
        Failure {
            class,
            reason: reason.into(),
        }
    }
}

impl ErrorClass {
    pub(crate) fn of(err: &trc::Error) -> Self {
        if let Some(retry_at) = err.value(Key::NextRetry).and_then(|value| match value {
            trc::Value::Timestamp(retry_at) => Some(*retry_at),
            value => value.to_uint(),
        }) {
            return ErrorClass::Retry(RetryClass::Throttled { retry_at });
        }

        match err.event_type() {
            EventType::Store(StoreEvent::AssertValueFailed) => {
                ErrorClass::Retry(RetryClass::Contention)
            }
            EventType::Store(StoreEvent::FoundationdbError) => {
                match err.value(Key::Code).and_then(|value| value.to_uint()) {
                    Some(FDB_TRANSACTION_TOO_OLD | FDB_NOT_COMMITTED) => {
                        ErrorClass::Retry(RetryClass::Contention)
                    }
                    Some(code) if FDB_PAYLOAD_TOO_LARGE.contains(&code) => ErrorClass::Fatal,
                    _ => ErrorClass::Retry(RetryClass::Transient),
                }
            }
            EventType::Store(
                StoreEvent::DataCorruption
                | StoreEvent::DecompressError
                | StoreEvent::DeserializeError
                | StoreEvent::NotSupported
                | StoreEvent::NotConfigured
                | StoreEvent::CryptoError,
            )
            | EventType::Security(SecurityEvent::Unauthorized) => ErrorClass::Fatal,
            _ => ErrorClass::Retry(RetryClass::Transient),
        }
    }
}

impl NextAttempt {
    pub(crate) fn plan(
        manager: &TaskManager,
        task: &Task,
        class: RetryClass,
        reason: String,
        now: u64,
    ) -> Self {
        let (created_at, first_failed_at, failures) = match task.status() {
            TaskStatus::Pending(status) => (status.created_at, None, 0),
            TaskStatus::Retry(status) | TaskStatus::Stalled(status) => (
                status.created_at,
                Some(status.first_failed_at),
                status.attempt_number,
            ),
            TaskStatus::Failed(status) => (status.created_at, None, 0),
        };
        let attempt = failures.saturating_add(1);
        let delay = match class {
            RetryClass::Transient => retry_delay(manager, attempt),
            RetryClass::Throttled { retry_at } => retry_at
                .saturating_sub(now)
                .max(retry_delay(manager, attempt)),
            RetryClass::Contention if attempt <= CONTENTION_FAST_RETRIES => {
                rand::rng().random_range(CONTENTION_DELAY)
            }
            RetryClass::Contention => {
                retry_delay(manager, attempt.saturating_sub(CONTENTION_FAST_RETRIES))
            }
        };
        let due = now.saturating_add(delay);

        if expires_at(task).is_some_and(|expires_at| due > expires_at) {
            return NextAttempt::Expired(reason);
        }

        let retry = TaskStatusRetry {
            created_at,
            due: UTCDateTime::from_timestamp(due as i64),
            attempt_number: attempt,
            first_failed_at: first_failed_at
                .unwrap_or_else(|| UTCDateTime::from_timestamp(now as i64)),
            failure_reason: truncate_reason(reason),
        };

        NextAttempt::Retry {
            retry,
            is_stalled: attempt >= manager.alert_after,
        }
    }
}

pub(crate) fn retry_delay(manager: &TaskManager, attempt: u64) -> u64 {
    match &manager.strategy {
        TaskRetryStrategy::FixedDelay(fixed) => fixed.delay.as_secs(),
        TaskRetryStrategy::ExponentialBackoff(backoff) => {
            let max_delay = backoff.max_delay.as_secs();
            let exponent = i32::try_from(attempt.saturating_sub(1)).unwrap_or(i32::MAX);
            let delay = (backoff.initial_delay.as_secs() as f64
                * backoff.factor.into_inner().powi(exponent))
            .min(max_delay as f64) as u64;

            if backoff.jitter && delay > 1 {
                rand::rng().random_range(delay / 2..=delay)
            } else {
                delay
            }
        }
    }
    .max(1)
}

fn expires_at(task: &Task) -> Option<u64> {
    match task {
        Task::CalendarItipMessage(_) => {
            Some((task.status().created_at().timestamp() as u64).saturating_add(ITIP_EXPIRY))
        }
        _ => None,
    }
}

fn truncate_reason(mut reason: String) -> String {
    if reason.len() > MAX_REASON_LEN {
        reason.truncate(reason.floor_char_boundary(MAX_REASON_LEN));
    }
    reason
}

pub(crate) async fn commit(
    server: &Server,
    job: &TaskJob,
    task: Task,
    hash: u64,
    outcome: Outcome,
) -> Commit {
    let id = TaskId::Assigned(job.id);
    let task_key = ValueClass::TaskQueue(TaskQueueClass::Task { id });
    let mut batch = BatchBuilder::new();
    batch
        .assert_value(task_key.clone(), AssertValue::Hash(hash))
        .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
            id,
            typ: job.typ,
            due: job.due,
        }));

    match outcome {
        Outcome::Done(tasks) => {
            batch.clear(task_key);
            for task in tasks {
                batch.schedule_task(task);
            }
        }
        Outcome::Replace(ops) => {
            for op in ops {
                batch.any_op(op);
            }
        }
        Outcome::Partial { remaining, failure } => {
            schedule_retry(server, &mut batch, job, *remaining, failure);
        }
        Outcome::Retry(failure) => {
            schedule_retry(server, &mut batch, job, task, failure);
        }
        Outcome::Fatal(reason) => {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskFailed),
                TaskId = job.id,
                Name = task.name(),
                Reason = CompactString::from(reason.as_str()),
            );

            let mut task = task;
            let status = TaskStatus::Failed(TaskStatusFailed {
                created_at: task.status().created_at(),
                failed_at: UTCDateTime::now(),
                failed_attempt_number: task.attempt_number().saturating_add(1),
                failure_reason: truncate_reason(reason),
            });
            task.set_status(status);
            batch
                .set_task_due(id, job.typ, u64::MAX)
                .set(task_key, task.to_pickled_vec());
        }
        Outcome::Obsolete(reason) => {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskIgnored),
                TaskId = job.id,
                Name = task.name(),
                Reason = reason,
            );

            batch.clear(task_key);
        }
    }

    let task_types = batch.queue_notify().task_types;
    match server.store().write_batch(&mut batch).await {
        Ok(_) => Commit::Committed(task_types),
        Err(err) if err.is_assertion_failure() => {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskIgnored),
                TaskId = job.id,
                Reason = "Task was changed or deleted while being processed; skipping update.",
            );
            Commit::Conflict
        }
        Err(err) => {
            trc::error!(
                err.ctx(trc::Key::TaskId, job.id)
                    .details("Failed to update task after processing.")
            );
            Commit::Failed
        }
    }
}

fn schedule_retry(
    server: &Server,
    batch: &mut BatchBuilder,
    job: &TaskJob,
    mut task: Task,
    failure: Failure,
) {
    let id = TaskId::Assigned(job.id);
    let task_key = ValueClass::TaskQueue(TaskQueueClass::Task { id });
    let manager = &server.core.network.task_manager;

    match NextAttempt::plan(manager, &task, failure.class, failure.reason, now()) {
        NextAttempt::Retry { retry, is_stalled } => {
            let due = retry.due.timestamp() as u64;
            let attempt = retry.attempt_number;
            if attempt == manager.alert_after {
                trc::event!(
                    TaskManager(TaskManagerEvent::TaskStalled),
                    TaskId = job.id,
                    Name = task.name(),
                    Reason = CompactString::from(retry.failure_reason.as_str()),
                    Attempt = attempt,
                    NextRetry = trc::Value::Timestamp(due),
                );
            } else {
                trc::event!(
                    TaskManager(TaskManagerEvent::TaskRetry),
                    TaskId = job.id,
                    Name = task.name(),
                    Reason = CompactString::from(retry.failure_reason.as_str()),
                    Attempt = attempt,
                    NextRetry = trc::Value::Timestamp(due),
                );
            }

            let (status, marker) = if is_stalled {
                (TaskStatus::Stalled(retry), TaskQueueClass::DUE_STALLED)
            } else {
                (TaskStatus::Retry(retry), TaskQueueClass::DUE_RETRY)
            };
            task.set_status(status);
            batch
                .set_task_due_marked(id, job.typ, due, Some(marker))
                .set(task_key, task.to_pickled_vec());
        }
        NextAttempt::Expired(reason) => {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskExpired),
                TaskId = job.id,
                Name = task.name(),
                Reason = CompactString::from(reason),
            );

            batch.clear(task_key);
        }
    }
}

