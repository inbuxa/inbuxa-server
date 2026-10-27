/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::task_manager::LEASE_DURATION;
use common::{KV_LOCK_TASK, Server};
use std::future::Future;
use store::{InMemoryStore, rand};
use trc::TaskManagerEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskLock {
    id: u64,
    lease: u64,
}

pub trait TaskLockManager: Sync + Send {
    fn lock_task(&self, id: u64) -> impl Future<Output = Option<TaskLock>> + Send;

    fn renew_task_lock(&self, lock: TaskLock) -> impl Future<Output = bool> + Send;

    fn unlock_task(&self, lock: TaskLock) -> impl Future<Output = ()> + Send;
}

impl TaskLock {
    pub fn new(id: u64) -> Self {
        TaskLock {
            id,
            lease: rand::random(),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn extend(self, store: &InMemoryStore) -> trc::Result<bool> {
        let key = self.id.to_be_bytes();
        let renewed = store
            .renew_lease(KV_LOCK_TASK, &key, self.lease, LEASE_DURATION)
            .await;
        if matches!(renewed, Ok(true)) {
            return Ok(true);
        }

        match store
            .try_lease(KV_LOCK_TASK, &key, self.lease, LEASE_DURATION)
            .await
        {
            Ok(acquired) => Ok(acquired),
            Err(err) => renewed.and(Err(err)),
        }
    }
}

impl TaskLockManager for Server {
    async fn lock_task(&self, id: u64) -> Option<TaskLock> {
        // inbuxa: a node that is stopping claims nothing new
        let locks = &self.inner.ipc.task_locks;
        if locks.is_stopping() {
            return None;
        }

        let lock = TaskLock::new(id);
        match self
            .in_memory_store()
            .try_lease(KV_LOCK_TASK, &id.to_be_bytes(), lock.lease, LEASE_DURATION)
            .await
        {
            Ok(true) => {
                locks.insert(id, lock.lease);
                Some(lock)
            }
            Ok(false) => {
                trc::event!(
                    TaskManager(TaskManagerEvent::TaskLocked),
                    TaskId = id,
                    Details = "Task is locked",
                );
                None
            }
            Err(err) => {
                trc::error!(err.ctx(trc::Key::TaskId, id).details("Failed to lock task"));
                None
            }
        }
    }

    async fn renew_task_lock(&self, lock: TaskLock) -> bool {
        match lock.extend(self.in_memory_store()).await {
            Ok(true) => true,
            Ok(false) => {
                trc::event!(
                    TaskManager(TaskManagerEvent::TaskLocked),
                    TaskId = lock.id,
                    Details = "Task lease was lost while the task was running",
                );
                false
            }
            Err(err) => {
                trc::error!(
                    err.ctx(trc::Key::TaskId, lock.id)
                        .details("Failed to renew task lease")
                );
                false
            }
        }
    }

    async fn unlock_task(&self, lock: TaskLock) {
        self.inner.ipc.task_locks.remove(lock.id);
        if let Err(err) = self
            .in_memory_store()
            .release_lease(KV_LOCK_TASK, &lock.id.to_be_bytes(), lock.lease)
            .await
        {
            trc::error!(
                err.details("Failed to unlock task")
                    .ctx(trc::Key::TaskId, lock.id)
                    .caused_by(trc::location!())
            );
        }
    }
}

/// inbuxa: on a graceful stop, stops claiming tasks and releases every task
/// lease this node holds, so the rest of the cluster can pick the tasks up at
/// once instead of after the lease lapses. Returns how many were released.
pub async fn release_task_locks(server: &Server) -> usize {
    let leases = server.inner.ipc.task_locks.stop();
    for (id, lease) in &leases {
        if let Err(err) = server
            .in_memory_store()
            .release_lease(KV_LOCK_TASK, &id.to_be_bytes(), *lease)
            .await
        {
            trc::error!(
                err.details("Failed to release task lock on shutdown")
                    .ctx(trc::Key::TaskId, *id)
                    .caused_by(trc::location!())
            );
        }
    }
    leases.len()
}
