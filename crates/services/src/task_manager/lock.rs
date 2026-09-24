/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::task_manager::*;

pub trait TaskLockManager: Sync + Send {
    fn try_lock_task(&self, task: u64) -> impl Future<Output = bool> + Send;
    fn remove_index_lock(&self, id: u64) -> impl Future<Output = ()> + Send;
}

impl TaskLockManager for Server {
    async fn try_lock_task(&self, id: u64) -> bool {
        // inbuxa: a node that is stopping claims nothing new
        let locks = &self.inner.ipc.task_locks;
        if locks.is_stopping() {
            return false;
        }

        match self
            .in_memory_store()
            .try_lock(KV_LOCK_TASK, &id.to_be_bytes(), locks.expiry())
            .await
        {
            Ok(result) => {
                if result {
                    locks.insert(id);
                } else {
                    trc::event!(
                        TaskManager(TaskManagerEvent::TaskLocked),
                        Id = id,
                        Details = "Task details not available",
                    );
                }
                result
            }
            Err(err) => {
                trc::error!(err.id(id).details("Failed to lock task"));

                false
            }
        }
    }

    async fn remove_index_lock(&self, id: u64) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_TASK, &id.to_be_bytes())
            .await
        {
            trc::error!(
                err.details("Failed to unlock task")
                    .ctx(trc::Key::Id, id)
                    .caused_by(trc::location!())
            );
        }
        self.inner.ipc.task_locks.remove(id);
    }
}

/// inbuxa: on a graceful stop, stops claiming tasks and releases every task
/// lock this node holds, so the rest of the cluster can pick the tasks up at
/// once instead of after the lock expires. Returns how many were released.
pub async fn release_task_locks(server: &Server) -> usize {
    let ids = server.inner.ipc.task_locks.stop();
    for id in &ids {
        if let Err(err) = server
            .in_memory_store()
            .remove_lock(KV_LOCK_TASK, &id.to_be_bytes())
            .await
        {
            trc::error!(
                err.details("Failed to release task lock on shutdown")
                    .ctx(trc::Key::Id, *id)
                    .caused_by(trc::location!())
            );
        }
    }
    ids.len()
}

/// inbuxa: renews the lease on every task this node is running, so it stays
/// claimed for as long as it runs while a node that dies loses its claims
/// within one lock lifetime. Returns how many leases were renewed and how
/// many were found lost (expired, perhaps taken by another node).
pub async fn renew_task_locks(server: &Server) -> (usize, usize) {
    let locks = &server.inner.ipc.task_locks;
    let expiry = locks.expiry();
    let (mut renewed, mut lost) = (0, 0);
    for id in locks.held_ids() {
        match server
            .in_memory_store()
            .renew_lock(KV_LOCK_TASK, &id.to_be_bytes(), expiry)
            .await
        {
            Ok(true) => renewed += 1,
            Ok(false) => {
                // Still held here as far as this node knows; the task
                // finishes and its lock is removed as usual
                if locks.is_held(id) {
                    lost += 1;
                    trc::event!(
                        TaskManager(TaskManagerEvent::TaskLocked),
                        Id = id,
                        Details = "Task lock expired while the task was running",
                    );
                }
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to renew task lock")
                        .ctx(trc::Key::Id, id)
                        .caused_by(trc::location!())
                );
            }
        }
    }
    (renewed, lost)
}
