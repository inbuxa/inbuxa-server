/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

// inbuxa: composite stores (sharded members, read replicas) nest store
// futures deeply enough to pass rustc's default query depth
#![recursion_limit = "512"]

#![warn(clippy::large_futures)]

use broadcast::publisher::spawn_broadcast_publisher;
use common::{
    BuildServer, Inner,
    manager::boot::{BootManager, IpcReceivers},
};
use state_manager::manager::spawn_push_router;
use std::sync::Arc;

use crate::task_manager::{manager::spawn_task_manager, scheduler::spawn_task_scheduler};

pub mod broadcast;
// inbuxa: AL-5, delegations end at their date
pub mod inbuxa_lock_expiry;
pub mod inbuxa_log_retention; // inbuxa: personal-data catalog, D1
pub mod state_manager;
pub mod task_manager;

pub trait StartServices: Sync + Send {
    fn start_services(&mut self) -> impl Future<Output = ()> + Send;
}

pub trait SpawnServices {
    fn spawn_services(&mut self, inner: Arc<Inner>);
}

impl StartServices for BootManager {
    async fn start_services(&mut self) {
        let server = self.inner.build_server();
        // Unpack webadmin
        self.inner
            .data
            .applications
            .unpack_all(&server, false)
            .await;

        if !server.registry().is_recovery_mode() {
            self.ipc_rxs.spawn_services(self.inner.clone());
        }
    }
}

impl SpawnServices for IpcReceivers {
    fn spawn_services(&mut self, inner: Arc<Inner>) {
        if !inner.shared_core.load().storage.registry.is_recovery_mode() {
            // Spawn push manager
            spawn_push_router(inner.clone(), self.push_rx.take().unwrap());

            // Spawn broadcast publisher
            if let Some(event_rx) = self.broadcast_rx.take() {
                // Spawn broadcast publisher
                spawn_broadcast_publisher(inner.clone(), event_rx);
            }

            // Spawn task manager
            spawn_task_manager(inner.clone());

            // inbuxa: AL-5, end delegations at their `until`
            inbuxa_lock_expiry::spawn_lock_expiry(inner.clone());

            // inbuxa: personal-data catalog, D1: old log files go, per node
            inbuxa_log_retention::spawn_log_retention(inner.clone());

            // Spawn task scheduler
            spawn_task_scheduler(inner);
        }
    }
}
