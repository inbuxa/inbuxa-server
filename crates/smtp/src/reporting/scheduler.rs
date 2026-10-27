/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::aggregate::{REPORT_BURST, ReportScheduler};
use common::{BuildServer, Inner, ipc::ReportingEvent};
use std::sync::Arc;
use tokio::sync::mpsc;

pub trait SpawnReport {
    fn spawn(self, core: Arc<Inner>);
}

impl SpawnReport for mpsc::Receiver<ReportingEvent> {
    fn spawn(mut self, inner: Arc<Inner>) {
        tokio::spawn(async move {
            let mut scheduler = ReportScheduler::default();
            let mut events = Vec::with_capacity(REPORT_BURST);
            while self.recv_many(&mut events, REPORT_BURST).await > 0 {
                if scheduler.process(&inner.build_server(), &mut events).await {
                    break;
                }
            }
        });
    }
}
