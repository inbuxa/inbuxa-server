/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{dmarc::DmarcReporting, tls::TlsReporting};
use common::{BuildServer, Inner, ipc::ReportingEvent};
use std::sync::Arc;
use tokio::sync::mpsc;

pub trait SpawnReport {
    fn spawn(self, core: Arc<Inner>);
}

impl SpawnReport for mpsc::Receiver<ReportingEvent> {
    fn spawn(mut self, inner: Arc<Inner>) {
        tokio::spawn(async move {
            while let Some(event) = self.recv().await {
                let server = inner.build_server();
                // inbuxa: reports are the outbound MTA's business, as at
                // boot, but the role is read per event so a change applies
                // without a restart. Events that arrive while the role is
                // off are dropped, as they were on a node started without it
                if !matches!(event, ReportingEvent::Stop) && !server.core.network.roles.outbound_mta
                {
                    continue;
                }
                match event {
                    ReportingEvent::Dmarc(event) => server.schedule_dmarc(event).await,
                    ReportingEvent::Tls(event) => server.schedule_tls(event).await,
                    ReportingEvent::Stop => break,
                }
            }
        });
    }
}
