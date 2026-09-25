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
                // inbuxa: every node records what it received, whatever its
                // role. An aggregate report covers all of a domain's mail,
                // whichever node took it, and recording is a store write
                // that nodes already share: the report's primary key is
                // versioned, so concurrent appends from several nodes retry
                // rather than overwrite. Only building and sending the
                // report (the DmarcReport and TlsReport tasks) belongs to
                // the outbound MTA; the task manager keeps those to nodes
                // with that role. Upstream ran this only on outbound MTA
                // nodes, so mail received anywhere else never reached a
                // report.
                match event {
                    ReportingEvent::Dmarc(event) => server.schedule_dmarc(event).await,
                    ReportingEvent::Tls(event) => server.schedule_tls(event).await,
                    ReportingEvent::Stop => break,
                }
            }
        });
    }
}
