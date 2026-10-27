/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::outcome::Outcome;
use common::Server;
use registry::{schema::prelude::ObjectType, types::datetime::UTCDateTime};
use smtp::reporting::{
    aggregate::window::create_window_reports, dmarc::DmarcReporting, tls::TlsReporting,
};

pub enum ReportId {
    Dmarc(u64),
    Tls(u64),
    DmarcWindow(UTCDateTime),
    TlsWindow(UTCDateTime),
}

pub(crate) trait SubmitReportTask: Sync + Send {
    fn submit_report(&self, report_id: ReportId) -> impl Future<Output = Outcome> + Send;
}

impl SubmitReportTask for Server {
    async fn submit_report(&self, report_id: ReportId) -> Outcome {
        match submit_report(self, report_id).await {
            Ok(()) => Outcome::done(),
            Err(err) => {
                let outcome = Outcome::error(&err);
                trc::error!(err.details("Failed to submit report"));
                outcome
            }
        }
    }
}

async fn submit_report(server: &Server, report_id: ReportId) -> trc::Result<()> {
    match report_id {
        ReportId::Dmarc(item_id) => server.send_dmarc_aggregate_report(item_id).await,
        ReportId::Tls(item_id) => server.send_tls_aggregate_report(item_id).await,
        ReportId::DmarcWindow(end) => {
            create_window_reports(
                server,
                ObjectType::DmarcInternalReport,
                end.timestamp().cast_unsigned(),
            )
            .await
        }
        ReportId::TlsWindow(end) => {
            create_window_reports(
                server,
                ObjectType::TlsInternalReport,
                end.timestamp().cast_unsigned(),
            )
            .await
        }
    }
}
