/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod analyze;
pub mod dmarc;
pub mod reschedule; // inbuxa: report reschedules and unreadable queue rows
pub mod scheduler;
pub mod tls;

use common::{Server, config::smtp::report::AggregateFrequency};
use registry::schema::{enums::TaskType, prelude::ObjectType, structs::Task};
use smtp::reporting::{AggregateTimestamp, aggregate::window::create_window_reports};
use smtp_report::dmarc::{Disposition, DmarcStatus, Record};
use std::{net::IpAddr, time::Duration};
use store::{
    ValueKey,
    write::{TaskId, TaskQueueClass, ValueClass},
};

/// Time 1.0 waits after a window ends before creating its reports.
pub const REPORT_SEND_DELAY: i64 = 300;
/// Spread 1.0 adds to each report's delivery after `REPORT_SEND_DELAY`.
pub const REPORT_SEND_JITTER: i64 = 600;

/// inbuxa: 1.0 aggregates report rows per window and only creates the
/// DmarcInternalReport/TlsInternalReport objects when the window's task runs,
/// five minutes after the window ends. Waits for that task to be queued (the
/// scheduler may still be writing the rows), checks it, and runs what it runs.
/// Returns the window end.
pub async fn close_report_window(
    server: &Server,
    object: ObjectType,
    interval: AggregateFrequency,
) -> u64 {
    let window_end = interval.to_timestamp() + interval.as_secs();
    let typ = match object {
        ObjectType::DmarcInternalReport => TaskType::DmarcReportWindow,
        ObjectType::TlsInternalReport => TaskType::TlsReportWindow,
        _ => panic!("{object:?} has no report window"),
    };
    let key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task {
        id: TaskId::Assigned(TaskId::singleton(typ, 0, window_end)),
    }));

    let mut task = None;
    for _ in 0..50 {
        task = server.store().get_value::<Task>(key.clone()).await.unwrap();
        if task.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let task =
        task.unwrap_or_else(|| panic!("No {typ:?} task queued for the window ending {window_end}"));
    match &task {
        Task::DmarcReportWindow(window) | Task::TlsReportWindow(window) => {
            assert_eq!(window.window_end.timestamp(), window_end as i64);
        }
        other => panic!("Unexpected task {other:?}"),
    }
    assert_eq!(task.object_type(), typ);
    assert_eq!(
        task.due_timestamp(),
        window_end + REPORT_SEND_DELAY as u64,
        "the window task runs five minutes after the window ends"
    );

    create_window_reports(server, object, window_end)
        .await
        .unwrap();
    window_end
}

// inbuxa: 1.0's report Record lost its builder methods; the tests that build
// DMARC events keep them here
pub trait TestDmarcRecord: Sized {
    fn with_source_ip(self, source_ip: IpAddr) -> Self;
    fn with_action_disposition(self, disposition: Disposition) -> Self;
    fn with_dmarc_dkim_result(self, result: DmarcStatus) -> Self;
    fn with_dmarc_spf_result(self, result: DmarcStatus) -> Self;
    fn with_envelope_from(self, envelope_from: impl Into<String>) -> Self;
    fn with_envelope_to(self, envelope_to: impl Into<String>) -> Self;
    fn with_header_from(self, header_from: impl Into<String>) -> Self;
}

impl TestDmarcRecord for Record {
    fn with_source_ip(mut self, source_ip: IpAddr) -> Self {
        self.row.source_ip = Some(source_ip);
        self
    }

    fn with_action_disposition(mut self, disposition: Disposition) -> Self {
        self.row.policy_evaluated.disposition = disposition;
        self
    }

    fn with_dmarc_dkim_result(mut self, result: DmarcStatus) -> Self {
        self.row.policy_evaluated.dkim = result;
        self
    }

    fn with_dmarc_spf_result(mut self, result: DmarcStatus) -> Self {
        self.row.policy_evaluated.spf = result;
        self
    }

    fn with_envelope_from(mut self, envelope_from: impl Into<String>) -> Self {
        self.identifiers.envelope_from = envelope_from.into();
        self
    }

    fn with_envelope_to(mut self, envelope_to: impl Into<String>) -> Self {
        self.identifiers.envelope_to = Some(envelope_to.into());
        self
    }

    fn with_header_from(mut self, header_from: impl Into<String>) -> Self {
        self.identifiers.header_from = header_from.into();
        self
    }
}
