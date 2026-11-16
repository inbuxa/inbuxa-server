/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::core::Session;
use ahash::AHashMap;
use common::USER_AGENT;
use mail_auth::report::{
    ActionDisposition, AuthFailureType, DeliveryResult, DmarcResult, Feedback, FeedbackType,
    Report,
    tlsrpt::{Policy, TlsReport},
};
use std::{collections::hash_map::Entry, time::SystemTime};
use store::write::now;
use tokio::io::{AsyncRead, AsyncWrite};
use trc::IncomingReportEvent;

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub fn new_auth_failure(&self, ft: AuthFailureType, rejected: bool) -> Feedback<'_> {
        Feedback::new(FeedbackType::AuthFailure)
            .with_auth_failure(ft)
            .with_arrival_date(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()) as i64,
            )
            .with_source_ip(self.data.remote_ip)
            .with_reporting_mta(&self.hostname)
            .with_user_agent(USER_AGENT)
            .with_delivery_result(if rejected {
                DeliveryResult::Reject
            } else {
                DeliveryResult::Unspecified
            })
    }

    pub fn is_report(&self) -> bool {
        let analysis = &self.server.core.smtp.report.analysis;

        self.data
            .rcpt_to
            .iter()
            .any(|addr| analysis.is_report_address(addr.orig_address()))
    }
}

pub(crate) trait LogReport {
    fn log(&self);
}

impl LogReport for Report {
    fn log(&self) {
        let mut dmarc_pass = 0;
        let mut dmarc_quarantine = 0;
        let mut dmarc_reject = 0;
        let mut dmarc_none = 0;
        let mut dkim_pass = 0;
        let mut dkim_fail = 0;
        let mut dkim_none = 0;
        let mut spf_pass = 0;
        let mut spf_fail = 0;
        let mut spf_none = 0;

        for record in self.records() {
            let count = std::cmp::min(record.count(), 1);

            match record.action_disposition() {
                ActionDisposition::Pass => {
                    dmarc_pass += count;
                }
                ActionDisposition::Quarantine => {
                    dmarc_quarantine += count;
                }
                ActionDisposition::Reject => {
                    dmarc_reject += count;
                }
                ActionDisposition::None | ActionDisposition::Unspecified => {
                    dmarc_none += count;
                }
            }
            match record.dmarc_dkim_result() {
                DmarcResult::Pass => {
                    dkim_pass += count;
                }
                DmarcResult::Fail => {
                    dkim_fail += count;
                }
                DmarcResult::Unspecified => {
                    dkim_none += count;
                }
            }
            match record.dmarc_spf_result() {
                DmarcResult::Pass => {
                    spf_pass += count;
                }
                DmarcResult::Fail => {
                    spf_fail += count;
                }
                DmarcResult::Unspecified => {
                    spf_none += count;
                }
            }
        }

        trc::event!(
            IncomingReport(if fails_dmarc(self.records()) {
                IncomingReportEvent::DmarcReportWithWarnings
            } else {
                IncomingReportEvent::DmarcReport
            }),
            RangeFrom = trc::Value::Timestamp(self.date_range_begin()),
            RangeTo = trc::Value::Timestamp(self.date_range_end()),
            Domain = self.domain().to_string(),
            From = self.email().to_string(),
            Id = self.report_id().to_string(),
            DmarcPass = dmarc_pass,
            DmarcQuarantine = dmarc_quarantine,
            DmarcReject = dmarc_reject,
            DmarcNone = dmarc_none,
            DkimPass = dkim_pass,
            DkimFail = dkim_fail,
            DkimNone = dkim_none,
            SpfPass = spf_pass,
            SpfFail = spf_fail,
            SpfNone = spf_none,
        );
    }
}

/// inbuxa: whether a DMARC report shows mail that failed DMARC: a row where
/// neither the aligned SPF nor the aligned DKIM result passed. One failing
/// on its own is not a warning: forwarded mail fails SPF and still passes on
/// DKIM, which is what DMARC is for, and the console's reports page counts it
/// as passed too (#391). A row that fails DMARC carries its quarantine or
/// reject disposition with it.
fn fails_dmarc(records: &[mail_auth::report::Record]) -> bool {
    records.iter().any(|record| {
        record.count() > 0
            && !matches!(record.dmarc_dkim_result(), DmarcResult::Pass)
            && !matches!(record.dmarc_spf_result(), DmarcResult::Pass)
    })
}

impl LogReport for TlsReport {
    fn log(&self) {
        // One event per report, not per policy (#402): the dashboard counts
        // these events as reports, and a report that covers both an MTA-STS
        // and a DANE policy counted twice. Each policy's figures stay in the
        // event, for the first five policies as before.
        let (successes, failures) = tls_totals(&self.policies);
        let mut domains: Vec<trc::Value> = Vec::new();
        let mut policies = Vec::new();
        let mut details = Vec::new();
        for policy in self.policies.iter().take(5) {
            let domain = policy.policy.policy_domain.as_str();
            if !domains
                .iter()
                .any(|d| matches!(d, trc::Value::String(s) if s.as_str() == domain))
            {
                domains.push(trc::Value::String(domain.into()));
            }
            policies.push(trc::Value::String(
                format!("{:?}", policy.policy.policy_type).into(),
            ));

            let mut failed = AHashMap::with_capacity(policy.failure_details.len());
            for failure in &policy.failure_details {
                let num_failures = std::cmp::min(1, failure.failed_session_count);
                match failed.entry(failure.result_type) {
                    Entry::Occupied(mut e) => {
                        *e.get_mut() += num_failures;
                    }
                    Entry::Vacant(e) => {
                        e.insert(num_failures);
                    }
                }
            }
            details.push(trc::Value::String(
                format!(
                    "{domain} {:?}: {} succeeded, {} failed {failed:?}",
                    policy.policy.policy_type,
                    policy.summary.total_success,
                    policy.summary.total_failure
                )
                .into(),
            ));
        }

        trc::event!(
            IncomingReport(if failures > 0 {
                IncomingReportEvent::TlsReportWithWarnings
            } else {
                IncomingReportEvent::TlsReport
            }),
            RangeFrom = trc::Value::Timestamp(self.date_range.start_datetime.to_timestamp() as u64),
            RangeTo = trc::Value::Timestamp(self.date_range.end_datetime.to_timestamp() as u64),
            Domain = domains,
            From = self.contact_info.as_deref().unwrap_or_default().to_string(),
            Id = self.report_id.clone(),
            Policy = policies,
            TotalSuccesses = successes,
            TotalFailures = failures,
            Details = details,
        );
    }
}

/// A TLS report's successful and failed sessions, over all its policies.
fn tls_totals(policies: &[Policy]) -> (u64, u64) {
    policies.iter().fold((0, 0), |(ok, failed), p| {
        (
            ok + u64::from(p.summary.total_success),
            failed + u64::from(p.summary.total_failure),
        )
    })
}

impl LogReport for Feedback<'_> {
    fn log(&self) {
        trc::event!(
            IncomingReport(match self.feedback_type() {
                mail_auth::report::FeedbackType::Abuse => IncomingReportEvent::AbuseReport,
                mail_auth::report::FeedbackType::AuthFailure =>
                    IncomingReportEvent::AuthFailureReport,
                mail_auth::report::FeedbackType::Fraud => IncomingReportEvent::FraudReport,
                mail_auth::report::FeedbackType::NotSpam => IncomingReportEvent::NotSpamReport,
                mail_auth::report::FeedbackType::Other => IncomingReportEvent::OtherReport,
                mail_auth::report::FeedbackType::Virus => IncomingReportEvent::VirusReport,
            }),
            RangeFrom = trc::Value::Timestamp(
                self.arrival_date()
                    .map(|d| d as u64)
                    .unwrap_or_else(|| { now() })
            ),
            Domain = self
                .reported_domain()
                .iter()
                .map(|d| trc::Value::String(d.as_ref().into()))
                .collect::<Vec<_>>(),
            Hostname = self.reporting_mta().map(|d| trc::Value::String(d.into())),
            Url = self
                .reported_uri()
                .iter()
                .map(|d| trc::Value::String(d.as_ref().into()))
                .collect::<Vec<_>>(),
            RemoteIp = self.source_ip(),
            Total = self.incidents(),
            Result = format!("{:?}", self.delivery_result()),
            Details = self
                .authentication_results()
                .iter()
                .map(|d| trc::Value::String(d.as_ref().into()))
                .collect::<Vec<_>>(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{fails_dmarc, tls_totals};
    use mail_auth::report::{
        ActionDisposition, DmarcResult, Record,
        tlsrpt::{Policy, PolicyDetails, PolicyType, Summary},
    };

    fn row(dkim: DmarcResult, spf: DmarcResult) -> Record {
        Record::new()
            .with_count(1)
            .with_dmarc_dkim_result(dkim)
            .with_dmarc_spf_result(spf)
    }

    #[test]
    fn forwarded_mail_passing_on_dkim_is_not_a_warning() {
        // #391: DKIM pass, SPF fail is a DMARC pass
        assert!(!fails_dmarc(&[
            row(DmarcResult::Pass, DmarcResult::Pass),
            row(DmarcResult::Pass, DmarcResult::Fail),
        ]));
        assert!(!fails_dmarc(&[row(DmarcResult::Fail, DmarcResult::Pass)]));
        assert!(!fails_dmarc(&[row(
            DmarcResult::Pass,
            DmarcResult::Unspecified
        )]));
        assert!(!fails_dmarc(&[]));
    }

    #[test]
    fn a_row_failing_both_is_a_warning() {
        assert!(fails_dmarc(&[
            row(DmarcResult::Pass, DmarcResult::Pass),
            row(DmarcResult::Fail, DmarcResult::Fail)
                .with_action_disposition(ActionDisposition::Reject),
        ]));
        assert!(fails_dmarc(&[row(
            DmarcResult::Fail,
            DmarcResult::Unspecified
        )]));
    }

    #[test]
    fn an_empty_row_counts_for_nothing() {
        assert!(!fails_dmarc(&[
            row(DmarcResult::Fail, DmarcResult::Fail).with_count(0)
        ]));
    }

    fn policy(policy_type: PolicyType, ok: u32, failed: u32) -> Policy {
        Policy {
            policy: PolicyDetails::new(policy_type, "example.org"),
            summary: Summary {
                total_success: ok,
                total_failure: failed,
            },
            failure_details: vec![],
        }
    }

    #[test]
    fn a_tls_report_is_one_report_whatever_its_policies() {
        // #402: two policies with failures are still one report with warnings
        let report = [
            policy(PolicyType::Sts, 10, 2),
            policy(PolicyType::Tlsa, 7, 1),
        ];
        assert_eq!(tls_totals(&report), (17, 3));
        assert_eq!(
            tls_totals(&[
                policy(PolicyType::Sts, 4, 0),
                policy(PolicyType::Tlsa, 4, 0)
            ]),
            (8, 0)
        );
        assert_eq!(tls_totals(&[]), (0, 0));
    }
}
