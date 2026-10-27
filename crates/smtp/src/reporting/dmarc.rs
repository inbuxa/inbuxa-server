/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    core::Session,
    queue::RecipientDomain,
    reporting::{
        ReportAddress,
        aggregate::{
            ReportItem, ReportScheduler, ReportWindow, read_dmarc_records, report_size_limit,
        },
        index::InternalReportIndex,
        send::MtaReportSend,
    },
};
use common::{
    Server,
    config::smtp::report::AggregateFrequency,
    expr::Bump,
    ipc::{DmarcEvent, ReportingEvent},
    network::SessionStream,
};
use compact_str::{CompactString, ToCompactString};
use mail_auth::{
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimOutput, DkimResult, DmarcOutput,
    DmarcResult, SpfResult,
    dkim2::Dkim2Output,
    dmarc::{self, FailureOptions},
};
use registry::{
    schema::{
        enums::FailureReportingOption,
        prelude::ObjectType,
        structs::{DmarcInternalReport, DmarcReport, Rate},
    },
    types::{EnumImpl, datetime::UTCDateTime, map::Map},
};
use smtp_report::{
    ReportEnvelope,
    arf::{AuthFailureType, FeedbackReport, IdentityAlignment},
    dmarc::{AggregateReport, PolicyPublished, Record, SpfScope},
};
use std::{borrow::Cow, future::Future};
use store::{
    ValueKey,
    write::{BatchBuilder, RegistryClass, ValueClass},
};
use trc::{AddContext, OutgoingReportEvent};
use utils::DomainPart;

impl<T: SessionStream> Session<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn send_dmarc_report(
        &self,
        message: &AuthenticatedMessage<'_>,
        auth_results: &AuthenticationResults<'_>,
        rejected: bool,
        dmarc_output: DmarcOutput,
        dkim_output: &[DkimOutput<'_>],
        dkim2_output: Option<&Dkim2Output<'_>>,
        arc_output: &Option<ArcOutput<'_>>,
    ) {
        let Some(dmarc_record) = dmarc_output.record().cloned() else {
            return;
        };
        let config = &self.server.core.smtp.report.dmarc;
        let mut arena = Bump::new();

        if self
            .server
            .is_local_report_domain(dmarc_output.domain(), self.data.session_id)
            .await
        {
            return;
        }

        // Send failure report. RFC 9991 Section 2: report generators MUST NOT
        // honor "ruf" for policy records published with "psd=y".
        if !matches!(dmarc_record.psd, dmarc::Psd::Yes)
            && let (Some(failure_rate), Some(report_options)) = (
                self.server
                    .eval_if::<Rate, _>(&config.send, self, &mut arena, self.data.session_id)
                    .await,
                dmarc_output.failure_report(),
            )
        {
            // Verify that any external reporting addresses are authorized
            let rcpts = match self
                .server
                .core
                .smtp
                .resolvers
                .dns
                .authorized_report_addresses(
                    self.server
                        .inner
                        .cache
                        .build_auth_parameters((dmarc_output.domain(), dmarc_record.ruf())),
                )
                .await
            {
                Ok(rcpts) => {
                    if !rcpts.is_empty() {
                        let mut new_rcpts = Vec::with_capacity(rcpts.len());

                        for rcpt in rcpts {
                            if ReportAddress::checked(rcpt.uri(), self.data.session_id).is_some() {
                                new_rcpts.push(rcpt.uri());
                            }
                        }

                        new_rcpts
                    } else {
                        if !dmarc_record.ruf().is_empty() {
                            trc::event!(
                                OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress),
                                SpanId = self.data.session_id,
                                Url = dmarc_record
                                    .ruf()
                                    .iter()
                                    .map(|u| trc::Value::String(u.uri().to_compact_string()))
                                    .collect::<Vec<_>>(),
                            );
                        }
                        vec![]
                    }
                }
                Err(_) => {
                    trc::event!(
                        OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError),
                        SpanId = self.data.session_id,
                        Url = dmarc_record
                            .ruf()
                            .iter()
                            .map(|u| trc::Value::String(u.uri().to_compact_string()))
                            .collect::<Vec<_>>(),
                    );

                    vec![]
                }
            };

            if !rcpts.is_empty() {
                let from_addr = self
                    .server
                    .eval_if(&config.address, self, &mut arena, self.data.session_id)
                    .await
                    .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_compact_string());
                let mut auth_failure = FeedbackReport {
                    authentication_results: vec![auth_results.to_string().into()],
                    headers: Some(
                        std::str::from_utf8(message.raw_headers())
                            .unwrap_or_default()
                            .into(),
                    ),
                    ..self.new_auth_failure(AuthFailureType::Dmarc, rejected)
                };

                let dkim_aligned = matches!(dmarc_output.dkim_result(), DmarcResult::Pass);
                let spf_aligned = matches!(dmarc_output.spf_result(), DmarcResult::Pass);

                // Report the first failed signature
                if let (
                    FailureOptions::Dkim
                    | FailureOptions::DkimSpf
                    | FailureOptions::All
                    | FailureOptions::Any,
                    Some(signature),
                ) = (
                    &report_options,
                    if !dkim_aligned {
                        dkim_output
                            .iter()
                            .find_map(|o| {
                                let s = o.signature()?;
                                if !matches!(o.result(), DkimResult::Pass) {
                                    Some(s)
                                } else {
                                    None
                                }
                            })
                            .or_else(|| dkim_output.iter().find_map(|o| o.signature()))
                    } else {
                        None
                    },
                ) {
                    auth_failure.dkim_domain = Some(signature.d.as_str().into());
                    auth_failure.dkim_selector = Some(signature.s.as_str().into());
                    auth_failure.dkim_identity = Some(signature.identity().into());
                }

                // Report SPF failure
                if let (
                    FailureOptions::Spf
                    | FailureOptions::DkimSpf
                    | FailureOptions::All
                    | FailureOptions::Any,
                    Some(output),
                ) = (
                    &report_options,
                    if !spf_aligned {
                        self.data
                            .spf_ehlo
                            .as_ref()
                            .and_then(|s| {
                                if s.result() != SpfResult::Pass {
                                    s.into()
                                } else {
                                    None
                                }
                            })
                            .or_else(|| {
                                self.data.spf_mail_from.as_ref().and_then(|s| {
                                    if s.result() != SpfResult::Pass {
                                        s.into()
                                    } else {
                                        None
                                    }
                                })
                            })
                            .or(self.data.spf_mail_from.as_ref())
                    } else {
                        None
                    },
                ) {
                    auth_failure.spf_dns =
                        Some(format!("txt : {} : v=SPF1", output.domain()).into());
                    // TODO use DNS record
                }

                auth_failure.identity_alignment = match (dkim_aligned, spf_aligned) {
                    (false, false) => IdentityAlignment::DkimSpf,
                    (false, true) => IdentityAlignment::Dkim,
                    (true, false) => IdentityAlignment::Spf,
                    (true, true) => IdentityAlignment::None,
                };
                let from_name = self
                    .server
                    .eval_if(&config.name, self, &mut arena, self.data.session_id)
                    .await
                    .unwrap_or_else(|| "Mail Delivery Subsystem".to_compact_string());
                let subject = self
                    .server
                    .eval_if(&config.subject, self, &mut arena, self.data.session_id)
                    .await
                    .unwrap_or_else(|| "DMARC Report".to_compact_string());
                let write_report = |to| {
                    let envelope = ReportEnvelope {
                        from: (from_name.as_str(), from_addr.as_str()).into(),
                        to,
                        submitter: &self.hostname,
                        report_domain: "",
                        subject: Some(&subject),
                    };
                    let mut report = Vec::with_capacity(128);
                    auth_failure
                        .write_rfc5322(&envelope, &mut report)
                        .map(|_| (report, envelope.to))
                };
                let report = match write_report(rcpts) {
                    Ok((report, validated)) => {
                        let mut allowed = Vec::with_capacity(validated.len());
                        for rcpt in &validated {
                            if self.throttle_rcpt(rcpt, &failure_rate, "dmarc").await {
                                allowed.push(*rcpt);
                            }
                        }
                        match allowed.len() {
                            0 => None,
                            len if len == validated.len() => Some(Ok((report, allowed))),
                            _ => Some(write_report(allowed)),
                        }
                    }
                    Err(err) => Some(Err(err)),
                };
                match report {
                    Some(Ok((report, rcpts))) => {
                        trc::event!(
                            OutgoingReport(OutgoingReportEvent::DmarcReport),
                            SpanId = self.data.session_id,
                            From = from_addr.clone(),
                            To = rcpts
                                .iter()
                                .map(|a| trc::Value::String(a.to_compact_string()))
                                .collect::<Vec<_>>(),
                        );

                        self.server
                            .send_report(
                                &from_addr,
                                rcpts.into_iter(),
                                report,
                                &config.sign,
                                true,
                                self.data.session_id,
                            )
                            .await;
                    }
                    Some(Err(err)) => {
                        trc::event!(
                            OutgoingReport(OutgoingReportEvent::SubmissionError),
                            SpanId = self.data.session_id,
                            Reason = err.to_string(),
                        );
                    }
                    None => {
                        trc::event!(
                            OutgoingReport(OutgoingReportEvent::DmarcRateLimited),
                            SpanId = self.data.session_id,
                            Limit = failure_rate.count,
                            Period = failure_rate.period.into_inner(),
                        );
                    }
                }
            } else {
                trc::event!(
                    OutgoingReport(OutgoingReportEvent::DmarcRateLimited),
                    SpanId = self.data.session_id,
                    Limit = failure_rate.count,
                    Period = failure_rate.period.into_inner(),
                );
            }
        }

        // Send aggregate reports
        let interval = self
            .server
            .eval_if(
                &self.server.core.smtp.report.dmarc_aggregate.send,
                self,
                &mut arena,
                self.data.session_id,
            )
            .await
            .unwrap_or(AggregateFrequency::Never);

        if matches!(interval, AggregateFrequency::Never) || dmarc_record.rua().is_empty() {
            return;
        }

        // Report the same identifier forms that were used for alignment
        let message_from = message.first_from_address();
        let header_from = message_from.domain_part();
        let header_from = header_from
            .to_ascii_domain()
            .unwrap_or(Cow::Borrowed(header_from));
        let envelope_from = self
            .data
            .mail_from
            .as_ref()
            .map(|mf| mf.domain.as_str())
            .unwrap_or_else(|| self.data.helo_domain.as_str());
        let envelope_from = envelope_from
            .to_ascii_domain()
            .unwrap_or(Cow::Borrowed(envelope_from));

        // Create DMARC report record
        let mut report_record = Record::default()
            .with_dmarc_output(&dmarc_output)
            .with_dkim_output(dkim_output);
        report_record.row.source_ip = Some(self.data.remote_ip);
        report_record.identifiers.header_from = header_from.into_owned();
        report_record.identifiers.envelope_from = envelope_from.into_owned();
        if let Some(dkim2_output) = dkim2_output {
            report_record = report_record.with_dkim2_output(dkim2_output);
        }
        if let Some(spf_mail_from) = &self.data.spf_mail_from {
            report_record = report_record.with_spf_output(spf_mail_from, SpfScope::MailFrom);
        }
        if let Some(arc_output) = arc_output {
            report_record = report_record.with_arc_output(arc_output);
        }

        // Submit DMARC report event
        self.server
            .schedule_report(DmarcEvent {
                domain: dmarc_output.into_domain(),
                report_record,
                dmarc_record,
                interval,
                span_id: self.data.session_id,
            })
            .await;
    }
}

pub trait DmarcReporting: Sync + Send {
    fn send_dmarc_aggregate_report(
        &self,
        report_id: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;
    fn schedule_dmarc(&self, event: Box<DmarcEvent>) -> impl Future<Output = ()> + Send;
}

impl DmarcReporting for Server {
    async fn send_dmarc_aggregate_report(&self, item_id: u64) -> trc::Result<()> {
        let object_id = ObjectType::DmarcInternalReport.to_id();
        let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });

        let Some(mut report) = self
            .store()
            .get_value::<DmarcInternalReport>(ValueKey::from(key.clone()))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };
        let span_id = self.inner.data.span_id_gen.generate();
        let max_size = self
            .eval_if(
                &self.core.smtp.report.dmarc_aggregate.max_size,
                &RecipientDomain::new(report.domain.as_str()),
                &mut Bump::new(),
                span_id,
            )
            .await;
        read_dmarc_records(
            self.store(),
            item_id,
            &mut report,
            report_size_limit(max_size),
        )
        .await?;

        let mut batch = BatchBuilder::new();
        batch.clear(key).clear(report.primary_key());
        let item = ReportItem::new(ObjectType::DmarcInternalReport, item_id);
        item.clear(&mut batch);
        let now = UTCDateTime::now();
        if now < report.report.date_range_end {
            report.report.date_range_end = now;
        }

        // Delete report
        self.store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
        if let Err(err) = item.clear_orphans(self.store()).await {
            trc::error!(
                err.span_id(span_id)
                    .details("Failed to clear orphaned report rows")
            );
        }

        if let Some(message) = DmarcMessage::build(self, report, span_id).await {
            message.queue(self, span_id).await;
        }
        Ok(())
    }

    async fn schedule_dmarc(&self, event: Box<DmarcEvent>) {
        ReportScheduler::default()
            .process(self, &mut vec![ReportingEvent::Dmarc(event)])
            .await;
    }
}

struct DmarcMessage {
    from_addr: CompactString,
    rcpts: Vec<String>,
    message: Vec<u8>,
}

impl DmarcMessage {
    async fn build(server: &Server, report: DmarcInternalReport, span_id: u64) -> Option<Self> {
        if report.report.records.is_empty() {
            return None;
        }
        let config = &server.core.smtp.report.dmarc_aggregate;
        let mut arena = Bump::new();
        let event_from = report.report.date_range_start.timestamp() as u64;
        let event_to = report.report.date_range_end.timestamp() as u64;

        trc::event!(
            OutgoingReport(OutgoingReportEvent::DmarcAggregateReport),
            SpanId = span_id,
            ReportId = event_from,
            Domain = report.domain.clone(),
            RangeFrom = trc::Value::Timestamp(event_from),
            RangeTo = trc::Value::Timestamp(event_to),
        );

        // Verify external reporting addresses
        let rua = match server
            .core
            .smtp
            .resolvers
            .dns
            .authorized_report_addresses(
                server
                    .inner
                    .cache
                    .build_auth_parameters((report.domain.as_str(), report.rua.as_slice())),
            )
            .await
        {
            Ok(rcpts) => {
                let rcpts = rcpts
                    .into_iter()
                    .filter(|rcpt| ReportAddress::checked(rcpt.as_str(), span_id).is_some())
                    .map(|rcpt| rcpt.as_str().to_string())
                    .collect::<Vec<_>>();
                if !rcpts.is_empty() {
                    rcpts
                } else {
                    trc::event!(
                        OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress),
                        SpanId = span_id,
                        Url = report
                            .rua
                            .into_iter()
                            .map(|u| trc::Value::String(u.into()))
                            .collect::<Vec<_>>(),
                    );

                    return None;
                }
            }
            Err(_) => {
                trc::event!(
                    OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError),
                    SpanId = span_id,
                    Url = report
                        .rua
                        .into_iter()
                        .map(|u| trc::Value::String(u.into()))
                        .collect::<Vec<_>>(),
                );

                return None;
            }
        };

        // Serialize report
        let from_addr = server
            .eval_if(
                &config.address,
                &RecipientDomain::new(report.domain.as_str()),
                &mut arena,
                span_id,
            )
            .await
            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_compact_string());
        let submitter = server
            .eval_if(
                &server.core.smtp.report.submitter,
                &RecipientDomain::new(report.domain.as_str()),
                &mut arena,
                span_id,
            )
            .await
            .unwrap_or_else(|| "localhost".to_compact_string());
        let from_name = server
            .eval_if(
                &config.name,
                &RecipientDomain::new(report.domain.as_str()),
                &mut arena,
                span_id,
            )
            .await
            .unwrap_or_else(|| "Mail Delivery Subsystem".to_compact_string());
        let mut message = Vec::with_capacity(2048);
        if let Err(err) = AggregateReport::from(report.report).write_rfc5322(
            &ReportEnvelope {
                from: (from_name.as_str(), from_addr.as_str()).into(),
                to: rua.iter().map(|a| a.as_str()).collect(),
                submitter: &submitter,
                report_domain: "",
                subject: None,
            },
            &mut message,
        ) {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::SubmissionError),
                SpanId = span_id,
                Reason = err.to_string(),
            );
            return None;
        }

        Some(DmarcMessage {
            from_addr,
            rcpts: rua,
            message,
        })
    }

    async fn queue(self, server: &Server, span_id: u64) {
        server
            .send_report(
                &self.from_addr,
                self.rcpts.iter(),
                self.message,
                &server.core.smtp.report.dmarc_aggregate.sign,
                false,
                span_id,
            )
            .await;
    }
}

pub(crate) fn dmarc_report_descriptor(
    event: &DmarcEvent,
    window: ReportWindow,
    item: ReportItem,
    policy_hash: u64,
) -> DmarcInternalReport {
    let date_range_start = UTCDateTime::from_timestamp(window.start.cast_signed());
    let policy = PolicyPublished::from_record(event.domain.clone(), &event.dmarc_record);

    DmarcInternalReport {
        created_at: date_range_start,
        deliver_at: UTCDateTime::from_timestamp(item.deliver_at(window).cast_signed()),
        domain: event.domain.clone(),
        report: DmarcReport {
            date_range_start,
            date_range_end: UTCDateTime::from_timestamp(window.end.cast_signed()),
            policy_adkim: policy.adkim.into(),
            policy_aspf: policy.aspf.into(),
            policy_disposition: policy.p.into(),
            policy_domain: policy.domain,
            policy_failure_reporting_options: match event.dmarc_record.fo {
                FailureOptions::All => vec![FailureReportingOption::All],
                FailureOptions::Any => vec![FailureReportingOption::Any],
                FailureOptions::Dkim => vec![FailureReportingOption::DkimFailure],
                FailureOptions::Spf => vec![FailureReportingOption::SpfFailure],
                FailureOptions::DkimSpf => vec![
                    FailureReportingOption::DkimFailure,
                    FailureReportingOption::SpfFailure,
                ],
            }
            .into(),
            policy_subdomain_disposition: policy.sp.into(),
            policy_np: policy.np.into(),
            policy_discovery_method: policy.discovery_method.into(),
            policy_testing_mode: policy.testing,
            policy_version: None,
            version: 1.0.into(),
            ..Default::default()
        },
        policy_identifier: policy_hash,
        rua: Map::new(
            event
                .dmarc_record
                .rua()
                .iter()
                .map(|u| u.uri.clone())
                .collect(),
        ),
    }
}

pub(crate) async fn complete_dmarc_report(
    server: &Server,
    report: &mut DmarcInternalReport,
    arena: &mut Bump,
    span_id: u64,
) {
    let config = &server.core.smtp.report.dmarc_aggregate;
    let domain = RecipientDomain::new(report.domain.as_str());
    report.report.report_id = format!(
        "{}_{}",
        report.report.date_range_start.timestamp(),
        server.inner.data.queue_id_gen.generate()
    );
    report.report.email = server
        .eval_if(&config.address, &domain, arena, span_id)
        .await
        .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
    report.report.extra_contact_info = server
        .eval_if::<String, _>(&config.contact_info, &domain, arena, span_id)
        .await;
    report.report.org_name = server
        .eval_if::<String, _>(&config.org_name, &domain, arena, span_id)
        .await
        .unwrap_or_default();
}
