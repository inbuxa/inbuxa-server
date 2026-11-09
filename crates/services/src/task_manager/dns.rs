/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::task_manager::TaskResult;
use common::{Server, network::dns::update::DnsUpdater};
use dns_update::{CAARecord, DnsRecord, DnsRecordType, Error as DnsUpdateError, KeyValue};
use registry::schema::structs::{
    DnsManagement, Domain, Task, TaskDnsManagement, TaskDomainManagement, TaskStatus,
};
use std::fmt::Write;
use store::ahash::AHashMap;
use trc::DnsEvent;

pub(crate) trait DnsManagementTask: Sync + Send {
    fn dns_management(&self, task: &TaskDnsManagement) -> impl Future<Output = TaskResult> + Send;
}

impl DnsManagementTask for Server {
    async fn dns_management(&self, task: &TaskDnsManagement) -> TaskResult {
        match dns_management(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to run DNS management task")
                );
                result
            }
        }
    }
}

async fn dns_management(server: &Server, task: &TaskDnsManagement) -> trc::Result<TaskResult> {
    if task.update_records.is_empty() {
        return Ok(TaskResult::permanent(
            "No DNS records to update".to_string(),
        ));
    }
    let Some(domain) = server.registry().object::<Domain>(task.domain_id).await? else {
        return Ok(TaskResult::permanent("Domain not found".to_string()));
    };
    let DnsManagement::Automatic(props) = &domain.dns_management else {
        return Ok(TaskResult::permanent(
            "Domain is not set to automatic DNS management".to_string(),
        ));
    };
    let dns_updater = match server.build_dns_updater(props.dns_server_id).await? {
        Ok(updater) => updater,
        Err(err) => {
            return Ok(TaskResult::permanent(format!(
                "Failed to build DNS updater: {}",
                err
            )));
        }
    };
    let origin = props.origin.as_deref().unwrap_or(&domain.name);
    let records = server
        .build_dns_records(task.domain_id, &domain, task.update_records.as_slice())
        .await?;

    // Group records by (name, type) so each RRSet is published in one call.
    let mut by_owner: AHashMap<(String, DnsRecordType), Vec<DnsRecord>> = AHashMap::new();
    for record in records {
        by_owner
            .entry((record.name, record.record.as_type()))
            .or_default()
            .push(record.record);
    }

    let (errors, transient) = publish_rrsets(&dns_updater, origin, by_owner).await;

    if errors.is_empty() {
        if task.on_success_renew_certificate {
            Ok(TaskResult::Success(vec![Task::AcmeRenewal(
                TaskDomainManagement {
                    domain_id: task.domain_id,
                    status: TaskStatus::now(),
                },
            )]))
        } else {
            Ok(TaskResult::Success(vec![]))
        }
    } else if transient {
        Ok(TaskResult::temporary(errors))
    } else {
        Ok(TaskResult::permanent(errors))
    }
}

/// What the task asks of a DNS provider, a trait so the tests can stand in
/// a provider that fails.
trait RrsetUpdater: Sync {
    fn list(
        &self,
        origin: &str,
        name: &str,
        record_type: DnsRecordType,
    ) -> impl Future<Output = dns_update::Result<Vec<DnsRecord>>> + Send;
    fn replace(
        &self,
        origin: &str,
        name: &str,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
    ) -> impl Future<Output = dns_update::Result<()>> + Send;
}

impl RrsetUpdater for DnsUpdater {
    fn list(
        &self,
        origin: &str,
        name: &str,
        record_type: DnsRecordType,
    ) -> impl Future<Output = dns_update::Result<Vec<DnsRecord>>> + Send {
        self.list_rrset(origin, name, record_type)
    }

    fn replace(
        &self,
        origin: &str,
        name: &str,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
    ) -> impl Future<Output = dns_update::Result<()>> + Send {
        self.replace_rrset(origin, name, record_type, records)
    }
}

/// Publishes each RRSet. Returns what failed, and whether any of it may pass
/// on its own so the task is worth trying again.
async fn publish_rrsets(
    dns_updater: &impl RrsetUpdater,
    origin: &str,
    by_owner: AHashMap<(String, DnsRecordType), Vec<DnsRecord>>,
) -> (String, bool) {
    let mut errors = String::new();
    let mut transient = false;
    for ((name, record_type), mut recs) in by_owner {
        let preserve_unrelated = match record_type {
            DnsRecordType::TXT => !is_owned_txt_name(&name),
            DnsRecordType::CAA => true,
            _ => false,
        };
        if preserve_unrelated {
            match dns_updater.list(origin, &name, record_type).await {
                Ok(existing) => {
                    for existing_rec in existing {
                        if !recs.iter().any(|new| same_rrset_family(new, &existing_rec)) {
                            recs.push(existing_rec);
                        }
                    }
                }
                Err(DnsUpdateError::Unsupported(reason)) => {
                    trc::event!(
                        Dns(DnsEvent::RecordLookupFailed),
                        Hostname = name.clone(),
                        Details = origin.to_string(),
                        Type = record_type.as_str(),
                        Reason = format!(
                            "DNS provider cannot list RRSet, unrelated records at this name may be overwritten: {reason}"
                        ),
                    );
                }
                Err(err) => {
                    trc::event!(
                        Dns(DnsEvent::RecordLookupFailed),
                        Hostname = name.clone(),
                        Details = origin.to_string(),
                        Type = record_type.as_str(),
                        Reason = format!("DNS provider failed to list RRSet: {err}"),
                    );
                    // inbuxa: without the list, writing ours would replace
                    // the other records at this name, so it waits
                    push_error(
                        &mut errors,
                        format_args!(
                            "Left the DNS RRSet for {name}/{} as it is: listing it failed: {err}",
                            record_type.as_str()
                        ),
                    );
                    transient |= is_transient(&err);
                    continue;
                }
            }
        }

        if let Err(err) = dns_updater.replace(origin, &name, record_type, recs).await {
            push_error(
                &mut errors,
                format_args!(
                    "Failed to set DNS RRSet for {}/{}: {}",
                    name,
                    record_type.as_str(),
                    err
                ),
            );
            transient |= is_transient(&err);
        }
    }

    (errors, transient)
}

fn push_error(errors: &mut String, error: std::fmt::Arguments<'_>) {
    if !errors.is_empty() {
        errors.push_str("; ");
    }
    let _ = errors.write_fmt(error);
}

/// inbuxa: whether a DNS provider's error may pass on its own, so the task
/// is tried again: the network, a timeout, the provider's server failing or
/// limiting the rate. Refused credentials, a zone the provider doesn't have
/// and a refused request stay failed.
fn is_transient(err: &DnsUpdateError) -> bool {
    match err {
        // HTTP providers: the request couldn't be sent or read, or the
        // status wasn't 401 or 404
        DnsUpdateError::Api(reason) => {
            reason.starts_with("Failed to send request")
                || reason.starts_with("Failed to read response")
                || reason
                    .strip_prefix("HTTP ")
                    .is_some_and(|status| status.starts_with('5') || status.starts_with("429"))
        }
        // RFC 2136: the connection or a timeout, or SERVFAIL
        DnsUpdateError::Client(reason) => {
            reason.starts_with("io error")
                || reason.contains("timed out")
                || reason.starts_with("no connections available")
                || reason.starts_with("resource too busy")
        }
        DnsUpdateError::Response(rcode) => rcode == "Server Failure",
        _ => false,
    }
}

fn same_rrset_family(a: &DnsRecord, b: &DnsRecord) -> bool {
    match (a, b) {
        (DnsRecord::TXT(_), DnsRecord::TXT(_)) => same_txt_family(a, b),
        (DnsRecord::CAA(_), DnsRecord::CAA(_)) => same_caa_family(a, b),
        _ => false,
    }
}

fn same_txt_family(a: &DnsRecord, b: &DnsRecord) -> bool {
    match (a, b) {
        (DnsRecord::TXT(va), DnsRecord::TXT(vb)) => match (txt_family(va), txt_family(vb)) {
            (Some(fa), Some(fb)) => fa.eq_ignore_ascii_case(fb),
            _ => false,
        },
        _ => false,
    }
}

fn same_caa_family(a: &DnsRecord, b: &DnsRecord) -> bool {
    match (a, b) {
        (DnsRecord::CAA(ca), DnsRecord::CAA(cb)) => match (ca, cb) {
            (CAARecord::Issue { options: oa, .. }, CAARecord::Issue { options: ob, .. })
            | (
                CAARecord::IssueWild { options: oa, .. },
                CAARecord::IssueWild { options: ob, .. },
            ) => match (caa_account_uri(oa), caa_account_uri(ob)) {
                (Some(ua), Some(ub)) => ua.eq_ignore_ascii_case(ub),
                _ => false,
            },
            (CAARecord::Iodef { url: ua, .. }, CAARecord::Iodef { url: ub, .. }) => {
                ua.eq_ignore_ascii_case(ub)
            }
            _ => false,
        },
        _ => false,
    }
}

fn caa_account_uri(options: &[KeyValue]) -> Option<&str> {
    options
        .iter()
        .find(|kv| kv.key.eq_ignore_ascii_case("accounturi"))
        .map(|kv| kv.value.as_str())
}

fn txt_family(value: &str) -> Option<&str> {
    value.trim_start().strip_prefix("v=").map(|rest| {
        rest.split_once([';', ' '])
            .map_or(rest, |(family, _)| family)
    })
}

fn is_owned_txt_name(name: &str) -> bool {
    name.contains("_dmarc.")
        || name.contains("_smtp._tls.")
        || name.contains("_mta-sts.")
        || name.contains("_ua-auto-config.")
        || name.contains("_validation-persist.")
        || name.contains("._domainkey.")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DNS provider holding one zone, whose lookups or writes can be made
    /// to fail.
    #[derive(Default)]
    struct FailingUpdater {
        records: std::sync::Mutex<Vec<(String, DnsRecord)>>,
        list_error: Option<fn() -> DnsUpdateError>,
        replace_error: Option<fn() -> DnsUpdateError>,
    }

    impl RrsetUpdater for FailingUpdater {
        fn list(
            &self,
            _origin: &str,
            name: &str,
            record_type: DnsRecordType,
        ) -> impl Future<Output = dns_update::Result<Vec<DnsRecord>>> + Send {
            let result = match self.list_error {
                Some(error) => Err(error()),
                None => Ok(self
                    .records
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(at, record)| at == name && record.as_type() == record_type)
                    .map(|(_, record)| record.clone())
                    .collect()),
            };
            async move { result }
        }

        fn replace(
            &self,
            _origin: &str,
            name: &str,
            record_type: DnsRecordType,
            records: Vec<DnsRecord>,
        ) -> impl Future<Output = dns_update::Result<()>> + Send {
            let result = match self.replace_error {
                Some(error) => Err(error()),
                None => {
                    let mut zone = self.records.lock().unwrap();
                    zone.retain(|(at, record)| !(at == name && record.as_type() == record_type));
                    zone.extend(records.into_iter().map(|record| (name.to_string(), record)));
                    Ok(())
                }
            };
            async move { result }
        }
    }

    fn txt(value: &str) -> DnsRecord {
        DnsRecord::TXT(value.to_string())
    }

    /// Publishes a new SPF record at the apex of a zone that also holds a
    /// site verification record. Returns the zone afterwards, the errors and
    /// whether the task would be tried again.
    async fn publish_spf(
        list_error: Option<fn() -> DnsUpdateError>,
        replace_error: Option<fn() -> DnsUpdateError>,
    ) -> (Vec<DnsRecord>, String, bool) {
        let updater = FailingUpdater {
            records: std::sync::Mutex::new(vec![
                ("example.org".to_string(), txt("site-verification=abc")),
                ("example.org".to_string(), txt("v=spf1 a -all")),
            ]),
            list_error,
            replace_error,
        };
        let by_owner = AHashMap::from_iter([(
            ("example.org".to_string(), DnsRecordType::TXT),
            vec![txt("v=spf1 mx -all")],
        )]);
        let (errors, transient) = publish_rrsets(&updater, "example.org", by_owner).await;
        let zone = updater
            .records
            .into_inner()
            .unwrap()
            .into_iter()
            .map(|(_, record)| record)
            .collect();
        (zone, errors, transient)
    }

    #[tokio::test]
    async fn other_records_at_the_name_are_kept() {
        let (zone, errors, _) = publish_spf(None, None).await;
        assert_eq!(errors, "");
        assert_eq!(
            zone,
            vec![txt("v=spf1 mx -all"), txt("site-verification=abc")]
        );
    }

    #[tokio::test]
    async fn a_failed_lookup_leaves_the_name_alone() {
        let before = vec![txt("site-verification=abc"), txt("v=spf1 a -all")];

        // A timeout is tried again
        let (zone, errors, transient) = publish_spf(
            Some(|| {
                DnsUpdateError::Api("Failed to send request to https://dns.test: timed out".into())
            }),
            None,
        )
        .await;
        assert_eq!(zone, before, "a failed lookup replaced the RRSet");
        assert!(errors.contains("timed out"), "{errors}");
        assert!(transient, "a timeout is not tried again: {errors}");

        // Refused credentials are not
        let (zone, errors, transient) =
            publish_spf(Some(|| DnsUpdateError::Unauthorized), None).await;
        assert_eq!(zone, before, "a failed lookup replaced the RRSet");
        assert!(!transient, "refused credentials are tried again: {errors}");

        // A provider that can't list at all still gets the record
        let (zone, errors, _) = publish_spf(
            Some(|| DnsUpdateError::Unsupported("no listing".into())),
            None,
        )
        .await;
        assert_eq!(errors, "");
        assert_eq!(zone, vec![txt("v=spf1 mx -all")]);
    }

    #[tokio::test]
    async fn only_errors_that_may_pass_are_tried_again() {
        for (error, expected) in [
            (
                (|| DnsUpdateError::Api("Failed to send request to https://dns.test: reset".into()))
                    as fn() -> DnsUpdateError,
                true,
            ),
            (|| DnsUpdateError::Api("HTTP 503: unavailable".into()), true),
            (|| DnsUpdateError::Api("HTTP 429".into()), true),
            (|| DnsUpdateError::Client("request timed out".into()), true),
            (
                || DnsUpdateError::Client("io error: connection refused".into()),
                true,
            ),
            (|| DnsUpdateError::Response("Server Failure".into()), true),
            (|| DnsUpdateError::Unauthorized, false),
            (|| DnsUpdateError::NotFound, false),
            (|| DnsUpdateError::BadRequest, false),
            (|| DnsUpdateError::Api("HTTP 403: forbidden".into()), false),
            (
                || DnsUpdateError::Api("BadRequest invalid content".into()),
                false,
            ),
            (|| DnsUpdateError::Response("Refused".into()), false),
            (
                || DnsUpdateError::Client("a.test is not in the DNS zone example.org".into()),
                false,
            ),
        ] {
            let (_, errors, transient) = publish_spf(None, Some(error)).await;
            assert!(!errors.is_empty());
            assert_eq!(transient, expected, "{errors}");
        }
    }
}
