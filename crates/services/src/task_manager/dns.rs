/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::task_manager::TaskResult;
use common::Server;
use dns_update::{CAARecord, DnsRecord, DnsRecordType, Error as DnsUpdateError, KeyValue};
use registry::{
    schema::{
        enums::DnsRecordType as RecordType,
        prelude::ObjectType,
        structs::{
            DnsManagement, Domain, Task, TaskDnsManagement, TaskDomainManagement, TaskStatus,
        },
    },
    types::{EnumImpl, map::Map},
};
use std::fmt::Write;
use store::{ahash::AHashMap, registry::RegistryQuery, write::BatchBuilder};
use trc::{AddContext, DnsEvent, TaskManagerEvent};
use types::id::Id;

/// Queues the MX and SPF records again for every domain whose DNS is
/// published and names them, when what the relays put in them changed
/// (relay spec, RL-25). Returns how many domains.
pub(crate) async fn queue_relay_dns(server: &Server) -> trc::Result<usize> {
    let domain_ids = server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Domain))
        .await
        .caused_by(trc::location!())?;
    let mut batch = BatchBuilder::new();
    let mut total = 0;
    for domain_id in domain_ids {
        let Some(domain) = server
            .registry()
            .object::<Domain>(domain_id)
            .await
            .caused_by(trc::location!())?
        else {
            continue;
        };
        let DnsManagement::Automatic(props) = &domain.dns_management else {
            continue;
        };
        let records: Vec<RecordType> = props
            .publish_records
            .iter()
            .filter(|r| matches!(r, RecordType::Mx | RecordType::Spf))
            .copied()
            .collect();
        if records.is_empty() {
            continue;
        }
        let task = Task::DnsManagement(TaskDnsManagement {
            domain_id,
            update_records: Map::new(records),
            on_success_renew_certificate: false,
            status: TaskStatus::now(),
        });
        trc::event!(
            TaskManager(TaskManagerEvent::TaskQueued),
            Type = task.object_type().as_str(),
            Domain = domain.name.clone(),
            Details = "The relays in its MX or SPF records changed",
        );
        batch.schedule_task(task);
        total += 1;
    }
    if !batch.is_empty() {
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
        server.notify_task_queue();
    }
    Ok(total)
}

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

    let mut errors = String::new();
    for ((name, record_type), mut recs) in by_owner {
        let preserve_unrelated = match record_type {
            DnsRecordType::TXT => !is_owned_txt_name(&name),
            DnsRecordType::CAA => true,
            _ => false,
        };
        if preserve_unrelated {
            match dns_updater.list_rrset(origin, &name, record_type).await {
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
                }
            }
        }

        // inbuxa: a publish never cuts a domain's MX set down to one host
        // (relay spec, RL-25)
        if record_type == DnsRecordType::MX
            && let Ok(existing) = dns_updater.list_rrset(origin, &name, record_type).await
            && let Some(hosts) = shrinks_mx_set(&existing, &recs)
        {
            if !errors.is_empty() {
                errors.push_str("; ");
            }
            let _ = write!(
                &mut errors,
                "Left the MX records for {name} as they are: publishing would replace their {hosts} hosts with one"
            );
            continue;
        }

        if let Err(err) = dns_updater
            .set_rrset(origin, &name, record_type, recs)
            .await
        {
            if !errors.is_empty() {
                errors.push_str("; ");
            }
            let _ = write!(
                &mut errors,
                "Failed to set DNS RRSet for {}/{}: {}",
                name,
                record_type.as_str(),
                err
            );
        }
    }

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
    } else {
        Ok(TaskResult::permanent(errors))
    }
}

/// How many hosts a published MX set has, when `new` would replace them
/// with one.
fn shrinks_mx_set(existing: &[DnsRecord], new: &[DnsRecord]) -> Option<usize> {
    let hosts = |records: &[DnsRecord]| {
        let mut hosts: Vec<String> = records
            .iter()
            .filter_map(|r| match r {
                DnsRecord::MX(mx) => Some(mx.exchange.trim_end_matches('.').to_ascii_lowercase()),
                _ => None,
            })
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts.len()
    };
    let (before, after) = (hosts(existing), hosts(new));
    (before > 1 && after == 1).then_some(before)
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
    use dns_update::MXRecord;

    fn mx(hosts: &[&str]) -> Vec<DnsRecord> {
        hosts
            .iter()
            .map(|host| {
                DnsRecord::MX(MXRecord {
                    exchange: host.to_string(),
                    priority: 10,
                })
            })
            .collect()
    }

    #[test]
    fn an_mx_set_isnt_cut_to_one() {
        let three = mx(&["mail.example.com.", "mx2.example.com.", "mx3.example.com."]);
        assert_eq!(shrinks_mx_set(&three, &mx(&["mail.example.com."])), Some(3));
        // The same host twice is one host
        assert_eq!(
            shrinks_mx_set(&mx(&["a.test.", "A.test"]), &mx(&["b.test."])),
            None
        );
        assert_eq!(shrinks_mx_set(&three, &mx(&["a.test.", "b.test."])), None);
        assert_eq!(shrinks_mx_set(&mx(&["a.test."]), &mx(&["b.test."])), None);
        assert_eq!(shrinks_mx_set(&[], &mx(&["a.test."])), None);
    }
}
