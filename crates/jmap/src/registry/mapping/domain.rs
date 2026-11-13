/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::registry::mapping::{
    ObjectResponse, RegistrySetResponse, ValidationResult, principal::validate_tenant_quota,
};
use common::network::{dkim::generate_dkim_selector, dns::update::DnsUpdater};
use jmap_proto::error::set::{SetError, SetErrorType};
use registry::{
    schema::{
        enums::{
            AcmeChallengeType, DkimSignatureType, DnsRecordType, TaskType, TenantStorageQuota,
        },
        prelude::{ObjectType, Property},
        structs::{
            AcmeProvider, CertificateManagement, DkimManagement, DkimManagementProperties,
            DnsManagement, DnsServer, Domain, Task, TaskDnsManagement, TaskDomainManagement,
            TaskStatus,
        },
    },
    types::map::Map,
};
use types::id::Id;

pub(crate) async fn validate_domain(
    set: &RegistrySetResponse<'_>,
    domain: &mut Domain,
    old_domain: Option<&Domain>,
    tasks: &mut Vec<Task>,
) -> ValidationResult {
    let response = if old_domain.is_none() {
        match validate_tenant_quota(set.server, set.access_token, TenantStorageQuota::MaxDomains)
            .await?
        {
            Ok(response) => response,
            Err(err) => {
                return Ok(Err(err));
            }
        }
    } else {
        ObjectResponse::default()
    };

    // Validate DKIM selector template
    if let DkimManagement::Automatic(DkimManagementProperties {
        selector_template, ..
    }) = &domain.dkim_management
        && old_domain.is_none_or(|old| {
            matches!(
                &old.dkim_management,
                DkimManagement::Automatic(DkimManagementProperties {
                    selector_template: old_selector_template,
                    ..
                }) if old_selector_template != selector_template
            )
        })
        && let Err(err) =
            generate_dkim_selector(selector_template, DkimSignatureType::Dkim1RsaSha256)
    {
        return Ok(Err(SetError::invalid_properties()
            .with_property(Property::SelectorTemplate)
            .with_description(err)));
    }

    // Validate that names and aliases do not collide with another domain
    let registry = set.server.registry();
    if old_domain.is_none_or(|old| old.name != domain.name)
        && let Some(existing) = registry
            .primary_key(
                ObjectType::Domain.into(),
                Property::Aliases,
                domain.name.as_bytes().to_vec(),
            )
            .await?
    {
        return Ok(Err(SetError::new(SetErrorType::PrimaryKeyViolation)
            .with_property(Property::Name)
            .with_object_id(existing)));
    }

    for alias in domain.aliases.iter() {
        if alias == &domain.name
            || old_domain.is_some_and(|old| old.aliases.contains(alias) || &old.name == alias)
        {
            continue;
        }

        for index in [Property::Name, Property::Aliases] {
            if let Some(existing) = registry
                .primary_key(ObjectType::Domain.into(), index, alias.as_bytes().to_vec())
                .await?
            {
                return Ok(Err(SetError::new(SetErrorType::PrimaryKeyViolation)
                    .with_property(Property::Aliases)
                    .with_object_id(existing)));
            }
        }
    }

    let will_trigger_acme = schedule_dns_tasks(domain, old_domain, tasks);

    // Schedule ACME renewal task if needed
    if !will_trigger_acme
        && let CertificateManagement::Automatic(details) = &domain.certificate_management
        && needs_certificate_order(domain, old_domain)
    {
        let Some(provider) = set
            .server
            .registry()
            .object::<AcmeProvider>(details.acme_provider_id)
            .await?
        else {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::AcmeProviderId)
                .with_description("ACME provider not found")));
        };

        if matches!(provider.challenge_type, AcmeChallengeType::Dns01)
            && !matches!(domain.dns_management, DnsManagement::Automatic(_))
        {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::AcmeProviderId)
                .with_description(
                    "ACME provider requires automatic DNS management",
                )));
        }

        // inbuxa: CAA and the DNS-PERSIST-01 record name the provider, and the
        // persist record says whether wildcards are allowed. Publish them
        // before ordering, or the CA refuses the order (#290).
        let publishes_caa = matches!(
            &domain.dns_management,
            DnsManagement::Automatic(dns) if dns.publish_records.contains(&DnsRecordType::Caa)
        );
        if matches!(domain.dns_management, DnsManagement::Automatic(_))
            && (publishes_caa || matches!(provider.challenge_type, AcmeChallengeType::DnsPersist01))
            && acme_records_outdated(domain, old_domain)
        {
            tasks.push(Task::DnsManagement(TaskDnsManagement {
                domain_id: Id::default(),
                update_records: Map::new(if publishes_caa {
                    vec![DnsRecordType::Caa]
                } else {
                    vec![]
                }),
                on_success_renew_certificate: true,
                status: TaskStatus::now(),
            }));
        } else {
            tasks.push(Task::AcmeRenewal(TaskDomainManagement {
                domain_id: Id::default(),
                status: TaskStatus::now(),
            }));
        }
    }

    Ok(Ok(response))
}

/// inbuxa: the queued tasks a saved domain should lose (#327): those for
/// something it stopped managing itself, and its DKIM task when the save
/// queues a new one, which would otherwise run alongside it for good.
pub(crate) fn domain_tasks_to_clear(
    domain: &Domain,
    old_domain: &Domain,
    tasks: &[Task],
) -> Vec<TaskType> {
    let mut types = Vec::new();
    let stopped = |was: bool, is: bool| was && !is;
    if stopped(
        matches!(old_domain.dkim_management, DkimManagement::Automatic(_)),
        matches!(domain.dkim_management, DkimManagement::Automatic(_)),
    ) || tasks
        .iter()
        .any(|task| matches!(task, Task::DkimManagement(_)))
    {
        types.push(TaskType::DkimManagement);
    }
    if stopped(
        matches!(old_domain.dns_management, DnsManagement::Automatic(_)),
        matches!(domain.dns_management, DnsManagement::Automatic(_)),
    ) {
        types.push(TaskType::DnsManagement);
    }
    if stopped(
        matches!(
            old_domain.certificate_management,
            CertificateManagement::Automatic(_)
        ),
        matches!(
            domain.certificate_management,
            CertificateManagement::Automatic(_)
        ),
    ) {
        types.push(TaskType::AcmeRenewal);
    }
    types
}

/// inbuxa: whether a save changed what the domain's certificate is ordered
/// for. The renewal task decides what to do about it: a certificate that
/// already has these names just waits for its renewal date (#290).
fn needs_certificate_order(domain: &Domain, old_domain: Option<&Domain>) -> bool {
    let CertificateManagement::Automatic(new) = &domain.certificate_management else {
        return false;
    };
    let Some(old_domain) = old_domain else {
        return true;
    };
    let CertificateManagement::Automatic(old) = &old_domain.certificate_management else {
        return true;
    };
    let names = |list: &'_ Map<String>| {
        let mut names = list.as_slice().to_vec();
        names.sort();
        names.dedup();
        names
    };

    old_domain.name != domain.name
        || old.acme_provider_id != new.acme_provider_id
        || names(&old.subject_alternative_names) != names(&new.subject_alternative_names)
}

/// inbuxa: whether a save left the published CAA and DNS-PERSIST-01 records
/// out of date. Only an empty name list asks for a wildcard, so changing one
/// list of names for another doesn't touch them.
fn acme_records_outdated(domain: &Domain, old_domain: Option<&Domain>) -> bool {
    let CertificateManagement::Automatic(new) = &domain.certificate_management else {
        return false;
    };
    let Some(old_domain) = old_domain else {
        return true;
    };
    let CertificateManagement::Automatic(old) = &old_domain.certificate_management else {
        return true;
    };

    old_domain.name != domain.name
        || old.acme_provider_id != new.acme_provider_id
        || old.subject_alternative_names.is_empty() != new.subject_alternative_names.is_empty()
}

// Keep task planning independent of registry I/O so update transitions can be
// checked without contacting a DNS provider or starting a task manager.
fn schedule_dns_tasks(domain: &Domain, old_domain: Option<&Domain>, tasks: &mut Vec<Task>) -> bool {
    let will_trigger_dkim = matches!(domain.dkim_management, DkimManagement::Automatic(_))
        && old_domain
            .is_none_or(|old| !matches!(old.dkim_management, DkimManagement::Automatic(_)));
    let will_schedule_dkim = !will_trigger_dkim
        && matches!(domain.dkim_management, DkimManagement::Automatic(_))
        && publishes_dkim(domain)
        && old_domain.is_some_and(|old| !publishes_dkim(old));
    let mut will_trigger_acme = false;
    if let DnsManagement::Automatic(details) = &domain.dns_management {
        let old_records = old_domain.and_then(|old| match &old.dns_management {
            DnsManagement::Automatic(details) => Some(&details.publish_records),
            DnsManagement::Manual => None,
        });
        // Only publish newly enabled families on Automatic -> Automatic updates.
        // The DNS task does not delete records for disabled families. Compare
        // membership rather than Map equality: JSON key order is not a change.
        let update_records = Map::new(
            details
                .publish_records
                .iter()
                .filter(|&&record| {
                    old_records.is_none_or(|old| !old.contains(&record))
                        && (record != DnsRecordType::Dkim || !will_trigger_dkim)
                })
                .copied()
                .collect(),
        );
        let on_success_renew_certificate = old_domain.is_none()
            && matches!(
                domain.certificate_management,
                CertificateManagement::Automatic(_)
            );
        // inbuxa: with nothing to publish and no certificate to order after,
        // the task would only end as a failure (#304)
        if !update_records.is_empty() || on_success_renew_certificate {
            will_trigger_acme = on_success_renew_certificate;
            tasks.push(Task::DnsManagement(TaskDnsManagement {
                domain_id: Id::default(),
                update_records,
                on_success_renew_certificate,
                status: TaskStatus::now(),
            }));
        }
    }

    // Schedule DKIM key rotation task
    if will_trigger_dkim || will_schedule_dkim {
        tasks.push(Task::DkimManagement(TaskDomainManagement {
            domain_id: Id::default(),
            status: TaskStatus::now(),
        }));
    }

    will_trigger_acme
}

fn publishes_dkim(domain: &Domain) -> bool {
    matches!(
        &domain.dns_management,
        DnsManagement::Automatic(details) if details.publish_records.contains(&DnsRecordType::Dkim)
    )
}

pub(crate) async fn validate_dns_server(
    set: &RegistrySetResponse<'_>,
    dns: &mut DnsServer,
    old_dns: Option<&DnsServer>,
) -> ValidationResult {
    let response = if old_dns.is_none() {
        match validate_tenant_quota(
            set.server,
            set.access_token,
            TenantStorageQuota::MaxDnsServers,
        )
        .await?
        {
            Ok(response) => response,
            Err(err) => {
                return Ok(Err(err));
            }
        }
    } else {
        ObjectResponse::default()
    };

    if old_dns.is_none_or(|old_dns| old_dns != dns)
        && let Err(err) = DnsUpdater::build(dns.clone(), set.server.core.clone()).await
    {
        return Ok(Err(SetError::invalid_properties()
            .with_description(format!("Failed to build DNS server: {err}"))));
    }

    Ok(Ok(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry::schema::structs::{CertificateManagementProperties, DnsManagementProperties};

    fn domain(name: &str, provider: u64, names: &[&str]) -> Domain {
        Domain {
            name: name.to_string(),
            certificate_management: CertificateManagement::Automatic(
                CertificateManagementProperties {
                    acme_provider_id: Id::from(provider),
                    subject_alternative_names: Map::new(
                        names.iter().map(|name| name.to_string()).collect(),
                    ),
                },
            ),
            ..Default::default()
        }
    }

    #[test]
    fn saving_the_same_names_orders_nothing() {
        let old = domain("example.org", 1, &["mail", "imap"]);
        assert!(!needs_certificate_order(
            &domain("example.org", 1, &["imap", "mail"]),
            Some(&old)
        ));
        assert!(!acme_records_outdated(
            &domain("example.org", 1, &["imap", "mail"]),
            Some(&old)
        ));
    }

    #[test]
    fn changing_the_names_orders_a_certificate() {
        let old = domain("example.org", 1, &["mail"]);
        for new in [
            domain("example.org", 1, &["mail", "imap"]),
            domain("example.org", 1, &["imap"]),
            domain("example.org", 1, &[]),
            domain("example.org", 2, &["mail"]),
            domain("example.net", 1, &["mail"]),
        ] {
            assert!(needs_certificate_order(&new, Some(&old)));
        }
    }

    #[test]
    fn switching_to_automatic_orders_a_certificate_and_manual_doesnt() {
        let manual = Domain {
            certificate_management: CertificateManagement::Manual,
            ..domain("example.org", 1, &[])
        };
        let automatic = domain("example.org", 1, &[]);
        assert!(needs_certificate_order(&automatic, Some(&manual)));
        assert!(needs_certificate_order(&automatic, None));
        assert!(!needs_certificate_order(&manual, Some(&automatic)));
        assert!(!needs_certificate_order(&manual, Some(&manual)));
    }

    #[test]
    fn records_only_go_stale_when_what_they_say_changes() {
        let old = domain("example.org", 1, &["mail"]);
        // Still no wildcard, same provider
        assert!(!acme_records_outdated(
            &domain("example.org", 1, &["imap"]),
            Some(&old)
        ));
        // Wildcard allowed from here on
        assert!(acme_records_outdated(
            &domain("example.org", 1, &[]),
            Some(&old)
        ));
        // A different provider or owner name
        assert!(acme_records_outdated(
            &domain("example.org", 2, &["mail"]),
            Some(&old)
        ));
        assert!(acme_records_outdated(
            &domain("example.net", 1, &["mail"]),
            Some(&old)
        ));
    }

    fn automatic(records: &[DnsRecordType]) -> Domain {
        Domain {
            dns_management: DnsManagement::Automatic(DnsManagementProperties {
                publish_records: Map::new(records.to_vec()),
                ..Default::default()
            }),
            dkim_management: DkimManagement::Automatic(Default::default()),
            ..Default::default()
        }
    }

    fn plan(old: Option<&Domain>, new: &Domain) -> (Vec<Task>, bool) {
        let mut tasks = Vec::new();
        let renew = schedule_dns_tasks(new, old, &mut tasks);
        (tasks, renew)
    }

    fn dns_tasks(tasks: &[Task]) -> Vec<&TaskDnsManagement> {
        tasks
            .iter()
            .filter_map(|task| match task {
                Task::DnsManagement(task) => Some(task),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn automatic_enabling_dmarc_queues_only_new_families() {
        let old = automatic(&[DnsRecordType::Dkim, DnsRecordType::Spf, DnsRecordType::Mx]);
        let new = automatic(&[
            DnsRecordType::Dkim,
            DnsRecordType::Spf,
            DnsRecordType::Mx,
            DnsRecordType::Dmarc,
        ]);
        let (tasks, renew) = plan(Some(&old), &new);
        assert_eq!(tasks.len(), 1);
        let dns = dns_tasks(&tasks);
        assert_eq!(dns[0].update_records.as_slice(), &[DnsRecordType::Dmarc]);
        assert!(!dns[0].on_success_renew_certificate);
        assert!(!renew);
    }

    #[test]
    fn automatic_unchanged_or_reordered_records_do_not_queue() {
        let old = automatic(&[DnsRecordType::Dkim, DnsRecordType::Spf]);
        assert!(plan(Some(&old), &old).0.is_empty());
        let mut new = automatic(&[]);
        let DnsManagement::Automatic(details) = &mut new.dns_management else {
            unreachable!();
        };
        details.publish_records =
            serde_json::from_str(r#"{"spf":true,"dmarc":false,"mx":null,"dkim":true}"#).unwrap();
        assert!(plan(Some(&old), &new).0.is_empty());
    }

    #[test]
    fn manual_record_changes_do_not_queue_automatic_dns() {
        // Manual has no publishRecords field in the typed schema; any such
        // input is discarded by deserialization before task planning.
        let old = Domain::default();
        let new = Domain {
            dns_management: serde_json::from_str(
                r#"{"@type":"Manual","publishRecords":{"dmarc":true}}"#,
            )
            .unwrap(),
            ..Default::default()
        };
        assert!(plan(Some(&old), &new).0.is_empty());
    }

    #[test]
    fn manual_to_automatic_keeps_initial_publication() {
        let old = Domain::default();
        let mut new = automatic(&[DnsRecordType::Spf, DnsRecordType::Dmarc]);
        new.dkim_management = DkimManagement::Manual;
        let (tasks, renew) = plan(Some(&old), &new);
        assert_eq!(tasks.len(), 1);
        assert_eq!(
            dns_tasks(&tasks)[0].update_records.as_slice(),
            &[DnsRecordType::Spf, DnsRecordType::Dmarc]
        );
        assert!(!renew);
    }

    #[test]
    fn newly_published_dkim_is_combined_with_other_new_families() {
        let old = automatic(&[DnsRecordType::Spf]);
        let new = automatic(&[
            DnsRecordType::Spf,
            DnsRecordType::Dkim,
            DnsRecordType::Dmarc,
        ]);
        let (tasks, _) = plan(Some(&old), &new);
        let dns = dns_tasks(&tasks);
        assert_eq!(dns.len(), 1);
        assert_eq!(
            dns[0].update_records.as_slice(),
            &[DnsRecordType::Dkim, DnsRecordType::Dmarc]
        );
        assert_eq!(tasks.len(), 2);
        assert!(matches!(tasks[1], Task::DkimManagement(_)));
    }

    #[test]
    fn newly_automatic_dkim_keeps_its_own_publication_path() {
        let mut old = automatic(&[DnsRecordType::Spf]);
        old.dkim_management = DkimManagement::Manual;
        let new = automatic(&[
            DnsRecordType::Spf,
            DnsRecordType::Dkim,
            DnsRecordType::Dmarc,
        ]);
        let (tasks, _) = plan(Some(&old), &new);
        assert_eq!(tasks.len(), 2);
        let dns = dns_tasks(&tasks);
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].update_records.as_slice(), &[DnsRecordType::Dmarc]);
        assert!(matches!(tasks[1], Task::DkimManagement(_)));
        let dkim_only = automatic(&[DnsRecordType::Spf, DnsRecordType::Dkim]);
        let (tasks, _) = plan(Some(&old), &dkim_only);
        assert_eq!(tasks.len(), 1);
        assert!(matches!(tasks[0], Task::DkimManagement(_)));
    }

    #[test]
    fn removing_families_does_not_delete_or_republish_records() {
        let old = automatic(&[DnsRecordType::Spf, DnsRecordType::Dmarc]);
        let new = automatic(&[DnsRecordType::Spf]);
        assert!(plan(Some(&old), &new).0.is_empty());
        let replaced = automatic(&[DnsRecordType::Mx]);
        let (tasks, _) = plan(Some(&old), &replaced);
        assert_eq!(tasks.len(), 1);
        assert_eq!(
            dns_tasks(&tasks)[0].update_records.as_slice(),
            &[DnsRecordType::Mx]
        );
    }

    #[test]
    fn automatic_to_manual_does_not_queue_dns() {
        let old = automatic(&[DnsRecordType::Spf, DnsRecordType::Dmarc]);
        let mut new = old.clone();
        new.dns_management = DnsManagement::Manual;
        assert!(plan(Some(&old), &new).0.is_empty());
    }

    #[test]
    fn new_automatic_domain_keeps_certificate_handoff() {
        let mut new = automatic(&[DnsRecordType::Spf, DnsRecordType::Dkim]);
        new.certificate_management = CertificateManagement::Automatic(Default::default());
        let (tasks, renew) = plan(None, &new);
        assert_eq!(tasks.len(), 2);
        let dns = dns_tasks(&tasks);
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].update_records.as_slice(), &[DnsRecordType::Spf]);
        assert!(dns[0].on_success_renew_certificate);
        assert!(renew);
        assert!(matches!(tasks[1], Task::DkimManagement(_)));
    }

    #[test]
    fn automatic_with_nothing_to_publish_queues_nothing() {
        // #304: no records and no certificate to order would only fail
        let old = Domain::default();
        let mut new = automatic(&[]);
        new.dkim_management = DkimManagement::Manual;
        assert!(plan(Some(&old), &new).0.is_empty());
        assert!(plan(None, &new).0.is_empty());
    }
}
