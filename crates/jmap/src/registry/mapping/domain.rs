/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{
    ObjectResponse, RegistrySetResponse, ValidationResult, principal::validate_tenant_quota,
};
use common::network::{dkim::generate_dkim_selector, dns::update::DnsUpdater};
use jmap_proto::error::set::{SetError, SetErrorType};
use registry::{
    schema::{
        enums::{AcmeChallengeType, DkimSignatureType, DnsRecordType, TenantStorageQuota},
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
        && old_domain.is_none_or(|old| {
            !matches!(
                old.certificate_management,
                CertificateManagement::Automatic(_)
            )
        })
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

        tasks.push(Task::AcmeRenewal(TaskDomainManagement {
            domain_id: Id::default(),
            status: TaskStatus::now(),
        }));
    }

    Ok(Ok(response))
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
        if old_records.is_none() || !update_records.is_empty() {
            will_trigger_acme = old_domain.is_none()
                && matches!(
                    domain.certificate_management,
                    CertificateManagement::Automatic(_)
                );
            tasks.push(Task::DnsManagement(TaskDnsManagement {
                domain_id: Id::default(),
                update_records,
                on_success_renew_certificate: will_trigger_acme,
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
    use registry::schema::structs::DnsManagementProperties;

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
}
