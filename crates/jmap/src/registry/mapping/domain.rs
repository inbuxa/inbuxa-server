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

    // Schedule DNS update task
    let will_trigger_dkim = matches!(domain.dkim_management, DkimManagement::Automatic(_))
        && old_domain
            .is_none_or(|old| !matches!(old.dkim_management, DkimManagement::Automatic(_)));
    let will_schedule_dkim = !will_trigger_dkim
        && matches!(domain.dkim_management, DkimManagement::Automatic(_))
        && publishes_dkim(domain)
        && old_domain.is_some_and(|old| !publishes_dkim(old));
    let will_trigger_acme = if let DnsManagement::Automatic(details) = &domain.dns_management
        && old_domain.is_none_or(|old| !matches!(old.dns_management, DnsManagement::Automatic(_)))
    {
        let on_success_renew_certificate = old_domain.is_none()
            && matches!(
                domain.certificate_management,
                CertificateManagement::Automatic(_)
            );
        let update_records: Vec<DnsRecordType> = details
            .publish_records
            .iter()
            .filter(|&&r| r != DnsRecordType::Dkim || !will_trigger_dkim)
            .copied()
            .collect();
        // inbuxa: with nothing to publish and no certificate to order after,
        // the task would only end as a failure (#304)
        if !update_records.is_empty() || on_success_renew_certificate {
            tasks.push(Task::DnsManagement(TaskDnsManagement {
                domain_id: Id::default(),
                update_records: Map::new(update_records),
                on_success_renew_certificate,
                status: TaskStatus::now(),
            }));
        }
        on_success_renew_certificate
    } else {
        if will_schedule_dkim {
            tasks.push(Task::DnsManagement(TaskDnsManagement {
                domain_id: Id::default(),
                update_records: Map::new(vec![DnsRecordType::Dkim]),
                on_success_renew_certificate: false,
                status: TaskStatus::now(),
            }));
        }
        false
    };

    // Schedule DKIM key rotation task
    if will_trigger_dkim || will_schedule_dkim {
        tasks.push(Task::DkimManagement(TaskDomainManagement {
            domain_id: Id::default(),
            status: TaskStatus::now(),
        }));
    }

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
    use registry::schema::structs::CertificateManagementProperties;

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
}
