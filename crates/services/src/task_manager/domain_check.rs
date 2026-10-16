/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Keeps automatic DKIM rotation and certificate renewal running. Both
//! tasks are only queued when a domain is saved into automatic mode, and
//! each run queues the next one. A domain whose first run was missed (or
//! whose chain was broken) never got another, so its keys stopped rotating.
//! This check runs on the task scheduler and queues the missing task.

use common::Server;
use registry::{
    schema::{
        enums::{DnsRecordType, TaskType},
        prelude::{ObjectType, Property},
        structs::{
            CertificateManagement, DkimManagement, DnsManagement, Domain, Task,
            TaskDomainManagement, TaskStatus,
        },
    },
    types::EnumImpl,
};
use std::collections::HashSet;
use store::{
    IterateParams, U64_LEN, ValueKey,
    registry::RegistryQuery,
    write::{BatchBuilder, TaskQueueClass, ValueClass, key::DeserializeBigEndian},
};
use trc::{AddContext, TaskManagerEvent};
use types::id::Id;

/// Domains that already have a task of each kind, whatever its state
/// (pending, retrying, running or failed).
#[derive(Default)]
pub struct QueuedDomainTasks {
    pub dkim: HashSet<Id>,
    pub acme: HashSet<Id>,
}

/// Queues the DKIM and ACME tasks that automatic domains are missing.
/// Returns how many were queued.
pub async fn check_domain_tasks(server: &Server) -> trc::Result<usize> {
    // Registry::list() returns no Domain objects, so query their ids
    let domain_ids = server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Domain))
        .await
        .caused_by(trc::location!())?;

    check_tasks_for_domains(server, &domain_ids).await
}

/// The same check for the given domains only.
pub async fn check_tasks_for_domains(server: &Server, domain_ids: &[Id]) -> trc::Result<usize> {
    let queued = queued_domain_tasks(server).await?;
    let mut batch = BatchBuilder::new();
    let mut total = 0;

    for &domain_id in domain_ids {
        let Some(domain) = server
            .registry()
            .object::<Domain>(domain_id)
            .await
            .caused_by(trc::location!())?
        else {
            continue;
        };

        for task in missing_tasks(server, domain_id, &domain, &queued).await? {
            trc::event!(
                TaskManager(TaskManagerEvent::TaskQueued),
                Type = task.object_type().as_str(),
                Domain = domain.name.clone(),
                Details = "Re-queued a missing domain task",
            );
            batch.schedule_task(task);
            total += 1;
        }
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

async fn missing_tasks(
    server: &Server,
    domain_id: Id,
    domain: &Domain,
    queued: &QueuedDomainTasks,
) -> trc::Result<Vec<Task>> {
    let mut tasks = Vec::new();

    // Without published DNS a DKIM run can't rotate anything, and it doesn't
    // queue a follow-up; it's only needed when the domain has no keys yet.
    if needs_dkim_task(domain, queued.dkim.contains(&domain_id))
        && (publishes_dkim(domain) || !has_dkim_keys(server, domain_id).await?)
    {
        tasks.push(Task::DkimManagement(TaskDomainManagement {
            domain_id,
            status: TaskStatus::now(),
        }));
    }

    // A renewal that finds a certificate still valid reschedules itself for
    // when it falls due (renew.rs), so queuing one now orders nothing early.
    if needs_acme_task(domain, queued.acme.contains(&domain_id)) {
        tasks.push(Task::AcmeRenewal(TaskDomainManagement {
            domain_id,
            status: TaskStatus::now(),
        }));
    }

    Ok(tasks)
}

pub fn needs_dkim_task(domain: &Domain, has_task: bool) -> bool {
    !has_task && matches!(domain.dkim_management, DkimManagement::Automatic(_))
}

pub fn needs_acme_task(domain: &Domain, has_task: bool) -> bool {
    !has_task
        && matches!(
            domain.certificate_management,
            CertificateManagement::Automatic(_)
        )
}

pub fn publishes_dkim(domain: &Domain) -> bool {
    matches!(
        &domain.dns_management,
        DnsManagement::Automatic(details) if details.publish_records.contains(&DnsRecordType::Dkim)
    )
}

async fn has_dkim_keys(server: &Server, domain_id: Id) -> trc::Result<bool> {
    server
        .registry()
        .query::<Vec<Id>>(
            RegistryQuery::new(ObjectType::DkimSignature)
                .equal(Property::DomainId, domain_id.document_id()),
        )
        .await
        .map(|ids| !ids.is_empty())
        .caused_by(trc::location!())
}

async fn queued_domain_tasks(server: &Server) -> trc::Result<QueuedDomainTasks> {
    // The due index carries each task's type, so only the few domain tasks
    // are read in full. Failed tasks sit at the end of it (due u64::MAX).
    let mut ids = Vec::new();
    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due { id: 0, due: 1 })),
                ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
                    id: u64::MAX,
                    due: u64::MAX,
                })),
            )
            .ascending(),
            |key, value| {
                let task_type = value.deserialize_be_u16(0).ok().and_then(TaskType::from_id);
                if matches!(
                    task_type,
                    Some(TaskType::DkimManagement | TaskType::AcmeRenewal)
                ) {
                    ids.push(key.deserialize_be_u64(U64_LEN)?);
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let mut queued = QueuedDomainTasks::default();
    for id in ids {
        match server
            .store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task { id },
            )))
            .await
            .caused_by(trc::location!())?
        {
            Some(Task::DkimManagement(task)) => {
                queued.dkim.insert(task.domain_id);
            }
            Some(Task::AcmeRenewal(task)) => {
                queued.acme.insert(task.domain_id);
            }
            _ => {}
        }
    }

    Ok(queued)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry::schema::structs::{
        CertificateManagementProperties, DkimManagementProperties, DnsManagementProperties,
    };
    use registry::types::map::Map;

    fn domain(cert: bool, dkim: bool, dns_dkim: Option<bool>) -> Domain {
        Domain {
            certificate_management: if cert {
                CertificateManagement::Automatic(CertificateManagementProperties::default())
            } else {
                CertificateManagement::Manual
            },
            dkim_management: if dkim {
                DkimManagement::Automatic(DkimManagementProperties::default())
            } else {
                DkimManagement::Manual
            },
            dns_management: match dns_dkim {
                None => DnsManagement::Manual,
                Some(with_dkim) => DnsManagement::Automatic(DnsManagementProperties {
                    publish_records: Map::new(if with_dkim {
                        vec![DnsRecordType::Dkim]
                    } else {
                        vec![DnsRecordType::Mx]
                    }),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }
    }

    #[test]
    fn dkim_task_only_for_automatic_domains_without_one() {
        assert!(needs_dkim_task(&domain(false, true, None), false));
        assert!(!needs_dkim_task(&domain(false, true, None), true));
        assert!(!needs_dkim_task(&domain(false, false, None), false));
    }

    #[test]
    fn acme_task_only_for_automatic_domains_without_one() {
        assert!(needs_acme_task(&domain(true, false, None), false));
        assert!(!needs_acme_task(&domain(true, false, None), true));
        assert!(!needs_acme_task(&domain(false, false, None), false));
    }

    #[test]
    fn publishes_dkim_needs_automatic_dns_with_dkim_records() {
        assert!(publishes_dkim(&domain(false, true, Some(true))));
        assert!(!publishes_dkim(&domain(false, true, Some(false))));
        assert!(!publishes_dkim(&domain(false, true, None)));
    }
}
