/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::outcome::{Failure, Outcome, RetryClass};
use common::{Server, network::acme::AcmeError};
use compact_str::ToCompactString;
use registry::schema::structs::{
    CertificateManagement, Domain, Task, TaskDomainManagement, TaskStatus,
};
use store::write::now;

pub(crate) trait AcmeTask: Sync + Send {
    fn acme_management(&self, task: &TaskDomainManagement) -> impl Future<Output = Outcome> + Send;
}

impl AcmeTask for Server {
    async fn acme_management(&self, task: &TaskDomainManagement) -> Outcome {
        match acme_management(self, task).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let outcome = Outcome::error(&err);
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to run ACME task")
                );
                outcome
            }
        }
    }
}

async fn acme_management(server: &Server, task: &TaskDomainManagement) -> trc::Result<Outcome> {
    match server.registry().object::<Domain>(task.domain_id).await? {
        Some(domain) => {
            if matches!(domain.certificate_management, CertificateManagement::Manual) {
                return Ok(Outcome::Obsolete(
                    "Domain no longer uses automatic certificate management",
                ));
            }
        }
        None => return Ok(Outcome::Obsolete("Domain no longer exists")),
    }

    let err = match server.acme_renew(task.domain_id).await {
        Ok(tasks) => return Ok(Outcome::Done(tasks)),
        Err(err) => err,
    };

    if !matches!(
        err,
        AcmeError::NotDue { .. }
            | AcmeError::Internal(_)
            | AcmeError::AuthInvalid(_)
            | AcmeError::OrderInvalid(_)
            | AcmeError::AuthTimeout
            | AcmeError::Backoff { .. }
    ) {
        trc::event!(
            Acme(trc::AcmeEvent::Error),
            Id = task.domain_id.to_compact_string(),
            Reason = err.to_compact_string(),
        );
    }

    Ok(match err {
        AcmeError::NotDue { renew_at, .. } => {
            Outcome::Done(vec![Task::AcmeRenewal(TaskDomainManagement {
                domain_id: task.domain_id,
                status: TaskStatus::at(renew_at as i64),
            })])
        }
        AcmeError::Crypto(_) | AcmeError::Invalid(_) | AcmeError::ChallengeNotSupported { .. } => {
            Outcome::fatal(err.to_string())
        }
        AcmeError::Backoff { wait: Some(wait) } => Outcome::Retry(Failure::new(
            RetryClass::Throttled {
                retry_at: now().saturating_add(wait.as_secs()),
            },
            err.to_string(),
        )),
        AcmeError::Http(_)
        | AcmeError::HttpStatus(_)
        | AcmeError::Dns(_)
        | AcmeError::Json(_)
        | AcmeError::AuthInvalid(_)
        | AcmeError::OrderInvalid(_)
        | AcmeError::Registry(_)
        | AcmeError::OrderTimeout
        | AcmeError::AuthTimeout
        | AcmeError::Backoff { wait: None } => Outcome::transient(err.to_string()),
        AcmeError::Internal(error) => return Err(error),
    })
}
