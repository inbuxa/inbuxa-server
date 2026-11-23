/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::TaskResult;
use common::{
    Server,
    cache::invalidate::CacheInvalidationBuilder,
    ipc::CacheInvalidation,
    network::dkim::{
        generate_dkim_dns_record, generate_dkim_dns_record_name, generate_dkim_private_key,
        generate_dkim_selector,
    },
};
use registry::{
    schema::{
        enums::{DkimRotationStage, DkimSignatureType, DnsRecordType},
        prelude::{Object, ObjectType, Property},
        structs::{
            Dkim1Signature, Dkim2Signature, DkimManagement, DkimSignature, DnsManagement, Domain,
            SecretText, SecretTextValue, Task, TaskDomainManagement, TaskStatus,
        },
    },
    types::{datetime::UTCDateTime, id::ObjectId},
};
use std::fmt::Write;
use store::{
    registry::{
        RegistryObject, RegistryQuery,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::now,
};
use trc::{DkimEvent, DnsEvent};
use types::id::Id;

pub(crate) trait DkimManagementTask: Sync + Send {
    fn dkim_management(
        &self,
        task: &TaskDomainManagement,
    ) -> impl Future<Output = TaskResult> + Send;
}

impl DkimManagementTask for Server {
    async fn dkim_management(&self, task: &TaskDomainManagement) -> TaskResult {
        match dkim_management(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to run DKIM management task")
                );
                result
            }
        }
    }
}

async fn dkim_management(server: &Server, task: &TaskDomainManagement) -> trc::Result<TaskResult> {
    let Some(domain) = server.registry().object::<Domain>(task.domain_id).await? else {
        return Ok(TaskResult::permanent("Domain not found".to_string()));
    };
    let DkimManagement::Automatic(dkim) = domain.dkim_management else {
        return Ok(TaskResult::permanent(
            "Domain is not set to automatic DKIM management".to_string(),
        ));
    };
    let configured = dkim.algorithms.into_inner();
    if configured.is_empty() {
        return Ok(TaskResult::permanent(
            "No DKIM algorithms configured for domain".to_string(),
        ));
    }
    let mut create_signatures = configured.clone();
    let mut active_types: Vec<DkimSignatureType> = Vec::with_capacity(configured.len());

    let dns_updater = match domain.dns_management {
        DnsManagement::Automatic(props) if props.publish_records.contains(&DnsRecordType::Dkim) => {
            match server.build_dns_updater(props.dns_server_id).await? {
                Ok(updater) => Some((updater, props.origin.unwrap_or_else(|| domain.name.clone()))),
                Err(err) => {
                    return Ok(TaskResult::permanent(format!(
                        "Failed to build DNS updater: {}",
                        err
                    )));
                }
            }
        }
        _ => None,
    };

    // Fetch existing DKIM keys
    let mut publish_signatures = Vec::new();
    let mut retire_signatures = Vec::new();
    let mut retiring_signatures = Vec::new();
    let mut delete_signatures = Vec::new();
    let mut schedule_signatures = Vec::new();
    let mut next_transition = None;

    let signature_ids = server
        .registry()
        .query::<Vec<Id>>(
            RegistryQuery::new(ObjectType::DkimSignature)
                .equal(Property::DomainId, task.domain_id.document_id()),
        )
        .await?;

    for id in signature_ids {
        let id = ObjectId::new(ObjectType::DkimSignature, id);
        let Some(key) = server.registry().get(id).await? else {
            continue;
        };
        let key: RegistryObject<DkimSignature> = RegistryObject {
            id,
            revision: key.revision,
            object: key.into(),
        };

        let key_algo = key.object.object_type();
        if let Some(current_stage) = key.object.rotation_due() {
            match current_stage {
                DkimRotationStage::Pending => {
                    create_signatures.retain(|algo| algo != &key_algo);
                    publish_signatures.push(key)
                }
                DkimRotationStage::Active if dns_updater.is_some() => retiring_signatures.push(key),
                DkimRotationStage::Active => {
                    create_signatures.retain(|algo| algo != &key_algo);
                    active_types.push(key_algo);
                }
                DkimRotationStage::Retiring => retire_signatures.push(key),
                DkimRotationStage::Retired => delete_signatures.push(key),
            }
        } else {
            let transition = key.object.next_transition();
            match key.object.stage() {
                DkimRotationStage::Active => {
                    create_signatures.retain(|algo| algo != &key_algo);
                    active_types.push(key_algo);
                    if transition.is_none() && dns_updater.is_some() {
                        schedule_signatures.push(key);
                    }
                }
                DkimRotationStage::Pending => {
                    create_signatures.retain(|algo| algo != &key_algo);
                    if transition.is_none() || dns_updater.is_none() {
                        publish_signatures.push(key);
                        continue;
                    }
                }
                DkimRotationStage::Retiring | DkimRotationStage::Retired => {}
            }

            if let Some(transition) = transition
                && next_transition.is_none_or(|next| transition < next)
            {
                next_transition = Some(transition);
            }
        }
    }

    let now = now();
    let mut do_refresh = false;
    let mut temporary_errors = String::new();

    for algorithm in create_signatures {
        #[cfg(feature = "test_mode")]
        let secret = {
            if dkim.selector_template.contains("dummy") {
                match algorithm {
                    DkimSignatureType::Dkim1Ed25519Sha256
                    | DkimSignatureType::Dkim2Ed25519Sha256 => TEST_ED25519_KEY.to_string(),
                    DkimSignatureType::Dkim1RsaSha256 | DkimSignatureType::Dkim2RsaSha256 => {
                        TEST_RSA_KEY.to_string()
                    }
                }
            } else {
                generate_dkim_private_key(algorithm).await.unwrap().unwrap()
            }
        };

        // Generate new key and selector
        #[cfg(not(feature = "test_mode"))]
        let secret = match generate_dkim_private_key(algorithm).await? {
            Ok(secret) => secret,
            Err(err) => {
                return Ok(TaskResult::permanent(err.to_string()));
            }
        };
        let selector = match generate_dkim_selector(&dkim.selector_template, algorithm) {
            Ok(selector) => selector,
            Err(err) => {
                return Ok(TaskResult::permanent(format!(
                    "Failed to generate DKIM selector: {}",
                    err
                )));
            }
        };

        // Build key
        let private_key = SecretText::Text(SecretTextValue { secret });
        let replaces = retiring_signatures
            .iter()
            .map(|key| &key.object)
            .find(|key| key.object_type() == algorithm);
        let mut signature = build_signature(
            algorithm,
            replaces,
            task.domain_id,
            domain.member_tenant_id,
            selector.clone(),
            private_key,
        );

        // Publish key
        if let Some((updater, origin)) = &dns_updater {
            let record = generate_dkim_dns_record(&signature, &domain.name).await?;
            let dns_update::DnsRecord::TXT(txt_value) = &record.record else {
                return Ok(TaskResult::permanent(
                    "DKIM record must be a TXT record".to_string(),
                ));
            };
            let propagation_target = txt_value.clone();
            let published = match updater
                .set_rrset(
                    origin,
                    &record.name,
                    dns_update::DnsRecordType::TXT,
                    vec![record.record.clone()],
                )
                .await
            {
                Ok(_) => {
                    let propagated = updater
                        .wait_for_txt_propagation(&record.name, origin, &propagation_target)
                        .await;
                    if !propagated {
                        if !temporary_errors.is_empty() {
                            temporary_errors.push_str("; ");
                        }
                        let _ = write!(
                            &mut temporary_errors,
                            "DKIM record {} did not propagate, will retry.",
                            record.name
                        );
                    }
                    propagated
                }
                Err(err) => {
                    if !temporary_errors.is_empty() {
                        temporary_errors.push_str("; ");
                    }
                    let _ = write!(
                        &mut temporary_errors,
                        "Failed to publish DKIM record {}: {err}.",
                        record.name
                    );
                    trc::event!(
                        Dns(DnsEvent::RecordCreationFailed),
                        Hostname = record.name.clone(),
                        Details = origin.clone(),
                        Type = "TXT",
                        Reason = err,
                    );
                    false
                }
            };
            let signature_transition = if published {
                trc::event!(
                    Dkim(DkimEvent::SignaturePublished),
                    Id = selector.clone(),
                    Details = domain.name.clone()
                );

                do_refresh = true;
                UTCDateTime::from_timestamp((now + dkim.rotate_after.as_secs()) as i64)
            } else {
                // Something went wrong, reschedule.
                signature.set_stage(DkimRotationStage::Pending);
                UTCDateTime::from_timestamp(now as i64)
            };

            if next_transition.is_none_or(|next| signature_transition < next) {
                next_transition = Some(signature_transition);
            }

            signature.set_next_transition(signature_transition);
        }

        // Write key
        let is_active = signature.is_active();
        match server
            .registry()
            .write(RegistryWrite::insert(&signature.into()))
            .await?
        {
            RegistryWriteResult::Success(_) => {
                if is_active {
                    active_types.push(algorithm);
                }
                trc::event!(
                    Dkim(DkimEvent::SignatureCreated),
                    Id = selector,
                    Details = domain.name.clone()
                );
            }
            err => {
                return Ok(TaskResult::permanent(format!(
                    "Failed to write DKIM signature: {err}"
                )));
            }
        }
    }

    for signature in schedule_signatures {
        let record = generate_dkim_dns_record_name(&signature.object, &domain.name);
        let signature_transition =
            UTCDateTime::from_timestamp((now + dkim.rotate_after.as_secs()) as i64);

        if next_transition.is_none_or(|next| signature_transition < next) {
            next_transition = Some(signature_transition);
        }

        let mut new_signature = signature.object.clone();
        new_signature.set_next_transition(signature_transition);

        if let SignatureUpdate::Failed(task_result) = update_signature(
            server,
            signature,
            new_signature,
            &record,
            &mut temporary_errors,
        )
        .await?
        {
            return Ok(task_result);
        }
    }

    // Publish signatures
    if let Some((updater, origin)) = &dns_updater {
        for signature in publish_signatures {
            let record = generate_dkim_dns_record(&signature.object, &domain.name).await?;
            let dns_update::DnsRecord::TXT(txt_value) = &record.record else {
                return Ok(TaskResult::permanent(
                    "DKIM record must be a TXT record".to_string(),
                ));
            };
            let propagation_target = txt_value.clone();
            let publish_result = updater
                .set_rrset(
                    origin,
                    &record.name,
                    dns_update::DnsRecordType::TXT,
                    vec![record.record.clone()],
                )
                .await;
            let propagation_result = match &publish_result {
                Ok(_) => Ok(updater
                    .wait_for_txt_propagation(&record.name, origin, &propagation_target)
                    .await),
                Err(err) => Err(err.clone()),
            };
            match propagation_result {
                Ok(true) => {
                    let signature_transition =
                        UTCDateTime::from_timestamp((now + dkim.rotate_after.as_secs()) as i64);

                    if next_transition.is_none_or(|next| signature_transition < next) {
                        next_transition = Some(signature_transition);
                    }

                    let signature_type = signature.object.object_type();
                    let mut new_signature = signature.object.clone();

                    new_signature.set_next_transition(signature_transition);
                    new_signature.set_stage(DkimRotationStage::Active);

                    trc::event!(
                        Dkim(DkimEvent::SignaturePublished),
                        Id = new_signature.selector().to_string(),
                        Details = domain.name.clone()
                    );

                    // Write key
                    match update_signature(
                        server,
                        signature,
                        new_signature,
                        &record.name,
                        &mut temporary_errors,
                    )
                    .await?
                    {
                        SignatureUpdate::Written => active_types.push(signature_type),
                        SignatureUpdate::Conflict => {}
                        SignatureUpdate::Failed(task_result) => return Ok(task_result),
                    }
                    do_refresh = true;
                }
                Ok(false) => {
                    if !temporary_errors.is_empty() {
                        temporary_errors.push_str("; ");
                    }
                    let _ = write!(
                        &mut temporary_errors,
                        "DKIM record {} did not propagate, will retry.",
                        record.name
                    );
                }
                Err(err) => {
                    if !temporary_errors.is_empty() {
                        temporary_errors.push_str("; ");
                    }
                    let _ = write!(
                        &mut temporary_errors,
                        "Failed to publish DKIM record {}: {err}.",
                        record.name
                    );
                }
            }
        }
    } else {
        for signature in publish_signatures {
            let signature_type = signature.object.object_type();
            if active_types.contains(&signature_type) || !configured.contains(&signature_type) {
                continue;
            }

            let record = generate_dkim_dns_record_name(&signature.object, &domain.name);
            let mut new_signature = signature.object.clone();
            new_signature.set_stage(DkimRotationStage::Active);
            match &mut new_signature {
                DkimSignature::Dkim1Ed25519Sha256(sign) | DkimSignature::Dkim1RsaSha256(sign) => {
                    sign.next_transition_at = None
                }
                DkimSignature::Dkim2Ed25519Sha256(sign) | DkimSignature::Dkim2RsaSha256(sign) => {
                    sign.next_transition_at = None
                }
            }

            match update_signature(
                server,
                signature,
                new_signature,
                &record,
                &mut temporary_errors,
            )
            .await?
            {
                SignatureUpdate::Written => {
                    active_types.push(signature_type);
                    do_refresh = true;
                }
                SignatureUpdate::Conflict => active_types.push(signature_type),
                SignatureUpdate::Failed(task_result) => return Ok(task_result),
            }
        }
    }

    // Retiring signatures
    for signature in retiring_signatures {
        let signature_type = signature.object.object_type();
        if configured.contains(&signature_type) && !active_types.contains(&signature_type) {
            continue;
        }

        let record = generate_dkim_dns_record_name(&signature.object, &domain.name);
        let signature_transition =
            UTCDateTime::from_timestamp((now + dkim.retire_after.as_secs()) as i64);

        if next_transition.is_none_or(|next| signature_transition < next) {
            next_transition = Some(signature_transition);
        }

        let mut new_signature = signature.object.clone();

        new_signature.set_next_transition(signature_transition);
        new_signature.set_stage(DkimRotationStage::Retiring);

        trc::event!(
            Dkim(DkimEvent::SignatureRetiring),
            Id = new_signature.selector().to_string(),
            Details = domain.name.clone()
        );

        // Write key
        if let SignatureUpdate::Failed(task_result) = update_signature(
            server,
            signature,
            new_signature,
            &record,
            &mut temporary_errors,
        )
        .await?
        {
            return Ok(task_result);
        }
        do_refresh = true;
    }

    // Retire signatures
    if let Some((updater, origin)) = &dns_updater {
        for signature in retire_signatures {
            let record = generate_dkim_dns_record_name(&signature.object, &domain.name);
            match updater
                .set_rrset(origin, &record, dns_update::DnsRecordType::TXT, Vec::new())
                .await
            {
                Ok(_) => {
                    let signature_transition =
                        UTCDateTime::from_timestamp((now + dkim.delete_after.as_secs()) as i64);

                    if next_transition.is_none_or(|next| signature_transition < next) {
                        next_transition = Some(signature_transition);
                    }

                    let mut new_signature = signature.object.clone();

                    new_signature.set_next_transition(signature_transition);
                    new_signature.set_stage(DkimRotationStage::Retired);

                    trc::event!(
                        Dkim(DkimEvent::SignatureRetired),
                        Id = new_signature.selector().to_string(),
                        Details = domain.name.clone()
                    );

                    // Write key
                    if let SignatureUpdate::Failed(task_result) = update_signature(
                        server,
                        signature,
                        new_signature,
                        &record,
                        &mut temporary_errors,
                    )
                    .await?
                    {
                        return Ok(task_result);
                    }

                    do_refresh = true;
                }
                Err(err) => {
                    if !temporary_errors.is_empty() {
                        temporary_errors.push_str("; ");
                    }
                    let _ = write!(
                        &mut temporary_errors,
                        "Failed to remove DKIM record {}: {err}.",
                        record
                    );
                }
            }
        }
    }

    // Delete signatures
    for signature in delete_signatures {
        let record = generate_dkim_dns_record_name(&signature.object, &domain.name);

        if let Some((updater, origin)) = &dns_updater
            && let Err(err) = updater
                .set_rrset(origin, &record, dns_update::DnsRecordType::TXT, Vec::new())
                .await
        {
            trc::event!(
                Dns(DnsEvent::RecordDeletionFailed),
                Hostname = record.clone(),
                Details = origin.clone(),
                Type = "TXT",
                Reason = err.to_string(),
            );
        }

        trc::event!(
            Dkim(DkimEvent::SignatureDeleted),
            Id = signature.object.selector().to_string(),
            Details = domain.name.clone()
        );

        match server
            .registry()
            .write(RegistryWrite::delete_object(
                signature.id,
                &Object {
                    inner: signature.object.into(),
                    revision: signature.revision,
                },
            ))
            .await
        {
            Ok(RegistryWriteResult::Success(_)) => {}
            Ok(err) => {
                return Ok(TaskResult::permanent(format!(
                    "Failed to delete DKIM signature for record {record}: {err}"
                )));
            }
            Err(err) => {
                if err.is_assertion_failure() {
                    if !temporary_errors.is_empty() {
                        temporary_errors.push_str("; ");
                    }
                    let _ = write!(
                        temporary_errors,
                        "Failed to delete DKIM signature for record {record} due to concurrent modification, will retry.",
                    );
                } else {
                    return Err(err);
                }
            }
        }
    }

    if do_refresh
        && let Err(err) = server
            .invalidate_caches(CacheInvalidationBuilder::default().with_invalidation(
                CacheInvalidation::DkimSignature(task.domain_id.document_id()),
            ))
            .await
    {
        trc::error!(
            err.caused_by(trc::location!())
                .details("Failed to invalidate caches after DKIM management task")
        );
    }

    if !temporary_errors.is_empty() {
        Ok(TaskResult::temporary(temporary_errors))
    } else {
        let tasks = if let Some(next_transition) = next_transition {
            vec![Task::DkimManagement(TaskDomainManagement {
                domain_id: task.domain_id,
                status: TaskStatus::at(next_transition.timestamp()),
            })]
        } else {
            vec![]
        };

        Ok(TaskResult::Success(tasks))
    }
}

// inbuxa (#534): a key that replaces one of the same algorithm keeps its
// settings (headers, canonicalization, flags and the rest), so signatures
// don't change shape on rotation; only a domain's first key takes defaults
fn build_signature(
    algorithm: DkimSignatureType,
    replaces: Option<&DkimSignature>,
    domain_id: Id,
    member_tenant_id: Option<Id>,
    selector: String,
    private_key: SecretText,
) -> DkimSignature {
    match algorithm {
        DkimSignatureType::Dkim1Ed25519Sha256 | DkimSignatureType::Dkim1RsaSha256 => {
            let settings = match replaces {
                Some(
                    DkimSignature::Dkim1Ed25519Sha256(key) | DkimSignature::Dkim1RsaSha256(key),
                ) => key.clone(),
                _ => Dkim1Signature::default(),
            };
            let signature = Dkim1Signature {
                stage: DkimRotationStage::Active,
                domain_id,
                member_tenant_id,
                selector,
                private_key,
                created_at: UTCDateTime::now(),
                next_transition_at: None,
                ..settings
            };
            if algorithm == DkimSignatureType::Dkim1Ed25519Sha256 {
                DkimSignature::Dkim1Ed25519Sha256(signature)
            } else {
                DkimSignature::Dkim1RsaSha256(signature)
            }
        }
        DkimSignatureType::Dkim2Ed25519Sha256 | DkimSignatureType::Dkim2RsaSha256 => {
            let settings = match replaces {
                Some(
                    DkimSignature::Dkim2Ed25519Sha256(key) | DkimSignature::Dkim2RsaSha256(key),
                ) => key.clone(),
                _ => Dkim2Signature::default(),
            };
            let signature = Dkim2Signature {
                stage: DkimRotationStage::Active,
                domain_id,
                member_tenant_id,
                selector,
                private_key,
                created_at: UTCDateTime::now(),
                next_transition_at: None,
                ..settings
            };
            if algorithm == DkimSignatureType::Dkim2Ed25519Sha256 {
                DkimSignature::Dkim2Ed25519Sha256(signature)
            } else {
                DkimSignature::Dkim2RsaSha256(signature)
            }
        }
    }
}

enum SignatureUpdate {
    Written,
    Conflict,
    Failed(TaskResult),
}

async fn update_signature(
    server: &Server,
    signature: RegistryObject<DkimSignature>,
    new_signature: DkimSignature,
    name: &str,
    temporary_errors: &mut String,
) -> trc::Result<SignatureUpdate> {
    match server
        .registry()
        .write(RegistryWrite::update(
            signature.id.id(),
            &new_signature.into(),
            &Object {
                inner: signature.object.into(),
                revision: signature.revision,
            },
        ))
        .await
    {
        Ok(RegistryWriteResult::Success(_)) => Ok(SignatureUpdate::Written),
        Ok(err) => Ok(SignatureUpdate::Failed(TaskResult::permanent(format!(
            "Failed to write DKIM signature for record {name}: {err}"
        )))),
        Err(err) => {
            if err.is_assertion_failure() {
                if !temporary_errors.is_empty() {
                    temporary_errors.push_str("; ");
                }
                let _ = write!(
                    temporary_errors,
                    "Failed to write DKIM signature for record {name} due to concurrent modification, will retry.",
                );
                Ok(SignatureUpdate::Conflict)
            } else {
                Err(err)
            }
        }
    }
}

#[cfg(feature = "test_mode")]
const TEST_RSA_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAv9XYXG3uK95115mB4nJ37nGeNe2CrARm1agrbcnSk5oIaEfM
ZLUR/X8gPzoiNHZcfMZEVR6bAytxUhc5EvZIZrjSuEEeny+fFd/cTvcm3cOUUbIa
UmSACj0dL2/KwW0LyUaza9z9zor7I5XdIl1M53qVd5GI62XBB76FH+Q0bWPZNkT4
NclzTLspD/MTpNCCPhySM4Kdg5CuDczTH4aNzyS0TqgXdtw6A4Sdsp97VXT9fkPW
9rso3lrkpsl/9EQ1mR/DWK6PBmRfIuSFuqnLKY6v/z2hXHxF7IoojfZLa2kZr9Ae
d4l9WheQOTA19k5r2BmlRw/W9CrgCBo0Sdj+KQIDAQABAoIBAFPChEi/OvnulReB
ECQWhOUYuNKlFKQU++2YEvZJ4+bMn5UgnE7wfJ1pj2Pr9xlfALz+OMHNrjMxGbaV
KzdrT2uCkYcf78XjnhuH9gKIiXDUv4L4N+P3u6w8yOx4bFgOS9IjS53yDOPM7SC5
g6dIg5aigHaHlffqIuFFv4yQMI/+Ai+zBKxS7wRhxK/7nnAuo28fe5MEdp57ho9/
AGlDNsdg9zCgjwhokwFE3+AaD+bkUFm4gQ1XjkUFrlmnQn8vDQ0i9toEWhCj+UPY
iOKL63MJnr90MXTXWLHoFj99wBp//mYygbF9Lj8fa28/oa8LWp3Jhb7QeMgH46iv
3aLHbTECgYEA5M2dAw+nyMw9vYlkMejhwObKYP8Mr/6zcGMLCalYvRJM5iUAM0JI
H6sM6pV9/nv167cbKocj3xYPdtE7FPOn4132MLM8Ne1f8nPE64Qrcbj5WBXvLnU8
hpWbwe2Z8h7UUMKx6q4F1/TXYkc3ScxYwfjM4mP/pLsAOgVzRSEEgrUCgYEA1qNQ
xaQHNWZ1O8WuTnqWd5JSsic6iURAmUcLeFDZY2PWhVoaQ8L/xMQhDYs1FIbLWArW
4Qq3Ibu8AbSejAKuaJz7Uf26PX+PYVUwAOO0qamCJ8d/qd6So7qWMDyAY2yXI39Y
1nMqRjr7bkEsggAZao7BKqA7ZtmogjOusBT38iUCgYEA06agJ8TDoKvOMRZ26PRU
YO0dKLzGL8eclcoI29cbj0rud7aiiMg3j5PbTuUat95TjsjDCIQaWrM9etvxm2AJ
Xfn9Uu96MyhyKQWOk46f4YMKpMElkARDCPw8KRhx39dE77AqhLyWCz8iPndCXbH6
KPTOEl4OjYOuof2Is9nnIkECgYBh948RdsnXhNlzm8nwhiGRmBbou+EK8D0v+O5y
Tyy6IcKzgSnFzgZh8EdJ4EUtBk1f9SqY8wQdgIvSl3daXorusuA/TzkngsaV3YUY
ktZOLlF7CKLrjOyPkMWmZKcROmpNyH1q/IvKHHfQnizLdXIkYd4nL5WNX0F7lE1i
j1+QhQKBgB2lviBK7rJFwlFYdQUP1NAN2dKxMZk8uJS8JglHrM0+8nRI83HbTdEQ
vB0ManEKBkbS4T5n+gRtdEqKSDmWDTXDlrBfcdCHNQLwYtBpOotCqQn/AmfjcPBl
byAbwh4+HiZ5JISoRZpiZqy67aJNVoXmdtb/E9mi7ozzytpxMNql
-----END RSA PRIVATE KEY-----
"#;

#[cfg(feature = "test_mode")]
const TEST_ED25519_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAO3hAf144lTAVjTkht3ZwBTK0CMCCd1bI0alggneN3B
-----END PRIVATE KEY-----
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use registry::{
        schema::enums::{Dkim2Flag, DkimCanonicalization, DkimHash},
        types::{duration::Duration, map::Map},
    };

    fn key(secret: &str) -> SecretText {
        SecretText::Text(SecretTextValue {
            secret: secret.to_string(),
        })
    }

    // inbuxa (#534): the key a rotation creates signs the way the key it
    // replaces did; it only gets a new selector, private key and schedule
    #[test]
    fn rotated_key_keeps_the_retiring_key_settings() {
        let old_domain = Id::new(1);
        let new_domain = Id::new(2);
        let created_at = UTCDateTime::from_timestamp(1_000_000);
        let next_transition_at = Some(UTCDateTime::from_timestamp(2_000_000));

        let old_v1 = Dkim1Signature {
            auid: Some("@mail.example.org".to_string()),
            canonicalization: DkimCanonicalization::SimpleRelaxed,
            expire: Some(Duration::from_millis(86_400_000)),
            headers: Map::new(vec!["From".to_string(), "Reply-To".to_string()]),
            private_key: key("old"),
            report: false,
            third_party: Some("example.net".to_string()),
            third_party_hash: Some(DkimHash::Sha1),
            domain_id: old_domain,
            member_tenant_id: None,
            selector: "old-rsa".to_string(),
            created_at,
            next_transition_at,
            stage: DkimRotationStage::Active,
        };
        let old_v2 = Dkim2Signature {
            flags: Map::new(vec![Dkim2Flag::Donotexplode, Dkim2Flag::Feedback]),
            private_key: key("old"),
            domain_id: old_domain,
            member_tenant_id: None,
            selector: "old-ed".to_string(),
            created_at,
            next_transition_at,
            stage: DkimRotationStage::Active,
        };

        for (algorithm, old) in [
            (
                DkimSignatureType::Dkim1RsaSha256,
                DkimSignature::Dkim1RsaSha256(old_v1.clone()),
            ),
            (
                DkimSignatureType::Dkim1Ed25519Sha256,
                DkimSignature::Dkim1Ed25519Sha256(old_v1.clone()),
            ),
            (
                DkimSignatureType::Dkim2Ed25519Sha256,
                DkimSignature::Dkim2Ed25519Sha256(old_v2.clone()),
            ),
            (
                DkimSignatureType::Dkim2RsaSha256,
                DkimSignature::Dkim2RsaSha256(old_v2.clone()),
            ),
        ] {
            let new = build_signature(
                algorithm,
                Some(&old),
                new_domain,
                Some(Id::new(3)),
                "new".to_string(),
                key("new"),
            );
            assert_eq!(new.object_type(), algorithm);
            match new {
                DkimSignature::Dkim1RsaSha256(new) | DkimSignature::Dkim1Ed25519Sha256(new) => {
                    let Dkim1Signature {
                        auid,
                        canonicalization,
                        expire,
                        headers,
                        report,
                        third_party,
                        third_party_hash,
                        ..
                    } = &old_v1;
                    assert_eq!(&new.auid, auid, "{algorithm:?}");
                    assert_eq!(&new.canonicalization, canonicalization, "{algorithm:?}");
                    assert_eq!(&new.expire, expire, "{algorithm:?}");
                    assert_eq!(&new.headers, headers, "{algorithm:?}");
                    assert_eq!(&new.report, report, "{algorithm:?}");
                    assert_eq!(&new.third_party, third_party, "{algorithm:?}");
                    assert_eq!(&new.third_party_hash, third_party_hash, "{algorithm:?}");
                    assert_eq!(new.private_key, key("new"));
                    assert_eq!(new.domain_id, new_domain);
                    assert_eq!(new.member_tenant_id, Some(Id::new(3)));
                    assert_eq!(new.selector, "new");
                    assert_eq!(new.stage, DkimRotationStage::Active);
                    assert_eq!(new.next_transition_at, None);
                    assert!(new.created_at > created_at);
                }
                DkimSignature::Dkim2Ed25519Sha256(new) | DkimSignature::Dkim2RsaSha256(new) => {
                    assert_eq!(new.flags, old_v2.flags, "{algorithm:?}");
                    assert_eq!(new.private_key, key("new"));
                    assert_eq!(new.domain_id, new_domain);
                    assert_eq!(new.member_tenant_id, Some(Id::new(3)));
                    assert_eq!(new.selector, "new");
                    assert_eq!(new.stage, DkimRotationStage::Active);
                    assert_eq!(new.next_transition_at, None);
                    assert!(new.created_at > created_at);
                }
            }
        }

        // A domain's first key of an algorithm takes the defaults
        let DkimSignature::Dkim1RsaSha256(first) = build_signature(
            DkimSignatureType::Dkim1RsaSha256,
            None,
            new_domain,
            None,
            "first".to_string(),
            key("first"),
        ) else {
            panic!("expected a DKIM1 RSA key");
        };
        let defaults = Dkim1Signature::default();
        assert_eq!(
            Dkim1Signature {
                created_at: defaults.created_at,
                ..first
            },
            Dkim1Signature {
                domain_id: new_domain,
                selector: "first".to_string(),
                private_key: key("first"),
                ..defaults
            }
        );
    }
}
