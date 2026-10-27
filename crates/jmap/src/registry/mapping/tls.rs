/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, ValidationResult};
use common::network::acme::{
    ParsedCert,
    account::{EabSettings, acme_create_account},
};
use jmap_proto::error::set::SetError;
use registry::{
    jmap::JmapValue,
    schema::{
        prelude::Property,
        structs::{AcmeProvider, Certificate},
    },
    types::map::Map,
};
use utils::{map::vec_map::VecMap, outbound::OutboundPolicy};

pub(crate) async fn validate_acme_provider(
    provider: &mut AcmeProvider,
    unpatched_properties: VecMap<Property, JmapValue<'_>>,
    outbound_policy: OutboundPolicy,
) -> ValidationResult {
    if let Err(err) = validate_acme_directory(provider, outbound_policy) {
        return Ok(Err(err));
    }

    let response = ObjectResponse::default();

    // Obtain EAB credentials
    let mut eab_key_id = None;
    let mut eab_hmac_key = None;
    for (key, value) in unpatched_properties {
        match (key, value) {
            (Property::EabKeyId, JmapValue::Str(value)) => {
                eab_key_id = Some(value);
            }
            (Property::EabHmacKey, JmapValue::Str(value)) => {
                eab_hmac_key = Some(value);
            }
            (_, JmapValue::Null) => {}
            _ => {
                return Ok(Err(SetError::invalid_properties().with_property(key)));
            }
        }
    }

    let eab = if let (Some(key_id), Some(hmac_key)) = (eab_key_id, eab_hmac_key) {
        match EabSettings::new(key_id.into_owned(), hmac_key.as_ref()) {
            Ok(eab) => Some(eab),
            Err(err) => {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(Property::EabKeyId)
                    .with_property(Property::EabHmacKey)
                    .with_description(format!("Invalid EAB credentials: {err}"))));
            }
        }
    } else {
        None
    };

    match acme_create_account(provider, eab).await {
        Ok(_) => Ok(Ok(response)),
        Err(err) => Ok(Err(SetError::invalid_properties()
            .with_property(Property::Directory)
            .with_description(format!("Failed to create ACME account: {err}")))),
    }
}

pub(crate) async fn validate_certificate(
    cert: &mut Certificate,
    old_cert: Option<&Certificate>,
) -> ValidationResult {
    if old_cert.is_none_or(|old_cert| old_cert.certificate != cert.certificate) {
        match cert.certificate.value().await {
            Ok(pem) => match ParsedCert::parse(pem.as_ref()) {
                Ok(parsed) => {
                    cert.not_valid_after = parsed.valid_not_after;
                    cert.not_valid_before = parsed.valid_not_before;
                    cert.issuer = parsed.issuer;
                    cert.subject_alternative_names = Map::new(parsed.sans);

                    Ok(Ok(ObjectResponse::default()))
                }
                Err(err) => Ok(Err(SetError::invalid_properties()
                    .with_property(Property::Certificate)
                    .with_description(format!("Failed to read certificate: {err}")))),
            },
            Err(err) => Ok(Err(SetError::invalid_properties()
                .with_property(Property::Certificate)
                .with_description(format!("Failed to read certificate: {err}")))),
        }
    } else {
        Ok(Ok(ObjectResponse::default()))
    }
}

pub(crate) fn validate_acme_directory(
    provider: &AcmeProvider,
    outbound_policy: OutboundPolicy,
) -> Result<(), SetError<Property>> {
    outbound_policy
        .parse_url(&provider.directory)
        .map(|_| ())
        .map_err(|err| {
            SetError::invalid_properties()
                .with_property(Property::Directory)
                .with_description(err.as_str())
        })
}
