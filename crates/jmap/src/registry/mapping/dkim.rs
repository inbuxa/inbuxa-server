/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, ValidationResult};
use common::config::smtp::auth::DkimSigners;
use jmap_proto::error::set::SetError;
use registry::schema::structs::DkimSignature;

pub(crate) async fn validate_dkim_signature(
    key: &mut DkimSignature,
    old_key: Option<&DkimSignature>,
) -> ValidationResult {
    let response = ObjectResponse::default();

    if old_key.is_none_or(|old_key| old_key.private_key() != key.private_key())
        && let Err(err) = DkimSigners::default()
            .insert("example.com".to_string(), key.clone())
            .await
    {
        return Ok(Err(SetError::invalid_properties().with_description(
            format!("Failed to validate DKIM signature: {err}"),
        )));
    }

    Ok(Ok(response))
}
