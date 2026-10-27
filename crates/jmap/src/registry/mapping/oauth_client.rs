/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ObjectResponse, ValidationResult};
use common::{
    Server,
    auth::{AccessToken, oauth::registration::validate_oauth_client},
};
use directory::core::secret::{hash_secret, is_password_hash};
use jmap_proto::error::set::SetError;
use registry::schema::{enums::Permission, structs::OAuthClient};
use trc::AddContext;

pub fn is_superuser(access_token: &AccessToken) -> bool {
    #[cfg(not(feature = "enterprise"))]
    let is_tenant_member = false;
    !is_tenant_member && access_token.has_permission(Permission::Impersonate)
}

#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
pub async fn validate_oauth_client_object(
    server: &Server,
    access_token: &AccessToken,
    client: &mut OAuthClient,
) -> ValidationResult {
    if let Err((property, err)) = validate_oauth_client(client, is_superuser(access_token)) {
        return Ok(Err(SetError::invalid_properties()
            .with_property(property)
            .with_description(err.error_description.unwrap_or(err.error))));
    }

    if let Some(secret) = client.secret.as_mut()
        && !secret.is_empty()
        && !(matches!(secret.as_bytes().first(), Some(&b'$' | &b'{')) && is_password_hash(secret))
    {
        *secret = hash_secret(
            &server.inner.data.password_verifier,
            server.core.network.security.password_hash_algorithm,
            std::mem::take(secret).into_bytes(),
        )
        .await
        .caused_by(trc::location!())?;
    }

    Ok(Ok(ObjectResponse::default()))
}
