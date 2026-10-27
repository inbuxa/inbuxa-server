/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{TOKEN_ENDPOINT_AUTH_METHODS, authorize::issuer, logout::END_SESSION_PATH};
use common::{
    Server,
    auth::oauth::{SCOPE_OPENID, client::RequestOrigin, oidc::Userinfo, supported_scopes},
};
use http_proto::*;
use serde::Serialize;
use std::future::Future;

#[derive(Debug, Serialize)]
pub struct OpenIdMetadata<'x> {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: String,
    pub device_authorization_endpoint: String,
    pub revocation_endpoint: String,
    pub end_session_endpoint: String,
    pub scopes_supported: &'static [&'static str],
    pub response_types_supported: &'static [&'static str],
    pub subject_types_supported: &'static [&'static str],
    pub grant_types_supported: &'static [&'static str],
    pub token_endpoint_auth_methods_supported: &'static [&'static str],
    pub revocation_endpoint_auth_methods_supported: &'static [&'static str],
    pub id_token_signing_alg_values_supported: [&'static str; 1],
    pub claims_supported: &'static [&'static str],
    pub code_challenge_methods_supported: &'static [&'static str],
    pub authorization_response_iss_parameter_supported: bool,
    pub client_id_metadata_document_supported: bool,
    pub protected_resources: &'x [Box<str>],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stalwart_required_scopes: Option<&'static [&'static str]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcMetadataRequest {
    WellKnown,
    Discover { is_tls: bool },
}

const DISCOVER_REQUIRED_SCOPES: &[&str] = &[SCOPE_OPENID];

pub trait OpenIdHandler: Sync + Send {
    fn handle_userinfo_request(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_oidc_metadata(
        &self,
        request: OidcMetadataRequest,
        origin: RequestOrigin<'_>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl OpenIdHandler for Server {
    async fn handle_userinfo_request(&self, account_id: u32) -> trc::Result<HttpResponse> {
        let account = self.account(account_id).await?;

        Ok(JsonResponse::new(Userinfo {
            sub: Some(account_id.to_string()),
            name: account.description().map(|d| d.to_string()),
            preferred_username: Some(account.name().to_string()),
            email: account.name().to_string().into(),
            email_verified: true,
            ..Default::default()
        })
        .no_cache()
        .into_http_response())
    }

    async fn handle_oidc_metadata(
        &self,
        request: OidcMetadataRequest,
        origin: RequestOrigin<'_>,
    ) -> trc::Result<HttpResponse> {
        let strip_base_url = matches!(request, OidcMetadataRequest::Discover { is_tls: false });
        let request_issuer = issuer(self, origin);
        let base_url: &str = if strip_base_url {
            #[cfg(feature = "dev_mode")]
            {
                &request_issuer
            }

            #[cfg(not(feature = "dev_mode"))]
            {
                ""
            }
        } else {
            &request_issuer
        };
        let issuer = if strip_base_url && !self.core.network.http.url_https.is_empty() {
            base_url
        } else {
            &request_issuer
        };

        Ok(JsonResponse::new(OpenIdMetadata {
            authorization_endpoint: format!("{base_url}/login",),
            token_endpoint: format!("{base_url}/auth/token"),
            userinfo_endpoint: format!("{base_url}/auth/userinfo"),
            jwks_uri: format!("{base_url}/auth/jwks.json"),
            registration_endpoint: format!("{base_url}/auth/register"),
            device_authorization_endpoint: format!("{base_url}/auth/device"),
            revocation_endpoint: format!("{base_url}/auth/revoke"),
            end_session_endpoint: format!("{base_url}{END_SESSION_PATH}"),
            response_types_supported: &["code"],
            grant_types_supported: &[
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            scopes_supported: supported_scopes(self.core.network.resources.serves_files),
            subject_types_supported: &["public"],
            token_endpoint_auth_methods_supported: TOKEN_ENDPOINT_AUTH_METHODS,
            revocation_endpoint_auth_methods_supported: TOKEN_ENDPOINT_AUTH_METHODS,
            id_token_signing_alg_values_supported: [self.core.oauth.oidc_signature_algorithm_name],
            claims_supported: &[
                "sub",
                "name",
                "preferred_username",
                "email",
                "email_verified",
            ],
            code_challenge_methods_supported: &["S256"],
            authorization_response_iss_parameter_supported: true,
            client_id_metadata_document_supported: true,
            protected_resources: &self.core.network.resources.identifiers,
            stalwart_required_scopes: matches!(request, OidcMetadataRequest::Discover { .. })
                .then_some(DISCOVER_REQUIRED_SCOPES),
            issuer: issuer.to_string(),
        })
        .into_http_response()
        .with_cors_unrestricted())
    }
}
