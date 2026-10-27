/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Server, auth::oauth::SCOPE_MAIL};
use directory::{Credentials, backend::oidc::openid_configuration_url};
use encodify::base64::STANDARD;
use serde::Serialize;

const XOAUTH2_SCHEMES: &str = "Bearer";
pub const SASL_CANCEL: &str = "*";
pub const SASL_EMPTY: &str = "=";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerMechanism {
    OAuthBearer,
    XOAuth2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerFailure {
    InvalidToken,
    InsufficientScope,
}

#[derive(Serialize)]
struct OAuthBearerFailure {
    status: &'static str,
    scope: &'static str,
    #[serde(
        rename = "openid-configuration",
        skip_serializing_if = "Option::is_none"
    )]
    openid_configuration: Option<String>,
}

#[derive(Serialize)]
struct XOAuth2Failure {
    status: &'static str,
    schemes: &'static str,
    scope: &'static str,
}

impl BearerFailure {
    pub fn insufficient_scope(cause: trc::Error) -> trc::Error {
        trc::AuthEvent::Error
            .into_err()
            .details("The token scope does not allow access to this service.")
            .caused_by(cause)
    }

    pub fn from_error(err: &trc::Error) -> Option<Self> {
        matches!(
            err.as_ref(),
            trc::EventType::Auth(
                trc::AuthEvent::Failed
                    | trc::AuthEvent::TokenExpired
                    | trc::AuthEvent::CredentialExpired
            )
        )
        .then_some(BearerFailure::InvalidToken)
    }

    fn oauthbearer_status(self) -> &'static str {
        match self {
            BearerFailure::InvalidToken => "invalid_token",
            BearerFailure::InsufficientScope => "insufficient_scope",
        }
    }

    fn xoauth2_status(self) -> &'static str {
        match self {
            BearerFailure::InvalidToken => "401",
            BearerFailure::InsufficientScope => "403",
        }
    }
}

impl Server {
    #[inline]
    pub fn accepts_bearer_tokens(&self, is_tls: bool) -> bool {
        is_tls || self.registry().is_bootstrap_mode() || self.registry().is_recovery_mode()
    }

    pub async fn bearer_failure_challenge(
        &self,
        mechanism: BearerMechanism,
        failure: BearerFailure,
        credentials: Option<&Credentials>,
    ) -> String {
        let json = match mechanism {
            BearerMechanism::OAuthBearer => serde_json::to_vec(&OAuthBearerFailure {
                status: failure.oauthbearer_status(),
                scope: SCOPE_MAIL,
                openid_configuration: self.sasl_openid_configuration(credentials).await,
            }),
            BearerMechanism::XOAuth2 => serde_json::to_vec(&XOAuth2Failure {
                status: failure.xoauth2_status(),
                schemes: XOAUTH2_SCHEMES,
                scope: SCOPE_MAIL,
            }),
        }
        .unwrap_or_default();

        STANDARD.encode(json)
    }

    pub async fn sasl_openid_configuration(
        &self,
        credentials: Option<&Credentials>,
    ) -> Option<String> {
        if let Some(Credentials::Bearer { username, token }) = credentials
            && let Ok(Some(discovery)) = self
                .bearer_directory(username.as_deref(), token)
                .await
                .map(|directory| {
                    directory.and_then(|directory| directory.oidc_discovery_document())
                })
        {
            return Some(discovery.configuration_url().to_string());
        }

        let url_https = &self.core.network.http.url_https;
        (!url_https.is_empty()).then(|| openid_configuration_url(url_https))
    }
}

