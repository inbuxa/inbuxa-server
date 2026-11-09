/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{Server, auth::oauth::GrantType};
use serde::{Deserialize, Serialize};
use trc::{AuthEvent, EventType};

#[derive(Debug, Default, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct OAuthIntrospect {
    #[serde(default)]
    pub active: bool,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

impl Server {
    pub async fn introspect_access_token(&self, token: &str) -> trc::Result<OAuthIntrospect> {
        // inbuxa: only an access token is active; refresh, RSVP and live
        // tokens can't be presented as a bearer token
        match self
            .validate_access_token(Some(GrantType::AccessToken), token)
            .await
        {
            // inbuxa: the token is described by its owner, not by whoever
            // asks; a token whose account is gone is inactive
            Ok(token_info) => match self.account(token_info.account_id).await {
                Ok(owner) => Ok(OAuthIntrospect {
                    active: true,
                    username: owner.name().to_string().into(),
                    token_type: Some("bearer".into()),
                    exp: Some(token_info.expiry as i64),
                    iat: Some(token_info.issued_at as i64),
                    ..Default::default()
                }),
                Err(err) if err.matches(EventType::Auth(AuthEvent::Error)) => {
                    Ok(OAuthIntrospect::default())
                }
                Err(err) => Err(err.caused_by(trc::location!())),
            },
            Err(err)
                if matches!(
                    err.event_type(),
                    EventType::Auth(AuthEvent::Error) | EventType::Auth(AuthEvent::TokenExpired)
                ) =>
            {
                Ok(OAuthIntrospect::default())
            }
            Err(err) => Err(err),
        }
    }
}
