/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    authorize::{issuer, redirect_location},
    request_origin,
};
use common::{Server, auth::oauth::client::RequestOrigin};
use http_proto::{
    HttpRequest, HttpResponse, HttpSessionData, form_urlencoded, request::fetch_body,
};
use hyper::{
    Method, StatusCode,
    header::{CONTENT_SECURITY_POLICY, X_FRAME_OPTIONS},
};
use std::{borrow::Cow, future::Future};

pub const END_SESSION_PATH: &str = "/auth/logout";
const MAX_LOGOUT_REQUEST_LEN: usize = 8 * 1024;
const LOGGED_OUT_PAGE: &str = concat!(
    "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
    "<title>Signed out</title></head>",
    "<body style=\"font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem\">",
    "<h1>You have been signed out</h1>",
    "<p>You can close this window.</p></body></html>"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Param {
    ClientId,
    PostLogoutRedirectUri,
    State,
    IdTokenHint,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct EndSessionParams<'x> {
    pub client_id: Option<Cow<'x, str>>,
    pub post_logout_redirect_uri: Option<Cow<'x, str>>,
    pub state: Option<Cow<'x, str>>,
    pub id_token_hint: Option<Cow<'x, str>>,
}

pub trait EndSessionHandler: Sync + Send {
    fn handle_end_session(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn post_logout_location(
        &self,
        params: &EndSessionParams<'_>,
        origin: RequestOrigin<'_>,
    ) -> impl Future<Output = trc::Result<Option<String>>> + Send;
}

impl EndSessionHandler for Server {
    async fn handle_end_session(
        &self,
        req: &mut HttpRequest,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let body = if req.method() == Method::POST {
            fetch_body(req, MAX_LOGOUT_REQUEST_LEN, session.session_id).await
        } else {
            None
        };
        let query = match &body {
            Some(body) => body.as_slice(),
            None => req.uri().query().unwrap_or_default().as_bytes(),
        };
        let params = if query.len() <= MAX_LOGOUT_REQUEST_LEN {
            EndSessionParams::parse(query)
        } else {
            None
        };
        let location = match params {
            Some(params) => {
                self.post_logout_location(&params, request_origin(req, session))
                    .await?
            }
            None => None,
        };

        Ok(match location {
            Some(location) => HttpResponse::new(StatusCode::SEE_OTHER)
                .with_location(location)
                .with_no_store(),
            None => HttpResponse::new(StatusCode::OK)
                .with_content_type("text/html; charset=utf-8")
                .with_header(X_FRAME_OPTIONS, "DENY")
                .with_header(
                    CONTENT_SECURITY_POLICY,
                    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
                )
                .with_no_store()
                .with_text_body(LOGGED_OUT_PAGE),
        })
    }

    async fn post_logout_location(
        &self,
        params: &EndSessionParams<'_>,
        origin: RequestOrigin<'_>,
    ) -> trc::Result<Option<String>> {
        let Some(redirect_uri) = params.post_logout_redirect_uri.as_deref() else {
            return Ok(None);
        };
        let hint_audience = match params.id_token_hint.as_deref() {
            Some(hint) => match self.verify_id_token_hint(hint, &issuer(self, origin)) {
                Some(hint) => Some(hint.aud),
                None => return Ok(None),
            },
            None => None,
        };
        let client_id = match (params.client_id.as_deref(), hint_audience.as_deref()) {
            (Some(client_id), Some(audience)) if client_id != audience => return Ok(None),
            (Some(client_id), _) => client_id,
            (None, Some(audience)) => audience,
            (None, None) => return Ok(None),
        };

        if !self
            .is_post_logout_redirect_uri_allowed(client_id, redirect_uri, origin)
            .await?
        {
            return Ok(None);
        }

        Ok(Some(match params.state.as_deref() {
            Some(state) => redirect_location(redirect_uri, [("state", state)]),
            None => redirect_uri.to_string(),
        }))
    }
}

impl Param {
    fn parse(name: &str) -> Option<Self> {
        hashify::map!(
            name.as_bytes(),
            Param,
            "client_id" => Param::ClientId,
            "post_logout_redirect_uri" => Param::PostLogoutRedirectUri,
            "state" => Param::State,
            "id_token_hint" => Param::IdTokenHint,
        )
        .copied()
    }
}

impl<'x> EndSessionParams<'x> {
    pub fn parse(query: &'x [u8]) -> Option<Self> {
        let mut params = EndSessionParams::default();
        for (name, value) in form_urlencoded::parse(query) {
            let slot = match Param::parse(&name) {
                Some(Param::ClientId) => &mut params.client_id,
                Some(Param::PostLogoutRedirectUri) => &mut params.post_logout_redirect_uri,
                Some(Param::State) => &mut params.state,
                Some(Param::IdTokenHint) => &mut params.id_token_hint,
                None => continue,
            };
            if slot.is_some() {
                return None;
            }
            if !value.is_empty() {
                *slot = Some(value);
            }
        }
        Some(params)
    }
}

