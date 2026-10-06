/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `/scim/v2` (SCIM spec): routes, authenticates with an API key only,
//! enforces the rate limits and the body cap, and hands the request to the
//! `scim` crate.

use crate::auth::authenticate::{Authenticator, HttpHeaders};
use common::Server;
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use percent_encoding::percent_decode_str;
use scim::{Route, ScimRequest, ScimResponse};
use scim_proto::ScimError;

/// Seconds until a rate limit resets, from the error the limiter gave.
fn retry_after(err: &trc::Error) -> u64 {
    let now = store::write::now();
    match err.value(trc::Key::Expires).and_then(|v| v.to_uint()) {
        Some(at) if at > now => at - now,
        Some(seconds) if seconds > 0 => seconds,
        _ => 1,
    }
}

/// A limiter refusal as `429` with `Retry-After` (SCIM-14), anything else
/// as `401` (SCIM-7).
fn refusal(err: trc::Error) -> ScimResponse {
    match err.event_type() {
        trc::EventType::Limit(
            trc::LimitEvent::TooManyRequests | trc::LimitEvent::ConcurrentRequest,
        ) => ScimResponse::error(ScimError::new(429, "Too many requests"))
            .with_header("Retry-After", retry_after(&err).to_string()),
        _ => ScimResponse::error(ScimError::unauthorized(
            "The API key is missing, invalid, expired, revoked, or not allowed from this address",
        )),
    }
}

pub async fn handle(
    server: &Server,
    req: &mut HttpRequest,
    session: &HttpSessionData,
) -> HttpResponse {
    respond(server, req, session).await.into_http_response()
}

async fn respond(
    server: &Server,
    req: &mut HttpRequest,
    session: &HttpSessionData,
) -> ScimResponse {
    let segments = req
        .uri()
        .path()
        .split('/')
        .skip(3)
        .map(|segment| percent_decode_str(segment).decode_utf8_lossy().into_owned())
        .collect::<Vec<_>>();
    let route = match Route::parse(req.method(), &segments) {
        Ok(route) => route,
        Err(response) => return response,
    };
    let query = req.uri().query().map(str::to_string);

    // SCIM-3: discovery is anonymous, under the anonymous rate limit
    if route.is_anonymous() {
        if let Err(err) = server
            .is_http_anonymous_request_allowed(session.remote_ip)
            .await
        {
            return refusal(err);
        }
        return scim::handle_anonymous(server, &route, query.as_deref());
    }

    // SCIM-7: an API key as a bearer token, and nothing else
    match req.authorization() {
        None => {
            return ScimResponse::error(ScimError::unauthorized(
                "An API key is required, as an Authorization: Bearer token",
            ));
        }
        Some((mechanism, _)) if mechanism.eq_ignore_ascii_case("basic") => {
            return ScimResponse::error(ScimError::unauthorized(
                "Basic authentication isn't accepted: send an API key as an Authorization: Bearer token",
            ));
        }
        Some((mechanism, token))
            if !mechanism.eq_ignore_ascii_case("bearer") || !token.starts_with("API_") =>
        {
            return ScimResponse::error(ScimError::unauthorized(
                "Only API keys are accepted, as an Authorization: Bearer token",
            ));
        }
        Some(_) => {}
    }
    let (_in_flight, access_token) = match server.authenticate_headers(req, session).await {
        Ok(result) => result,
        Err(err) => {
            trc::error!(err.clone().span_id(session.session_id));
            return refusal(err);
        }
    };

    // SCIM-51: 1 MiB for every body, /Bulk included
    let Some(body) = fetch_body(req, scim::MAX_PAYLOAD, session.session_id).await else {
        return ScimResponse::error(ScimError::new(
            413,
            format!("The body is larger than {} bytes", scim::MAX_PAYLOAD),
        ));
    };

    scim::handle(
        server,
        &access_token,
        session,
        ScimRequest {
            route,
            query: query.as_deref(),
            headers: req.headers(),
            body,
        },
    )
    .await
}
