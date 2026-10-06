/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `GET /logo` (branding spec BT-5 to BT-8) and the RSVP page's answer
//! (BT-20, BT-21).

use common::Server;
use http_proto::{HttpRequest, HttpResponse};
use hyper::{
    StatusCode,
    header::{self, CONTENT_ENCODING},
};
use inbuxa_features::branding::{logo::Logo, templates};

const LOGO_CACHE: &str = "public, max-age=300";
const SVG_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
const RSVP_CSP: &str = concat!(
    "default-src 'self'; script-src 'self' 'unsafe-inline'; ",
    "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; ",
    "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
);

/// The domain a `/logo` request asks about: `?domain=`, else the `Host`
/// (BT-2).
fn requested_domain(req: &HttpRequest) -> String {
    req.uri()
        .query()
        .and_then(|query| {
            http_proto::form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "domain")
                .map(|(_, value)| value.into_owned())
        })
        .filter(|domain| !domain.is_empty())
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|host| host.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

/// `GET /logo`: the image, a redirect to a URL logo, or `404` when no
/// custom logo applies. The server never fetches a URL (BT-7).
pub async fn logo(server: &Server, req: &HttpRequest) -> trc::Result<HttpResponse> {
    let response = match server
        .logos_for(&requested_domain(req))
        .await?
        .into_iter()
        .next()
    {
        Some(Logo::Image {
            content_type,
            bytes,
        }) => {
            let response = HttpResponse::new(StatusCode::OK)
                .with_content_type(content_type)
                .with_binary_body(bytes);
            if content_type == "image/svg+xml" {
                // BT-8: a scripted SVG must never run on the server's origin
                response.with_header(header::CONTENT_SECURITY_POLICY, SVG_CSP)
            } else {
                response
            }
        }
        Some(Logo::Url(url)) => {
            HttpResponse::new(StatusCode::FOUND).with_header(header::LOCATION, url)
        }
        None => HttpResponse::new(StatusCode::NOT_FOUND),
    };
    Ok(response
        .with_cache_control(LOGO_CACHE)
        .with_header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
}

/// `GET /calendar/rsvp`: the operator's page byte for byte if one is set,
/// else the built-in, with headers that keep the token on the server
/// (BT-20, BT-21).
pub async fn rsvp_page(server: &Server, built_in_gzipped: &'static [u8]) -> trc::Result<HttpResponse> {
    let response = match templates::rsvp_page(server.registry()).await? {
        Some(page) => HttpResponse::new(StatusCode::OK).with_binary_body(page.into_bytes()),
        None => HttpResponse::new(StatusCode::OK)
            .with_header(CONTENT_ENCODING, "gzip")
            .with_binary_body(built_in_gzipped),
    };
    Ok(response
        .with_content_type("text/html; charset=utf-8")
        .with_no_store()
        .with_header(header::REFERRER_POLICY, "no-referrer")
        .with_header(header::CONTENT_SECURITY_POLICY, RSVP_CSP))
}
