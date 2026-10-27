/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::network::acme::{AcmeError, AcmeResult};
use compact_str::CompactString;
use hyper::{
    Method, StatusCode,
    header::{CONTENT_TYPE, USER_AGENT},
};
use jiff::{Timestamp, fmt::rfc2822::DateTimeParser};
use registry::schema::structs::AcmeProvider;
use reqwest::Response;
use std::time::Duration;
use utils::{
    HttpLimitResponse,
    outbound::{OutboundClient, OutboundPolicy, Redirects},
};

const MAX_ERROR_BODY_LEN: usize = 512;
const MAX_RESPONSE_LEN: usize = 1024 * 1024;
const MAX_REDIRECTS: usize = 10;

#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
pub(crate) fn acme_client(provider: &AcmeProvider) -> OutboundClient {
    #[cfg(any(feature = "dev_mode", inbuxa_tests))]
    let allow_invalid_certs = provider.directory.starts_with("https://localhost")
        || provider.directory.starts_with("https://127.0.0.1");
    #[cfg(not(any(feature = "dev_mode", inbuxa_tests)))]
    let allow_invalid_certs = false;

    #[cfg(not(feature = "enterprise"))]
    let policy = OutboundPolicy::Trusted;

    OutboundClient::new(
        utils::http::http1_client_builder(allow_invalid_certs).timeout(Duration::from_secs(30)),
        policy,
        Redirects::Limited(MAX_REDIRECTS),
    )
}

pub(crate) async fn https(
    client: &OutboundClient,
    url: &str,
    method: Method,
    body: Option<String>,
) -> AcmeResult<Response> {
    let mut request = client
        .request(method, url)
        .map_err(|err| AcmeError::Invalid(format!("Rejected ACME URL {url}: {err}")))?
        .header(USER_AGENT, crate::USER_AGENT);

    if let Some(body) = body {
        request = request
            .header(CONTENT_TYPE, "application/jose+json")
            .body(body);
    }

    let response = request.send().await?;
    if response.status().is_success() {
        Ok(response)
    } else if matches!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    ) {
        let wait = parse_retry_after(&response);

        trc::event!(
            Acme(trc::AcmeEvent::RenewBackoff),
            Url = CompactString::from(url),
            Code = response.status().as_u16(),
            Elapsed = wait.unwrap_or_default(),
        );

        Err(AcmeError::Backoff { wait })
    } else {
        let status = response.status();
        let text = read_body_prefix(response).await;
        Err(AcmeError::HttpStatus(format!(
            "Unexpected status {}: {}",
            status, text
        )))
    }
}

pub(crate) async fn read_body(response: Response) -> AcmeResult<String> {
    let body = response
        .bytes_with_limit(MAX_RESPONSE_LEN)
        .await?
        .ok_or_else(|| AcmeError::Invalid("ACME response exceeds maximum size".to_string()))?;
    String::from_utf8(body)
        .map_err(|_| AcmeError::Invalid("ACME response is not valid UTF-8".to_string()))
}

async fn read_body_prefix(mut response: Response) -> String {
    let mut prefix = Vec::with_capacity(MAX_ERROR_BODY_LEN);
    while prefix.len() < MAX_ERROR_BODY_LEN
        && let Ok(Some(chunk)) = response.chunk().await
    {
        let remaining = MAX_ERROR_BODY_LEN - prefix.len();
        prefix.extend_from_slice(chunk.get(..remaining).unwrap_or(&chunk));
    }
    String::from_utf8_lossy(&prefix).into_owned()
}

pub(crate) fn get_header(response: &Response, header: &'static str) -> AcmeResult<String> {
    match response.headers().get_all(header).iter().next_back() {
        Some(value) => Ok(value
            .to_str()
            .map_err(|err| {
                AcmeError::Invalid(format!("Failed to read header {}: {}", header, err))
            })?
            .to_string()),
        None => Err(AcmeError::Invalid(format!("Missing header: {}", header))),
    }
}

pub(crate) fn parse_alternate_links(response: &Response) -> Vec<String> {
    alternate_links(
        response
            .headers()
            .get_all("Link")
            .iter()
            .filter_map(|value| value.to_str().ok()),
    )
}

fn alternate_links<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut urls = Vec::new();
    for value in values {
        for link in value.split(',') {
            let mut url = None;
            let mut is_alternate = false;
            for (index, part) in link.split(';').enumerate() {
                let part = part.trim();
                if index == 0 {
                    url = part
                        .strip_prefix('<')
                        .and_then(|part| part.strip_suffix('>'));
                } else if let Some(rel) = part.strip_prefix("rel=") {
                    is_alternate = rel.trim_matches('"') == "alternate";
                }
            }
            if is_alternate && let Some(url) = url {
                urls.push(url.to_string());
            }
        }
    }
    urls
}

pub(crate) fn parse_retry_after(response: &Response) -> Option<Duration> {
    retry_after(
        response.headers().get("Retry-After")?.to_str().ok()?,
        Timestamp::now(),
    )
}

fn retry_after(value: &str, now: Timestamp) -> Option<Duration> {
    if let Ok(secs) = value.parse::<u64>() {
        Some(Duration::from_secs(secs + 1))
    } else {
        let retry_at = DateTimeParser::new().parse_timestamp(value).ok()?;
        Duration::try_from(retry_at.duration_since(now))
            .ok()
            .map(|delay| delay + Duration::from_secs(1))
    }
}

