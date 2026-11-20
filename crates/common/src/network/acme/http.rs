/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::network::{
    acme::{AcmeError, AcmeResult},
    is_global_ip,
    public_only::PublicOnly,
};
use chrono::{DateTime, Utc};
use hyper::{
    Method, StatusCode,
    header::{CONTENT_TYPE, USER_AGENT},
};
use reqwest::Response;
use std::time::Duration;

#[allow(unused_mut)]
///
/// inbuxa: `public_only` is set for a tenant's own ACME provider. Its
/// administrator picks the directory URL and the directory names every URL
/// after it, so each request must be HTTPS to a public address, checked when
/// the name resolves, with no redirects (a redirect to an IP literal would
/// skip that check).
pub(crate) async fn https(
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
    max_retries: u32,
    public_only: bool,
) -> AcmeResult<Response> {
    let url = url.as_ref();
    if public_only && !(starts_with_ignore_case(url, "https://") && has_public_ip_or_name(url)) {
        return Err(AcmeError::Invalid(format!(
            "A tenant's ACME provider must use a public HTTPS address: {}",
            redact_url(url)
        )));
    }

    #[allow(unused_mut)]
    #[allow(unused_assignments)]
    let mut allow_invalid_certs = false;

    #[cfg(any(feature = "dev_mode", feature = "test_mode"))]
    {
        allow_invalid_certs =
            url.starts_with("https://localhost") || url.starts_with("https://127.0.0.1");
    }

    let mut client =
        utils::http::http1_client_builder(allow_invalid_certs).timeout(Duration::from_secs(30));
    if public_only {
        client = client
            .public_only()
            .redirect(reqwest::redirect::Policy::none());
    }
    let mut request = client
        .build()?
        .request(method, url)
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
            Url = url.to_string(),
            Code = response.status().as_u16(),
            Elapsed = wait.unwrap_or_default(),
        );

        Err(AcmeError::Backoff { wait, max_retries })
    } else {
        // inbuxa: this message reaches the JMAP caller. Only an ACME problem
        // document's own type and detail go into it, never the raw body of
        // whatever answered.
        let status = response.status();
        let problem = if is_problem_document(&response) {
            response
                .json::<Problem>()
                .await
                .map(|problem| problem.summary())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Err(AcmeError::HttpStatus(if problem.is_empty() {
            format!("Unexpected status {status}")
        } else {
            format!("Unexpected status {status}: {problem}")
        }))
    }
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
    let value = response.headers().get("Retry-After")?.to_str().ok()?;
    if let Ok(secs) = value.parse::<u64>() {
        Some(Duration::from_secs(secs + 1))
    } else if let Ok(dt) = DateTime::parse_from_rfc2822(value) {
        Utc::now()
            .signed_duration_since(dt.with_timezone(&Utc))
            .to_std()
            .map(|dur| dur + Duration::from_secs(1))
            .ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::alternate_links;

    #[test]
    fn parses_single_alternate_link() {
        let links =
            alternate_links([r#"<https://acme.example/cert/1/1>;rel="alternate""#].into_iter());
        assert_eq!(links, vec!["https://acme.example/cert/1/1".to_string()]);
    }

    #[test]
    fn parses_multiple_alternates_in_one_header() {
        let links = alternate_links(
            [r#"<https://acme.example/cert/1/1>;rel="alternate", <https://acme.example/cert/1/2>;rel="alternate""#]
                .into_iter(),
        );
        assert_eq!(
            links,
            vec![
                "https://acme.example/cert/1/1".to_string(),
                "https://acme.example/cert/1/2".to_string(),
            ]
        );
    }

    #[test]
    fn parses_alternates_across_multiple_headers() {
        let links = alternate_links(
            [
                r#"<https://acme.example/cert/1/1>;rel="alternate""#,
                r#"<https://acme.example/cert/1/2>;rel="alternate""#,
            ]
            .into_iter(),
        );
        assert_eq!(
            links,
            vec![
                "https://acme.example/cert/1/1".to_string(),
                "https://acme.example/cert/1/2".to_string(),
            ]
        );
    }

    #[test]
    fn ignores_non_alternate_relations() {
        let links = alternate_links(
            [r#"<https://acme.example/index>;rel="index", <https://acme.example/cert/1/1>;rel="alternate""#]
                .into_iter(),
        );
        assert_eq!(links, vec!["https://acme.example/cert/1/1".to_string()]);
    }

    #[test]
    fn tolerates_unquoted_rel_and_extra_whitespace() {
        let links =
            alternate_links([r#" <https://acme.example/cert/1/1> ; rel=alternate "#].into_iter());
        assert_eq!(links, vec!["https://acme.example/cert/1/1".to_string()]);
    }

    #[test]
    fn returns_empty_when_no_alternates() {
        let links = alternate_links([r#"<https://acme.example/dir>;rel="index""#].into_iter());
        assert!(links.is_empty());
    }
}

/// inbuxa: the parts of an RFC 7807 problem document an ACME server explains
/// itself with (RFC 8555 section 6.7).
#[derive(serde::Deserialize)]
struct Problem {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    detail: String,
}

/// The longest detail passed on, in characters.
const MAX_PROBLEM_DETAIL: usize = 300;

impl Problem {
    fn summary(&self) -> String {
        let detail: String = self
            .detail
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_PROBLEM_DETAIL)
            .collect();
        let kind: String = self
            .kind
            .chars()
            .filter(|c| c.is_ascii_graphic())
            .take(100)
            .collect();
        match (kind.is_empty(), detail.is_empty()) {
            (false, false) => format!("{kind}: {detail}"),
            (false, true) => kind,
            (true, false) => detail,
            (true, true) => String::new(),
        }
    }
}

fn is_problem_document(response: &Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/problem+json")
        })
}

/// The URL's host is a name (checked when it resolves) or a public IP
/// literal. Unlike `public_only::has_public_host`, test builds get no
/// loopback exception: no test reaches a tenant's ACME server.
fn has_public_ip_or_name(url: &str) -> bool {
    let Some(host) = reqwest::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
    else {
        return false;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(&host);
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => is_global_ip(&ip),
        Err(_) => true,
    }
}

fn starts_with_ignore_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

/// The URL without its query or any credentials, for an error message.
fn redact_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => "(not a URL)".to_string(),
    }
}

#[cfg(test)]
mod tenant_tests {
    use super::*;

    fn outcome(result: &AcmeResult<Response>) -> String {
        match result {
            Ok(response) => format!("status {}", response.status()),
            Err(err) => err.to_string(),
        }
    }

    #[tokio::test]
    async fn tenant_destinations_are_checked_before_sending() {
        for url in [
            "http://acme.example.com/dir",
            "ftp://acme.example.com/dir",
            "https://10.0.0.1/dir",
            "https://169.254.169.254/latest/meta-data/",
            "https://[fd00::1]/dir",
            "https://[::ffff:192.168.1.1]/dir",
            "https://127.0.0.1/dir",
            "https://[::1]/dir",
            "not a url",
        ] {
            let result = https(url, Method::GET, None, 0, true).await;
            match &result {
                Err(AcmeError::Invalid(message)) => {
                    assert!(message.contains("public HTTPS"), "{url}: {message}")
                }
                _ => panic!("{url}: expected a refusal, got {}", outcome(&result)),
            }
        }
    }

    #[tokio::test]
    async fn tenant_host_names_must_resolve_to_public_addresses() {
        // localhost resolves to loopback: refused when it resolves, before
        // anything is sent.
        let result = https("https://localhost:9/dir", Method::GET, None, 0, true).await;
        match &result {
            Err(AcmeError::Http(err)) => assert!(err.is_connect() || err.is_request(), "{err}"),
            _ => panic!("expected a resolver refusal, got {}", outcome(&result)),
        }
    }

    #[test]
    fn problem_summary_is_bounded() {
        let problem = Problem {
            kind: "urn:ietf:params:acme:error:malformed".to_string(),
            detail: format!("bad\nthing {}", "x".repeat(1000)),
        };
        let summary = problem.summary();
        assert!(summary.starts_with("urn:ietf:params:acme:error:malformed: bad"));
        assert!(!summary.contains('\n'));
        assert!(summary.len() < 450, "{}", summary.len());
    }

    #[test]
    fn redacted_urls_drop_credentials_and_query() {
        assert_eq!(
            redact_url("https://user:pw@acme.example.com/dir?token=1#x"),
            "https://acme.example.com/dir"
        );
    }
}
