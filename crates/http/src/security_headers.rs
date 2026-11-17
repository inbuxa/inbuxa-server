/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The security headers every HTTP answer gets by default.
//!
//! Each one is added only when the answer doesn't already carry it, so a
//! page that sets its own (the RSVP page's policy) or a header the operator
//! sets in `http.response_headers` wins. An operator who must have the pages
//! framed sends their own `Content-Security-Policy` with `frame-ancestors`.

use hyper::{
    HeaderMap,
    header::{
        CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderValue, REFERRER_POLICY,
        STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
    },
};

/// 180 days. No `includeSubDomains` or `preload`: those reach past this host.
const HSTS: &str = "max-age=15552000";

/// Adds the defaults to an answer's headers. HSTS goes only on an answer
/// sent over TLS: behind a proxy on a plain listener it's the proxy's to send.
pub fn add_security_headers(headers: &mut HeaderMap, is_tls: bool) {
    headers
        .entry(X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    if is_tls {
        headers
            .entry(STRICT_TRANSPORT_SECURITY)
            .or_insert(HeaderValue::from_static(HSTS));
    }

    if is_html(headers) {
        // A page of this server is never shown inside another site's
        if !headers
            .get_all(CONTENT_SECURITY_POLICY)
            .iter()
            .any(|policy| contains_ignore_case(policy.as_bytes(), b"frame-ancestors"))
        {
            headers.append(
                CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("frame-ancestors 'none'"),
            );
        }
        headers
            .entry(X_FRAME_OPTIONS)
            .or_insert(HeaderValue::from_static("DENY"));
        headers
            .entry(REFERRER_POLICY)
            .or_insert(HeaderValue::from_static("strict-origin-when-cross-origin"));
    }
}

fn is_html(headers: &HeaderMap) -> bool {
    headers.get(CONTENT_TYPE).is_some_and(|value| {
        let value = value.as_bytes();
        let essence = value
            .split(|&byte| byte == b';')
            .next()
            .unwrap_or_default()
            .trim_ascii();
        essence.eq_ignore_ascii_case(b"text/html")
            || essence.eq_ignore_ascii_case(b"application/xhtml+xml")
    })
}

fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::add_security_headers;
    use hyper::{HeaderMap, header::HeaderValue};

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_static(value));
        }
        headers
    }

    fn all(headers: &HeaderMap, name: &str) -> Vec<String> {
        headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn a_page_over_tls_gets_every_header() {
        let mut page = headers(&[("content-type", "text/html; charset=utf-8")]);
        add_security_headers(&mut page, true);
        assert_eq!(all(&page, "x-frame-options"), ["DENY"]);
        assert_eq!(
            all(&page, "content-security-policy"),
            ["frame-ancestors 'none'"]
        );
        assert_eq!(all(&page, "x-content-type-options"), ["nosniff"]);
        assert_eq!(
            all(&page, "referrer-policy"),
            ["strict-origin-when-cross-origin"]
        );
        assert_eq!(
            all(&page, "strict-transport-security"),
            ["max-age=15552000"]
        );
    }

    #[test]
    fn a_plain_listener_sends_no_hsts() {
        let mut page = headers(&[("content-type", "TEXT/HTML")]);
        add_security_headers(&mut page, false);
        assert!(all(&page, "strict-transport-security").is_empty());
        assert_eq!(all(&page, "x-frame-options"), ["DENY"]);
    }

    #[test]
    fn other_answers_get_only_nosniff_and_hsts() {
        for content_type in [Some("application/json"), Some("image/png"), None] {
            let mut answer = match content_type {
                Some(content_type) => headers(&[("content-type", content_type)]),
                None => HeaderMap::new(),
            };
            add_security_headers(&mut answer, true);
            assert_eq!(all(&answer, "x-content-type-options"), ["nosniff"]);
            assert_eq!(
                all(&answer, "strict-transport-security"),
                ["max-age=15552000"]
            );
            for name in [
                "x-frame-options",
                "content-security-policy",
                "referrer-policy",
            ] {
                assert!(all(&answer, name).is_empty(), "{content_type:?}: {name}");
            }
        }
    }

    #[test]
    fn headers_already_set_are_kept() {
        // The RSVP page's own policy and referrer rule, and an operator's HSTS
        let mut page = headers(&[
            ("content-type", "text/html"),
            (
                "content-security-policy",
                "default-src 'self'; frame-ancestors 'none'",
            ),
            ("referrer-policy", "no-referrer"),
            ("strict-transport-security", "max-age=63072000; preload"),
        ]);
        add_security_headers(&mut page, true);
        assert_eq!(
            all(&page, "content-security-policy"),
            ["default-src 'self'; frame-ancestors 'none'"]
        );
        assert_eq!(all(&page, "referrer-policy"), ["no-referrer"]);
        assert_eq!(
            all(&page, "strict-transport-security"),
            ["max-age=63072000; preload"]
        );

        // A policy without frame-ancestors gets a second one that has it
        let mut page = headers(&[
            ("content-type", "text/html"),
            ("content-security-policy", "default-src 'self'"),
        ]);
        add_security_headers(&mut page, true);
        assert_eq!(
            all(&page, "content-security-policy"),
            ["default-src 'self'", "frame-ancestors 'none'"]
        );

        // An operator's frame-ancestors allows what it allows
        let mut page = headers(&[
            ("content-type", "text/html"),
            (
                "content-security-policy",
                "Frame-Ancestors https://portal.example.org",
            ),
        ]);
        add_security_headers(&mut page, true);
        assert_eq!(
            all(&page, "content-security-policy"),
            ["Frame-Ancestors https://portal.example.org"]
        );
    }
}
