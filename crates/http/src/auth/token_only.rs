/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Where HTTP Basic authentication is refused (contract C-23).
//!
//! Outside DAV, the HTTP endpoints take a token, never a password: JMAP, the
//! management API, and the OAuth endpoints that authenticate a user
//! (introspection, userinfo, authenticated client registration). CalDAV and
//! CardDAV keep Basic, since that's how calendar and contacts apps sign in.
//! The token endpoint's own client authentication isn't user sign-in and
//! isn't affected.
//!
//! Bootstrap and recovery mode accept Basic everywhere, as they keep
//! permissive CORS (C-16), and `INBUXA_HTTP_BASIC_AUTH=all` puts it back
//! everywhere for an operator who needs it.

use crate::auth::authenticate::HttpHeaders;
use http_proto::HttpRequest;

/// Whether `path` takes a token only when Basic isn't allowed everywhere.
pub fn is_token_only_path(path: &str) -> bool {
    let mut segments = path.trim_start_matches('/').split('/');
    match segments.next() {
        Some("jmap" | "api") => true,
        Some("auth") => matches!(
            segments.next(),
            Some("introspect" | "userinfo" | "register")
        ),
        _ => false,
    }
}

/// Whether this request signs in with a password where only a token is
/// accepted.
pub fn is_refused_basic(req: &HttpRequest, basic_auth_everywhere: bool) -> bool {
    !basic_auth_everywhere
        && req.authorization_basic().is_some()
        && is_token_only_path(req.uri().path())
}

#[cfg(test)]
mod tests {
    use super::is_token_only_path;

    #[test]
    fn token_only_paths() {
        for path in [
            "/jmap",
            "/jmap/",
            "/jmap/session",
            "/jmap/upload/a/",
            "/jmap/download/a/b/c",
            "/jmap/eventsource/",
            "/jmap/ws",
            "/api",
            "/api/account",
            "/api/schema",
            "/auth/introspect",
            "/auth/userinfo",
            "/auth/register",
        ] {
            assert!(is_token_only_path(path), "{path} should take a token only");
        }
    }

    #[test]
    fn basic_stays_where_apps_need_it() {
        for path in [
            "/dav/cal/user/",
            "/dav/card/user/",
            "/.well-known/caldav",
            "/.well-known/carddav",
            "/.well-known/jmap",
            "/auth/token",
            "/auth/device",
            "/scim/v2/Users",
            "/",
            "/login",
            "/jmapx",
            "/apis",
        ] {
            assert!(!is_token_only_path(path), "{path} should be left alone");
        }
    }
}
