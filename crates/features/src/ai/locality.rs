/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Whether a model's endpoint keeps message content on this network (AI-2).
//! Advisory only: it decides a warning, never whether a call is made.

use std::net::IpAddr;

/// The host in a URL, without brackets, userinfo or port.
pub fn host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split_once(']')?.0
    } else {
        authority.split(':').next()?
    };
    (!host.is_empty()).then_some(host)
}

/// Loopback, RFC 1918, RFC 4193 (and link-local) addresses.
pub fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || ip.to_ipv4_mapped().is_some_and(|v4| is_local_ip(IpAddr::V4(v4)))
        }
    }
}

/// What a URL's host says before any name lookup: `Some(true)` local,
/// `Some(false)` not, `None` a name to resolve.
pub fn classify(url: &str) -> Option<bool> {
    let Some(host) = host(url) else {
        return Some(false);
    };
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost")
    {
        return Some(true);
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => Some(is_local_ip(ip)),
        Err(_) => None,
    }
}

/// The warning's text (AI-2).
pub fn warning(model: &str, url: &str) -> String {
    format!(
        "AI model {model:?} points at {url}, which isn't on this network: message content sent \
         to it leaves this network."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_hosts() {
        for local in [
            "http://127.0.0.1:8080/v1/chat/completions",
            "http://localhost/v1",
            "https://10.0.0.5/v1",
            "https://192.168.1.2:443/x",
            "http://[::1]:8080/v1",
            "http://[fd12:3456::1]/v1",
            "http://user:pw@172.16.0.1/v1",
        ] {
            assert_eq!(classify(local), Some(true), "{local}");
        }
        for remote in ["https://8.8.8.8/v1", "http://[2001:db8::1]/v1", "not a url"] {
            assert_eq!(classify(remote), Some(false), "{remote}");
        }
        assert_eq!(classify("https://mail.example.net/v1"), None);
        assert_eq!(host("https://mail.example.net:8443/v1?x"), Some("mail.example.net"));
    }
}
