/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The client's address when inbuxa sits behind reverse proxies.
//!
//! Each proxy appends the address it received the request from, so the
//! client is the right-most address in the chain that no trusted proxy
//! accounts for. Everything to its left was written by the client and can
//! say anything. Forwarding headers are read only when the connection itself
//! comes from a trusted proxy, and only the one header that proxy writes: a
//! proxy appends to its own header and passes any other through as the client
//! sent it.
//!
//! A loopback address in a header is the loopback of whoever wrote it, so it
//! stands for this host only when every hop after it is loopback too.

use common::config::network::ForwardedHeader;
use hyper::HeaderMap;
use hyper::header::FORWARDED;
use registry::types::ipmask::IpAddrOrMask;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn is_trusted_proxy(trusted: &[IpAddrOrMask], ip: &IpAddr) -> bool {
    let ip = ip.to_canonical();
    trusted.iter().any(|net| net.matches(&ip))
}

/// The client behind `peer`, or `None` when `peer` isn't a trusted proxy or
/// the headers name no usable address.
pub fn forwarded_client(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpAddrOrMask],
    header: ForwardedHeader,
) -> Option<IpAddr> {
    if !is_trusted_proxy(trusted, &peer) {
        return None;
    }

    // Never fall back from one header to the other: the one the proxy
    // doesn't write is entirely the client's.
    let chain = match header {
        ForwardedHeader::XForwardedFor => x_forwarded_chain(headers),
        ForwardedHeader::Forwarded => forwarded_chain(headers),
    }?;
    let mut client = None;
    let mut writer = peer.to_canonical();
    for hop in chain.into_iter().rev() {
        // An address that can't be read ends the chain: what's left of it
        // can't be told apart from what the client wrote.
        let Some(ip) = hop else {
            break;
        };
        // Loopback as written by a proxy on another host is that host's,
        // not ours: the client is as far as we can vouch for, the writer.
        if ip.is_loopback() && !writer.is_loopback() {
            return Some(writer);
        }
        client = Some(ip);
        if !is_trusted_proxy(trusted, &ip) {
            break;
        }
        writer = ip;
    }
    client
}

// RFC 7239 `Forwarded: for=...` values in order, `None` for one that isn't an
// address (obfuscated or unknown). `None` overall when no element has `for`.
fn forwarded_chain(headers: &HeaderMap) -> Option<Vec<Option<IpAddr>>> {
    let mut chain = Vec::new();
    for value in headers.get_all(FORWARDED) {
        let Ok(value) = value.to_str() else {
            chain.push(None);
            continue;
        };
        for element in value.split(',') {
            if let Some(node) = element.split(';').find_map(|pair| {
                pair.split_once('=')
                    .filter(|(name, _)| name.trim().eq_ignore_ascii_case("for"))
                    .map(|(_, node)| node)
            }) {
                chain.push(parse_node(node));
            }
        }
    }
    (!chain.is_empty()).then_some(chain)
}

fn x_forwarded_chain(headers: &HeaderMap) -> Option<Vec<Option<IpAddr>>> {
    let mut chain = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        match value.to_str() {
            Ok(value) => chain.extend(value.split(',').map(parse_node)),
            Err(_) => chain.push(None),
        }
    }
    (!chain.is_empty()).then_some(chain)
}

// An address with an optional port: `192.0.2.1`, `192.0.2.1:8080`, `2001:db8::1`,
// `[2001:db8::1]:8080`, any of them in double quotes.
fn parse_node(node: &str) -> Option<IpAddr> {
    let node = node.trim();
    let node = node
        .strip_prefix('"')
        .and_then(|node| node.strip_suffix('"'))
        .unwrap_or(node);
    let ip = if let Some(rest) = node.strip_prefix('[') {
        let (ip, port) = rest.split_once(']')?;
        if !port.is_empty() && !port.strip_prefix(':').is_some_and(is_port) {
            return None;
        }
        IpAddr::V6(ip.parse::<Ipv6Addr>().ok()?)
    } else if let Ok(ip) = node.parse::<IpAddr>() {
        ip
    } else {
        let (ip, port) = node.split_once(':')?;
        if !is_port(port) {
            return None;
        }
        IpAddr::V4(ip.parse::<Ipv4Addr>().ok()?)
    };
    Some(ip.to_canonical())
}

fn is_port(port: &str) -> bool {
    port.parse::<u16>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn trusted() -> Vec<IpAddrOrMask> {
        ["127.0.0.0/8", "10.0.0.0/8", "::1"]
            .iter()
            .map(|net| net.parse().unwrap())
            .collect()
    }

    fn client_with(
        header: ForwardedHeader,
        peer: &str,
        headers: &[(&'static str, &str)],
    ) -> Option<IpAddr> {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        forwarded_client(peer.parse().unwrap(), &map, &trusted(), header)
    }

    fn client(peer: &str, headers: &[(&'static str, &str)]) -> Option<IpAddr> {
        client_with(ForwardedHeader::XForwardedFor, peer, headers)
    }

    fn client_fwd(peer: &str, headers: &[(&'static str, &str)]) -> Option<IpAddr> {
        client_with(ForwardedHeader::Forwarded, peer, headers)
    }

    fn ip(ip: &str) -> Option<IpAddr> {
        Some(ip.parse().unwrap())
    }

    #[test]
    fn right_most_untrusted_hop_is_the_client() {
        let xff = "x-forwarded-for";
        // One proxy: the client's own entries in front are ignored
        assert_eq!(
            client("127.0.0.1", &[(xff, "198.51.100.1, 203.0.113.7")]),
            ip("203.0.113.7")
        );
        // Two proxies: the inner one is skipped
        assert_eq!(
            client("127.0.0.1", &[(xff, "198.51.100.1, 203.0.113.7, 10.0.0.5")]),
            ip("203.0.113.7")
        );
        // Every hop trusted: the left-most one
        assert_eq!(client("127.0.0.1", &[(xff, "10.0.0.2")]), ip("10.0.0.2"));
        // Several header lines read as one list
        assert_eq!(
            client("127.0.0.1", &[(xff, "198.51.100.1"), (xff, "203.0.113.7")]),
            ip("203.0.113.7")
        );
        // An unreadable hop ends the chain at the last address before it
        assert_eq!(
            client("127.0.0.1", &[(xff, "198.51.100.1, junk, 10.0.0.5")]),
            ip("10.0.0.5")
        );
        assert_eq!(client("127.0.0.1", &[(xff, "198.51.100.1, junk")]), None);
        // IPv4-mapped peers and hops count as IPv4
        assert_eq!(
            client("::ffff:127.0.0.1", &[(xff, "::ffff:203.0.113.7")]),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn headers_from_an_untrusted_peer_are_ignored() {
        assert_eq!(
            client("192.0.2.10", &[("x-forwarded-for", "203.0.113.7")]),
            None
        );
        assert_eq!(
            client_fwd("192.0.2.10", &[("forwarded", "for=203.0.113.7")]),
            None
        );
    }

    #[test]
    fn forwarded_header() {
        let fwd = "forwarded";
        assert_eq!(
            client_fwd(
                "127.0.0.1",
                &[(fwd, "for=198.51.100.1, for=203.0.113.7;proto=https")]
            ),
            ip("203.0.113.7")
        );
        assert_eq!(
            client_fwd(
                "127.0.0.1",
                &[(fwd, r#"For="[2001:db8::7]:4711", for=10.0.0.5"#)]
            ),
            ip("2001:db8::7")
        );
        assert_eq!(
            client_fwd("127.0.0.1", &[(fwd, "for=203.0.113.7:8080")]),
            ip("203.0.113.7")
        );
        // An obfuscated hop ends the chain
        assert_eq!(
            client_fwd("127.0.0.1", &[(fwd, "for=_hidden, for=10.0.0.5")]),
            ip("10.0.0.5")
        );
    }

    #[test]
    fn only_the_configured_header_is_read() {
        let fwd = "forwarded";
        let xff = "x-forwarded-for";
        // X-Forwarded-For: a Forwarded header can only be the client's
        assert_eq!(
            client(
                "127.0.0.1",
                &[(fwd, "for=192.0.2.66"), (xff, "203.0.113.7")]
            ),
            ip("203.0.113.7")
        );
        assert_eq!(client("127.0.0.1", &[(fwd, "for=127.0.0.1")]), None);
        // Forwarded: an X-Forwarded-For header can only be the client's
        assert_eq!(
            client_fwd(
                "127.0.0.1",
                &[(xff, "192.0.2.66"), (fwd, "for=203.0.113.7")]
            ),
            ip("203.0.113.7")
        );
        assert_eq!(client_fwd("127.0.0.1", &[(xff, "127.0.0.1")]), None);
        assert_eq!(
            client_fwd("127.0.0.1", &[(fwd, "proto=https"), (xff, "192.0.2.66")]),
            None
        );
    }

    #[test]
    fn loopback_in_a_header_is_the_writer_s() {
        let xff = "x-forwarded-for";
        // A client on the proxy's network can't claim to be this host
        assert_eq!(
            client("127.0.0.1", &[(xff, "127.0.0.1, 10.0.0.9")]),
            ip("10.0.0.9")
        );
        assert_eq!(client("10.0.0.2", &[(xff, "127.0.0.1")]), ip("10.0.0.2"));
        assert_eq!(client("10.0.0.2", &[(xff, "::1")]), ip("10.0.0.2"));
        assert_eq!(
            client("127.0.0.1", &[(xff, "::ffff:127.0.0.1, 10.0.0.9")]),
            ip("10.0.0.9")
        );
        // A public client's claim never got that far anyway
        assert_eq!(
            client("127.0.0.1", &[(xff, "127.0.0.1, 203.0.113.7")]),
            ip("203.0.113.7")
        );
        // Loopback all the way: a client on this host, through a local proxy
        assert_eq!(client("127.0.0.1", &[(xff, "127.0.0.1")]), ip("127.0.0.1"));
        assert_eq!(client("::1", &[(xff, "::1")]), ip("::1"));
        assert_eq!(
            client_fwd("10.0.0.2", &[("forwarded", "for=127.0.0.1")]),
            ip("10.0.0.2")
        );
    }
}
