/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use hyper::header::{FORWARDED, HeaderMap, HeaderName};
use registry::schema::enums::ClientIpSource;
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::NonZeroU8,
    str::{FromStr, from_utf8},
};

pub const MAX_FORWARDED_HOPS: u8 = 16;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteIpSource {
    Peer,
    XForwardedFor { hops: NonZeroU8 },
    Forwarded { hops: NonZeroU8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIp {
    Peer,
    Forwarded(IpAddr),
    Missing,
    Invalid,
}

impl RemoteIpSource {
    pub fn new(source: ClientIpSource, hops: u64) -> Self {
        let hops = u8::try_from(hops.clamp(1, u64::from(MAX_FORWARDED_HOPS)))
            .ok()
            .and_then(NonZeroU8::new)
            .unwrap_or(NonZeroU8::MIN);
        match source {
            ClientIpSource::Peer => RemoteIpSource::Peer,
            ClientIpSource::XForwardedFor => RemoteIpSource::XForwardedFor { hops },
            ClientIpSource::Forwarded => RemoteIpSource::Forwarded { hops },
        }
    }

    pub fn is_peer(&self) -> bool {
        matches!(self, RemoteIpSource::Peer)
    }

    pub fn resolve(&self, headers: &HeaderMap) -> ClientIp {
        let node = match self {
            RemoteIpSource::Peer => return ClientIp::Peer,
            RemoteIpSource::XForwardedFor { hops } if headers.contains_key(X_FORWARDED_FOR) => {
                headers
                    .get_all(X_FORWARDED_FOR)
                    .iter()
                    .rev()
                    .flat_map(|value| value.as_bytes().rsplit(|&byte| byte == b','))
                    .map(<[u8]>::trim_ascii)
                    .filter(|entry| !entry.is_empty())
                    .nth(usize::from(hops.get() - 1))
            }
            RemoteIpSource::Forwarded { hops } if headers.contains_key(FORWARDED) => headers
                .get_all(FORWARDED)
                .iter()
                .rev()
                .flat_map(|value| RSplitUnquoted::new(value.as_bytes(), b','))
                .map(<[u8]>::trim_ascii)
                .filter(|element| !element.is_empty())
                .nth(usize::from(hops.get() - 1))
                .and_then(forwarded_for),
            RemoteIpSource::XForwardedFor { .. } | RemoteIpSource::Forwarded { .. } => {
                return ClientIp::Missing;
            }
        };
        node.and_then(parse_node)
            .map_or(ClientIp::Invalid, ClientIp::Forwarded)
    }
}

fn forwarded_for(element: &[u8]) -> Option<&[u8]> {
    let mut node = None;
    for pair in RSplitUnquoted::new(element, b';') {
        let pair = pair.trim_ascii();
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, |&byte| byte == b'=');
        let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
            return None;
        };
        if name.trim_ascii().eq_ignore_ascii_case(b"for")
            && node.replace(value.trim_ascii()).is_some()
        {
            return None;
        }
    }
    node.map(|node: &[u8]| {
        node.strip_prefix(b"\"")
            .and_then(|node| node.strip_suffix(b"\""))
            .unwrap_or(node)
    })
}

fn parse_node(node: &[u8]) -> Option<IpAddr> {
    let node = from_utf8(node).ok()?;
    let ip = IpAddr::from_str(node)
        .ok()
        .or_else(|| SocketAddr::from_str(node).ok().map(|addr| addr.ip()))
        .or_else(|| {
            node.strip_prefix('[')?
                .strip_suffix(']')?
                .parse::<Ipv6Addr>()
                .ok()
                .map(IpAddr::V6)
        })?
        .to_canonical();
    (!is_loopback_claim(ip)).then_some(ip)
}

fn is_loopback_claim(ip: IpAddr) -> bool {
    ip.is_loopback()
        || matches!(ip, IpAddr::V6(ip) if matches!(ip.octets(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, ..]))
}

struct RSplitUnquoted<'x> {
    bytes: Option<&'x [u8]>,
    delimiter: u8,
}

impl<'x> RSplitUnquoted<'x> {
    fn new(bytes: &'x [u8], delimiter: u8) -> Self {
        RSplitUnquoted {
            bytes: Some(bytes),
            delimiter,
        }
    }
}

impl<'x> Iterator for RSplitUnquoted<'x> {
    type Item = &'x [u8];

    fn next(&mut self) -> Option<&'x [u8]> {
        let bytes = self.bytes?;
        let mut in_quotes = false;
        for (pos, &byte) in bytes.iter().enumerate().rev() {
            if byte == b'"' {
                let is_escaped = in_quotes
                    && bytes
                        .get(..pos)
                        .unwrap_or_default()
                        .iter()
                        .rev()
                        .take_while(|&&byte| byte == b'\\')
                        .count()
                        % 2
                        == 1;
                if !is_escaped {
                    in_quotes = !in_quotes;
                }
            } else if byte == self.delimiter && !in_quotes {
                self.bytes = bytes.get(..pos);
                return bytes.get(pos + 1..);
            }
        }
        self.bytes = None;
        Some(bytes)
    }
}

