/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Public addresses, and an HTTP client that connects only to them.
//!
//! Requests to URLs that someone other than the server administrator chose
//! (a push endpoint, a report address, a tenant's provider) must not reach
//! inside the network. A host name is checked when it resolves, so a redirect
//! or a later re-resolution can't get round it. IP literals don't resolve:
//! callers check those with [`is_global_ip`] before sending.
//!
//! Moved here from `common::network` (is_global_ip) and
//! `common::network::public_only` (the resolver) so the directory crate,
//! which `common` depends on, can use them too.

use reqwest::{
    ClientBuilder,
    dns::{Addrs, Name, Resolve, Resolving},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Connect only to public addresses, and never through a proxy (which would
/// resolve the name itself, out of our sight).
pub fn public_only(builder: ClientBuilder) -> ClientBuilder {
    builder.no_proxy().dns_resolver(PublicResolver)
}

struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|addr| is_global_ip(&addr.ip()))
                .collect::<Vec<_>>();

            if !addrs.is_empty() {
                Ok(Box::new(addrs.into_iter()) as Addrs)
            } else {
                Err(format!("{} has no public address", name.as_str()).into())
            }
        })
    }
}

pub fn is_global_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_ipv4(ip),
        IpAddr::V6(ip) => is_global_ipv6(ip),
    }
}

fn is_global_ipv4(ip: &Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let is_this_network = a == 0;
    let is_shared = a == 100 && (64..128).contains(&b);
    let is_protocol_assignment = a == 192 && b == 0 && c == 0;
    let is_benchmarking = a == 198 && (b & 0xfe) == 18;
    let is_relay_6to4 = a == 192 && b == 88 && c == 99;
    let is_reserved = a >= 240;

    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || is_this_network
        || is_shared
        || is_protocol_assignment
        || is_benchmarking
        || is_relay_6to4
        || is_reserved)
}

fn is_global_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }

    if let Some(ip) = ip.to_ipv4() {
        return is_global_ipv4(&ip);
    }

    let segments = ip.segments();

    if segments[0] == 0x2002 {
        return is_global_ipv4(&Ipv4Addr::from(
            ((segments[1] as u32) << 16) | segments[2] as u32,
        ));
    }

    if segments[0] == 0x0064 && segments[1] == 0xff9b {
        let is_well_known_prefix =
            segments[2] == 0 && segments[3] == 0 && segments[4] == 0 && segments[5] == 0;

        return is_well_known_prefix
            && is_global_ipv4(&Ipv4Addr::from(
                ((segments[6] as u32) << 16) | segments[7] as u32,
            ));
    }

    let is_unique_local = (segments[0] & 0xfe00) == 0xfc00;
    let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
    let is_site_local = (segments[0] & 0xffc0) == 0xfec0;
    let is_discard_only =
        segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0;
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let is_teredo = segments[0] == 0x2001 && segments[1] == 0;
    let is_orchid = segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020;

    !(is_unique_local
        || is_link_local
        || is_site_local
        || is_discard_only
        || is_documentation
        || is_teredo
        || is_orchid)
}
