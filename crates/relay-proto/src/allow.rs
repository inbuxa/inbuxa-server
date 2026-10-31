/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Who may dial the link (RL-33): `linkAllowFrom`, a list of addresses and
//! CIDR ranges. Empty means anyone.

use std::net::IpAddr;

/// The most entries `linkAllowFrom` takes.
pub const MAX_ENTRIES: usize = 64;

/// One entry: an address and how many leading bits of it count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    addr: IpAddr,
    bits: u8,
}

impl Range {
    /// `192.0.2.7`, `192.0.2.0/24`, `2001:db8::/32`. An IPv4 address given
    /// as IPv6 (`::ffff:192.0.2.7`) is taken as the IPv4 one.
    pub fn parse(text: &str) -> Option<Range> {
        let text = text.trim();
        let (addr, bits) = match text.split_once('/') {
            Some((addr, bits)) => (addr, Some(bits)),
            None => (text, None),
        };
        let mut addr = addr.parse::<IpAddr>().ok()?.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            Some(bits) if !bits.is_empty() && bits.bytes().all(|b| b.is_ascii_digit()) => {
                bits.parse::<u8>().ok().filter(|bits| *bits <= max)?
            }
            Some(_) => return None,
            None => max,
        };
        addr = mask(addr, bits);
        Some(Range { addr, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.bits) == self.addr
    }
}

fn mask(addr: IpAddr, bits: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let keep = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            IpAddr::V4((u32::from(v4) & keep).into())
        }
        IpAddr::V6(v6) => {
            let keep = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            IpAddr::V6((u128::from(v6) & keep).into())
        }
    }
}

/// `linkAllowFrom`, parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowList(Vec<Range>);

impl AllowList {
    /// The list, or the first entry that isn't an address or range.
    pub fn parse(entries: &[String]) -> Result<AllowList, String> {
        entries
            .iter()
            .map(|entry| Range::parse(entry).ok_or_else(|| entry.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map(AllowList)
    }

    /// Whether `ip` may dial: always, when the list is empty.
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.0.is_empty() || self.0.iter().any(|range| range.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> AllowList {
        AllowList::parse(&entries.iter().map(|e| e.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn ranges() {
        let allow = list(&["192.0.2.0/24", "198.51.100.7", "2001:db8:1::/48"]);
        assert!(allow.allows(ip("192.0.2.1")));
        assert!(allow.allows(ip("192.0.2.255")));
        assert!(!allow.allows(ip("192.0.3.1")));
        assert!(allow.allows(ip("198.51.100.7")));
        assert!(!allow.allows(ip("198.51.100.8")));
        assert!(allow.allows(ip("2001:db8:1:ffff::1")));
        assert!(!allow.allows(ip("2001:db8:2::1")));
        // An IPv4 client on a [::] listener arrives mapped
        assert!(allow.allows(ip("::ffff:192.0.2.9")));
        assert!(!allow.allows(ip("::ffff:192.0.3.9")));
        // Host bits are ignored, as a range is meant
        assert!(list(&["192.0.2.77/24"]).allows(ip("192.0.2.1")));
        assert!(list(&["::ffff:203.0.113.5"]).allows(ip("203.0.113.5")));
        assert!(list(&["0.0.0.0/0"]).allows(ip("203.0.113.5")));
        assert!(!list(&["0.0.0.0/0"]).allows(ip("2001:db8::1")));
        assert!(list(&["::/0"]).allows(ip("2001:db8::1")));
        assert!(AllowList::default().allows(ip("203.0.113.5")));
    }

    #[test]
    fn refused() {
        for bad in [
            "",
            "example.com",
            "192.0.2.0/33",
            "2001:db8::/129",
            "192.0.2.0/",
            "192.0.2.0/+8",
            "192.0.2.0/24/1",
            "192.0.2",
        ] {
            assert_eq!(
                AllowList::parse(&[bad.to_string()]),
                Err(bad.to_string()),
                "{bad}"
            );
        }
    }
}
