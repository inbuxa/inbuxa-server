/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The blocklists a node asks about itself (deliverability spec, DL-6), and
//! how to read each one's answer.
//!
//! A list answers with an address in 127.0.0.0/8. Each list says which of
//! those mean "listed" and which mean "I won't answer you": Spamhaus, for
//! one, answers `127.255.255.254` to a query that came through a public
//! resolver. A refusal is never read as a listing (DL-4).

use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Looked up by the reversed address: `2.0.0.127.zen.spamhaus.org`.
    Ip,
    /// Looked up by name: `example.org.dbl.spamhaus.org`.
    Domain,
}

#[derive(Debug, Clone, Copy)]
pub struct BlockList {
    /// What the page and the settings call it.
    pub name: &'static str,
    pub zone: &'static str,
    pub scope: Scope,
    /// Where an administrator looks the address up and asks for removal.
    pub lookup: &'static str,
    /// Something the page says beside the list.
    pub note: Option<&'static str>,
    read: fn(Ipv4Addr) -> Answer,
}

/// What a list's answer means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Listed(&'static str),
    /// The list won't answer this resolver, or not now.
    Refused(&'static str),
    /// A code the list doesn't define: neither listed nor clean.
    Unknown,
}

impl BlockList {
    pub fn read(&self, answer: Ipv4Addr) -> Answer {
        (self.read)(answer)
    }

    /// The name to look up for `subject`, or None when the subject doesn't
    /// suit the list (a domain on an IP list, or an IPv6 address: none of
    /// these lists publish IPv6 zones worth asking).
    pub fn query(&self, subject: &Subject<'_>) -> Option<String> {
        match (self.scope, subject) {
            (Scope::Ip, Subject::Ip(IpAddr::V4(ip))) => {
                let [a, b, c, d] = ip.octets();
                Some(format!("{d}.{c}.{b}.{a}.{}.", self.zone))
            }
            (Scope::Domain, Subject::Domain(domain)) => {
                Some(format!("{}.{}.", domain.trim_end_matches('.'), self.zone))
            }
            _ => None,
        }
    }
}

pub enum Subject<'x> {
    Ip(IpAddr),
    Domain(&'x str),
}

/// Spamhaus' error codes, the same on every Spamhaus zone.
fn spamhaus_refusal(ip: Ipv4Addr) -> Option<Answer> {
    match ip.octets() {
        [127, 255, 255, 252] => Some(Answer::Refused("The query was malformed")),
        [127, 255, 255, 254] => Some(Answer::Refused(
            "Spamhaus doesn't answer public resolvers; use the server's own",
        )),
        [127, 255, 255, 255] => Some(Answer::Refused("Too many queries from this resolver")),
        _ => None,
    }
}

fn zen(ip: Ipv4Addr) -> Answer {
    if let Some(refused) = spamhaus_refusal(ip) {
        return refused;
    }
    match ip.octets() {
        [127, 0, 0, 2] => Answer::Listed("SBL: a known spam source"),
        [127, 0, 0, 3] => Answer::Listed("CSS: sent spam recently"),
        [127, 0, 0, 4..=7] => Answer::Listed("XBL: a compromised or infected host"),
        [127, 0, 0, 9] => Answer::Listed("DROP: a hijacked or criminal network"),
        [127, 0, 0, 10 | 11] => {
            Answer::Listed("PBL: an address that isn't meant to send mail directly")
        }
        _ => Answer::Unknown,
    }
}

fn dbl(ip: Ipv4Addr) -> Answer {
    if let Some(refused) = spamhaus_refusal(ip) {
        return refused;
    }
    match ip.octets() {
        [127, 0, 1, 2] => Answer::Listed("A spam domain"),
        [127, 0, 1, 4] => Answer::Listed("A phishing domain"),
        [127, 0, 1, 5] => Answer::Listed("A malware domain"),
        [127, 0, 1, 6] => Answer::Listed("A botnet controller"),
        [127, 0, 1, 102..=106] => Answer::Listed("A legitimate domain being abused"),
        [127, 0, 1, 255] => Answer::Refused("The query was malformed"),
        _ => Answer::Unknown,
    }
}

/// Most lists answer 127.0.0.2 for "listed" and define nothing else.
fn just_two(ip: Ipv4Addr) -> Answer {
    match ip.octets() {
        [127, 0, 0, 2] => Answer::Listed("Listed"),
        _ => Answer::Unknown,
    }
}

fn surbl(ip: Ipv4Addr) -> Answer {
    match ip.octets() {
        [127, 0, 0, 1] => Answer::Refused("SURBL doesn't answer this resolver"),
        [127, 0, 0, bits] if bits & (8 | 16 | 64 | 128) != 0 => {
            Answer::Listed("Seen in phishing, malware, abuse or cracked sites")
        }
        _ => Answer::Unknown,
    }
}

fn uribl(ip: Ipv4Addr) -> Answer {
    match ip.octets() {
        [127, 0, 0, 1] => Answer::Refused("URIBL doesn't answer public resolvers"),
        [127, 0, 0, bits] if bits & (2 | 8) != 0 => Answer::Listed("Seen in spam"),
        [127, 0, 0, bits] if bits & 4 != 0 => {
            Answer::Listed("Grey: seen in bulk mail some people don't want")
        }
        _ => Answer::Unknown,
    }
}

pub const LISTS: &[BlockList] = &[
    BlockList {
        name: "Spamhaus ZEN",
        zone: "zen.spamhaus.org",
        scope: Scope::Ip,
        lookup: "https://check.spamhaus.org/",
        note: None,
        read: zen,
    },
    BlockList {
        name: "SpamCop",
        zone: "bl.spamcop.net",
        scope: Scope::Ip,
        lookup: "https://www.spamcop.net/bl.shtml",
        note: None,
        read: just_two,
    },
    BlockList {
        name: "Barracuda",
        zone: "b.barracudacentral.org",
        scope: Scope::Ip,
        lookup: "https://www.barracudacentral.org/lookups",
        note: Some(
            "Barracuda answers only resolvers whose address is registered with it (free, at barracudacentral.org/rbl). Until then its lookups can't be checked.",
        ),
        read: just_two,
    },
    BlockList {
        name: "UCEPROTECT level 1",
        zone: "dnsbl-1.uceprotect.net",
        scope: Scope::Ip,
        lookup: "https://www.uceprotect.net/en/rblcheck.php",
        note: None,
        read: just_two,
    },
    BlockList {
        name: "Mailspike",
        zone: "bl.mailspike.net",
        scope: Scope::Ip,
        lookup: "https://mailspike.org/iplookup.html",
        note: None,
        read: just_two,
    },
    BlockList {
        name: "PSBL",
        zone: "psbl.surriel.com",
        scope: Scope::Ip,
        lookup: "https://psbl.org/",
        note: None,
        read: just_two,
    },
    BlockList {
        name: "Spamhaus DBL",
        zone: "dbl.spamhaus.org",
        scope: Scope::Domain,
        lookup: "https://check.spamhaus.org/",
        note: None,
        read: dbl,
    },
    BlockList {
        name: "SURBL",
        zone: "multi.surbl.org",
        scope: Scope::Domain,
        lookup: "https://surbl.org/surbl-analysis",
        note: None,
        read: surbl,
    },
    BlockList {
        name: "URIBL",
        zone: "multi.uribl.com",
        scope: Scope::Domain,
        lookup: "https://admin.uribl.com/",
        note: None,
        read: uribl,
    },
];

pub fn by_name(name: &str) -> Option<&'static BlockList> {
    LISTS.iter().find(|list| list.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn a_refusal_is_not_a_listing() {
        let zen = by_name("Spamhaus ZEN").unwrap();
        assert!(matches!(
            zen.read(ip("127.255.255.254")),
            Answer::Refused(_)
        ));
        assert!(matches!(zen.read(ip("127.0.0.2")), Answer::Listed(_)));
        assert!(matches!(zen.read(ip("127.0.0.10")), Answer::Listed(_)));
        assert_eq!(zen.read(ip("127.0.0.200")), Answer::Unknown);

        let uribl = by_name("URIBL").unwrap();
        assert!(matches!(uribl.read(ip("127.0.0.1")), Answer::Refused(_)));
        assert!(matches!(uribl.read(ip("127.0.0.2")), Answer::Listed(_)));
    }

    #[test]
    fn queries_are_built_per_scope() {
        let zen = by_name("Spamhaus ZEN").unwrap();
        let dbl = by_name("Spamhaus DBL").unwrap();
        let v4 = Subject::Ip("192.0.2.10".parse().unwrap());
        let v6 = Subject::Ip("2001:db8::1".parse().unwrap());
        let domain = Subject::Domain("example.org");
        assert_eq!(
            zen.query(&v4).as_deref(),
            Some("10.2.0.192.zen.spamhaus.org.")
        );
        assert_eq!(zen.query(&v6), None);
        assert_eq!(zen.query(&domain), None);
        assert_eq!(
            dbl.query(&domain).as_deref(),
            Some("example.org.dbl.spamhaus.org.")
        );
        assert_eq!(dbl.query(&v4), None);
    }

    #[test]
    fn names_are_unique() {
        for (i, a) in LISTS.iter().enumerate() {
            assert!(
                LISTS[i + 1..].iter().all(|b| b.name != a.name),
                "{}",
                a.name
            );
        }
    }
}
