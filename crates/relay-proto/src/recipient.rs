/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The accepted-recipient set (RL-1, RL-11).
//!
//! The downstream pushes every address it accepts as
//! `HMAC-SHA256(recipientKey, address)`, over the address lowercased and with
//! any sub-address removed, plus per-domain rules. The hashes keep the
//! directory from being read off a seized relay as a list. They don't stop
//! someone holding the key from testing guessed addresses: nothing on the
//! relay could, since the relay has to check real ones.

use crate::b64;
use aws_lc_rs::hmac;
use serde::{Deserialize, Serialize};

pub type RecipientHash = [u8; 32];

/// Domain-wide rules, one per served domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientDomain {
    pub domain: String,
    /// Every address at the domain is accepted.
    #[serde(default)]
    pub catch_all: bool,
    /// `+` for `user+tag@example.com`, or none.
    #[serde(default)]
    pub subaddress_separator: Option<String>,
}

/// One accepted address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipient {
    #[serde(with = "b64")]
    pub hash: RecipientHash,
}

/// Splits `address` into a lowercased local part and domain, or `None` if
/// it isn't an address.
pub fn split(address: &str) -> Option<(String, String)> {
    let (local, domain) = address.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return None;
    }
    let domain = domain.trim_end_matches('.').to_lowercase();
    if domain.is_empty() {
        return None;
    }
    Some((local.to_lowercase(), domain))
}

/// The form an address is hashed in: lowercased, without its sub-address.
pub fn normalize(address: &str, separator: Option<&str>) -> Option<String> {
    let (local, domain) = split(address)?;
    let local = match separator.filter(|s| !s.is_empty()) {
        Some(sep) => match local.split_once(sep) {
            Some((base, _)) if !base.is_empty() => base.to_string(),
            _ => local,
        },
        None => local,
    };
    Some(format!("{local}@{domain}"))
}

/// The hash of an already normalized address.
pub fn hash(key: &[u8; 32], normalized: &str) -> RecipientHash {
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        normalized.as_bytes(),
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// What the relay answers at RCPT (RL-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    Accept,
    /// The domain is served but the address isn't known: `550 5.1.1`.
    UnknownUser,
    /// The domain isn't served: `550 5.7.1`.
    NotServed,
    /// Not an address at all: `501 5.1.3`.
    BadAddress,
}

/// Decides a recipient against the pushed rules. `domain_rules` finds a
/// served domain's rules; `known` says whether a hash is in the set.
pub fn lookup<'a>(
    address: &str,
    key: &[u8; 32],
    domain_rules: impl Fn(&str) -> Option<&'a RecipientDomain>,
    known: impl Fn(&RecipientHash) -> bool,
) -> Lookup {
    let Some((_, domain)) = split(address) else {
        return Lookup::BadAddress;
    };
    let Some(rules) = domain_rules(&domain) else {
        return Lookup::NotServed;
    };
    if rules.catch_all {
        return Lookup::Accept;
    }
    let Some(normalized) = normalize(address, rules.subaddress_separator.as_deref()) else {
        return Lookup::BadAddress;
    };
    // The full local part first: an address may itself contain the separator.
    let full = normalize(address, None).filter(|full| *full != normalized);
    if known(&hash(key, &normalized)) || full.is_some_and(|full| known(&hash(key, &full))) {
        Lookup::Accept
    } else {
        Lookup::UnknownUser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const KEY: [u8; 32] = [5; 32];

    #[test]
    fn normalizes() {
        assert_eq!(
            normalize("John+News@Example.COM.", Some("+")).as_deref(),
            Some("john@example.com")
        );
        assert_eq!(
            normalize("+tag@example.com", Some("+")).as_deref(),
            Some("+tag@example.com")
        );
        assert_eq!(
            normalize("a+b@example.com", None).as_deref(),
            Some("a+b@example.com")
        );
        assert_eq!(normalize("nobody", None), None);
        assert_eq!(normalize("@example.com", None), None);
        assert_eq!(normalize("a@", None), None);
    }

    #[test]
    fn decides() {
        let domains = [
            RecipientDomain {
                domain: "example.com".into(),
                catch_all: false,
                subaddress_separator: Some("+".into()),
            },
            RecipientDomain {
                domain: "example.org".into(),
                catch_all: true,
                subaddress_separator: None,
            },
        ];
        let set: HashSet<RecipientHash> = ["john@example.com", "sales+eu@example.com"]
            .iter()
            .map(|a| hash(&KEY, a))
            .collect();
        let decide = |addr: &str| {
            lookup(
                addr,
                &KEY,
                |d| domains.iter().find(|r| r.domain == d),
                |h| set.contains(h),
            )
        };
        assert_eq!(decide("John@example.com"), Lookup::Accept);
        assert_eq!(decide("john+news@example.com"), Lookup::Accept);
        assert_eq!(decide("sales+eu@example.com"), Lookup::Accept);
        assert_eq!(decide("jane@example.com"), Lookup::UnknownUser);
        assert_eq!(decide("anyone@example.org"), Lookup::Accept);
        assert_eq!(decide("john@example.net"), Lookup::NotServed);
        assert_eq!(decide("john"), Lookup::BadAddress);
    }

    #[test]
    fn hash_depends_on_key() {
        assert_ne!(hash(&KEY, "a@example.com"), hash(&[6; 32], "a@example.com"));
    }
}
