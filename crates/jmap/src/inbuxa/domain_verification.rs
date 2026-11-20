/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! MT-24: a tenant proves it owns the domain names it adds.
//!
//! A domain name or alias a tenant administrator adds is saved as unverified.
//! An unverified name receives no mail, gives no addresses to send as and
//! signs nothing (see `DomainCache::serves`), so a tenant can't take mail
//! meant for a name it doesn't own. The tenant proves a name by publishing a
//! TXT record at `_inbuxa-verification.<name>` with
//! `inbuxa-verification=<token>`, the domain's `verificationToken`, then
//! taking the name off `unverifiedNames`: the save looks the record up and
//! is refused if it isn't there. Names a server administrator adds are
//! trusted, and a server administrator can clear or add entries freely.

use common::{Server, auth::AccessToken};
use jmap_proto::error::set::SetError;
use rand::{RngExt, distr::Alphanumeric};
use registry::schema::{prelude::Property, structs::Domain};

/// The TXT record's owner name, without the trailing dot.
pub fn record_name(name: &str) -> String {
    format!("_inbuxa-verification.{name}")
}

/// What the TXT record must contain.
pub fn record_value(token: &str) -> String {
    format!("inbuxa-verification={token}")
}

fn new_token() -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn names(domain: &Domain) -> impl Iterator<Item = &String> {
    std::iter::once(&domain.name).chain(domain.aliases.iter())
}

/// Applies MT-24 to a domain about to be saved: names the domain no longer
/// has are forgotten, names a tenant adds start unverified, and names a
/// tenant takes off the list must be proven in DNS now.
pub async fn check(
    server: &Server,
    access_token: &AccessToken,
    domain: &mut Domain,
    old: Option<&Domain>,
) -> trc::Result<Result<(), SetError<Property>>> {
    let current = names(domain).cloned().collect::<Vec<_>>();
    domain
        .unverified_names
        .inner_mut()
        .retain(|name| current.contains(name));

    if access_token.tenant_id().is_some() {
        let before = old.map(|old| names(old).collect::<Vec<_>>());
        for name in &current {
            if before.as_ref().is_none_or(|before| !before.contains(&name))
                && !domain.unverified_names.contains(name)
            {
                domain.unverified_names.push(name.clone());
            }
        }

        if let Some(old) = old {
            let to_prove = old
                .unverified_names
                .iter()
                .filter(|name| current.contains(name) && !domain.unverified_names.contains(name))
                .collect::<Vec<_>>();
            if !to_prove.is_empty() {
                let Some(token) = old.verification_token.as_deref() else {
                    return Ok(Err(unproven(to_prove[0], None)));
                };
                for name in to_prove {
                    if !proven(server, name, token).await {
                        return Ok(Err(unproven(name, Some(token))));
                    }
                }
            }
        }
    }

    if !domain.unverified_names.is_empty() && domain.verification_token.is_none() {
        domain.verification_token = Some(new_token());
    }
    Ok(Ok(()))
}

/// Records the system tests publish, as they have no DNS of their own.
#[cfg(feature = "test_mode")]
pub static TEST_RECORDS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, String>>,
> = std::sync::LazyLock::new(Default::default);

/// Whether `name`'s verification record carries `token`.
async fn proven(server: &Server, name: &str, token: &str) -> bool {
    let expected = record_value(token);
    #[cfg(feature = "test_mode")]
    if let Some(found) = TEST_RECORDS.lock().unwrap().get(&record_name(name)) {
        return record_matches(found.as_bytes(), &expected);
    }
    match server
        .core
        .smtp
        .resolvers
        .dns
        .txt_raw_lookup(format!("{}.", record_name(name)))
        .await
    {
        Ok(found) => record_matches(&found, &expected),
        Err(_) => false,
    }
}

/// The record's text holds the expected value as a whole word.
fn record_matches(found: &[u8], expected: &str) -> bool {
    std::str::from_utf8(found).is_ok_and(|text| {
        text.split(|c: char| c.is_whitespace() || c == '"')
            .any(|part| part == expected)
    })
}

fn unproven(name: &str, token: Option<&str>) -> SetError<Property> {
    SetError::invalid_properties()
        .with_property(Property::UnverifiedNames)
        .with_description(match token {
            Some(token) => format!(
                "{name} isn't proven yet. Publish a TXT record at {} with the value {}, \
                 then try again. DNS changes can take a few minutes to appear.",
                record_name(name),
                record_value(token),
            ),
            None => format!("{name} has no verification token to check against."),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_must_hold_the_whole_value() {
        let expected = record_value("abc123");
        assert!(record_matches(b"inbuxa-verification=abc123", &expected));
        assert!(record_matches(
            b"v=spf1 -all inbuxa-verification=abc123",
            &expected
        ));
        assert!(record_matches(b"\"inbuxa-verification=abc123\"", &expected));
        assert!(!record_matches(b"inbuxa-verification=abc1234", &expected));
        assert!(!record_matches(b"xinbuxa-verification=abc123", &expected));
        assert!(!record_matches(b"", &expected));
    }

    #[test]
    fn names_and_values() {
        assert_eq!(
            record_name("example.org"),
            "_inbuxa-verification.example.org"
        );
        assert_eq!(record_value("t"), "inbuxa-verification=t");
        assert_eq!(new_token().len(), 32);
    }
}
