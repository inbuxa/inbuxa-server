/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Masked addresses: their format, and making sure none is ever issued twice
//! (ME-13).
//!
//! The local part is `{emailPrefix}_{random}` when a prefix is given, else
//! `{random}`, where `{random}` is 12 characters from `a-z0-9`, about 62
//! bits. It never contains a `.`, so a fork-issued address can't be mistaken
//! for an upstream one, whose addresses always do.

use crate::masked_email::data;
use registry::schema::prelude::Property;
use store::{RegistryStore, Store, rand::RngExt as _};

/// The characters `{random}` draws from.
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
/// The length of `{random}`.
const RANDOM_LEN: usize = 12;
/// The longest prefix a client may ask for.
pub const MAX_PREFIX_LEN: usize = 64;
/// Tries before giving up on finding a free address. At 62 bits a single
/// collision is already unlikely; this only guards against a broken RNG.
const MAX_TRIES: usize = 16;

/// Whether `prefix` is a valid `emailPrefix`: 1 to 64 characters from
/// `a-z`, `0-9` and `_`. Anything else is refused `invalidProperties`
/// (acceptance test 7).
pub fn is_valid_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.len() <= MAX_PREFIX_LEN
        && prefix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A local part in the fork's format, with a fresh random part.
pub fn local_part(prefix: Option<&str>) -> String {
    let mut rng = store::rand::rng();
    let random = (0..RANDOM_LEN)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect::<String>();
    match prefix {
        Some(prefix) => format!("{prefix}_{random}"),
        None => random,
    }
}

/// The registry's key for an address, as accounts, aliases and lists index
/// theirs.
fn email_key(local_part: &str, domain_id: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(local_part.len() + 8);
    key.extend_from_slice(local_part.as_bytes());
    key.extend_from_slice(&(domain_id as u64).to_be_bytes());
    key
}

/// Whether an address is taken by anything the server knows: an account, an
/// alias, a list, a mask, or a mask that was destroyed (a tombstone).
pub async fn is_taken(
    data: &Store,
    registry: &RegistryStore,
    local_part: &str,
    domain_id: u32,
    domain_name: &str,
) -> trc::Result<bool> {
    Ok(registry
        .primary_key(None, Property::Email, email_key(local_part, domain_id))
        .await?
        .is_some()
        || data::address(data, &format!("{local_part}@{domain_name}"))
            .await?
            .is_some())
}

/// A new, never-issued address on a domain.
pub async fn generate(
    data: &Store,
    registry: &RegistryStore,
    prefix: Option<&str>,
    domain_id: u32,
    domain_name: &str,
) -> trc::Result<String> {
    for _ in 0..MAX_TRIES {
        let local = local_part(prefix);
        if !is_taken(data, registry, &local, domain_id, domain_name).await? {
            return Ok(format!("{local}@{}", domain_name.to_lowercase()));
        }
    }
    Err(trc::StoreEvent::UnexpectedError
        .into_err()
        .details("No free masked address found")
        .caused_by(trc::location!()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        assert!(is_valid_prefix("shop"));
        assert!(is_valid_prefix("my_shop_2"));
        assert!(!is_valid_prefix("Shop!"), "acceptance test 7");
        assert!(!is_valid_prefix("Shop"));
        assert!(!is_valid_prefix("shop.x"));
        assert!(!is_valid_prefix(""));
        assert!(is_valid_prefix(&"a".repeat(64)));
        assert!(!is_valid_prefix(&"a".repeat(65)));
    }

    #[test]
    fn format() {
        let plain = local_part(None);
        assert_eq!(plain.len(), RANDOM_LEN);
        assert!(plain.bytes().all(|b| ALPHABET.contains(&b)));
        let prefixed = local_part(Some("shop"));
        assert!(prefixed.starts_with("shop_"), "acceptance test 7");
        assert_eq!(prefixed.len(), "shop_".len() + RANDOM_LEN);
        assert!(!prefixed.contains('.'), "never upstream's shape");
        assert_ne!(local_part(None), local_part(None));
    }
}
