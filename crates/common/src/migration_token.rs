/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: the run tokens a migration's inbuxa-migrate signs in with
//! (migrations spec, MG-10). A run gets one when it starts and loses it when
//! it ends. It acts as the administrator who started the migration, from
//! this node's loopback only.
//!
//! Tokens are held in this node's memory and nowhere else, not even hashed
//! in the store: the child runs here, so no other node needs them, and a
//! restart ends them along with the runs they were for.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::IpAddr, sync::LazyLock};

/// What a run token starts with, so authentication knows it at a glance.
pub const PREFIX: &str = "MIG_";

/// Whom a run token acts as, and for which migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holder {
    pub account_id: u32,
    pub migration_id: u32,
}

/// By the token's hash: a lookup compares digests, never the token.
static TOKENS: LazyLock<Mutex<HashMap<[u8; 32], Holder>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// A new token for a run of `migration_id`, acting as `account_id`.
pub fn issue(account_id: u32, migration_id: u32) -> String {
    let token = format!(
        "{PREFIX}{}",
        URL_SAFE_NO_PAD.encode(store::rand::random::<[u8; 32]>())
    );
    TOKENS.lock().insert(
        digest(&token),
        Holder {
            account_id,
            migration_id,
        },
    );
    token
}

/// Ends a token; it signs nothing in after this.
pub fn revoke(token: &str) {
    TOKENS.lock().remove(&digest(token));
}

/// Whom `token` acts as, if it's a live run token and the request came
/// from this node's loopback.
pub fn holder(token: &str, remote_ip: IpAddr) -> Option<Holder> {
    if !remote_ip.to_canonical().is_loopback() {
        return None;
    }
    TOKENS.lock().get(&digest(token)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_token_works_from_loopback_until_revoked() {
        let token = issue(7, 3);
        assert!(token.starts_with(PREFIX));
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let expected = Some(Holder {
            account_id: 7,
            migration_id: 3,
        });
        assert_eq!(holder(&token, local), expected);
        assert_eq!(holder(&token, IpAddr::V6(Ipv6Addr::LOCALHOST)), expected);
        assert_eq!(
            holder(&token, "::ffff:127.0.0.1".parse().unwrap()),
            expected
        );
        assert_eq!(holder(&token, "192.0.2.1".parse().unwrap()), None);
        assert_eq!(holder(&format!("{token}x"), local), None);
        revoke(&token);
        assert_eq!(holder(&token, local), None);
    }
}
