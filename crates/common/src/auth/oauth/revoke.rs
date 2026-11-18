/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: K-S4: revoking OAuth tokens (RFC 7009).
//!
//! Tokens are sealed, not stored, so revoking one means remembering it until
//! it would have expired anyway. Each account keeps one list in the
//! in-memory store, which every node shares. The list is read with the
//! account's access token and cached with it; revoking a token rewrites the
//! list and then drops that cache entry on every node, so the next request
//! anywhere reads the new list.
//!
//! A refresh token is also checked against the store itself when it is
//! redeemed, so a node that was rebuilding its cache entry while the
//! revocation went in can't mint a new access token from it.

use crate::{
    KV_OAUTH_REVOKED, Server, cache::invalidate::CacheInvalidationBuilder, ipc::CacheInvalidation,
};
use std::time::Duration;
use store::{dispatch::lookup::KeyValue, write::now};
use trc::AddContext;
use xxhash_rust::xxh3;

/// How many unexpired revocations one account may hold. Each needs a token
/// of that account that is still valid, so only its owner (or whoever holds
/// its tokens) can fill it, and they expire with the tokens.
pub const MAX_REVOKED_PER_ACCOUNT: usize = 2048;

const LOCK_TRIES: usize = 20;
const LOCK_SECONDS: u64 = 10;

/// What a revoked token is remembered by.
pub fn oauth_token_id(token: &str) -> u128 {
    xxh3::xxh3_128(token.as_bytes())
}

fn list_key(account_id: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(5);
    key.push(b'R');
    key.extend_from_slice(&account_id.to_be_bytes());
    key
}

fn lock_key(account_id: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(5);
    key.push(b'L');
    key.extend_from_slice(&account_id.to_be_bytes());
    key
}

/// One revocation: the token's id and when the token expires, in seconds
/// since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revoked {
    pub id: u128,
    pub expires: u64,
}

/// Parses a stored list, keeping the entries that haven't expired. Lines
/// that don't parse are skipped: a damaged entry can't revoke anything.
pub fn parse_revoked(text: &str, now: u64) -> Vec<Revoked> {
    text.lines()
        .filter_map(|line| {
            let (id, expires) = line.split_once(':')?;
            let id = u128::from_str_radix(id, 16).ok()?;
            let expires = expires.parse::<u64>().ok()?;
            (expires > now).then_some(Revoked { id, expires })
        })
        .collect()
}

pub fn serialize_revoked(list: &[Revoked]) -> String {
    let mut text = String::with_capacity(list.len() * 44);
    for entry in list {
        text.push_str(&format!("{:032x}:{}\n", entry.id, entry.expires));
    }
    text
}

/// The ids of a list, sorted for a binary search.
pub fn revoked_ids(list: &[Revoked]) -> Box<[u128]> {
    let mut ids = list.iter().map(|entry| entry.id).collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids.into_boxed_slice()
}

#[derive(Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    Revoked,
    AlreadyRevoked,
    /// The account already holds [`MAX_REVOKED_PER_ACCOUNT`] revocations.
    Full,
}

impl Server {
    async fn read_revoked(&self, account_id: u32) -> trc::Result<Vec<Revoked>> {
        Ok(self
            .in_memory_store()
            .key_get::<String>(KeyValue::<()>::build_key(
                KV_OAUTH_REVOKED,
                list_key(account_id),
            ))
            .await
            .caused_by(trc::location!())?
            .map(|text| parse_revoked(&text, now()))
            .unwrap_or_default())
    }

    /// This account's revoked tokens, for its cached access token.
    pub async fn revoked_oauth_tokens(&self, account_id: u32) -> trc::Result<Box<[u128]>> {
        self.read_revoked(account_id)
            .await
            .map(|list| revoked_ids(&list))
    }

    /// Whether the store holds this token as revoked, bypassing the cache.
    pub async fn is_oauth_token_revoked_in_store(
        &self,
        account_id: u32,
        token_id: u128,
    ) -> trc::Result<bool> {
        self.read_revoked(account_id)
            .await
            .map(|list| list.iter().any(|entry| entry.id == token_id))
    }

    /// Remembers a token as revoked until `expires` (Unix seconds), then has
    /// every node drop the account's cached access token.
    pub async fn revoke_oauth_token(
        &self,
        account_id: u32,
        token_id: u128,
        expires: u64,
    ) -> trc::Result<RevokeOutcome> {
        let store = self.in_memory_store();
        let lock = lock_key(account_id);

        // One writer per account at a time, so two revocations can't each
        // write a list missing the other's token
        let mut locked = false;
        for _ in 0..LOCK_TRIES {
            if store
                .try_lock(KV_OAUTH_REVOKED, &lock, LOCK_SECONDS)
                .await
                .caused_by(trc::location!())?
            {
                locked = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if !locked {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Timed out waiting to revoke a token")
                .account_id(account_id)
                .caused_by(trc::location!()));
        }

        let result = self
            .revoke_oauth_token_locked(account_id, token_id, expires)
            .await;
        let unlock = store.remove_lock(KV_OAUTH_REVOKED, &lock).await;
        let outcome = result?;
        unlock.caused_by(trc::location!())?;

        if outcome == RevokeOutcome::Revoked {
            let mut changes = CacheInvalidationBuilder::default();
            changes.invalidate(CacheInvalidation::AccessToken(account_id));
            self.invalidate_caches(changes)
                .await
                .caused_by(trc::location!())?;
        }

        Ok(outcome)
    }

    async fn revoke_oauth_token_locked(
        &self,
        account_id: u32,
        token_id: u128,
        expires: u64,
    ) -> trc::Result<RevokeOutcome> {
        let now = now();
        if expires <= now {
            // Expired already: nothing left to refuse
            return Ok(RevokeOutcome::AlreadyRevoked);
        }

        let mut list = self.read_revoked(account_id).await?;
        if list.iter().any(|entry| entry.id == token_id) {
            return Ok(RevokeOutcome::AlreadyRevoked);
        }
        if list.len() >= MAX_REVOKED_PER_ACCOUNT {
            return Ok(RevokeOutcome::Full);
        }
        list.push(Revoked {
            id: token_id,
            expires,
        });

        // The list lives as long as its longest-lived entry
        let ttl = list
            .iter()
            .map(|entry| entry.expires)
            .max()
            .unwrap_or(expires)
            - now;
        self.in_memory_store()
            .key_set(
                KeyValue::with_prefix(
                    KV_OAUTH_REVOKED,
                    list_key(account_id),
                    serialize_revoked(&list).into_bytes(),
                )
                .expires(ttl),
            )
            .await
            .caused_by(trc::location!())?;

        Ok(RevokeOutcome::Revoked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_round_trips_and_drops_expired() {
        let list = vec![
            Revoked {
                id: oauth_token_id("sw1.a"),
                expires: 2_000,
            },
            Revoked {
                id: 7,
                expires: 900,
            },
        ];
        let text = serialize_revoked(&list);
        assert_eq!(parse_revoked(&text, 0), list);
        assert_eq!(parse_revoked(&text, 1_000), vec![list[0]]);
    }

    #[test]
    fn damaged_lines_are_skipped() {
        let text = "zz:10\n00000000000000000000000000000005:abc\n\
                    00000000000000000000000000000006:50\nnot a line\n";
        assert_eq!(parse_revoked(text, 0), vec![Revoked { id: 6, expires: 50 }]);
    }

    #[test]
    fn ids_are_sorted_for_search() {
        let list = [9u128, 3, 9, 1].map(|id| Revoked { id, expires: 10 });
        let ids = revoked_ids(&list);
        assert_eq!(&*ids, &[1, 3, 9]);
        assert!(ids.binary_search(&3).is_ok());
        assert!(ids.binary_search(&4).is_err());
    }

    #[test]
    fn token_ids_differ() {
        assert_ne!(oauth_token_id("sw1.a"), oauth_token_id("sw1.b"));
        assert_eq!(oauth_token_id("sw1.a"), oauth_token_id("sw1.a"));
    }
}
