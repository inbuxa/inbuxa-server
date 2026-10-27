/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{HttpAuthCache, auth::TokenScope};
use quick_cache::sync::DefaultLifecycle;
use siphasher::sip128::{Hasher128, SipHasher13};
use std::{
    hash::{BuildHasher, Hash, Hasher},
    sync::atomic::{AtomicU64, Ordering},
};
use store::rand;
use utils::cache::{Cache, CacheItemWeight, TtlClock};

pub struct HttpAuthEntries {
    entries: Cache<
        HttpAuthKey,
        HttpAuthCache,
        DefaultLifecycle<HttpAuthKey, HttpAuthCache>,
        HttpAuthKeyHasher,
    >,
    keys: (u64, u64),
    clock: TtlClock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpAuthKey([u64; 2]);

#[derive(Debug, Clone, Copy, Default)]
pub struct HttpAuthKeyHasher(u64);

#[derive(Debug, Default)]
pub struct GrantRevocations(AtomicU64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationEpoch(u64);

impl HttpAuthEntries {
    pub fn new(weight_capacity: u64) -> Self {
        HttpAuthEntries {
            entries: Cache::new_with_hasher(
                weight_capacity,
                (size_of::<HttpAuthKey>() + size_of::<HttpAuthCache>()) as u64,
            )
            .with_name("httpAuth"),
            keys: (rand::random(), rand::random()),
            clock: TtlClock::new(),
        }
    }

    fn key(&self, token: &str) -> HttpAuthKey {
        let mut hasher = SipHasher13::new_with_keys(self.keys.0, self.keys.1);
        hasher.write(token.as_bytes());
        let hash = hasher.finish128();
        HttpAuthKey([hash.h1, hash.h2])
    }

    #[inline]
    pub fn get(&self, token: &str) -> Option<HttpAuthCache> {
        self.entries.get(&self.key(token))
    }

    #[inline]
    pub fn remove(&self, token: &str) {
        self.entries.remove(&self.key(token));
    }

    #[inline]
    pub fn is_live(&self, entry: &HttpAuthCache) -> bool {
        self.clock.is_live(entry.expires)
    }

    #[inline]
    pub fn expires_in(&self, ttl_secs: u64) -> u32 {
        self.clock
            .now()
            .saturating_add(u32::try_from(ttl_secs).unwrap_or(u32::MAX))
    }

    pub fn retain(&self, f: impl Fn(&HttpAuthCache) -> bool) {
        self.entries.inner().retain(|_, entry| f(entry));
    }

    pub fn weight(&self) -> u64 {
        self.entries.weight()
    }

    fn insert(&self, key: HttpAuthKey, entry: HttpAuthCache) {
        self.entries.insert(key, entry);
    }

    fn clear(&self) {
        self.entries.clear();
    }
}

impl GrantRevocations {
    #[inline]
    pub fn epoch(&self) -> RevocationEpoch {
        RevocationEpoch(self.0.load(Ordering::Acquire))
    }

    pub fn insert(
        &self,
        entries: &HttpAuthEntries,
        token: &str,
        entry: HttpAuthCache,
        epoch: RevocationEpoch,
    ) {
        if self.epoch() == epoch {
            let key = entries.key(token);
            entries.insert(key, entry);
            if self.epoch() != epoch {
                entries.entries.remove(&key);
            }
        }
    }

    pub fn evict(&self, entries: &HttpAuthEntries, grant_ids: &[u64]) {
        self.advance();
        entries.retain(|entry| {
            entry
                .token_scope
                .and_then(TokenScope::grant_id)
                .is_none_or(|grant_id| !grant_ids.contains(&grant_id))
        });
    }

    pub fn clear(&self, entries: &HttpAuthEntries) {
        self.advance();
        entries.clear();
    }

    #[inline]
    fn advance(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

impl Hash for HttpAuthKey {
    #[inline(always)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.0[0]);
    }
}

impl Hasher for HttpAuthKeyHasher {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(byte);
        }
    }

    #[inline(always)]
    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

impl BuildHasher for HttpAuthKeyHasher {
    type Hasher = HttpAuthKeyHasher;

    #[inline(always)]
    fn build_hasher(&self) -> Self::Hasher {
        HttpAuthKeyHasher(0)
    }
}

impl CacheItemWeight for HttpAuthKey {
    fn weight(&self) -> u64 {
        size_of::<HttpAuthKey>() as u64
    }
}

