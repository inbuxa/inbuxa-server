/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: a per-node cache of message blobs, keyed by content hash.
//!
//! Upstream fetches a message's blob from the blob store on every read: the
//! spool blob straight back for delivery, the same message for an IMAP
//! BODYSTRUCTURE and then its BODY[], every outbound retry. On the cluster
//! each of those is a round trip to Garage. The cache holds the blobs this
//! node wrote or read recently, capped in size; only content-hash keys go
//! through it (a hash never changes meaning), so named keys that are
//! rewritten in place never do.
//!
//! `INBUXA_BLOB_CACHE` sets the capacity (`64M` by default, `0` turns it
//! off). A blob above a sixteenth of the capacity is not cached.

use std::sync::Arc;
use types::blob_hash::BLOB_HASH_LEN;
use utils::cache::{Cache, CacheItemWeight};

pub const BLOB_CACHE_ENV: &str = "INBUXA_BLOB_CACHE";
const DEFAULT_CAPACITY: u64 = 64 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BlobKey([u8; BLOB_HASH_LEN]);

impl CacheItemWeight for BlobKey {
    fn weight(&self) -> u64 {
        BLOB_HASH_LEN as u64
    }
}

#[derive(Clone)]
pub struct CachedBlob(Arc<[u8]>);

impl CacheItemWeight for CachedBlob {
    fn weight(&self) -> u64 {
        self.0.len() as u64 + 64
    }
}

pub struct BlobCache {
    cache: Cache<BlobKey, CachedBlob>,
    max_item: u64,
}

impl BlobCache {
    /// The cache the environment asks for, or `None` when it is turned off.
    pub fn from_env() -> Option<Self> {
        let capacity = match std::env::var(BLOB_CACHE_ENV) {
            Ok(value) => parse_size(&value).unwrap_or_else(|| {
                trc::event!(
                    Server(trc::ServerEvent::Startup),
                    Details =
                        format!("{BLOB_CACHE_ENV}={value:?} is not a size; using the default"),
                );
                DEFAULT_CAPACITY
            }),
            Err(_) => DEFAULT_CAPACITY,
        };
        Self::with_capacity(capacity)
    }

    pub fn with_capacity(capacity: u64) -> Option<Self> {
        if capacity < 1024 * 1024 {
            return None;
        }
        let max_item = capacity / 16;
        Some(Self {
            cache: Cache::new(capacity, max_item / 4),
            max_item,
        })
    }

    fn key(hash: &[u8]) -> Option<BlobKey> {
        hash.try_into().ok().map(BlobKey)
    }

    pub fn get(&self, hash: &[u8]) -> Option<Arc<[u8]>> {
        self.cache.get(&Self::key(hash)?).map(|blob| blob.0)
    }

    /// Keeps `data` under its content hash when it fits.
    pub fn insert(&self, hash: &[u8], data: &[u8]) {
        if data.len() as u64 <= self.max_item
            && let Some(key) = Self::key(hash)
        {
            self.cache.insert(key, CachedBlob(Arc::from(data)));
        }
    }

    pub fn capacity(&self) -> u64 {
        self.cache.weight_capacity()
    }
}

/// `64M`, `512K`, `1G` or plain bytes.
fn parse_size(value: &str) -> Option<u64> {
    let value = value.trim();
    let (digits, unit) = value
        .find(|c: char| !c.is_ascii_digit())
        .map(|at| value.split_at(at))
        .unwrap_or((value, ""));
    let number = digits.parse::<u64>().ok()?;
    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        _ => return None,
    };
    number.checked_mul(multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("64M"), Some(64 * 1024 * 1024));
        assert_eq!(parse_size(" 512 KiB "), Some(512 * 1024));
        assert_eq!(parse_size("1g"), Some(1 << 30));
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(parse_size("0"), Some(0));
        assert_eq!(parse_size("lots"), None);
        assert_eq!(parse_size("1t"), None);
    }

    #[test]
    fn off_below_a_megabyte() {
        assert!(BlobCache::with_capacity(0).is_none());
        assert!(BlobCache::with_capacity(1024 * 1024).is_some());
    }

    #[test]
    fn only_hash_keys_and_fitting_blobs() {
        let cache = BlobCache::with_capacity(16 * 1024 * 1024).unwrap();
        let hash = [7u8; BLOB_HASH_LEN];
        cache.insert(&hash, b"hello");
        assert_eq!(cache.get(&hash).as_deref(), Some(&b"hello"[..]));
        cache.insert(b"INBUXA_SPAM_CLASSIFIER_MODEL", b"x");
        assert!(cache.get(b"INBUXA_SPAM_CLASSIFIER_MODEL").is_none());
        let big = vec![0u8; 1024 * 1024 + 1];
        let other = [9u8; BLOB_HASH_LEN];
        cache.insert(&other, &big);
        assert!(
            cache.get(&other).is_none(),
            "above a sixteenth of the capacity"
        );
    }
}
