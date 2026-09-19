/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Scale-out storage (`docs/spec/features/scale-out-storage.md`): sharded
//! blob stores (ST-16 to ST-22) and sharded in-memory and lookup stores
//! (ST-23 to ST-29). Each is one more variant of the store enums, whose
//! members are ordinary stores.

pub mod blob;
pub mod layout;
pub mod memory;
pub mod replica;
pub mod replica_health;

/// Calls a PostgreSQL or MySQL backend directly. Replicated stores use it
/// instead of going back through `Store`, whose futures would then contain
/// themselves.
#[macro_export]
#[doc(hidden)]
macro_rules! sql_backend {
    ($store:expr, $backend:ident => $call:expr) => {
        match $store {
            #[cfg(feature = "postgres")]
            $crate::Store::PostgreSQL($backend) => $call,
            #[cfg(feature = "mysql")]
            $crate::Store::MySQL($backend) => $call,
            _ => Err(trc::StoreEvent::NotConfigured
                .into_err()
                .details("A replicated store's member isn't PostgreSQL or MySQL")),
        }
    };
}

pub use blob::ShardedBlobStore;
pub use memory::ShardedInMemoryStore;

/// A key's home: `xxh3_64(key) mod N`, seed 0, over the whole key (ST-16).
/// Fixed forever once shipped.
pub fn home(key: &[u8], members: usize) -> usize {
    (xxhash_rust::xxh3::xxh3_64(key) % members.max(1) as u64) as usize
}

/// A URL without its user information, for records and logs.
pub fn without_credentials(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let rest = match rest.split_once('/') {
                Some((authority, path)) => {
                    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
                    format!("{host}/{path}")
                }
                None => rest.rsplit_once('@').map_or(rest, |(_, h)| h).to_string(),
            };
            format!("{scheme}://{rest}")
        }
        None => url.rsplit_once('@').map_or(url, |(_, h)| h).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_and_hides_credentials() {
        // Stable placement: these values must never change (ST-16)
        assert_eq!(home(b"", 3), (xxhash_rust::xxh3::xxh3_64(b"") % 3) as usize);
        let spread = (0u32..3000)
            .map(|n| home(&n.to_be_bytes(), 3))
            .fold([0; 3], |mut acc, h| {
                acc[h] += 1;
                acc
            });
        assert!(spread.iter().all(|n| *n > 800), "{spread:?}");

        assert_eq!(
            without_credentials("redis://user:secret@host:6379/0"),
            "redis://host:6379/0"
        );
        assert_eq!(without_credentials("rediss://:pw@host"), "rediss://host");
        assert_eq!(
            without_credentials("redis://host:6379"),
            "redis://host:6379"
        );
    }
}
