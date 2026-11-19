/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: one node at a time sets up the defaults (#436).
//!
//! Every normal start checks what the store is missing (roles, listeners,
//! throttles, spam rules...) and adds it, each as "none of these yet, so
//! insert them". Two nodes starting together on a fresh store both did
//! that at once: one could find some of the default listeners already
//! written by the other, take the store as set up, and come up without the
//! rest (on the lab cluster, every listener but `http`, the last one). The
//! same race could store the default roles twice.
//!
//! So the defaults run under a short lease in the store, taken with a
//! compare-and-swap like the store layout lease. A node that finds it held
//! waits until it's released, or runs out because its holder stopped, and
//! then checks the store itself, which by then has everything.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use store::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    rand::{RngExt, rng},
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue, now},
};
use trc::AddContext;

/// Under `B`, the first boot defaults (store-layout SL-16).
pub const LEASE_KEY: &[u8] = b"Bl";
/// How long a lease lasts unless renewed.
const LEASE_SECONDS: u64 = 60;
const RENEWAL: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(250);

struct Raw(Vec<u8>);

impl Deserialize for Raw {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Raw(bytes.to_vec()))
    }
}

fn lease_class() -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: LEASE_KEY.to_vec(),
    })
}

/// The holder's token, then when the lease runs out.
fn lease_bytes(token: u64, expires: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&token.to_be_bytes());
    bytes.extend_from_slice(&expires.to_be_bytes());
    bytes
}

/// When a stored lease runs out; 0 (long gone) for one that can't be read.
fn expires_of(bytes: &[u8]) -> u64 {
    bytes
        .get(8..16)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

fn hash(bytes: &[u8]) -> AssertValue {
    AssertValue::Hash(store::xxhash_rust::xxh3::xxh3_64(bytes))
}

fn is_assert_failure(err: &trc::Error) -> bool {
    matches!(
        err.as_ref(),
        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
    )
}

/// Replaces `current` (None: no lease) with `new`; false if another node
/// wrote the lease in between.
async fn swap(store: &Store, current: Option<&[u8]>, new: Vec<u8>) -> trc::Result<bool> {
    let mut batch = BatchBuilder::new();
    batch.assert_value(lease_class(), current.map_or(AssertValue::None, hash));
    batch.set(lease_class(), new);
    match store.write(batch.build_all()).await {
        Ok(_) => Ok(true),
        Err(err) if is_assert_failure(&err) => Ok(false),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

pub struct DefaultsLease {
    bytes: Arc<Mutex<Vec<u8>>>,
    renewal: tokio::task::JoinHandle<()>,
}

impl DefaultsLease {
    /// Waits for the lease and takes it.
    pub async fn take(store: &Store) -> trc::Result<Self> {
        let token: u64 = rng().random();
        loop {
            let current = store
                .get_value::<Raw>(ValueKey::from(lease_class()))
                .await
                .caused_by(trc::location!())?
                .map(|Raw(bytes)| bytes);
            let free = current
                .as_deref()
                .is_none_or(|bytes| expires_of(bytes) <= now());
            if free {
                let new = lease_bytes(token, now() + LEASE_SECONDS);
                if swap(store, current.as_deref(), new.clone()).await? {
                    return Ok(Self::held(store, token, new));
                }
            }
            tokio::time::sleep(POLL).await;
        }
    }

    fn held(store: &Store, token: u64, bytes: Vec<u8>) -> Self {
        let bytes = Arc::new(Mutex::new(bytes));
        let renewal = {
            let (store, bytes) = (store.clone(), bytes.clone());
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(RENEWAL).await;
                    let current = bytes.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    let new = lease_bytes(token, now() + LEASE_SECONDS);
                    match swap(&store, Some(&current), new.clone()).await {
                        Ok(true) => *bytes.lock().unwrap_or_else(|e| e.into_inner()) = new,
                        // Taken over after it ran out: nothing left to renew
                        Ok(false) => return,
                        Err(err) => {
                            trc::error!(err.details("Failed to renew the defaults lease"));
                        }
                    }
                }
            })
        };
        DefaultsLease { bytes, renewal }
    }

    pub async fn release(self, store: &Store) {
        self.renewal.abort();
        let current = self.bytes.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut batch = BatchBuilder::new();
        batch.assert_value(lease_class(), hash(&current));
        batch.clear(lease_class());
        if let Err(err) = store.write(batch.build_all()).await
            && !is_assert_failure(&err)
        {
            // It runs out on its own
            trc::error!(err.details("Failed to release the defaults lease"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lease_says_when_it_runs_out() {
        let bytes = lease_bytes(7, 1_234);
        assert_eq!(bytes.len(), 16);
        assert_eq!(expires_of(&bytes), 1_234);
        // A value that can't be read counts as run out
        assert_eq!(expires_of(b"short"), 0);
    }
}
