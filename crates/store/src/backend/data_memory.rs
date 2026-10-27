/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The in-memory store kept in the data store. 0.16 had it as the default
//! in-memory store; 1.0 dropped it and asks clusters for Redis instead. A
//! cluster on a shared data store needs nothing more than that store.
//!
//! Layout:
//! - `Subspace::InMemoryValue`: key -> expiry (u64 BE, `NEVER` for none)
//!   followed by the payload. Locks have an empty payload, leases the
//!   owner's token (u64 BE). A counter's expiry is kept here too, as
//!   `COUNTER_MARK` followed by the expiry.
//! - `Subspace::InMemoryCounter`: key -> counter.
//!
//! Expired entries read as absent; `purge` removes them.

use crate::{
    Deserialize, IterateParams, Store, Subspace, U64_LEN, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue, serialize::RawValue},
};
use trc::AddContext;

const NEVER: u64 = u64::MAX;
const COUNTER_MARK: u64 = 0;

fn value_class(key: impl Into<Vec<u8>>) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: Subspace::InMemoryValue,
        key: key.into(),
    })
}

fn counter_class(key: impl Into<Vec<u8>>) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: Subspace::InMemoryCounter,
        key: key.into(),
    })
}

fn expiry_at(now: u64, ttl: u64) -> u64 {
    now.saturating_add(ttl).min(NEVER - 1)
}

fn encode(expires: u64, payload: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(U64_LEN + payload.len());
    value.extend_from_slice(&expires.to_be_bytes());
    value.extend_from_slice(payload);
    value
}

enum Entry {
    Value { expires: u64, payload: Vec<u8> },
    Counter { expires: u64 },
}

impl Entry {
    fn decode(bytes: &[u8]) -> trc::Result<Self> {
        let expires = bytes
            .get(..U64_LEN)
            .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
            .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?;
        let payload = &bytes[U64_LEN..];
        if expires == COUNTER_MARK {
            let expires = payload
                .get(..U64_LEN)
                .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
                .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?;
            Ok(Entry::Counter { expires })
        } else {
            Ok(Entry::Value {
                expires,
                payload: payload.to_vec(),
            })
        }
    }

    fn expires(&self) -> u64 {
        match self {
            Entry::Value { expires, .. } | Entry::Counter { expires } => *expires,
        }
    }

    fn is_live(&self, now: u64) -> bool {
        self.expires() > now
    }
}

impl Store {
    async fn in_memory_read(&self, key: &[u8]) -> trc::Result<Option<(Vec<u8>, Entry)>> {
        match self
            .get_value::<RawValue>(ValueKey::from(value_class(key)))
            .await?
        {
            Some(RawValue(raw)) => match Entry::decode(&raw) {
                Ok(entry) => Ok(Some((raw, entry))),
                // An unreadable entry is cleared rather than kept forever
                Err(_) => {
                    let mut batch = BatchBuilder::new();
                    batch.clear(value_class(key));
                    self.write_batch(&mut batch).await?;
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    pub(crate) async fn in_memory_set(
        &self,
        key: Vec<u8>,
        value: &[u8],
        expires: Option<u64>,
        now: u64,
    ) -> trc::Result<()> {
        let expires = expires.map_or(NEVER, |ttl| expiry_at(now, ttl));
        let mut batch = BatchBuilder::new();
        batch.set(value_class(key), encode(expires, value));
        self.write_batch(&mut batch).await.map(|_| ())
    }

    pub(crate) async fn in_memory_incr(
        &self,
        key: Vec<u8>,
        delta: i64,
        expires: Option<u64>,
        now: u64,
    ) -> trc::Result<i64> {
        let mut batch = BatchBuilder::new();

        // An expired counter starts over, as it would in memory
        if let Some((raw, Entry::Counter { expires })) = self.in_memory_read(&key).await?
            && expires <= now
        {
            batch
                .assert_value(
                    value_class(key.clone()),
                    AssertValue::Hash(xxhash_rust::xxh3::xxh3_64(&raw)),
                )
                .clear(value_class(key.clone()))
                .clear(counter_class(key.clone()));
            match self.write_batch(&mut batch).await {
                Ok(_) => {}
                Err(err) if err.is_assertion_failure() => {}
                Err(err) => return Err(err),
            }
            batch = BatchBuilder::new();
        }

        if let Some(ttl) = expires {
            let mut mark = Vec::with_capacity(U64_LEN * 2);
            mark.extend_from_slice(&COUNTER_MARK.to_be_bytes());
            mark.extend_from_slice(&expiry_at(now, ttl).to_be_bytes());
            batch.set(value_class(key.clone()), mark);
        }
        batch.add_and_get(counter_class(key), delta);
        self.write_batch(&mut batch)
            .await
            .map(|ids| ids.last_counter_id())
    }

    pub(crate) async fn in_memory_get<T: Deserialize>(
        &self,
        key: &[u8],
        now: u64,
    ) -> trc::Result<Option<T>> {
        match self.in_memory_read(key).await? {
            Some((_, Entry::Value { expires, payload })) if expires > now => {
                T::deserialize(&payload).map(Some)
            }
            _ => Ok(None),
        }
    }

    pub(crate) async fn in_memory_exists(&self, key: &[u8], now: u64) -> trc::Result<bool> {
        Ok(self
            .in_memory_read(key)
            .await?
            .is_some_and(|(_, entry)| entry.is_live(now)))
    }

    pub(crate) async fn in_memory_delete(&self, key: &[u8], now: u64) -> trc::Result<bool> {
        let was_live = self
            .in_memory_read(key)
            .await?
            .is_some_and(|(_, entry)| entry.is_live(now));
        let mut batch = BatchBuilder::new();
        batch.clear(value_class(key)).clear(counter_class(key));
        self.write_batch(&mut batch).await.map(|_| was_live)
    }

    pub(crate) async fn in_memory_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        if prefix.is_empty() {
            return Ok(());
        }

        let from = prefix.to_vec();
        let mut to = Vec::with_capacity(prefix.len() + 3);
        to.extend_from_slice(prefix);
        to.extend_from_slice(&[u8::MAX, u8::MAX, u8::MAX]);

        self.delete_range(
            ValueKey::from(counter_class(from.clone())),
            ValueKey::from(counter_class(to.clone())),
        )
        .await?;
        self.delete_range(
            ValueKey::from(value_class(from)),
            ValueKey::from(value_class(to)),
        )
        .await
    }

    /// Writes `payload` under `key` unless a live entry is there.
    pub(crate) async fn in_memory_try_insert(
        &self,
        key: Vec<u8>,
        payload: &[u8],
        duration: u64,
        now: u64,
    ) -> trc::Result<bool> {
        let current = self.in_memory_read(&key).await?;
        if current
            .as_ref()
            .is_some_and(|(_, entry)| entry.is_live(now))
        {
            return Ok(false);
        }

        let mut batch = BatchBuilder::new();
        batch.assert_value(
            value_class(key.clone()),
            match &current {
                Some((raw, _)) => AssertValue::Hash(xxhash_rust::xxh3::xxh3_64(raw)),
                None => AssertValue::None,
            },
        );
        if let Some((_, Entry::Counter { .. })) = current {
            batch.clear(counter_class(key.clone()));
        }
        batch.set(value_class(key), encode(expiry_at(now, duration), payload));
        match self.write_batch(&mut batch).await {
            Ok(_) => Ok(true),
            Err(err) if err.is_assertion_failure() => Ok(false),
            Err(err) => Err(err.details("Failed to lock.").caused_by(trc::location!())),
        }
    }

    pub(crate) async fn in_memory_renew_lock(
        &self,
        key: Vec<u8>,
        duration: u64,
        now: u64,
    ) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        batch.set(value_class(key), encode(expiry_at(now, duration), &[]));
        self.write_batch(&mut batch).await.map(|_| ())
    }

    /// Replaces a live lease held by `token`; false when another owns it.
    async fn in_memory_lease_swap(
        &self,
        key: Vec<u8>,
        token: u64,
        new_value: Option<Vec<u8>>,
        now: Option<u64>,
    ) -> trc::Result<bool> {
        let Some((raw, Entry::Value { expires, payload })) = self.in_memory_read(&key).await?
        else {
            return Ok(false);
        };
        if payload != token.to_be_bytes() || now.is_some_and(|now| expires <= now) {
            return Ok(false);
        }

        let mut batch = BatchBuilder::new();
        batch.assert_value(
            value_class(key.clone()),
            AssertValue::Hash(xxhash_rust::xxh3::xxh3_64(&raw)),
        );
        match new_value {
            Some(value) => batch.set(value_class(key), value),
            None => batch.clear(value_class(key)),
        };
        match self.write_batch(&mut batch).await {
            Ok(_) => Ok(true),
            Err(err) if err.is_assertion_failure() => Ok(false),
            Err(err) => Err(err.caused_by(trc::location!())),
        }
    }

    pub(crate) async fn in_memory_renew_lease(
        &self,
        key: Vec<u8>,
        token: u64,
        duration: u64,
        now: u64,
    ) -> trc::Result<bool> {
        self.in_memory_lease_swap(
            key,
            token,
            Some(encode(expiry_at(now, duration), &token.to_be_bytes())),
            Some(now),
        )
        .await
    }

    pub(crate) async fn in_memory_release_lease(
        &self,
        key: Vec<u8>,
        token: u64,
    ) -> trc::Result<bool> {
        self.in_memory_lease_swap(key, token, None, None).await
    }

    /// Removes expired keys, locks, leases and counters.
    pub async fn purge_in_memory(&self, now: u64) -> trc::Result<()> {
        let mut expired = Vec::new();
        self.iterate(
            IterateParams::new(
                ValueKey::from(value_class(vec![0u8])),
                ValueKey::from(value_class(vec![u8::MAX; 10])),
            ),
            |key, value| {
                if Entry::decode(value).is_ok_and(|entry| !entry.is_live(now)) {
                    expired.push(key.to_vec());
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        let mut batch = BatchBuilder::new();
        for key in expired {
            batch
                .clear(counter_class(key.clone()))
                .clear(value_class(key));
            if batch.is_large_batch() {
                self.write_batch(&mut batch)
                    .await
                    .caused_by(trc::location!())?;
                batch = BatchBuilder::new();
            }
        }
        if !batch.is_empty() {
            self.write_batch(&mut batch)
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }
}
