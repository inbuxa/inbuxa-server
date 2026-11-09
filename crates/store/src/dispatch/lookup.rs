/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use registry::schema::structs::Rate;
use std::borrow::Cow;
use trc::AddContext;

#[allow(unused_imports)]
use crate::{
    Deserialize, InMemoryStore, IterateParams, QueryResult, Store, U64_LEN, Value, ValueKey,
    write::{
        BatchBuilder, Operation, ValueClass, ValueOp,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use crate::{
    SerializeInfallible,
    backend::{http::lookup::HttpStoreGet, memory::StaticMemoryStore},
    write::{InMemoryClass, assert::AssertValue},
};

pub struct KeyValue<T> {
    pub key: Vec<u8>,
    pub value: T,
    pub expires: Option<u64>,
}

/// inbuxa: SL-14. A counter with an expiry keeps it in a marker row next to
/// it, which the purge reads to find expired counters. Upstream rewrote the
/// marker on every increment, although the counters that expire (rate limits,
/// upload quotas) are time buckets whose expiry is the end of the bucket and
/// never changes. This remembers, per process, the markers already written,
/// so an increment writes only the counter once its bucket's marker is in the
/// store with an expiry at least as late as the one asked for.
///
/// What this remembers can go stale: another node's maintenance task can
/// delete the bucket, or a node whose clock runs ahead can purge it. That is
/// caught from the increment's result: a counter that comes back equal to
/// the amount added was just created, so if its marker wasn't in the same
/// write it is written right after. A counter is never left without a
/// marker, which would keep it in the store for good.
static COUNTER_MARKERS: std::sync::LazyLock<CounterMarkers> =
    std::sync::LazyLock::new(CounterMarkers::default);

#[derive(Default)]
pub(crate) struct CounterMarkers(parking_lot::Mutex<ahash::AHashMap<Vec<u8>, CounterMarker>>);

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) struct CounterMarker {
    expires_at: u64,
    written: bool,
}

impl CounterMarkers {
    const MAX_ENTRIES: usize = 100_000;

    /// Whether this increment can leave the marker out. When it can't, the
    /// marker is noted as being written.
    pub(crate) fn can_skip(&self, key: &[u8], expires_at: u64, now: u64) -> bool {
        let mut markers = self.0.lock();
        if let Some(marker) = markers.get(key)
            && marker.written
            && marker.expires_at >= expires_at
            && marker.expires_at > now
        {
            return true;
        }
        if markers.len() >= Self::MAX_ENTRIES {
            markers.retain(|_, marker| marker.expires_at > now);
            if markers.len() >= Self::MAX_ENTRIES {
                markers.clear();
            }
        }
        // A marker being written by another increment isn't counted on
        // until its write is in, so this one writes it too
        markers.insert(
            key.to_vec(),
            CounterMarker {
                expires_at,
                written: false,
            },
        );
        false
    }

    pub(crate) fn written(&self, key: &[u8], expires_at: u64) {
        let mut markers = self.0.lock();
        if let Some(marker) = markers.get_mut(key)
            && marker.expires_at <= expires_at
        {
            *marker = CounterMarker {
                expires_at,
                written: true,
            };
        }
    }

    pub(crate) fn forget(&self, key: &[u8]) {
        self.0.lock().remove(key);
    }
}

fn counter_marker_op(key: Vec<u8>, expires_at: u64) -> Operation {
    Operation::Value {
        class: ValueClass::InMemory(InMemoryClass::Key(key)),
        op: ValueOp::Set(
            KeySerializer::new(U64_LEN * 2)
                .write(0u64)
                .write(expires_at)
                .finalize(),
        ),
    }
}

/// inbuxa: SL-14: `counter_incr` for a counter with an expiry whose new value
/// is wanted, writing the marker only when the store may not have it.
async fn counter_incr_marked(store: &Store, kv: KeyValue<i64>) -> trc::Result<i64> {
    let now = now();
    let expires_at = now + kv.expires.unwrap_or_default();
    let skip_marker = COUNTER_MARKERS.can_skip(&kv.key, expires_at, now);

    let mut batch = BatchBuilder::new();
    if !skip_marker {
        batch.any_op(counter_marker_op(kv.key.clone(), expires_at));
    }
    batch.any_op(Operation::Value {
        class: ValueClass::InMemory(InMemoryClass::Counter(kv.key.clone())),
        op: ValueOp::AddAndGet(kv.value),
    });

    let value = match store
        .write(batch.build_all())
        .await
        .and_then(|r| r.last_counter_id())
    {
        Ok(value) => value,
        Err(err) => {
            if !skip_marker {
                COUNTER_MARKERS.forget(&kv.key);
            }
            return Err(err);
        }
    };

    if !skip_marker {
        COUNTER_MARKERS.written(&kv.key, expires_at);
    } else if value == kv.value {
        // The counter was just created without its marker: the bucket was
        // deleted or purged since the marker was written
        let mut batch = BatchBuilder::new();
        batch.any_op(counter_marker_op(kv.key.clone(), expires_at));
        if let Err(err) = store.write(batch.build_all()).await {
            COUNTER_MARKERS.forget(&kv.key);
            return Err(err);
        }
    }

    Ok(value)
}

impl InMemoryStore {
    pub async fn key_set(&self, kv: KeyValue<Vec<u8>>) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => {
                let mut batch = BatchBuilder::new();
                batch.any_op(Operation::Value {
                    class: ValueClass::InMemory(InMemoryClass::Key(kv.key)),
                    op: ValueOp::Set(
                        KeySerializer::new(kv.value.len() + U64_LEN)
                            .write(kv.expires.map_or(u64::MAX, |expires| now() + expires))
                            .write(kv.value.as_slice())
                            .finalize(),
                    ),
                });
                store.write(batch.build_all()).await.map(|_| ())
            }
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                let member = store.member(&kv.key);
                Box::pin(member.key_set(kv)).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_set(&kv.key, &kv.value, kv.expires).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_incr(&self, kv: KeyValue<i64>, return_value: bool) -> trc::Result<i64> {
        match self {
            // inbuxa: SL-10: on SQL a counter keeps its expiry in its own row
            InMemoryStore::Store(store) if kv.expires.is_some() && store.counters_keep_expiry() => {
                let expires_at = now() + kv.expires.unwrap_or_default();
                let mut batch = BatchBuilder::new();
                batch.any_op(Operation::Value {
                    class: ValueClass::InMemory(InMemoryClass::Counter(kv.key)),
                    op: ValueOp::AddAndGetExpiring(kv.value, expires_at),
                });
                store
                    .write(batch.build_all())
                    .await
                    .and_then(|r| r.last_counter_id())
                    .map(|value| if return_value { value } else { 0 })
            }
            // inbuxa: SL-14: a bucketed counter writes its expiry marker once
            InMemoryStore::Store(store) if return_value && kv.value > 0 && kv.expires.is_some() => {
                counter_incr_marked(store, kv).await
            }
            InMemoryStore::Store(store) => {
                let mut batch = BatchBuilder::new();

                if let Some(expires) = kv.expires {
                    batch.any_op(Operation::Value {
                        class: ValueClass::InMemory(InMemoryClass::Key(kv.key.clone())),
                        op: ValueOp::Set(
                            KeySerializer::new(U64_LEN * 2)
                                .write(0u64)
                                .write(now() + expires)
                                .finalize(),
                        ),
                    });
                }

                if return_value {
                    batch.any_op(Operation::Value {
                        class: ValueClass::InMemory(InMemoryClass::Counter(kv.key)),
                        op: ValueOp::AddAndGet(kv.value),
                    });

                    store
                        .write(batch.build_all())
                        .await
                        .and_then(|r| r.last_counter_id())
                } else {
                    batch.any_op(Operation::Value {
                        class: ValueClass::InMemory(InMemoryClass::Counter(kv.key)),
                        op: ValueOp::AtomicAdd(kv.value),
                    });

                    store.write(batch.build_all()).await.map(|_| 0)
                }
            }
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                let member = store.member(&kv.key);
                Box::pin(member.counter_incr(kv, return_value)).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_incr(&kv.key, kv.value, kv.expires).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => {
                let mut batch = BatchBuilder::new();
                batch.any_op(Operation::Value {
                    class: ValueClass::InMemory(InMemoryClass::Key(key.into().into_bytes())),
                    op: ValueOp::Clear,
                });
                store.write(batch.build_all()).await.map(|_| ())
            }
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                let key = key.into().into_bytes();
                Box::pin(store.member(&key).key_delete(key.clone())).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_delete(key.into().as_bytes()).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => {
                let mut batch = BatchBuilder::new();
                batch.any_op(Operation::Value {
                    class: ValueClass::InMemory(InMemoryClass::Counter(key.into().into_bytes())),
                    op: ValueOp::Clear,
                });
                store.write(batch.build_all()).await.map(|_| ())
            }
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                let key = key.into().into_bytes();
                Box::pin(store.member(&key).counter_delete(key.clone())).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_delete(key.into().as_bytes()).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => {
                if prefix.is_empty() {
                    return Ok(());
                }

                let from_range = prefix.to_vec();
                let mut to_range = Vec::with_capacity(prefix.len() + 3);
                to_range.extend_from_slice(prefix);
                to_range.extend_from_slice([u8::MAX, u8::MAX, u8::MAX].as_ref());

                store
                    .delete_range(
                        ValueKey::from(ValueClass::InMemory(InMemoryClass::Counter(
                            from_range.clone(),
                        ))),
                        ValueKey::from(ValueClass::InMemory(InMemoryClass::Counter(
                            to_range.clone(),
                        ))),
                    )
                    .await?;

                store
                    .delete_range(
                        ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(from_range))),
                        ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(to_range))),
                    )
                    .await
            }
            // inbuxa: ST-24: every member
            InMemoryStore::Sharded(store) => {
                for (index, member) in store.members.iter().enumerate() {
                    Box::pin(member.key_delete_prefix(prefix))
                        .await
                        .map_err(|err| err.details(format!("Member {}", index + 1)))?;
                }
                Ok(())
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_delete_prefix(prefix).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_get<T: Deserialize + From<Value<'static>> + std::fmt::Debug + 'static>(
        &self,
        key: impl Into<LookupKey<'_>>,
    ) -> trc::Result<Option<T>> {
        match self {
            InMemoryStore::Store(store) => store
                .get_value::<LookupValue<T>>(ValueKey::from(ValueClass::InMemory(
                    InMemoryClass::Key(key.into().into_bytes()),
                )))
                .await
                .map(|value| value.and_then(|v| v.into())),
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                let key = key.into().into_bytes();
                Box::pin(store.member(&key).key_get::<T>(key.clone())).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_get(key.into().as_bytes()).await,
            InMemoryStore::Static(store) => Ok(match store.as_ref() {
                StaticMemoryStore::Map(map) => map
                    .get(key.into().as_str())
                    .map(|value| T::from(value.clone())),
                StaticMemoryStore::Set(set) => {
                    if set.contains(key.into().as_str()) {
                        Some(T::from(Value::Bool(true)))
                    } else {
                        None
                    }
                }
            }),
            InMemoryStore::Http(store) => {
                Ok(store.get(key.into().as_str()).map(|value| T::from(value)))
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_get(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<i64> {
        match self {
            InMemoryStore::Store(store) => {
                store
                    .get_counter(ValueKey::from(ValueClass::InMemory(
                        InMemoryClass::Counter(key.into().into_bytes()),
                    )))
                    .await
            }
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                let key = key.into().into_bytes();
                Box::pin(store.member(&key).counter_get(key.clone())).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.counter_get(key.into().as_bytes()).await,
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_exists(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<bool> {
        match self {
            InMemoryStore::Store(store) => store
                .get_value::<LookupValue<Empty>>(ValueKey::from(ValueClass::InMemory(
                    InMemoryClass::Key(key.into().into_bytes()),
                )))
                .await
                .map(|value| matches!(value, Some(LookupValue::Value(Empty)))),
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                let key = key.into().into_bytes();
                Box::pin(store.member(&key).key_exists(key.clone())).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_exists(key.into().as_bytes()).await,
            InMemoryStore::Static(store) => Ok(match store.as_ref() {
                StaticMemoryStore::Map(map) => map.get(key.into().as_str()).is_some(),
                StaticMemoryStore::Set(set) => set.contains(key.into().as_str()),
            }),
            InMemoryStore::Http(store) => Ok(store.contains(key.into().as_str())),
        }
        .caused_by(trc::location!())
    }

    pub async fn is_rate_allowed(
        &self,
        prefix: u8,
        key: &[u8],
        rate: &Rate,
        soft_check: bool,
    ) -> trc::Result<Option<u64>> {
        let now = now();
        let period = rate.period.as_secs().max(1);
        let range_start = now / period;
        let range_end = (range_start * period) + period;
        let expires_in = range_end - now;

        let mut bucket = Vec::with_capacity(key.len() + U64_LEN + 1);
        bucket.push(prefix);
        bucket.extend_from_slice(key);
        bucket.extend_from_slice(range_start.to_be_bytes().as_slice());

        let requests = if !soft_check {
            self.counter_incr(KeyValue::new(bucket, 1).expires(expires_in), true)
                .await
                .caused_by(trc::location!())?
        } else {
            self.counter_get(bucket).await.caused_by(trc::location!())? + 1
        };

        if requests <= rate.count as i64 {
            Ok(None)
        } else {
            Ok(Some(expires_in))
        }
    }

    pub async fn try_lock(&self, prefix: u8, key: &[u8], duration: u64) -> trc::Result<bool> {
        match self {
            InMemoryStore::Store(store) => {
                let key = KeyValue::<()>::build_key(prefix, key);
                let lock_expiry = match store
                    .get_value::<u64>(ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(
                        key.clone(),
                    ))))
                    .await
                {
                    Ok(lock_expiry) => lock_expiry,
                    Err(err)
                        if err.matches(trc::EventType::Store(trc::StoreEvent::DataCorruption)) =>
                    {
                        // TODO remove in 1.0
                        let mut batch = BatchBuilder::new();
                        batch.any_op(Operation::Value {
                            class: ValueClass::InMemory(InMemoryClass::Key(key.clone())),
                            op: ValueOp::Clear,
                        });
                        store
                            .write(batch.build_all())
                            .await
                            .caused_by(trc::location!())?;
                        None
                    }
                    Err(err) => {
                        return Err(err
                            .details("Failed to read lock.")
                            .caused_by(trc::location!()));
                    }
                };

                let now = now();
                if lock_expiry.is_some_and(|expiry| expiry > now) {
                    return Ok(false);
                }

                let key: ValueClass = ValueClass::InMemory(InMemoryClass::Key(key));
                let mut batch = BatchBuilder::new();
                batch.assert_value(
                    key.clone(),
                    match lock_expiry {
                        Some(value) => AssertValue::U64(value),
                        None => AssertValue::None,
                    },
                );
                batch.set(key.clone(), (now + duration).serialize());
                match store.write(batch.build_all()).await {
                    Ok(_) => Ok(true),
                    Err(err) if err.is_assertion_failure() => Ok(false),
                    Err(err) => Err(err
                        .details("Failed to lock event.")
                        .caused_by(trc::location!())),
                }
            }
            // inbuxa: ST-23: a lock and its release meet on one member
            InMemoryStore::Sharded(store) => {
                Box::pin(
                    store
                        .member(&KeyValue::<()>::build_key(prefix, key))
                        .try_lock(prefix, key, duration),
                )
                .await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => {
                store
                    .try_lock(&KeyValue::<()>::build_key(prefix, key), duration)
                    .await
            }
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
    }

    /// inbuxa: extends a lock this node holds to `duration` seconds from now.
    /// Returns false when the lock is gone or has expired: it may have been
    /// taken by someone else since, so it is left alone.
    pub async fn renew_lock(&self, prefix: u8, key: &[u8], duration: u64) -> trc::Result<bool> {
        match self {
            InMemoryStore::Store(store) => {
                let key = KeyValue::<()>::build_key(prefix, key);
                let key = ValueClass::InMemory(InMemoryClass::Key(key));
                let Some(lock_expiry) = store
                    .get_value::<u64>(ValueKey::from(key.clone()))
                    .await
                    .caused_by(trc::location!())?
                else {
                    return Ok(false);
                };
                let now = now();
                if lock_expiry <= now {
                    return Ok(false);
                }

                let mut batch = BatchBuilder::new();
                batch.assert_value(key.clone(), AssertValue::U64(lock_expiry));
                batch.set(key, (now + duration).serialize());
                match store.write(batch.build_all()).await {
                    Ok(_) => Ok(true),
                    Err(err) if err.is_assertion_failure() => Ok(false),
                    Err(err) => Err(err
                        .details("Failed to renew lock.")
                        .caused_by(trc::location!())),
                }
            }
            InMemoryStore::Sharded(store) => {
                Box::pin(
                    store
                        .member(&KeyValue::<()>::build_key(prefix, key))
                        .renew_lock(prefix, key, duration),
                )
                .await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => {
                store
                    .renew_lock(&KeyValue::<()>::build_key(prefix, key), duration)
                    .await
            }
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
    }

    pub async fn remove_lock(&self, prefix: u8, key: &[u8]) -> trc::Result<()> {
        self.key_delete(KeyValue::<()>::build_key(prefix, key))
            .await
    }

    pub async fn purge_in_memory_store(&self) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => {
                // Delete expired keys and counters
                let from_key = ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![0u8])));
                let to_key =
                    ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![u8::MAX; 10])));

                let current_time = now();
                let mut expired_keys = Vec::new();
                let mut expired_counters = Vec::new();
                store
                    .iterate(IterateParams::new(from_key, to_key), |key, value| {
                        let expiry = value.deserialize_be_u64(0).caused_by(trc::location!())?;
                        if expiry == 0 {
                            if value
                                .deserialize_be_u64(U64_LEN)
                                .caused_by(trc::location!())?
                                <= current_time
                            {
                                expired_counters.push(key.to_vec());
                            }
                        } else if expiry <= current_time {
                            expired_keys.push(key.to_vec());
                        }
                        Ok(true)
                    })
                    .await
                    .caused_by(trc::location!())?;

                if !expired_keys.is_empty() {
                    let mut batch = BatchBuilder::new();
                    for key in expired_keys {
                        batch.any_op(Operation::Value {
                            class: ValueClass::InMemory(InMemoryClass::Key(key)),
                            op: ValueOp::Clear,
                        });
                        if batch.is_large_batch() {
                            store
                                .write(batch.build_all())
                                .await
                                .caused_by(trc::location!())?;
                            batch = BatchBuilder::new();
                        }
                    }
                    if !batch.is_empty() {
                        store
                            .write(batch.build_all())
                            .await
                            .caused_by(trc::location!())?;
                    }
                }

                // inbuxa: SL-12: counters that keep their own expiry
                store
                    .purge_expired_counters(current_time)
                    .await
                    .caused_by(trc::location!())?;

                if !expired_counters.is_empty() {
                    let mut batch = BatchBuilder::new();
                    for key in expired_counters {
                        batch.any_op(Operation::Value {
                            class: ValueClass::InMemory(InMemoryClass::Counter(key.clone())),
                            op: ValueOp::Clear,
                        });
                        batch.any_op(Operation::Value {
                            class: ValueClass::InMemory(InMemoryClass::Key(key)),
                            op: ValueOp::Clear,
                        });
                        if batch.is_large_batch() {
                            store
                                .write(batch.build_all())
                                .await
                                .caused_by(trc::location!())?;
                            batch = BatchBuilder::new();
                        }
                    }
                    if !batch.is_empty() {
                        store
                            .write(batch.build_all())
                            .await
                            .caused_by(trc::location!())?;
                    }
                }
            }
            // inbuxa: ST-24: every member
            InMemoryStore::Sharded(store) => {
                for (index, member) in store.members.iter().enumerate() {
                    Box::pin(member.purge_in_memory_store())
                        .await
                        .map_err(|err| err.details(format!("Member {}", index + 1)))?;
                }
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(_) => {}
            InMemoryStore::Static(_) | InMemoryStore::Http(_) => {}
        }

        Ok(())
    }

    pub fn is_sql(&self) -> bool {
        match self {
            InMemoryStore::Store(store) => store.is_sql(),
            _ => false,
        }
    }

    pub fn is_redis(&self) -> bool {
        match self {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(_) => true,
            // inbuxa: ST-3: as its members are
            InMemoryStore::Sharded(store) => store.members.iter().all(|m| m.is_redis()),
            InMemoryStore::Static(_) => false,
            _ => false,
        }
    }

    pub fn into_store(self) -> Option<Store> {
        match self {
            InMemoryStore::Store(store) => Some(store),
            _ => None,
        }
    }
}

pub enum LookupKey<'x> {
    String(String),
    StringRef(&'x str),
    Bytes(Vec<u8>),
    BytesRef(&'x [u8]),
}

impl<'x> From<&'x str> for LookupKey<'x> {
    fn from(key: &'x str) -> Self {
        LookupKey::StringRef(key)
    }
}

impl<'x> From<&'x String> for LookupKey<'x> {
    fn from(key: &'x String) -> Self {
        LookupKey::StringRef(key.as_str())
    }
}

impl<'x> From<&'x [u8]> for LookupKey<'x> {
    fn from(key: &'x [u8]) -> Self {
        LookupKey::BytesRef(key)
    }
}

impl<'x> From<Cow<'x, str>> for LookupKey<'x> {
    fn from(key: Cow<'x, str>) -> Self {
        match key {
            Cow::Borrowed(key) => LookupKey::StringRef(key),
            Cow::Owned(key) => LookupKey::String(key),
        }
    }
}

impl From<String> for LookupKey<'static> {
    fn from(key: String) -> Self {
        LookupKey::String(key)
    }
}

impl From<Vec<u8>> for LookupKey<'static> {
    fn from(key: Vec<u8>) -> Self {
        LookupKey::Bytes(key)
    }
}

impl LookupKey<'_> {
    pub fn as_str(&self) -> &str {
        match self {
            LookupKey::String(string) => string,
            LookupKey::StringRef(string) => string,
            LookupKey::Bytes(bytes) => std::str::from_utf8(bytes).unwrap_or_default(),
            LookupKey::BytesRef(bytes) => std::str::from_utf8(bytes).unwrap_or_default(),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            LookupKey::String(string) => string.into_bytes(),
            LookupKey::StringRef(string) => string.as_bytes().to_vec(),
            LookupKey::Bytes(bytes) => bytes,
            LookupKey::BytesRef(bytes) => bytes.to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            LookupKey::String(string) => string.as_bytes(),
            LookupKey::StringRef(string) => string.as_bytes(),
            LookupKey::Bytes(bytes) => bytes.as_slice(),
            LookupKey::BytesRef(bytes) => bytes,
        }
    }
}

impl<T> KeyValue<T> {
    pub fn build_key(prefix: u8, key: impl AsRef<[u8]>) -> Vec<u8> {
        let key_ = key.as_ref();
        let mut key = Vec::with_capacity(key_.len() + 1);
        key.push(prefix);
        key.extend_from_slice(key_);
        key
    }

    pub fn with_prefix(prefix: u8, key: impl AsRef<[u8]>, value: T) -> Self {
        Self {
            key: Self::build_key(prefix, key),
            value,
            expires: None,
        }
    }

    pub fn new(key: impl Into<Vec<u8>>, value: T) -> Self {
        Self {
            key: key.into(),
            value,
            expires: None,
        }
    }

    pub fn expires(mut self, expires: u64) -> Self {
        self.expires = expires.into();
        self
    }

    pub fn expires_opt(mut self, expires: Option<u64>) -> Self {
        self.expires = expires;
        self
    }
}

struct Empty;

enum LookupValue<T> {
    Value(T),
    None,
}

impl<T: Deserialize> Deserialize for LookupValue<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        bytes.deserialize_be_u64(0).and_then(|expires| {
            Ok(if expires > now() {
                LookupValue::Value(
                    T::deserialize(bytes.get(U64_LEN..).unwrap_or_default())
                        .caused_by(trc::location!())?,
                )
            } else {
                LookupValue::None
            })
        })
    }
}

impl Deserialize for Empty {
    fn deserialize(_bytes: &[u8]) -> trc::Result<Self> {
        Ok(Empty)
    }
}

impl<T> From<LookupValue<T>> for Option<T> {
    fn from(value: LookupValue<T>) -> Self {
        match value {
            LookupValue::Value(value) => Some(value),
            LookupValue::None => None,
        }
    }
}

impl From<Value<'static>> for String {
    fn from(value: Value<'static>) -> Self {
        match value {
            Value::Text(string) => string.into_owned(),
            Value::Blob(bytes) => String::from_utf8_lossy(bytes.as_ref()).into_owned(),
            Value::Bool(boolean) => boolean.to_string(),
            Value::Null => String::new(),
            Value::Integer(num) => num.to_string(),
            Value::Float(num) => num.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CounterMarkers;

    #[test]
    fn a_bucket_writes_its_marker_once() {
        let markers = CounterMarkers::default();
        // The first increment writes the marker, and so does any increment
        // made before that write is in
        assert!(!markers.can_skip(b"rate", 160, 100));
        assert!(!markers.can_skip(b"rate", 160, 100));
        markers.written(b"rate", 160);
        // Then the bucket's later increments leave it out
        assert!(markers.can_skip(b"rate", 160, 101));
        assert!(markers.can_skip(b"rate", 159, 130));
        // A later expiry is written
        assert!(!markers.can_skip(b"rate", 161, 130));
        markers.written(b"rate", 161);
        assert!(markers.can_skip(b"rate", 161, 130));
        // An expired marker is written again
        assert!(!markers.can_skip(b"rate", 200, 161));
        // Other keys are their own
        assert!(!markers.can_skip(b"other", 160, 100));
    }

    #[test]
    fn a_failed_write_is_forgotten() {
        let markers = CounterMarkers::default();
        assert!(!markers.can_skip(b"rate", 160, 100));
        markers.forget(b"rate");
        markers.written(b"rate", 160);
        assert!(!markers.can_skip(b"rate", 160, 100));
    }

    #[test]
    fn an_earlier_write_does_not_confirm_a_later_marker() {
        let markers = CounterMarkers::default();
        assert!(!markers.can_skip(b"rate", 160, 100));
        assert!(!markers.can_skip(b"rate", 170, 100));
        // The write for 160 lands first: 170 isn't in the store yet
        markers.written(b"rate", 160);
        assert!(!markers.can_skip(b"rate", 170, 100));
        markers.written(b"rate", 170);
        assert!(markers.can_skip(b"rate", 170, 100));
    }
}
