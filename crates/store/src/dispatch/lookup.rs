/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    Deserialize, InMemoryStore, Store, U64_LEN, Value,
    backend::{http::lookup::HttpStoreGet, memory::StaticMemoryStore},
    write::now,
};
use registry::schema::structs::Rate;
use std::borrow::Cow;
use trc::AddContext;

// inbuxa: the data store may itself use the in-memory store (read replicas
// share their marks through it), so the `Store` arms box their futures to
// keep the types finite.

pub struct KeyValue<T> {
    pub key: Vec<u8>,
    pub value: T,
    pub expires: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateWindow {
    pub index: u64,
    pub expires_in: u64,
}

impl RateWindow {
    pub fn new(rate: &Rate, now: u64) -> Self {
        let period = rate.period.as_secs().max(1);
        RateWindow {
            index: now / period,
            expires_in: period - now % period,
        }
    }

    pub fn bucket(&self, prefix: u8, key: &[u8]) -> Vec<u8> {
        let mut bucket = Vec::with_capacity(key.len() + U64_LEN + 1);
        bucket.push(prefix);
        bucket.extend_from_slice(key);
        bucket.extend_from_slice(&self.index.to_be_bytes());
        bucket
    }
}

impl InMemoryStore {
    pub async fn key_set(&self, kv: KeyValue<Vec<u8>>) -> trc::Result<()> {

        match self {
            InMemoryStore::Local(store) => store.key_set(kv.key, kv.value, kv.expires, now()),
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => {
                Box::pin(store.in_memory_set(kv.key, &kv.value, kv.expires, now())).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_set(&kv.key, &kv.value, kv.expires).await,
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                let member = store.member(&kv.key);
                Box::pin(member.key_set(kv)).await
            }
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_incr(&self, kv: KeyValue<i64>) -> trc::Result<i64> {
        self.key_incr_at(kv, now()).await
    }

    async fn key_incr_at(&self, kv: KeyValue<i64>, now: u64) -> trc::Result<i64> {

        match self {
            InMemoryStore::Local(store) => store.key_incr(kv.key, kv.value, kv.expires, now),
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => {
                Box::pin(store.in_memory_incr(kv.key, kv.value, kv.expires, now)).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_incr(&kv.key, kv.value, kv.expires).await,
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                let member = store.member(&kv.key);
                Box::pin(member.key_incr_at(kv, now)).await
            }
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<bool> {

        match self {
            InMemoryStore::Local(store) => Ok(store.key_delete(key.into().as_bytes(), now())),
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => {
                Box::pin(store.in_memory_delete(key.into().as_bytes(), now())).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_delete(key.into().as_bytes()).await,
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                // an owned key, so the recursion is one type
                let key = key.into().as_bytes().to_vec();
                Box::pin(store.member(&key).key_delete(key.clone())).await
            }
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn counter_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<()> {

        match self {
            InMemoryStore::Local(store) => {
                store.key_delete(key.into().as_bytes(), now());
                Ok(())
            }
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => {
                Box::pin(store.in_memory_delete(key.into().as_bytes(), now()))
                    .await
                    .map(|_| ())
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => {
                store.key_delete(key.into().as_bytes()).await.map(|_| ())
            }
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                // an owned key, so the recursion is one type
                let key = key.into().as_bytes().to_vec();
                Box::pin(store.member(&key).counter_delete(key.clone())).await
            }
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
        .caused_by(trc::location!())
    }

    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {

        match self {
            InMemoryStore::Local(store) => {
                store.key_delete_prefix(prefix);
                Ok(())
            }
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => Box::pin(store.in_memory_delete_prefix(prefix)).await,
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_delete_prefix(prefix).await,
            // inbuxa: ST-24: every member
            InMemoryStore::Sharded(store) => {
                for (index, member) in store.members.iter().enumerate() {
                    Box::pin(member.key_delete_prefix(prefix))
                        .await
                        .map_err(|err| err.details(format!("Member {}", index + 1)))?;
                }
                Ok(())
            }
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
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
            InMemoryStore::Local(store) => store.key_get(key.into().as_bytes(), now()),
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => {
                Box::pin(store.in_memory_get(key.into().as_bytes(), now())).await
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
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                // an owned key, so the recursion is one type
                let key = key.into().as_bytes().to_vec();
                Box::pin(store.member(&key).key_get::<T>(key.clone())).await
            }
            InMemoryStore::Sql(_) => Err(trc::StoreEvent::NotSupported.into_err()),
        }
        .caused_by(trc::location!())
    }

    pub async fn key_exists(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<bool> {

        match self {
            InMemoryStore::Local(store) => Ok(store.key_exists(key.into().as_bytes(), now())),
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => {
                Box::pin(store.in_memory_exists(key.into().as_bytes(), now())).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.key_exists(key.into().as_bytes()).await,
            InMemoryStore::Static(store) => Ok(match store.as_ref() {
                StaticMemoryStore::Map(map) => map.get(key.into().as_str()).is_some(),
                StaticMemoryStore::Set(set) => set.contains(key.into().as_str()),
            }),
            InMemoryStore::Http(store) => Ok(store.contains(key.into().as_str())),
            // inbuxa: ST-23
            InMemoryStore::Sharded(store) => {
                // an owned key, so the recursion is one type
                let key = key.into().as_bytes().to_vec();
                Box::pin(store.member(&key).key_exists(key.clone())).await
            }
            InMemoryStore::Sql(_) => Err(trc::StoreEvent::NotSupported.into_err()),
        }
        .caused_by(trc::location!())
    }

    pub async fn is_rate_allowed(
        &self,
        prefix: u8,
        key: &[u8],
        rate: &Rate,
    ) -> trc::Result<Option<u64>> {
        let now = now();
        let window = RateWindow::new(rate, now);

        let requests = self
            .key_incr_at(
                KeyValue::new(window.bucket(prefix, key), 1).expires(window.expires_in),
                now,
            )
            .await
            .caused_by(trc::location!())?;

        if requests <= rate.count as i64 {
            Ok(None)
        } else {
            Ok(Some(window.expires_in))
        }
    }

    pub async fn rate_reset(&self, prefix: u8, key: &[u8], rate: &Rate) -> trc::Result<()> {
        self.counter_delete(RateWindow::new(rate, now()).bucket(prefix, key))
            .await
    }

    pub async fn try_lock(&self, prefix: u8, key: &[u8], duration: u64) -> trc::Result<bool> {

        match self {
            InMemoryStore::Local(store) => {
                store.try_lock(KeyValue::<()>::build_key(prefix, key), duration, now())
            }
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => {
                Box::pin(store.in_memory_try_insert(
                    KeyValue::<()>::build_key(prefix, key),
                    &[],
                    duration,
                    now(),
                ))
                .await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => {
                store
                    .try_lock(&KeyValue::<()>::build_key(prefix, key), duration)
                    .await
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
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
    }

    pub async fn renew_lock(&self, prefix: u8, key: &[u8], duration: u64) -> trc::Result<()> {

        match self {
            InMemoryStore::Local(store) => {
                store.renew_lock(KeyValue::<()>::build_key(prefix, key), duration, now())
            }
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => {
                Box::pin(store.in_memory_renew_lock(
                    KeyValue::<()>::build_key(prefix, key),
                    duration,
                    now(),
                ))
                .await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => {
                store
                    .renew_lock(&KeyValue::<()>::build_key(prefix, key), duration)
                    .await
            }
            // inbuxa: ST-23: a lock and its release meet on one member
            InMemoryStore::Sharded(store) => {
                Box::pin(
                    store
                        .member(&KeyValue::<()>::build_key(prefix, key))
                        .renew_lock(prefix, key, duration),
                )
                .await
            }
            InMemoryStore::Sql(_) | InMemoryStore::Static(_) | InMemoryStore::Http(_) => {
                Err(trc::StoreEvent::NotSupported.into_err())
            }
        }
    }

    pub async fn try_lease(
        &self,
        prefix: u8,
        key: &[u8],
        token: u64,
        duration: u64,
    ) -> trc::Result<bool> {

        // inbuxa: ST-23: a lease and its renewals meet on one member
        if let InMemoryStore::Sharded(store) = self {
            return Box::pin(
                store
                    .member(&KeyValue::<()>::build_key(prefix, key))
                    .try_lease(prefix, key, token, duration),
            )
            .await;
        }

        let key = KeyValue::<()>::build_key(prefix, key);
        match self {
            InMemoryStore::Local(store) => store.try_lease(key, token, duration, now()),
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => {
                Box::pin(store.in_memory_try_insert(key, &token.to_be_bytes(), duration, now())).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.try_lease(&key, token, duration).await,
            InMemoryStore::Sql(_)
            | InMemoryStore::Static(_)
            | InMemoryStore::Http(_)
            | InMemoryStore::Sharded(_) => Err(trc::StoreEvent::NotSupported.into_err()),
        }
    }

    pub async fn renew_lease(
        &self,
        prefix: u8,
        key: &[u8],
        token: u64,
        duration: u64,
    ) -> trc::Result<bool> {

        // inbuxa: ST-23: a lease and its renewals meet on one member
        if let InMemoryStore::Sharded(store) = self {
            return Box::pin(
                store
                    .member(&KeyValue::<()>::build_key(prefix, key))
                    .renew_lease(prefix, key, token, duration),
            )
            .await;
        }

        let key = KeyValue::<()>::build_key(prefix, key);
        match self {
            InMemoryStore::Local(store) => Ok(store.renew_lease(&key, token, duration, now())),
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => {
                Box::pin(store.in_memory_renew_lease(key, token, duration, now())).await
            }
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.renew_lease(&key, token, duration).await,
            InMemoryStore::Sql(_)
            | InMemoryStore::Static(_)
            | InMemoryStore::Http(_)
            | InMemoryStore::Sharded(_) => Err(trc::StoreEvent::NotSupported.into_err()),
        }
    }

    pub async fn release_lease(&self, prefix: u8, key: &[u8], token: u64) -> trc::Result<bool> {

        // inbuxa: ST-23: a lease and its renewals meet on one member
        if let InMemoryStore::Sharded(store) = self {
            return Box::pin(
                store
                    .member(&KeyValue::<()>::build_key(prefix, key))
                    .release_lease(prefix, key, token),
            )
            .await;
        }

        let key = KeyValue::<()>::build_key(prefix, key);
        match self {
            InMemoryStore::Local(store) => Ok(store.release_lease(key, token)),
            // inbuxa: kept in the data store
            InMemoryStore::Store(store) => Box::pin(store.in_memory_release_lease(key, token)).await,
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(store) => store.release_lease(&key, token).await,
            InMemoryStore::Sql(_)
            | InMemoryStore::Static(_)
            | InMemoryStore::Http(_)
            | InMemoryStore::Sharded(_) => Err(trc::StoreEvent::NotSupported.into_err()),
        }
    }

    pub async fn remove_lock(&self, prefix: u8, key: &[u8]) -> trc::Result<()> {
        self.key_delete(KeyValue::<()>::build_key(prefix, key))
            .await
            .map(|_| ())
    }

    /// inbuxa: removes expired entries from an in-memory store kept in the
    /// data store; the others expire entries themselves.
    pub async fn purge_in_memory_store(&self) -> trc::Result<()> {
        match self {
            InMemoryStore::Store(store) => store.purge_in_memory(now()).await,
            InMemoryStore::Sharded(store) => {
                for member in store.members.iter() {
                    Box::pin(member.purge_in_memory_store()).await?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub fn is_sql(&self) -> bool {
        match self {
            InMemoryStore::Sql(store) | InMemoryStore::Store(store) => store.is_sql(),
            _ => false,
        }
    }

    pub fn is_redis(&self) -> bool {
        match self {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(_) => true,
            // inbuxa: ST-3: as its members are
            InMemoryStore::Sharded(store) => store.members.iter().all(|m| m.is_redis()),
            _ => false,
        }
    }

    pub fn is_remote(&self) -> bool {
        match self {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(_) => true,
            // inbuxa: shared by every node, a round trip away
            InMemoryStore::Store(_) => true,
            // inbuxa: as its members are
            InMemoryStore::Sharded(store) => store.members.iter().all(|m| m.is_remote()),
            _ => false,
        }
    }

    pub fn supports_chunked_keys(&self) -> bool {
        match self {
            #[cfg(feature = "redis")]
            InMemoryStore::Redis(_) => true,
            // inbuxa: as its members are
            InMemoryStore::Sharded(store) => {
                store.members.iter().all(|m| m.supports_chunked_keys())
            }
            _ => false,
        }
    }

    pub fn into_store(self) -> Option<Store> {
        match self {
            InMemoryStore::Sql(store) | InMemoryStore::Store(store) => Some(store),
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
