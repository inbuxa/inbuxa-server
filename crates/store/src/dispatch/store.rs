/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    Deserialize, IterateParams, Key, QueryResult, Store, Subspace, U32_LEN, Value, ValueKey,
    write::{
        AnyKey, AssignedIds, Batch, BatchBuilder, ValueClass,
        key::{CounterKind, KeySerializer},
    },
};
use compact_str::ToCompactString;
use std::time::Instant;
use trc::{AddContext, StoreEvent};

impl Store {
    pub async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_value(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_value(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_value(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_value(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_value(key).await,
            Self::Ephemeral(store) => store.get_value(key).await,
            // inbuxa: ST-6 to ST-8, ST-12
            Self::Replicated(store) => match store.read_target(key.subspace()).await {
                Some(index) => {
                    match crate::sql_backend!(&store.replicas[index].store, db => db.get_value::<U>(key.clone()).await) {
                        Ok(Some(value)) => {
                            store.served(index);
                            Ok(Some(value))
                        }
                        Ok(None) => crate::sql_backend!(&store.primary, db => db.get_value(key).await),
                        Err(err) => {
                            store.failed(index, err);
                            crate::sql_backend!(&store.primary, db => db.get_value(key).await)
                        }
                    }
                }
                None => crate::sql_backend!(&store.primary, db => db.get_value(key).await),
            },
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }


    /// inbuxa: reads a set of keys in one round trip where the backend can
    /// (PostgreSQL: `k = ANY($1)`), one `get_value` per key elsewhere.
    /// Values come back in the keys' order, `None` for a missing key.
    /// Callers bound a batch at [`crate::READ_BATCH_SIZE`] keys so a
    /// FETCH of a whole mailbox never holds every archive at once.
    pub async fn get_values<U>(&self, keys: &[impl Key]) -> trc::Result<Vec<Option<U>>>
    where
        U: Deserialize + 'static,
    {
        async fn read<U>(store: &Store, keys: &[impl Key]) -> trc::Result<Vec<Option<U>>>
        where
            U: Deserialize + 'static,
        {
            match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(db) => db.get_values(keys).await,
                _ => {
                    let mut values = Vec::with_capacity(keys.len());
                    for key in keys {
                        values.push(store.get_value(key.clone()).await?);
                    }
                    Ok(values)
                }
            }
        }

        match self {
            // ST-6 to ST-8, ST-12: one replica serves the batch when every
            // key is in a replicated subspace; keys it has not received yet
            // are read again from the primary
            Self::Replicated(store) => {
                let subspace = keys
                    .first()
                    .map(|key| key.subspace())
                    .filter(|subspace| keys.iter().all(|key| key.subspace() == *subspace));
                match subspace {
                    Some(subspace) => match store.read_target(subspace).await {
                        Some(index) => match read(&store.replicas[index].store, keys).await {
                            Ok(mut values) => {
                                store.served(index);
                                let missing = values
                                    .iter()
                                    .enumerate()
                                    .filter(|(_, value)| value.is_none())
                                    .map(|(pos, _)| pos)
                                    .collect::<Vec<_>>();
                                if !missing.is_empty() {
                                    let retry = missing
                                        .iter()
                                        .map(|pos| keys[*pos].clone())
                                        .collect::<Vec<_>>();
                                    for (pos, value) in missing
                                        .into_iter()
                                        .zip(read::<U>(&store.primary, &retry).await?)
                                    {
                                        values[pos] = value;
                                    }
                                }
                                Ok(values)
                            }
                            Err(err) => {
                                store.failed(index, err);
                                read(&store.primary, keys).await
                            }
                        },
                        None => read(&store.primary, keys).await,
                    },
                    None => read(self, keys).await,
                }
            }
            _ => read(self, keys).await,
        }
        .caused_by(trc::location!())
    }

    pub async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {

        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.key_exists(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.key_exists(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.key_exists(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.key_exists(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.key_exists(key).await,
            Self::Ephemeral(store) => store.key_exists(key).await,
            // inbuxa: ST-6 to ST-8, ST-12
            Self::Replicated(store) => match store.read_target(key.subspace()).await {
                Some(index) => match crate::sql_backend!(&store.replicas[index].store, db => db.key_exists(key.clone()).await) {
                    Ok(true) => {
                        store.served(index);
                        Ok(true)
                    }
                    Ok(false) => crate::sql_backend!(&store.primary, db => db.key_exists(key).await),
                    Err(err) => {
                        store.failed(index, err);
                        crate::sql_backend!(&store.primary, db => db.key_exists(key).await)
                    }
                },
                None => crate::sql_backend!(&store.primary, db => db.key_exists(key).await),
            },
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        if params.fetch == crate::Fetch::Limit(0) {
            return Ok(());
        }

        let start_time = Instant::now();
        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.iterate(params, cb).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.iterate(params, cb).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.iterate(params, cb).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.iterate(params, cb).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.iterate(params, cb).await,
            Self::Ephemeral(store) => store.iterate(params, cb).await,
            // inbuxa: ST-6, ST-12: a failed replica iteration is repeated on
            // the primary when nothing was handed to the callback yet
            #[allow(unused_mut, unused_variables)]
            Self::Replicated(store) => {
                let mut cb = cb;
                match store.read_target(params.begin.subspace()).await {
                    Some(index) => {
                        let mut called = false;
                        let result = crate::sql_backend!(&store.replicas[index].store, db => db
                            .iterate(params.clone(), |key, value| {
                                called = true;
                                cb(key, value)
                            })
                            .await);
                        match result {
                            Ok(()) => {
                                store.served(index);
                                Ok(())
                            }
                            Err(err) if !called => {
                                store.failed(index, err);
                                crate::sql_backend!(&store.primary, db => db.iterate(params, cb).await)
                            }
                            Err(err) => {
                                store.failed(index, err.clone());
                                Err(err)
                            }
                        }
                    }
                    None => crate::sql_backend!(&store.primary, db => db.iterate(params, cb).await),
                }
            }
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!());


        trc::event!(
            Store(StoreEvent::DataIterate),
            Elapsed = start_time.elapsed(),
        );

        result
    }

    pub async fn iterate_many<T: Key>(
        &self,
        ranges: Vec<IterateParams<T>>,
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        debug_assert!(ranges.iter().all(|params| {
            params.ascending
                && params.fetch == crate::Fetch::All
                && params.values == ranges[0].values
                && params.begin.subspace() == ranges[0].begin.subspace()
                && params.end.subspace() == ranges[0].begin.subspace()
        }));
        debug_assert!(
            ranges.windows(2).all(|pair| match pair {
                [previous, next] => previous.end.serialize(0) < next.begin.serialize(0),
                _ => true,
            }),
            "iterate_many ranges must be ascending and disjoint"
        );
        if ranges.is_empty() {
            return Ok(());
        }
        let start_time = Instant::now();
        let total = ranges.len();


        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.iterate_many(ranges, cb).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.iterate_many(ranges, cb).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.iterate_many(ranges, cb).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.iterate_many(ranges, cb).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.iterate_many(ranges, cb).await,
            Self::Ephemeral(store) => store.iterate_many(ranges, cb).await,
            // inbuxa: ST-6, ST-12: as iterate
            #[allow(unused_mut, unused_variables)]
            Self::Replicated(store) => {
                let mut cb = cb;
                match store.read_target(ranges[0].begin.subspace()).await {
                    Some(index) => {
                        let mut called = false;
                        let result = crate::sql_backend!(&store.replicas[index].store, db => db
                            .iterate_many(ranges.clone(), |key, value| {
                                called = true;
                                cb(key, value)
                            })
                            .await);
                        match result {
                            Ok(()) => {
                                store.served(index);
                                Ok(())
                            }
                            Err(err) if !called => {
                                store.failed(index, err);
                                crate::sql_backend!(&store.primary, db => db.iterate_many(ranges, cb).await)
                            }
                            Err(err) => {
                                store.failed(index, err.clone());
                                Err(err)
                            }
                        }
                    }
                    None => crate::sql_backend!(&store.primary, db => db.iterate_many(ranges, cb).await),
                }
            }
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!());


        trc::event!(
            Store(StoreEvent::DataIterate),
            Elapsed = start_time.elapsed(),
            Total = total,
        );

        result
    }

    pub async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {

        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_counter(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_counter(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_counter(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_counter(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_counter(key).await,
            Self::Ephemeral(store) => store.get_counter(key).await,
            // inbuxa: ST-6, ST-12
            Self::Replicated(store) => {
                let key: ValueKey<ValueClass> = key.into();
                match store.read_target(crate::Key::subspace(&key)).await {
                    Some(index) => {
                        match crate::sql_backend!(&store.replicas[index].store, db => db.get_counter(key.clone()).await) {
                            Ok(value) => {
                                store.served(index);
                                Ok(value)
                            }
                            Err(err) => {
                                store.failed(index, err);
                                crate::sql_backend!(&store.primary, db => db.get_counter(key).await)
                            }
                        }
                    }
                    None => crate::sql_backend!(&store.primary, db => db.get_counter(key).await),
                }
            }
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    #[allow(unreachable_patterns)]
    #[allow(unused_variables)]
    pub async fn sql_query<T: QueryResult + std::fmt::Debug>(
        &self,
        query: &str,
        params: Vec<Value<'_>>,
    ) -> trc::Result<T> {
        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.sql_query(query, &params).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.sql_query(query, &params).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.sql_query(query, &params).await,
            // inbuxa: ST-5: operator-written statements always go to the primary
            Self::Replicated(store) => {
                crate::sql_backend!(&store.primary, db => db.sql_query(query, &params).await)
            }
            _ => Err(trc::StoreEvent::NotSupported.into_err()),
        };

        trc::event!(
            Store(trc::StoreEvent::SqlQuery),
            Query = query.to_compact_string(),
            Value = params.as_slice(),
            Result = &result,
        );

        result.caused_by(trc::location!())
    }

    pub async fn write_batch(&self, builder: &mut BatchBuilder) -> trc::Result<AssignedIds> {

        let mut assigned_ids = AssignedIds::default();
        let mut commit_points = builder.commit_points();

        for commit_point in commit_points.iter() {
            let batch = builder.build_one(commit_point);
            self.write(batch, &mut assigned_ids).await?;
        }

        Ok(assigned_ids)
    }

    pub(crate) async fn write(
        &self,
        batch: Batch<'_>,
        assigned_ids: &mut AssignedIds,
    ) -> trc::Result<()> {

        let start_time = Instant::now();
        let ops = batch.ops.len();

        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.write(batch, assigned_ids).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.write(batch, assigned_ids).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.write(batch, assigned_ids).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.write(batch, assigned_ids).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.write(batch, assigned_ids).await,
            Self::Ephemeral(store) => store.write(batch, assigned_ids).await,
            // inbuxa: ST-5, ST-7: writes go to the primary, and record marks
            Self::Replicated(store) => {
                crate::backend::scaleout::replica::note_scope_write();
                let result =
                    crate::sql_backend!(&store.primary, db => db.write(batch, assigned_ids).await);
                if result.is_ok() {
                    store.note_write(assigned_ids).await;
                }
                result
            }
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        };


        trc::event!(
            Store(StoreEvent::DataWrite),
            Elapsed = start_time.elapsed(),
            Total = ops,
        );

        result
    }

    pub async fn purge_store(&self) -> trc::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.purge_store().await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.purge_store().await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.purge_store().await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.purge_store().await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.purge_store().await,
            Self::Ephemeral(store) => store.purge_store().await,
            Self::Replicated(store) => {
                crate::sql_backend!(&store.primary, db => db.purge_store().await)
            }
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {

        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.delete_range(from, to).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.delete_range(from, to).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.delete_range(from, to).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.delete_range(from, to).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.delete_range(from, to).await,
            Self::Ephemeral(store) => store.delete_range(from, to).await,
            Self::Replicated(store) => {
                crate::sql_backend!(&store.primary, db => db.delete_range(from, to).await)
            }
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn danger_destroy_account(&self, account_id: u32) -> trc::Result<()> {
        for kind in CounterKind::ACCOUNT_KINDS {
            self.delete_range(
                AnyKey {
                    subspace: Subspace::Counter,
                    key: KeySerializer::new(U32_LEN + 1)
                        .write(kind.byte())
                        .write(account_id)
                        .finalize(),
                },
                AnyKey {
                    subspace: Subspace::Counter,
                    key: KeySerializer::new(U32_LEN + 1)
                        .write(kind.byte())
                        .write(account_id + 1)
                        .finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
        }

        for subspace in [
            Subspace::Logs,
            Subspace::Indexes,
            Subspace::Property,
            Subspace::Immutable,
            Subspace::IndexProperty,
        ] {
            self.delete_range(
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U32_LEN).write(account_id).finalize(),
                },
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U32_LEN).write(account_id + 1).finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
        }

        self.delete_range(
            ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: ValueClass::Acl(account_id),
            },
            ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: ValueClass::Acl(account_id + 1),
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(())
    }

    pub async fn create_tables(&self) -> trc::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.create_tables(),
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.create_storage_tables().await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.create_storage_tables().await,
            // inbuxa: ST-5
            Self::Replicated(store) => {
                crate::sql_backend!(&store.primary, db => db.create_storage_tables().await)
            }
            _ => Ok(()),
        }
    }

    pub fn invalidate_read_snapshot(&self) {
        #[cfg(feature = "foundation")]
        if let Self::FoundationDb(store) = self {
            store.invalidate_read_snapshot();
        }
    }

    pub fn read_snapshot_version(&self) -> Option<u64> {
        match self {
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.read_snapshot_version(),
            _ => None,
        }
    }

    pub fn advance_read_snapshot(&self, version: u64) {
        #[cfg(feature = "foundation")]
        if let Self::FoundationDb(store) = self {
            store.advance_read_snapshot(version);
        }
        #[cfg(not(feature = "foundation"))]
        let _ = version;
    }
}

#[cfg(any(feature = "postgres", feature = "mysql"))]
pub(crate) fn point_keys<T: Key>(ranges: &[IterateParams<T>]) -> Option<Vec<Vec<u8>>> {
    let mut keys = Vec::with_capacity(ranges.len());
    let mut end = Vec::new();
    for params in ranges {
        let begin = params.begin.serialize(0);
        end.clear();
        params.end.serialize_into(&mut end, 0);
        if begin != end {
            return None;
        }
        keys.push(begin);
    }
    Some(keys)
}
