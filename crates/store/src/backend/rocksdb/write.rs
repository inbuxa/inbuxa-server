/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    CfCache, CfHandle, RocksDbStore, into_error,
    slots::{CounterSlot, SlotGroups, queue_quota_read_options, sum_slots},
};
use crate::{
    Deserialize, Key, Shape, Subspace,
    backend::deserialize_i64_le,
    write::{
        Advance, Allocation, AssignedIds, Batch, BatchCursor, LogSet, MAX_COMMIT_ATTEMPTS,
        MAX_COMMIT_TIME, MergeResult, ValueOp, commit_backoff, exhausted,
    },
};
use rocksdb::{
    BoundColumnFamily, ErrorKind, IteratorMode, OptimisticTransactionDB,
    OptimisticTransactionOptions, ReadOptions, WriteOptions,
};
use std::{sync::Arc, time::Instant};

impl RocksDbStore {
    pub(crate) async fn write(
        &self,
        mut batch: Batch<'_>,
        assigned_ids: &mut AssignedIds,
    ) -> trc::Result<()> {
        let db = self.db.clone();
        let mut retry_count = 0;
        let start = Instant::now();
        let mark = assigned_ids.mark();

        loop {
            let attempt = self
                .block_writer(|| {
                    assigned_ids.rollback(mark);
                    let slot = self.counter_slots.acquire();
                    let mut txn = RocksDBTransaction {
                        db: &db,
                        txn_opts: OptimisticTransactionOptions::default(),
                        batch: &mut batch,
                        result: assigned_ids,
                        counter_slot: slot.as_ref().map_or(0, CounterSlot::byte),
                        #[cfg(stalwart_tests)]
                        probe: &self.probe,
                    };
                    txn.txn_opts.set_snapshot(true);

                    match txn.commit() {
                        Ok(()) => Ok(Ok(())),
                        Err(CommitError::Internal(err)) => Err(err),
                        Err(CommitError::RocksDB(err)) => Ok(Err(err)),
                    }
                })
                .await?;

            match attempt {
                Ok(()) => {
                    #[cfg(stalwart_tests)]
                    self.probe.record_commit(retry_count);
                    return Ok(());
                }
                Err(err) => match err.kind() {
                    ErrorKind::Busy | ErrorKind::MergeInProgress | ErrorKind::TryAgain => {
                        if retry_count < MAX_COMMIT_ATTEMPTS && start.elapsed() < MAX_COMMIT_TIME {
                            #[cfg(stalwart_tests)]
                            {
                                self.probe.record_retry(err.kind());
                                crate::write::record_retry(retry_count);
                            }
                            tokio::time::sleep(commit_backoff(retry_count)).await;
                            retry_count += 1;
                        } else {
                            return Err(exhausted(into_error(err), retry_count));
                        }
                    }
                    _ => return Err(into_error(err)),
                },
            }
        }
    }

    pub(crate) fn delete_range(
        &self,
        from: impl Key,
        to: impl Key,
    ) -> impl Future<Output = trc::Result<()>> {
        let db = self.db.clone();
        let subspace = from.subspace();
        let from = from.serialize(0);
        let to = to.serialize(0);

        self.spawn_worker(move || {
            db.delete_range_cf(
                &db.subspace_handle(subspace),
                from.as_slice(),
                to.as_slice(),
            )
            .map_err(into_error)
        })
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            for subspace in Subspace::ALL
                .iter()
                .copied()
                .filter(|subspace| matches!(subspace.shape(), Shape::Counter))
            {
                let cf = db.subspace_handle(subspace);

                let mut delete_keys = Vec::new();
                let mut slots = SlotGroups::default();

                for row in db.iterator_cf(&cf, IteratorMode::Start) {
                    let (key, value) = row.map_err(into_error)?;

                    if i64::deserialize(&value)? == 0 {
                        delete_keys.push(key);
                    } else if subspace == Subspace::Counter {
                        let value = deserialize_i64_le(&key, &value)?;
                        slots.add(key, value);
                    }
                }

                let txn_opts = OptimisticTransactionOptions::default();
                for keys in slots.zero_sum() {
                    let txn = db.transaction_opt(&WriteOptions::default(), &txn_opts);
                    let mut total = 0i64;
                    for key in keys {
                        if let Some(value) = txn
                            .get_pinned_for_update_cf(&cf, key, true)
                            .map_err(into_error)?
                        {
                            total = total.saturating_add(deserialize_i64_le(key, &value)?);
                        }
                    }
                    if total == 0 {
                        for key in keys {
                            txn.delete_cf(&cf, key).map_err(into_error)?;
                        }
                        commit_unless_busy(txn)?;
                    } else {
                        txn.rollback().map_err(into_error)?;
                    }
                }

                for key in delete_keys {
                    let txn = db.transaction_opt(&WriteOptions::default(), &txn_opts);
                    if txn
                        .get_pinned_for_update_cf(&cf, &key, true)
                        .map_err(into_error)?
                        .map(|value| i64::deserialize(&value).map(|v| v == 0).unwrap_or(false))
                        .unwrap_or(false)
                    {
                        txn.delete_cf(&cf, key).map_err(into_error)?;
                        commit_unless_busy(txn)?;
                    } else {
                        txn.rollback().map_err(into_error)?;
                    }
                }
            }

            Ok(())
        })
        .await?;
        self.collect_blob_garbage().await
    }
}

fn commit_unless_busy(txn: rocksdb::Transaction<'_, OptimisticTransactionDB>) -> trc::Result<()> {
    match txn.commit() {
        Ok(()) => Ok(()),
        Err(err) if matches!(err.kind(), ErrorKind::Busy | ErrorKind::TryAgain) => Ok(()),
        Err(err) => Err(into_error(err)),
    }
}

struct RocksDBTransaction<'x, 'y> {
    db: &'x OptimisticTransactionDB,
    txn_opts: OptimisticTransactionOptions,
    batch: &'x mut Batch<'y>,
    result: &'x mut AssignedIds,
    counter_slot: u8,
    #[cfg(stalwart_tests)]
    probe: &'x super::probe::RocksDbProbe,
}

enum CommitError {
    Internal(trc::Error),
    RocksDB(rocksdb::Error),
}

fn read_counter(
    txn: &rocksdb::Transaction<'_, OptimisticTransactionDB>,
    cf: &Arc<BoundColumnFamily<'_>>,
    key: &[u8],
) -> Result<i64, CommitError> {
    match txn.get_pinned_for_update_cf(cf, key, true)? {
        Some(bytes) => deserialize_i64_le(key, &bytes).map_err(CommitError::from),
        None => Ok(0),
    }
}

impl RocksDBTransaction<'_, '_> {
    fn commit(&mut self) -> Result<(), CommitError> {
        let mut cursor = BatchCursor::new(self.batch);
        let result = &mut *self.result;
        let mut log_buf = Vec::new();
        let mut log_scratch = Vec::new();
        let mut cfs = CfCache::new(self.db);

        let txn = self
            .db
            .transaction_opt(&WriteOptions::default(), &self.txn_opts);

        if self.batch.has_allocations() {
            let cf = cfs.get(Subspace::Counter).clone();
            let mut key_buf = Vec::with_capacity(16);
            let mut slots = None;

            for allocation in self.batch.allocations() {
                key_buf.clear();
                allocation.serialize_key_into(&mut key_buf, 0);
                match allocation {
                    Allocation::Bounded(bound) if bound.allows_overshoot() => {
                        let iter = slots.get_or_insert_with(|| {
                            txn.raw_iterator_cf_opt(&cf, queue_quota_read_options())
                        });
                        let sum = sum_slots(iter, &key_buf, self.counter_slot)?;
                        bound.verify(sum.total.saturating_add(bound.by))?;
                        key_buf.push(self.counter_slot);
                        let value = sum.own.saturating_add(bound.by);
                        txn.put_cf(&cf, &key_buf, &value.to_le_bytes()[..])?;
                    }
                    _ => {
                        let last_id =
                            read_counter(&txn, &cf, &key_buf)? + allocation.increment_by();
                        txn.put_cf(&cf, &key_buf, &last_id.to_le_bytes()[..])?;
                        result.apply(allocation, last_id)?;
                    }
                }
            }
        }

        let mut key_buf = Vec::with_capacity(64);
        for op in self.batch.ops.iter_mut() {
            match cursor.advance(op, result) {
                Advance::Cursor => {}
                Advance::Value { class, op } => {
                    cursor.value_key(class, &mut key_buf, 0);
                    if matches!(op, ValueOp::AtomicAdd(_)) && class.is_queue_quota() {
                        key_buf.push(self.counter_slot);
                    }
                    let key = &key_buf;
                    let cf = cfs.get(cursor.subspace(class));

                    match op {
                        ValueOp::Set(value) => {
                            let value = value.resolve(result)?;
                            txn.put_cf(cf, key, &*value)?;
                        }
                        ValueOp::MergeFnc(merge_op) => {
                            let merge_result = (merge_op.0)(
                                result,
                                txn.get_pinned_for_update_cf(cf, key, true)?.as_deref(),
                            )?;

                            match merge_result {
                                MergeResult::Update(value) => {
                                    txn.put_cf(cf, key, value)?;
                                }
                                MergeResult::Delete => {
                                    txn.delete_cf(cf, key)?;
                                }
                                MergeResult::Skip => (),
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            let value = read_counter(&txn, cf, key)?.saturating_add(*by);
                            txn.put_cf(cf, key, &value.to_le_bytes()[..])?;
                        }
                        ValueOp::AddAndGet(by) => {
                            let num = txn
                                .get_pinned_for_update_cf(cf, key, true)
                                .map_err(CommitError::from)
                                .and_then(|bytes| {
                                    if let Some(bytes) = bytes {
                                        deserialize_i64_le(key, &bytes)
                                            .map(|v| v + *by)
                                            .map_err(CommitError::from)
                                    } else {
                                        Ok(*by)
                                    }
                                })?;
                            txn.put_cf(cf, key, &num.to_le_bytes()[..])?;
                            result.push_counter_id(num);
                        }
                        ValueOp::Clear => {
                            txn.delete_cf(cf, key)?;
                        }
                    }
                }
                Advance::Index { field, key, set } => {
                    cursor.index_key(field, key, &mut key_buf, 0);
                    let key = &key_buf;
                    let cf = cfs.get(Subspace::Indexes);

                    if set {
                        txn.put_cf(cf, key, [])?;
                    } else {
                        txn.delete_cf(cf, key)?;
                    }
                }
                Advance::Log { collection, set } => {
                    cursor.log_key(collection, result, &mut key_buf, 0);
                    let cf = cfs.get(Subspace::Logs);

                    match set {
                        LogSet::Bytes(bytes) => {
                            txn.put_cf(cf, &key_buf, &*bytes)?;
                        }
                        LogSet::Pending(changes) => {
                            changes.serialize_into(
                                collection.is_prefixed(),
                                result,
                                &mut log_scratch,
                                &mut log_buf,
                            );
                            txn.put_cf(cf, &key_buf, &log_buf)?;
                        }
                    }
                }
                Advance::ClearRange { subspace, from, to } => {
                    let cf = cfs.get(subspace);
                    let mut options = ReadOptions::default();
                    options.set_iterate_upper_bound(to.to_vec());
                    let mut iter = txn.raw_iterator_cf_opt(cf, options);
                    iter.seek(from);
                    let mut keys = Vec::new();
                    while let Some(key) = iter.key() {
                        keys.push(key.to_vec());
                        iter.next();
                    }
                    iter.status()?;
                    drop(iter);
                    for key in keys {
                        txn.delete_cf(cf, key)?;
                    }
                }
                Advance::Assert {
                    class,
                    assert_value,
                } => {
                    cursor.value_key(class, &mut key_buf, 0);
                    let cf = cfs.get(cursor.subspace(class));

                    let matches = txn
                        .get_pinned_for_update_cf(cf, &key_buf, true)?
                        .map(|value| assert_value.matches(&value))
                        .unwrap_or_else(|| assert_value.is_none());

                    if !matches {
                        txn.rollback()?;
                        return Err(CommitError::Internal(
                            trc::StoreEvent::AssertValueFailed.into(),
                        ));
                    }
                }
            }
        }

        #[cfg(stalwart_tests)]
        self.probe.stall();

        txn.commit().map_err(Into::into)
    }
}

impl From<rocksdb::Error> for CommitError {
    fn from(err: rocksdb::Error) -> Self {
        CommitError::RocksDB(err)
    }
}

impl From<trc::Error> for CommitError {
    fn from(err: trc::Error) -> Self {
        CommitError::Internal(err)
    }
}
