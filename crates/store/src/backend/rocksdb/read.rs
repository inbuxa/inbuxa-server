/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    RocksDbStore, into_error,
    slots::{queue_quota_read_options, sum_slots},
};
use crate::{
    Deserialize, Fetch, IterateParams, Key, ValueKey, backend::rocksdb::CfHandle, write::ValueClass,
};
use rocksdb::ReadOptions;
use std::{cmp::Ordering, mem};

const MULTI_GET_CHUNK: usize = 256;

impl RocksDbStore {
    pub(crate) fn get_value<U>(&self, key: impl Key) -> impl Future<Output = trc::Result<Option<U>>>
    where
        U: Deserialize + 'static,
    {
        let db = self.db.clone();
        let subspace = key.subspace();
        let key = key.serialize(0);

        self.spawn_worker(move || {
            let cf = db.subspace_handle(subspace);
            db.get_pinned_cf(&cf, &key)
                .map_err(into_error)
                .and_then(|value| {
                    if let Some(value) = value {
                        U::deserialize_with_key(&key, &value).map(Some)
                    } else {
                        Ok(None)
                    }
                })
        })
    }

    pub(crate) fn key_exists(&self, key: impl Key) -> impl Future<Output = trc::Result<bool>> {
        let db = self.db.clone();
        let subspace = key.subspace();
        let key = key.serialize(0);

        self.spawn_worker(move || {
            let cf = db.subspace_handle(subspace);
            db.get_pinned_cf(&cf, &key)
                .map_err(into_error)
                .map(|value| value.is_some())
        })
    }

    pub(crate) fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> impl Future<Output = trc::Result<()>> {
        let mut remaining = match params.fetch {
            Fetch::Limit(rows) => u64::from(rows),
            Fetch::All | Fetch::Expect(_) => u64::MAX,
        };
        let db = self.db.clone();

        self.block_reader(move || {
            let cf = db.subspace_handle(params.begin.subspace());
            let begin = params.begin.serialize(0);
            let end = params.end.serialize(0);
            let mut upper_bound = Vec::with_capacity(end.len() + 1);

            upper_bound.extend_from_slice(&end);
            upper_bound.push(0u8);

            let mut read_opts = ReadOptions::default();
            read_opts.set_iterate_lower_bound(begin.as_slice());
            read_opts.set_iterate_upper_bound(upper_bound);
            read_opts.set_auto_readahead_size(true);

            let mut it = db.raw_iterator_cf_opt(&cf, read_opts);
            if params.ascending {
                it.seek(&begin);
            } else {
                it.seek_for_prev(&end);
            }

            while it.valid() {
                let Some(key) = it.key() else {
                    break;
                };
                let value = if params.values {
                    it.value().unwrap_or_default()
                } else {
                    &[][..]
                };

                remaining -= 1;
                if !cb(key, value)? || remaining == 0 {
                    return Ok(());
                }

                if params.ascending {
                    it.next();
                } else {
                    it.prev();
                }
            }

            it.status().map_err(into_error)
        })
    }

    pub(crate) fn iterate_many<T: Key>(
        &self,
        ranges: Vec<IterateParams<T>>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> impl Future<Output = trc::Result<()>> {
        let db = self.db.clone();

        self.block_reader(move || {
            let Some((first, rest)) = ranges.split_first() else {
                return Ok(());
            };
            let cf = db.subspace_handle(first.begin.subspace());
            let mut point = Vec::new();
            let mut point_end = Vec::new();
            if first.values
                && ranges.iter().all(|params| {
                    point.clear();
                    params.begin.serialize_into(&mut point, 0);
                    point_end.clear();
                    params.end.serialize_into(&mut point_end, 0);
                    point == point_end
                })
            {
                let snapshot = (ranges.len() > MULTI_GET_CHUNK).then(|| db.snapshot());
                let mut read_opts = ReadOptions::default();
                if let Some(snapshot) = &snapshot {
                    read_opts.set_snapshot(snapshot);
                }
                let mut keys: Vec<Vec<u8>> = Vec::with_capacity(ranges.len().min(MULTI_GET_CHUNK));
                for chunk in ranges.chunks(MULTI_GET_CHUNK) {
                    keys.resize_with(chunk.len(), Vec::new);
                    for (key, params) in keys.iter_mut().zip(chunk) {
                        key.clear();
                        params.begin.serialize_into(key, 0);
                    }
                    let values =
                        db.batched_multi_get_cf_opt(&cf, &keys, keys.is_sorted(), &read_opts);
                    for (key, value) in keys.iter().zip(values) {
                        if let Some(value) = value.map_err(into_error)?
                            && !cb(key, &value)?
                        {
                            return Ok(());
                        }
                    }
                }
                return Ok(());
            }
            let mut lower_bound = first.begin.serialize(0);
            let mut upper_bound = first.end.serialize(0);
            let mut begin = Vec::with_capacity(lower_bound.capacity());
            let mut end = Vec::with_capacity(upper_bound.capacity());

            for params in rest {
                begin.clear();
                params.begin.serialize_into(&mut begin, 0);
                if begin < lower_bound {
                    mem::swap(&mut begin, &mut lower_bound);
                }

                end.clear();
                params.end.serialize_into(&mut end, 0);
                if end > upper_bound {
                    mem::swap(&mut end, &mut upper_bound);
                }
            }
            upper_bound.push(0u8);

            let mut read_opts = ReadOptions::default();
            read_opts.set_iterate_lower_bound(lower_bound);
            read_opts.set_iterate_upper_bound(upper_bound);
            read_opts.set_auto_readahead_size(true);

            let mut it = db.raw_iterator_cf_opt(&cf, read_opts);

            for params in &ranges {
                begin.clear();
                params.begin.serialize_into(&mut begin, 0);
                end.clear();
                params.end.serialize_into(&mut end, 0);
                it.seek(&begin);

                while it.valid() {
                    let Some(key) = it.key() else {
                        break;
                    };
                    let is_last = match key.cmp(end.as_slice()) {
                        Ordering::Less => false,
                        Ordering::Equal => true,
                        Ordering::Greater => break,
                    };
                    let value = if params.values {
                        it.value().unwrap_or_default()
                    } else {
                        &[][..]
                    };

                    if !cb(key, value)? {
                        return Ok(());
                    }

                    if is_last {
                        break;
                    }

                    it.next();
                }

                it.status().map_err(into_error)?;
            }

            Ok(())
        })
    }

    pub(crate) fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> impl Future<Output = trc::Result<i64>> {
        let key = key.into();
        let db = self.db.clone();
        let subspace = key.subspace();
        let slots = key.class.is_queue_quota();
        let key = key.serialize(0);

        self.spawn_worker(move || {
            let cf = db.subspace_handle(subspace);
            if slots {
                let mut iter = db.raw_iterator_cf_opt(&cf, queue_quota_read_options());
                return sum_slots(&mut iter, &key, 0).map(|sum| sum.total);
            }

            db.get_pinned_cf(&cf, &key)
                .map_err(into_error)
                .and_then(|bytes| {
                    Ok(if let Some(bytes) = bytes {
                        i64::from_le_bytes(bytes[..].try_into().map_err(|_| {
                            trc::Error::corrupted_key(&key, (&bytes[..]).into(), trc::location!())
                        })?)
                    } else {
                        0
                    })
                })
        })
    }
}

