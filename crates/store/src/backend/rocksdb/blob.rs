/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use super::{CF_BLOBS, RocksDbStore, into_error};
use rocksdb::WriteBatchWithTransaction;

impl RocksDbStore {
    pub(crate) fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> impl Future<Output = trc::Result<Option<Vec<u8>>>> {
        let db = self.db.clone();
        let key = key.to_vec();

        self.spawn_worker(move || {
            db.get_pinned_cf(&db.cf_handle(CF_BLOBS).unwrap(), &key)
                .map(|obj| {
                    obj.map(|bytes| {
                        if range.start == 0 && range.end == usize::MAX {
                            bytes.to_vec()
                        } else {
                            bytes
                                .get(range.start..std::cmp::min(bytes.len(), range.end))
                                .unwrap_or_default()
                                .to_vec()
                        }
                    })
                })
                .map_err(into_error)
        })
    }

    pub(crate) fn put_blob(
        &self,
        key: &[u8],
        data: Vec<u8>,
    ) -> impl Future<Output = trc::Result<()>> {
        let db = self.db.clone();
        let key = key.to_vec();

        self.spawn_worker(move || {
            db.put_cf(&db.cf_handle(CF_BLOBS).unwrap(), &key, &data)
                .map_err(into_error)
        })
    }

    pub(crate) fn delete_blob(&self, key: &[u8]) -> impl Future<Output = trc::Result<bool>> {
        let db = self.db.clone();
        let key = key.to_vec();

        self.spawn_worker(move || {
            db.delete_cf(&db.cf_handle(CF_BLOBS).unwrap(), &key)
                .map_err(into_error)
                .map(|_| true)
        })
    }

    pub(crate) async fn delete_blobs(&self, keys: &[&[u8]]) -> trc::Result<()> {
        let db = self.db.clone();
        let mut batch = WriteBatchWithTransaction::<true>::default();
        {
            let cf = db.cf_handle(CF_BLOBS).ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("Blob column family not found")
                    .caused_by(trc::location!())
            })?;
            for key in keys {
                batch.delete_cf(&cf, key);
            }
        }

        self.spawn_worker(move || db.write(batch).map_err(into_error))
            .await
    }
}
