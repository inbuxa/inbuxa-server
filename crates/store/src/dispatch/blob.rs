/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{BlobStore, CompressionAlgo, Store, U32_LEN};
use std::{borrow::Cow, ops::Range, time::Instant};
use trc::{AddContext, StoreEvent};

const MAGIC_MARKER: u8 = 0xa0;
const LZ4_MARKER: u8 = MAGIC_MARKER | 0x01;
//const ZSTD_MARKER: u8 = MAGIC_MARKER | 0x02;
const NONE_MARKER: u8 = 0x00;

fn decode<'x>(key: &[u8], data: &'x [u8]) -> trc::Result<Cow<'x, [u8]>> {
    match data.split_last() {
        Some((&LZ4_MARKER, payload)) => lz4_flex::decompress_size_prepended(payload)
            .map(Cow::Owned)
            .map_err(|err| {
                trc::StoreEvent::DecompressError
                    .reason(err)
                    .ctx(trc::Key::Key, key)
                    .ctx(trc::Key::CausedBy, trc::location!())
            }),
        Some((&NONE_MARKER, payload)) => Ok(Cow::Borrowed(payload)),
        Some(_) => {
            trc::event!(Store(StoreEvent::BlobMissingMarker), Key = key);
            Ok(Cow::Borrowed(data))
        }
        None => Ok(Cow::Borrowed(data)),
    }
}

fn store_uncompressed(data: &[u8]) -> Vec<u8> {
    let mut uncompressed = Vec::with_capacity(data.len() + 1);
    uncompressed.extend_from_slice(data);
    uncompressed.push(NONE_MARKER);
    uncompressed
}

impl BlobStore {
    pub async fn get_blob(&self, key: &[u8], range: Range<usize>) -> trc::Result<Option<Vec<u8>>> {
        #[cfg(stalwart_tests)]
        {
            crate::dispatch::StoreOps::count_blob_get();
            crate::dispatch::ops::wait(crate::dispatch::Latency::BlobGet).await;
        }

        let start_time = Instant::now();
        let result = self.get_raw_blob(key).await.caused_by(trc::location!())?;

        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_blob_get_bytes(&result);

        trc::event!(
            Store(StoreEvent::BlobRead),
            Key = key,
            Elapsed = start_time.elapsed(),
            Size = result.as_ref().map_or(0, |data| data.len()),
        );

        let Some(mut data) = result else {
            return Ok(None);
        };

        let mut data = match decode(key, &data)? {
            Cow::Owned(decompressed) => decompressed,
            Cow::Borrowed(payload) => {
                let len = payload.len();
                data.truncate(len);
                data
            }
        };

        if range.start == 0 {
            if range.end > data.len() {
                Ok(Some(data))
            } else {
                data.truncate(range.end);
                Ok(Some(data))
            }
        } else {
            Ok(Some(
                data.get(range.start..range.end)
                    .unwrap_or_default()
                    .to_vec(),
            ))
        }
    }

    async fn get_raw_blob(&self, key: &[u8]) -> trc::Result<Option<Vec<u8>>> {
        match &self {
            BlobStore::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.get_blob(key, 0..usize::MAX).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.get_blob(key, 0..usize::MAX).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.get_blob(key, 0..usize::MAX).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.get_blob(key, 0..usize::MAX).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.get_blob(key, 0..usize::MAX).await,
                Store::Ephemeral(store) => store.get_blob(key, 0..usize::MAX).await,
                Store::None => Err(trc::StoreEvent::NotConfigured.into()),
            },
            BlobStore::Fs(store) => store.get_blob(key, 0..usize::MAX).await,
            #[cfg(feature = "s3")]
            BlobStore::S3(store) => store.get_blob(key, 0..usize::MAX).await,
            #[cfg(feature = "azure")]
            BlobStore::Azure(store) => store.get_blob(key, 0..usize::MAX).await,
        }
    }

    pub async fn put_blob(
        &self,
        key: &[u8],
        data: &[u8],
        compression: CompressionAlgo,
    ) -> trc::Result<()> {
        let data = match compression {
            CompressionAlgo::Lz4 => {
                let mut compressed =
                    vec![
                        LZ4_MARKER;
                        lz4_flex::block::get_maximum_output_size(data.len()) + U32_LEN + 1
                    ];

                // Compress the data
                let compressed_len =
                    lz4_flex::compress_into(data, &mut compressed[U32_LEN..]).unwrap();

                if compressed_len + U32_LEN < data.len() {
                    // Prepend the length of the uncompressed data
                    compressed[..U32_LEN].copy_from_slice(&(data.len() as u32).to_le_bytes());

                    // Truncate to the actual size
                    compressed.truncate(compressed_len + U32_LEN + 1);
                    compressed
                } else {
                    store_uncompressed(data)
                }
            }
            CompressionAlgo::None => store_uncompressed(data),
        };

        #[cfg(stalwart_tests)]
        {
            crate::dispatch::StoreOps::count_blob_put(data.len());
            crate::dispatch::ops::wait(crate::dispatch::Latency::BlobPut).await;
        }

        let start_time = Instant::now();
        let size = data.len();
        let result = match &self {
            BlobStore::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.put_blob(key, data).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.put_blob(key, &data).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.put_blob(key, &data).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.put_blob(key, &data).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.put_blob(key, data).await,
                Store::Ephemeral(store) => store.put_blob(key, &data).await,
                Store::None => Err(trc::StoreEvent::NotConfigured.into()),
            },
            BlobStore::Fs(store) => store.put_blob(key, &data).await,
            #[cfg(feature = "s3")]
            BlobStore::S3(store) => store.put_blob(key, data).await,
            #[cfg(feature = "azure")]
            BlobStore::Azure(store) => store.put_blob(key, data).await,
        }
        .caused_by(trc::location!());

        trc::event!(
            Store(StoreEvent::BlobWrite),
            Key = key,
            Elapsed = start_time.elapsed(),
            Size = size,
        );

        result
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        #[cfg(stalwart_tests)]
        crate::dispatch::StoreOps::count_blob_delete();

        let start_time = Instant::now();
        let result = match &self {
            BlobStore::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.delete_blob(key).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.delete_blob(key).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.delete_blob(key).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.delete_blob(key).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.delete_blob(key).await,
                Store::Ephemeral(store) => store.delete_blob(key).await,
                Store::None => Err(trc::StoreEvent::NotConfigured.into()),
            },
            BlobStore::Fs(store) => store.delete_blob(key).await,
            #[cfg(feature = "s3")]
            BlobStore::S3(store) => store.delete_blob(key).await,
            #[cfg(feature = "azure")]
            BlobStore::Azure(store) => store.delete_blob(key).await,
        }
        .caused_by(trc::location!());

        trc::event!(
            Store(StoreEvent::BlobWrite),
            Key = key,
            Elapsed = start_time.elapsed(),
        );

        result
    }

    pub async fn delete_blobs(&self, keys: &[&[u8]]) -> trc::Result<()> {
        match self {
            #[cfg(feature = "rocks")]
            BlobStore::Store(Store::RocksDb(store)) => {
                delete_blobs_timed(keys, store.delete_blobs(keys)).await
            }
            #[cfg(feature = "s3")]
            BlobStore::S3(store) => delete_blobs_timed(keys, store.delete_blobs(keys)).await,
            _ => {
                for key in keys {
                    self.delete_blob(key).await?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(any(feature = "rocks", feature = "s3"))]
async fn delete_blobs_timed(
    keys: &[&[u8]],
    delete: impl Future<Output = trc::Result<()>>,
) -> trc::Result<()> {
    #[cfg(stalwart_tests)]
    crate::dispatch::StoreOps::count_blob_delete();

    let start_time = Instant::now();
    let result = delete.await.caused_by(trc::location!());

    trc::event!(
        Store(StoreEvent::BlobWrite),
        Total = keys.len(),
        Elapsed = start_time.elapsed(),
    );

    result
}

