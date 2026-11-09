/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::BlobStore;
use registry::schema::structs;
use std::{io::SeekFrom, ops::Range, path::PathBuf, sync::Arc};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use utils::codec::base32_custom::Base32Writer;

pub struct FsStore {
    path: PathBuf,
    hash_levels: usize,
}

impl FsStore {
    pub async fn open(config: structs::FileSystemStore) -> Result<BlobStore, String> {
        let path = PathBuf::from(&config.path);
        if !path.exists() {
            fs::create_dir_all(&path)
                .await
                .map_err(|e| format!("Failed to create directory: {e}"))?;
        }

        Ok(BlobStore::Fs(Arc::new(FsStore {
            path,
            hash_levels: std::cmp::min(config.depth as usize, 5),
        })))
    }

    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let blob_path = self.build_path(key);
        let blob_size = match fs::metadata(&blob_path).await {
            Ok(m) => m.len() as usize,
            Err(_) => return Ok(None),
        };
        let mut blob = File::open(&blob_path).await.map_err(into_error)?;

        Ok(Some(if range.start != 0 || range.end != usize::MAX {
            let from_offset = if range.start < blob_size {
                range.start
            } else {
                0
            };
            let mut buf = vec![0; (std::cmp::min(range.end, blob_size) - from_offset) as usize];

            if from_offset > 0 {
                blob.seek(SeekFrom::Start(from_offset as u64))
                    .await
                    .map_err(into_error)?;
            }
            blob.read_exact(&mut buf).await.map_err(into_error)?;
            buf
        } else {
            let mut buf = Vec::with_capacity(blob_size as usize);
            blob.read_to_end(&mut buf).await.map_err(into_error)?;
            buf
        }))
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        let blob_path = self.build_path(key);

        if fs::metadata(&blob_path)
            .await
            .map_or(true, |m| m.len() as usize != data.len())
        {
            fs::create_dir_all(blob_path.parent().unwrap())
                .await
                .map_err(into_error)?;
            // inbuxa: store-snapshot spec, SN-10: written beside it and
            // renamed into place, never rewritten in place. A snapshot holds
            // blobs by hard link, and a rewrite would change its copy too; a
            // stop mid-write would leave half a blob under its id.
            let temp_path = temp_path_for(&blob_path);
            let written = async {
                let mut blob_file = File::create(&temp_path).await?;
                blob_file.write_all(data).await?;
                blob_file.flush().await?;
                fs::rename(&temp_path, &blob_path).await
            }
            .await;
            if let Err(err) = written {
                let _ = fs::remove_file(&temp_path).await;
                return Err(into_error(err));
            }
        }

        Ok(())
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        let blob_path = self.build_path(key);
        if fs::metadata(&blob_path).await.is_ok() {
            fs::remove_file(&blob_path).await.map_err(into_error)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// inbuxa: the directory the blobs are under (store-snapshot spec).
    pub fn root(&self) -> &std::path::Path {
        &self.path
    }

    fn build_path(&self, key: &[u8]) -> PathBuf {
        let mut path = self.path.clone();

        for byte in key.iter().take(self.hash_levels) {
            path.push(format!("{:x}", byte));
        }
        path.push(Base32Writer::from_bytes(key).finalize());
        path
    }
}

/// inbuxa: SN-10. A blob's name is base32, so a name starting with a dot
/// is never a blob: the snapshot's copy and anything listing blobs skip it.
fn temp_path_for(blob_path: &std::path::Path) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = blob_path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    blob_path.with_file_name(format!(".{name}.{}-{n}.tmp", std::process::id()))
}

fn into_error(err: std::io::Error) -> trc::Error {
    trc::StoreEvent::FilesystemError.reason(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_go_through_a_temporary_file() {
        let dir = std::env::temp_dir().join(format!("inbuxa-fs-sn10-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let BlobStore::Fs(store) = FsStore::open(structs::FileSystemStore {
            path: dir.to_string_lossy().to_string(),
            depth: 2,
        })
        .await
        .unwrap() else {
            unreachable!()
        };
        let key = [7u8; 32];
        store.put_blob(&key, b"first").await.unwrap();
        let path = store.build_path(&key);

        // A file held by a hard link, as a snapshot holds it, keeps what it
        // had when the blob under its id is written again
        let held = dir.join("held");
        std::fs::hard_link(&path, &held).unwrap();
        store.put_blob(&key, b"second, longer").await.unwrap();
        assert_eq!(std::fs::read(&held).unwrap(), b"first");
        assert_eq!(
            store.get_blob(&key, 0..usize::MAX).await.unwrap().unwrap(),
            b"second, longer"
        );

        // Nothing is left beside it
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(
            temp_path_for(&path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with('.')
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
