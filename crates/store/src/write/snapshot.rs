/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: what the store-snapshot spec (docs/spec/features/store-snapshot.md)
//! needs from the store: holding the blob purge (SN-4), a checkpoint of the
//! data store and a copy of a filesystem blob store's files (SN-2).

use crate::{BlobStore, Store};
use std::{
    io,
    path::{Path, PathBuf},
};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// SN-4. A purge runs under the read side; a snapshot taking blobs holds
/// the write side. The data store is RocksDB, so one process has it open,
/// and a lock in that process is enough.
static BLOB_PURGE_GATE: RwLock<()> = RwLock::const_new(());

/// Whether a blob purge may run now: `None` while a snapshot takes blobs or
/// waits to. Keep the guard for as long as the purge runs.
pub fn blob_purge_may_run() -> Option<RwLockReadGuard<'static, ()>> {
    BLOB_PURGE_GATE.try_read().ok()
}

/// Holds the blob purge until the guard is dropped. A purge already running
/// finishes first.
pub async fn hold_blob_purge() -> RwLockWriteGuard<'static, ()> {
    BLOB_PURGE_GATE.write().await
}

/// What a snapshot can hold of this server's stores (SN-1, SN-2).
pub enum SnapshotSource {
    /// Blobs are in the data store, so the checkpoint holds them.
    DataOnly { data_path: PathBuf },
    /// Blobs are files under `blob_path`, copied after the checkpoint.
    DataAndFiles {
        data_path: PathBuf,
        blob_path: PathBuf,
    },
}

/// Why a snapshot can't be taken of these stores.
pub enum NotSnapshottable {
    DataStore(&'static str),
    BlobStore(&'static str),
    /// inbuxa: blob-store-change spec, BM-8: some blobs are still only in
    /// the blob store the server used before.
    BlobStoreChanging,
}

impl Store {
    /// SN-2: a checkpoint of the data store into `dest`, which must not
    /// exist yet. Only RocksDB has one.
    #[cfg_attr(not(feature = "rocks"), allow(unused_variables))]
    pub async fn checkpoint(&self, dest: PathBuf) -> trc::Result<()> {
        match self {
            #[cfg(feature = "rocks")]
            Store::RocksDb(store) => store.checkpoint(dest).await,
            _ => Err(trc::StoreEvent::NotSupported
                .into_err()
                .details("Only a RocksDB store has a checkpoint")),
        }
    }

    /// What a snapshot of this data store and `blobs` would hold, or why
    /// there can't be one.
    #[cfg_attr(not(feature = "rocks"), allow(unused_variables, unreachable_code))]
    pub fn snapshot_source(&self, blobs: &BlobStore) -> Result<SnapshotSource, NotSnapshottable> {
        let data_path = match self {
            #[cfg(feature = "rocks")]
            Store::RocksDb(store) => store.path().to_path_buf(),
            #[cfg(feature = "sqlite")]
            Store::SQLite(_) => return Err(NotSnapshottable::DataStore("SQLite")),
            #[cfg(feature = "foundation")]
            Store::FoundationDb(_) => return Err(NotSnapshottable::DataStore("FoundationDB")),
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(_) => return Err(NotSnapshottable::DataStore("PostgreSQL")),
            #[cfg(feature = "mysql")]
            Store::MySQL(_) => return Err(NotSnapshottable::DataStore("MySQL")),
            Store::Replicated(_) => {
                return Err(NotSnapshottable::DataStore("a replicated SQL database"));
            }
            Store::Ephemeral(_) | Store::None => {
                return Err(NotSnapshottable::DataStore("an in-memory store"));
            }
        };
        match blobs {
            BlobStore::Store(store) if store.is_same(self) => {
                Ok(SnapshotSource::DataOnly { data_path })
            }
            BlobStore::Fs(fs) => {
                let blob_path = fs.root().to_path_buf();
                // The blob files can't be told from the data store's own
                // in one directory. A blob directory that holds the data
                // store's is fine: the copy leaves that one out
                if data_path == blob_path {
                    return Err(NotSnapshottable::BlobStore(
                        "the data store's own directory",
                    ));
                }
                Ok(SnapshotSource::DataAndFiles {
                    data_path,
                    blob_path,
                })
            }
            BlobStore::Store(_) => Err(NotSnapshottable::BlobStore("another database")),
            #[cfg(feature = "s3")]
            BlobStore::S3(_) => Err(NotSnapshottable::BlobStore("S3")),
            #[cfg(feature = "azure")]
            BlobStore::Azure(_) => Err(NotSnapshottable::BlobStore("Azure")),
            BlobStore::Sharded(_) => Err(NotSnapshottable::BlobStore("a sharded set")),
            // inbuxa: blob-store-change spec, BM-8: blobs only an old store
            // has would be left out
            BlobStore::Moving(moving) if !moving.old_stores().is_empty() => {
                Err(NotSnapshottable::BlobStoreChanging)
            }
            BlobStore::Moving(moving) => self.snapshot_source(&moving.current),
        }
    }
}

/// What a copy of a tree did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TreeCopy {
    pub files: u64,
    pub bytes: u64,
    /// Files that couldn't be hard-linked and were copied.
    pub copied: u64,
}

/// SN-2, SN-3: every file under `from` into `to`, hard-linked where it can
/// be and copied where it can't, leaving out `skip` (the data store's
/// directory, with the snapshots in it). Names starting with a dot are
/// skipped: they're blobs being written (SN-10).
pub async fn copy_tree(from: PathBuf, to: PathBuf, skip: PathBuf) -> trc::Result<TreeCopy> {
    tokio::task::spawn_blocking(move || {
        let mut done = TreeCopy::default();
        copy_dir(&from, &to, &skip, &mut done).map(|_| done)
    })
    .await
    .map_err(|err| trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err))?
    .map_err(|err| trc::StoreEvent::FilesystemError.reason(err))
}

fn copy_dir(from: &Path, to: &Path, skip: &Path, done: &mut TreeCopy) -> io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.as_encoded_bytes().first() == Some(&b'.') {
            continue;
        }
        let (source, dest) = (entry.path(), to.join(&name));
        if source == skip {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_dir(&source, &dest, skip, done)?;
        } else if kind.is_file() {
            match std::fs::hard_link(&source, &dest) {
                Ok(()) => {}
                // Gone since it was listed: a purge ran before the hold, or
                // it's an orphan nothing links to
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    match std::fs::copy(&source, &dest) {
                        Ok(_) => {}
                        Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                        Err(err) => return Err(err),
                    }
                    done.copied += 1;
                }
            }
            done.files += 1;
            done.bytes += std::fs::metadata(&dest)?.len();
        }
    }
    Ok(())
}

/// Bytes in the files under `dir`.
pub async fn tree_size(dir: PathBuf) -> trc::Result<u64> {
    fn size(dir: &Path) -> io::Result<u64> {
        let mut total = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                total += size(&entry.path())?;
            } else if kind.is_file() {
                total += entry.metadata()?.len();
            }
        }
        Ok(total)
    }
    tokio::task::spawn_blocking(move || size(&dir))
        .await
        .map_err(|err| trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err))?
        .map_err(|err| trc::StoreEvent::FilesystemError.reason(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn copies_a_tree_and_skips_what_is_being_written() {
        let base = std::env::temp_dir().join(format!("inbuxa-sn-tree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let from = base.join("from");
        std::fs::create_dir_all(from.join("a/b")).unwrap();
        std::fs::write(from.join("a/b/BLOB1"), b"one").unwrap();
        std::fs::write(from.join("a/BLOB2"), b"two!").unwrap();
        std::fs::write(from.join("a/b/.BLOB3.1-0.tmp"), b"half").unwrap();
        std::fs::create_dir_all(from.join("rocks.db/snapshots")).unwrap();
        std::fs::write(from.join("rocks.db/000001.sst"), b"data").unwrap();

        let to = base.join("to");
        let done = copy_tree(from.clone(), to.clone(), from.join("rocks.db"))
            .await
            .unwrap();
        assert_eq!((done.files, done.bytes), (2, 7));
        assert_eq!(std::fs::read(to.join("a/b/BLOB1")).unwrap(), b"one");
        assert!(!to.join("a/b/.BLOB3.1-0.tmp").exists());
        assert!(!to.join("rocks.db").exists());
        assert_eq!(tree_size(to).await.unwrap(), 7);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_purge_waits_while_a_snapshot_holds_it() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!(blob_purge_may_run().is_some());
            let hold = hold_blob_purge().await;
            assert!(blob_purge_may_run().is_none());
            drop(hold);
            assert!(blob_purge_may_run().is_some());
        });
    }
}
