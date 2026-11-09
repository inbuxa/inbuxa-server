/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: what the blob-store-change spec
//! (docs/spec/features/blob-store-change.md) needs from the store: a blob
//! store that, while a change of blob store is unresolved, looks for what
//! it doesn't have in the stores the server used before, and keeps what it
//! finds there (BM-3). Writes and deletes go to the current store only.

use crate::BlobStore;
use arc_swap::ArcSwap;
use std::sync::Arc;
use trc::StoreEvent;

/// A blob store the server used before an unresolved change.
#[derive(Clone)]
pub struct OldBlobStore {
    /// The `inbuxa:BlobStoreChange` that moved away from it.
    pub change_id: u32,
    pub store: BlobStore,
}

/// The current blob store, and the old ones read through while their
/// changes are unresolved, newest first (BM-3).
pub struct MovingBlobStore {
    pub current: BlobStore,
    old: ArcSwap<Vec<OldBlobStore>>,
}

impl MovingBlobStore {
    pub fn new(current: BlobStore, old: Vec<OldBlobStore>) -> Self {
        MovingBlobStore {
            current,
            old: ArcSwap::from_pointee(old),
        }
    }

    /// The old stores still read through.
    pub fn old_stores(&self) -> Arc<Vec<OldBlobStore>> {
        self.old.load_full()
    }

    /// BM-10: keeps only the old stores of changes still unresolved.
    pub fn retain_changes(&self, unresolved: &[u32]) {
        let old = self.old.load();
        if old.iter().all(|o| unresolved.contains(&o.change_id)) {
            return;
        }
        let kept = old
            .iter()
            .filter(|o| unresolved.contains(&o.change_id))
            .cloned()
            .collect::<Vec<_>>();
        self.old.store(Arc::new(kept));
    }

    /// BM-3: the blob as the current store has it or, failing that, as the
    /// newest old store that has it does. A blob found in an old store is
    /// written to the current one under the same key, as it was stored.
    pub(crate) async fn raw_get(&self, key: &[u8]) -> trc::Result<Option<Vec<u8>>> {
        if let Some(data) = Box::pin(self.current.raw_get(key)).await? {
            return Ok(Some(data));
        }
        let old = self.old.load_full();
        for old in old.iter() {
            match Box::pin(old.store.raw_get(key)).await {
                Ok(Some(data)) => {
                    if let Err(err) = Box::pin(self.current.raw_put(key, &data)).await {
                        trc::error!(
                            err.details("Failed to keep a blob read through an old blob store")
                                .ctx(trc::Key::Id, old.change_id)
                                .ctx(trc::Key::Key, key)
                        );
                    }
                    trc::event!(
                        Store(StoreEvent::BlobReadThrough),
                        Key = key,
                        Id = old.change_id,
                        Size = data.len(),
                    );
                    return Ok(Some(data));
                }
                Ok(None) => {}
                Err(err) => {
                    // An old store that fails is skipped, not fatal: the
                    // current store answered, and it had nothing
                    trc::error!(
                        err.details("An old blob store failed to read")
                            .ctx(trc::Key::Id, old.change_id)
                            .ctx(trc::Key::Key, key)
                            .caused_by(trc::location!())
                    );
                }
            }
        }
        Ok(None)
    }

    /// Whether a read would find the blob: in the current store or in an
    /// old one still read through.
    pub(crate) async fn blob_present(&self, key: &[u8]) -> trc::Result<bool> {
        if Box::pin(self.current.blob_present(key)).await? {
            return Ok(true);
        }
        for old in self.old.load_full().iter() {
            if Box::pin(old.store.blob_present(key)).await.unwrap_or(false) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl BlobStore {
    /// The store blobs are written to: past any old stores read through.
    pub fn current(&self) -> &BlobStore {
        match self {
            BlobStore::Moving(moving) => moving.current.current(),
            store => store,
        }
    }

    /// The read-through wrapper, when there is one (BM-3).
    pub fn moving(&self) -> Option<&Arc<MovingBlobStore>> {
        match self {
            BlobStore::Moving(moving) => Some(moving),
            _ => None,
        }
    }

    /// A blob exactly as the backend keeps it, compression marker and all,
    /// without reading through (BM-5: a copy reads the old store itself).
    pub async fn get_stored(&self, key: &[u8]) -> trc::Result<Option<Vec<u8>>> {
        self.current().raw_get(key).await
    }

    /// Writes a blob exactly as [`BlobStore::get_stored`] gave it (BM-5).
    pub async fn put_stored(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        self.current().raw_put(key, data).await
    }

    /// Whether the store itself has the blob, not reading through (BM-5).
    pub async fn stored_present(&self, key: &[u8]) -> trc::Result<bool> {
        self.current().blob_present(key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompressionAlgo, backend::fs::FsStore};
    use registry::schema::structs;

    async fn fs_store(dir: &std::path::Path) -> BlobStore {
        FsStore::open(structs::FileSystemStore {
            path: dir.to_string_lossy().into_owned(),
            depth: 2,
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn reads_through_and_keeps_what_it_found() {
        let root = std::env::temp_dir().join(format!("inbuxa-blob-move-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let old = fs_store(&root.join("old")).await;
        let new = fs_store(&root.join("new")).await;
        old.put_blob(b"left-behind", b"hello", CompressionAlgo::Lz4)
            .await
            .unwrap();

        let moving = BlobStore::Moving(Arc::new(MovingBlobStore::new(
            new.clone(),
            vec![OldBlobStore {
                change_id: 7,
                store: old.clone(),
            }],
        )));

        // Only the old store has it: read through, then kept in the new one
        assert!(!new.blob_present(b"left-behind").await.unwrap());
        assert!(moving.blob_present(b"left-behind").await.unwrap());
        assert!(!moving.stored_present(b"left-behind").await.unwrap());
        assert_eq!(
            moving
                .get_blob(b"left-behind", 0..usize::MAX)
                .await
                .unwrap()
                .as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(
            new.get_blob(b"left-behind", 0..usize::MAX)
                .await
                .unwrap()
                .as_deref(),
            Some(&b"hello"[..])
        );

        // In neither: absent
        assert_eq!(
            moving.get_blob(b"nowhere", 0..usize::MAX).await.unwrap(),
            None
        );

        // Writes and deletes touch only the new store
        moving
            .put_blob(b"fresh", b"new mail", CompressionAlgo::None)
            .await
            .unwrap();
        assert!(new.blob_present(b"fresh").await.unwrap());
        assert!(!old.blob_present(b"fresh").await.unwrap());
        moving.delete_blob(b"left-behind").await.unwrap();
        assert!(!new.blob_present(b"left-behind").await.unwrap());
        assert!(old.blob_present(b"left-behind").await.unwrap());

        // Once the change is resolved, nothing more is read through
        moving.moving().unwrap().retain_changes(&[]);
        assert!(moving.moving().unwrap().old_stores().is_empty());
        assert_eq!(
            moving
                .get_blob(b"left-behind", 0..usize::MAX)
                .await
                .unwrap(),
            None
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
