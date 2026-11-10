/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: what the blob-store-change spec
//! (docs/spec/features/blob-store-change.md) needs from the store: a blob
//! store that, while a change of blob store is unresolved, looks for what
//! it doesn't have in the stores the server used before, and keeps what it
//! finds there (BM-3). Writes and deletes go to the current store only,
//! except that while a change is planned, a delete also goes to the planned
//! store (blob-store-copy-ahead spec, CA-4).

use crate::BlobStore;
use arc_swap::{ArcSwap, ArcSwapOption};
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
use trc::StoreEvent;

/// A blob store the server used before an unresolved change.
#[derive(Clone)]
pub struct OldBlobStore {
    /// The `inbuxa:BlobStoreChange` that moved away from it.
    pub change_id: u32,
    pub store: BlobStore,
}

/// The blob store a planned change will move to (CA-1), which deletes
/// follow until the switch (CA-4).
#[derive(Clone)]
pub struct PlannedBlobStore {
    /// The planned `inbuxa:BlobStoreChange`.
    pub change_id: u32,
    pub store: BlobStore,
}

/// The current blob store, and the old ones read through while their
/// changes are unresolved, newest first (BM-3). The server keeps its blob
/// store in one of these from start-up, with no old stores at all most of
/// the time, so a planned store can be set while it runs (CA-3).
pub struct MovingBlobStore {
    pub current: BlobStore,
    old: ArcSwap<Vec<OldBlobStore>>,
    planned: ArcSwapOption<PlannedBlobStore>,
    /// The planned change whose store couldn't be opened, so it's reported
    /// once rather than at every refresh.
    planned_failed: AtomicU32,
    /// Where this node's blob store is (BM-1), as the node notes it with the
    /// changes it reads (blob-store-cleanup spec, OC-2).
    location: ArcSwapOption<String>,
}

impl MovingBlobStore {
    pub fn new(current: BlobStore, old: Vec<OldBlobStore>) -> Self {
        MovingBlobStore {
            current,
            old: ArcSwap::from_pointee(old),
            planned: ArcSwapOption::empty(),
            planned_failed: AtomicU32::new(0),
            location: ArcSwapOption::empty(),
        }
    }

    /// OC-2: where this node's blob store is, once start-up has said.
    pub fn location(&self) -> Option<Arc<String>> {
        self.location.load_full()
    }

    pub fn set_location(&self, location: String) {
        self.location.store(Some(Arc::new(location)));
    }

    /// CA-4: the planned store deletes go to, if a change is planned.
    pub fn planned(&self) -> Option<Arc<PlannedBlobStore>> {
        self.planned.load_full()
    }

    /// CA-3, CA-5: the planned store, or none once the change is switched to
    /// or dismissed.
    pub fn set_planned(&self, planned: Option<PlannedBlobStore>) {
        self.planned.store(planned.map(Arc::new));
    }

    /// Whether this planned change's store failed to open before; marks it
    /// so when `failed`.
    pub fn planned_open_failed(&self, change_id: u32, failed: bool) -> bool {
        if failed {
            self.planned_failed.swap(change_id, Ordering::Relaxed) == change_id
        } else {
            self.planned_failed
                .compare_exchange(change_id, 0, Ordering::Relaxed, Ordering::Relaxed)
                .ok();
            false
        }
    }

    /// CA-4: deletes from the current store, then from the planned one. An
    /// error from the planned store is logged, not returned.
    pub(crate) async fn raw_delete(&self, key: &[u8]) -> trc::Result<bool> {
        let deleted = Box::pin(self.current.raw_delete(key)).await?;
        if let Some(planned) = self.planned.load_full()
            && let Err(err) = Box::pin(planned.store.raw_delete(key)).await
        {
            trc::error!(
                err.details("Failed to delete a blob from the planned blob store")
                    .ctx(trc::Key::Id, planned.change_id)
                    .ctx(trc::Key::Key, key)
                    .caused_by(trc::location!())
            );
        }
        Ok(deleted)
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

    /// A blob store as the server holds it: in a [`MovingBlobStore`], so old
    /// and planned stores can be added while it runs (BM-3, CA-3).
    pub fn wrapped(self, old: Vec<OldBlobStore>) -> BlobStore {
        BlobStore::Moving(Arc::new(MovingBlobStore::new(self, old)))
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

    #[tokio::test]
    async fn deletes_follow_to_a_planned_store() {
        let root = std::env::temp_dir().join(format!("inbuxa-blob-plan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let current = fs_store(&root.join("current")).await;
        let planned = fs_store(&root.join("planned")).await;
        let moving = current.clone().wrapped(Vec::new());
        for key in [&b"copied-ahead"[..], b"kept"] {
            current
                .put_blob(key, b"mail", CompressionAlgo::None)
                .await
                .unwrap();
            planned
                .put_blob(key, b"mail", CompressionAlgo::None)
                .await
                .unwrap();
        }

        // Nothing planned: a delete touches the current store only
        moving.delete_blob(b"kept").await.unwrap();
        assert!(!current.blob_present(b"kept").await.unwrap());
        assert!(planned.blob_present(b"kept").await.unwrap());

        // Planned: it follows
        moving.moving().unwrap().set_planned(Some(PlannedBlobStore {
            change_id: 3,
            store: planned.clone(),
        }));
        moving.delete_blob(b"copied-ahead").await.unwrap();
        assert!(!current.blob_present(b"copied-ahead").await.unwrap());
        assert!(!planned.blob_present(b"copied-ahead").await.unwrap());

        // Writes and reads still go to the current store only (CA-3)
        moving
            .put_blob(b"fresh", b"new mail", CompressionAlgo::None)
            .await
            .unwrap();
        assert!(current.blob_present(b"fresh").await.unwrap());
        assert!(!planned.blob_present(b"fresh").await.unwrap());

        // A planned store that fails doesn't fail the delete
        let _ = std::fs::remove_dir_all(root.join("planned"));
        std::fs::write(root.join("planned"), b"not a directory").unwrap();
        assert!(moving.delete_blob(b"fresh").await.is_ok());
        assert!(!current.blob_present(b"fresh").await.unwrap());

        // Switched to or dismissed: deletes stop following
        moving.moving().unwrap().set_planned(None);
        assert!(moving.moving().unwrap().planned().is_none());

        // An open failure is reported once per change
        let m = moving.moving().unwrap();
        assert!(!m.planned_open_failed(4, true));
        assert!(m.planned_open_failed(4, true));
        assert!(!m.planned_open_failed(4, false));
        assert!(!m.planned_open_failed(4, true));

        let _ = std::fs::remove_dir_all(&root);
    }
}
