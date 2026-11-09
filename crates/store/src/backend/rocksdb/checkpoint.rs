/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: a checkpoint of the store (store-snapshot spec, SN-2): every
//! column family at one point in time, hard-linked where it can be.

use super::{RocksDbStore, into_error};
use rocksdb::checkpoint::Checkpoint;
use std::path::{Path, PathBuf};

impl RocksDbStore {
    /// The store's directory.
    pub fn path(&self) -> &Path {
        self.db.path()
    }

    /// Writes a checkpoint to `dest`, which must not exist yet.
    pub async fn checkpoint(&self, dest: PathBuf) -> trc::Result<()> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            Checkpoint::new(&*db)
                .and_then(|checkpoint| checkpoint.create_checkpoint(&dest))
                .map_err(into_error)
        })
        .await
        .map_err(|err| trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err))?
    }
}
