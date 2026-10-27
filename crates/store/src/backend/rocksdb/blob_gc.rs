/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CfHandle, RocksDbStore, into_error};
use crate::Subspace;
use rocksdb::{
    BottommostLevelCompaction, BoundColumnFamily, CompactOptions, MultiThreaded,
    OptimisticTransactionDB,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::oneshot;

const BLOB_GC_GARBAGE_RATIO: u64 = 2;
const SETTLE_BACKOFF: u64 = 2;
const MIN_BLOB_GC_BYTES: u64 = 32 * 1024 * 1024;
const BLOB_GC_SUBSPACES: [Subspace; 2] = [Subspace::Blobs, Subspace::Immutable];
const LIVE_BLOB_BYTES: &str = "rocksdb.live-blob-file-size";
const BLOB_GARBAGE_BYTES: &str = "rocksdb.live-blob-file-garbage-size";
const TABLE_PROPERTIES: &str = "rocksdb.aggregated-table-properties";
const TABLE_ENTRIES: &str = "# entries=";
const TABLE_DELETIONS: &str = "# deletions=";
const TABLE_PROPERTY_DELIMITER: &str = "; ";
const MEMTABLE_ENTRIES: [&str; 2] = [
    "rocksdb.num-entries-active-mem-table",
    "rocksdb.num-entries-imm-mem-tables",
];
const MEMTABLE_DELETIONS: [&str; 2] = [
    "rocksdb.num-deletes-active-mem-table",
    "rocksdb.num-deletes-imm-mem-tables",
];
const ENABLE_BLOB_GC: [(&str, &str); 2] = [
    ("enable_blob_garbage_collection", "true"),
    ("blob_garbage_collection_age_cutoff", "1.0"),
];
const DISABLE_BLOB_GC: [(&str, &str); 1] = [("enable_blob_garbage_collection", "false")];
const BLOB_GC_THREAD: &str = "rocksdb-blob-gc";

type Db = OptimisticTransactionDB<MultiThreaded>;
type Cf<'db> = Arc<BoundColumnFamily<'db>>;
type Backoffs = [SettleBackoff; BLOB_GC_SUBSPACES.len()];

#[derive(Default)]
pub(super) struct BlobGcState {
    floors: [AtomicU64; BLOB_GC_SUBSPACES.len()],
    seen: [AtomicU64; BLOB_GC_SUBSPACES.len()],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SettleBackoff {
    floor: u64,
    seen: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlobBytes {
    total: u64,
    garbage: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingDeletes {
    entries: u64,
    deletions: u64,
}

impl RocksDbStore {
    pub(crate) async fn collect_blob_garbage(&self) -> trc::Result<()> {
        let db = self.db.clone();
        let backoffs = self.blob_gc.load();
        let (tx, rx) = oneshot::channel();
        std::thread::Builder::new()
            .name(BLOB_GC_THREAD.into())
            .spawn(move || {
                tx.send(run_pass(&db, backoffs)).ok();
            })
            .map_err(|err| trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err))?;
        let backoffs = rx
            .await
            .map_err(|err| trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err))??;
        self.blob_gc.store(backoffs);
        Ok(())
    }
}

impl BlobGcState {
    fn load(&self) -> Backoffs {
        std::array::from_fn(|family| SettleBackoff {
            floor: self.floors[family].load(Ordering::Relaxed),
            seen: self.seen[family].load(Ordering::Relaxed),
        })
    }

    fn store(&self, backoffs: Backoffs) {
        for ((floor, seen), backoff) in self.floors.iter().zip(&self.seen).zip(backoffs) {
            floor.store(backoff.floor, Ordering::Relaxed);
            seen.store(backoff.seen, Ordering::Relaxed);
        }
    }
}

impl SettleBackoff {
    fn observe(&mut self, deletions: u64) {
        if deletions <= self.seen {
            self.floor /= SETTLE_BACKOFF;
        }
        self.seen = deletions;
    }

    fn allows(self, deletions: u64) -> bool {
        deletions >= self.floor
    }

    fn after_settle(pending: u64, settled: u64) -> Self {
        Self {
            floor: pending.saturating_mul(SETTLE_BACKOFF),
            seen: settled,
        }
    }
}

fn run_pass(db: &Db, mut backoffs: Backoffs) -> trc::Result<Backoffs> {
    let mut opts = CompactOptions::default();
    opts.set_bottommost_level_compaction(BottommostLevelCompaction::ForceOptimized);

    for (subspace, backoff) in BLOB_GC_SUBSPACES.into_iter().zip(&mut backoffs) {
        let cf = db.subspace_handle(subspace);
        let mut bytes = BlobBytes::read(db, &cf)?;
        if bytes.total < MIN_BLOB_GC_BYTES {
            continue;
        }

        if !bytes.over_threshold() {
            let pending = PendingDeletes::read(db, &cf)?;
            backoff.observe(pending.deletions);
            if !backoff.allows(pending.deletions) || !bytes.with_pending(pending).over_threshold() {
                continue;
            }
            db.compact_range_cf_opt(&cf, None::<&[u8]>, None::<&[u8]>, &opts);
            bytes = BlobBytes::read(db, &cf)?;
            if bytes.total < MIN_BLOB_GC_BYTES || !bytes.over_threshold() {
                *backoff = SettleBackoff::after_settle(
                    pending.deletions,
                    PendingDeletes::read(db, &cf)?.deletions,
                );
                continue;
            }
        }

        db.set_options_cf(&cf, &ENABLE_BLOB_GC)
            .map_err(into_error)?;
        db.compact_range_cf_opt(&cf, None::<&[u8]>, None::<&[u8]>, &opts);
        db.set_options_cf(&cf, &DISABLE_BLOB_GC)
            .map_err(into_error)?;
        *backoff = SettleBackoff::default();
    }

    Ok(backoffs)
}

impl BlobBytes {
    fn read(db: &Db, cf: &Cf<'_>) -> trc::Result<Self> {
        Ok(Self {
            total: int_property(db, cf, LIVE_BLOB_BYTES)?,
            garbage: int_property(db, cf, BLOB_GARBAGE_BYTES)?,
        })
    }

    fn over_threshold(self) -> bool {
        self.garbage.saturating_mul(BLOB_GC_GARBAGE_RATIO) >= self.total
    }

    fn with_pending(self, pending: PendingDeletes) -> Self {
        let puts = pending.entries.saturating_sub(pending.deletions);
        let unaccounted = self.total.saturating_sub(self.garbage);
        let pending_garbage = match puts {
            0 => unaccounted,
            puts => u64::try_from(
                u128::from(unaccounted) * u128::from(pending.deletions) / u128::from(puts),
            )
            .unwrap_or(u64::MAX)
            .min(unaccounted),
        };
        Self {
            total: self.total,
            garbage: self.garbage + pending_garbage,
        }
    }
}

impl PendingDeletes {
    fn read(db: &Db, cf: &Cf<'_>) -> trc::Result<Self> {
        let tables = db
            .property_value_cf(cf, TABLE_PROPERTIES)
            .map_err(into_error)?
            .unwrap_or_default();
        let mut pending = Self::parse(&tables);
        for (entries, deletions) in MEMTABLE_ENTRIES.into_iter().zip(MEMTABLE_DELETIONS) {
            pending.entries += int_property(db, cf, entries)?;
            pending.deletions += int_property(db, cf, deletions)?;
        }
        Ok(pending)
    }

    fn parse(tables: &str) -> Self {
        let property = |name: &str| {
            tables
                .split(TABLE_PROPERTY_DELIMITER)
                .find_map(|property| property.strip_prefix(name)?.parse().ok())
                .unwrap_or(0)
        };
        Self {
            entries: property(TABLE_ENTRIES),
            deletions: property(TABLE_DELETIONS),
        }
    }
}

fn int_property(db: &Db, cf: &Cf<'_>, name: &str) -> trc::Result<u64> {
    db.property_int_value_cf(cf, name)
        .map(Option::unwrap_or_default)
        .map_err(into_error)
}

