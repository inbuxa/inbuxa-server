/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CfHandle, RocksDbStore, cache::block_cache};
use crate::{
    backend::worker::{self, Access, BlockingPermits},
    *,
};
use ::registry::schema::structs;
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, MultiThreaded,
    OptimisticTransactionDB, Options,
};
use std::path::PathBuf;

const MIN_WRITE_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const MAX_WRITE_BUFFER_SIZE: usize = 64 * 1024 * 1024;
const MIN_DB_WRITE_BUFFER_SIZE: usize = 32 * 1024 * 1024;
const BLOOM_BITS_PER_KEY: f64 = 10.0;
const SCAN_BLOCK_SIZE: usize = 16 * 1024;
const CHURN_TARGET_FILE_SIZE: u64 = 16 * 1024 * 1024;
const CHURN_DELETION_WINDOW: usize = 4096;
const CHURN_DELETION_TRIGGER: usize = 1024;
const CHURN_DELETION_RATIO: f64 = 0.5;
const BYTES_PER_SYNC: u64 = 1024 * 1024;
const COLD_MIN_BLOB_SIZE: u64 = 16 * 1024;
const LOGS_PERIODIC_COMPACTION: u64 = 24 * 60 * 60;
const MAX_LOG_FILE_SIZE: usize = 10 * 1024 * 1024;
const KEEP_LOG_FILE_NUM: usize = 5;
const SCAN_FLUSH_SUBSPACES: [Subspace; 3] = [
    Subspace::QueueEvent,
    Subspace::SearchQueue,
    Subspace::TaskQueue,
];
const SCAN_FLUSH_OPTIONS: [(&str, &str); 2] = [
    ("memtable_op_scan_flush_trigger", "10000"),
    ("memtable_avg_op_scan_flush_trigger", "1000"),
];

#[derive(Clone, Copy)]
enum CfProfile {
    /// Read through `get_value` / `key_exists`, so a whole key bloom filter pays off.
    PointLookup,
    /// Read through `iterate`, which never consults a whole key bloom filter, and point
    /// read only on administrative paths, so no bloom filter is built.
    Scan,
    /// Scanned like `Scan` and also point read per message or per command (`get_value`, or
    /// the GetForUpdate behind `merge_fnc`), so a whole key bloom filter is built.
    ScanLookup,
    /// Point read and point deleted at a high rate.
    Churn,
    HashedChurn,
    /// Scanned from the oldest key and point deleted once consumed, with empty values.
    Queue,
    /// Counters, read for update and rewritten by every commit that changes them.
    Counter,
    /// Blob values held in RocksDB blob files.
    Blob,
    /// Write-once values, large ones offloaded to RocksDB blob files.
    Cold,
}

trait RocksDbProfile {
    fn profile(self) -> CfProfile;
}

impl RocksDbProfile for Subspace {
    fn profile(self) -> CfProfile {
        match self {
            Subspace::Counter => CfProfile::Counter,
            Subspace::Blobs => CfProfile::Blob,
            Subspace::Immutable => CfProfile::Cold,
            Subspace::Indexes
            | Subspace::Acl
            | Subspace::Logs
            | Subspace::TelemetryMetric
            | Subspace::RegistryIndex => CfProfile::Scan,
            Subspace::SearchTerm | Subspace::IndexProperty => CfProfile::ScanLookup,
            Subspace::BlobLink => CfProfile::HashedChurn,
            Subspace::TaskQueue
            | Subspace::DeletedItems
            | Subspace::QueueMessage
            | Subspace::ReportOut
            | Subspace::ReportIn
            | Subspace::SpamSamples => CfProfile::Churn,
            Subspace::Property
            | Subspace::Registry
            | Subspace::TelemetrySpan
            | Subspace::RegistryPrimaryKey
            | Subspace::Directory
            | Subspace::SearchDocument
            | Subspace::System => CfProfile::PointLookup,
            Subspace::QueueEvent | Subspace::SearchQueue => CfProfile::Queue,
        }
    }
}

impl RocksDbStore {
    pub async fn open(config: structs::RocksDbStore) -> Result<Store, String> {
        // Create the database directory if it doesn't exist
        let idx_path: PathBuf = PathBuf::from(config.path);
        std::fs::create_dir_all(&idx_path).map_err(|err| {
            format!(
                "Failed to create database directory {}: {:?}",
                idx_path.display(),
                err
            )
        })?;

        let cache = block_cache(config.cache_size);
        let write_buffer_size =
            ((config.buffer_size as usize) / 4).clamp(MIN_WRITE_BUFFER_SIZE, MAX_WRITE_BUFFER_SIZE);
        let mut cfs = Vec::new();

        for subspace in Subspace::ALL.iter().copied() {
            let profile = subspace.profile();
            let mut cf_opts = cf_options(profile, &cache, write_buffer_size);

            if let Some(min_blob_size) = match profile {
                CfProfile::Blob => Some(config.blob_size),
                CfProfile::Cold => Some(COLD_MIN_BLOB_SIZE),
                _ => None,
            } {
                cf_opts.set_enable_blob_files(true);
                cf_opts.set_min_blob_size(min_blob_size);
                cf_opts.set_blob_cache(&cache);
                cf_opts.set_enable_blob_gc(false);

                if matches!(profile, CfProfile::Cold) {
                    cf_opts.set_blob_compression_type(DBCompressionType::Lz4);
                }
            }

            if matches!(subspace, Subspace::Logs) {
                cf_opts.set_periodic_compaction_seconds(LOGS_PERIODIC_COMPACTION);
            }

            cfs.push(ColumnFamilyDescriptor::new(subspace.name(), cf_opts));
        }

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        db_opts.set_max_background_jobs(std::cmp::max(num_cpus::get() as i32, 3));
        db_opts.increase_parallelism(std::cmp::max(num_cpus::get() as i32, 3));
        db_opts
            .set_db_write_buffer_size((config.buffer_size as usize).max(MIN_DB_WRITE_BUFFER_SIZE));
        db_opts.set_bytes_per_sync(BYTES_PER_SYNC);
        db_opts.set_wal_bytes_per_sync(BYTES_PER_SYNC);
        db_opts.set_max_log_file_size(MAX_LOG_FILE_SIZE);
        db_opts.set_keep_log_file_num(KEEP_LOG_FILE_NUM);

        #[cfg(stalwart_tests)]
        if super::probe::COLLECT_STATISTICS.load(std::sync::atomic::Ordering::Relaxed) {
            db_opts.enable_statistics();
        }

        let pool_workers = worker::pool_workers(config.pool_workers);

        let db: OptimisticTransactionDB<MultiThreaded> =
            OptimisticTransactionDB::open_cf_descriptors(&db_opts, idx_path, cfs)
                .map_err(|err| format!("Failed to open database: {:?}", err))?;

        for subspace in SCAN_FLUSH_SUBSPACES {
            db.set_options_cf(&db.subspace_handle(subspace), &SCAN_FLUSH_OPTIONS)
                .map_err(|err| format!("Failed to set {} options: {:?}", subspace.name(), err))?;
        }

        Ok(Store::RocksDb(Arc::new(RocksDbStore {
            db: Arc::new(db),
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(pool_workers)
                .build()
                .map_err(|err| format!("Failed to build worker pool: {:?}", err))?,
            blocking: BlockingPermits::new(pool_workers),
            blob_gc: Default::default(),
            counter_slots: super::slots::CounterSlots::new(pool_workers),
            #[cfg(stalwart_tests)]
            probe: Default::default(),
        })))
    }

    pub(crate) fn spawn_worker<U, V>(&self, f: U) -> impl Future<Output = trc::Result<V>>
    where
        U: FnOnce() -> trc::Result<V> + Send + 'static,
        V: Send + 'static,
    {
        worker::spawn(&self.worker_pool, f)
    }

    pub(crate) fn block_reader<U, V>(&self, f: U) -> impl Future<Output = trc::Result<V>>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Send,
    {
        self.blocking.block(Access::Read, f)
    }

    pub(crate) fn block_writer<U, V>(&self, f: U) -> impl Future<Output = trc::Result<V>>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Send,
    {
        self.blocking.block(Access::Write, f)
    }
}

fn cf_options(profile: CfProfile, cache: &Cache, write_buffer_size: usize) -> Options {
    let mut block_opts = BlockBasedOptions::default();
    block_opts.set_block_cache(cache);
    block_opts.set_cache_index_and_filter_blocks(true);
    block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);

    let mut opts = Options::default();
    opts.set_write_buffer_size(write_buffer_size);
    opts.set_max_write_buffer_number(4);

    if !matches!(profile, CfProfile::Scan | CfProfile::Queue) {
        block_opts.set_bloom_filter(BLOOM_BITS_PER_KEY, false);
    }

    match profile {
        CfProfile::PointLookup => {
            opts.set_compression_type(DBCompressionType::Lz4);
        }
        CfProfile::Scan | CfProfile::ScanLookup => {
            block_opts.set_block_size(SCAN_BLOCK_SIZE);
            opts.set_compression_type(DBCompressionType::Lz4);
            opts.add_compact_on_deletion_collector_factory(
                CHURN_DELETION_WINDOW,
                CHURN_DELETION_TRIGGER,
                CHURN_DELETION_RATIO,
            );
        }
        CfProfile::Churn => {
            opts.set_compression_type(DBCompressionType::Lz4);
            opts.set_target_file_size_base(CHURN_TARGET_FILE_SIZE);
            opts.add_compact_on_deletion_collector_factory(
                CHURN_DELETION_WINDOW,
                CHURN_DELETION_TRIGGER,
                CHURN_DELETION_RATIO,
            );
        }
        CfProfile::HashedChurn => {
            opts.set_compression_type(DBCompressionType::Lz4);
            opts.set_target_file_size_base(CHURN_TARGET_FILE_SIZE);
        }
        CfProfile::Queue => {
            block_opts.set_block_size(SCAN_BLOCK_SIZE);
            opts.set_compression_type(DBCompressionType::None);
            opts.set_target_file_size_base(CHURN_TARGET_FILE_SIZE);
            opts.add_compact_on_deletion_collector_factory(
                CHURN_DELETION_WINDOW,
                CHURN_DELETION_TRIGGER,
                CHURN_DELETION_RATIO,
            );
        }
        CfProfile::Counter => {
            opts.set_compression_type(DBCompressionType::None);
        }
        CfProfile::Blob => {
            opts.set_compression_type(DBCompressionType::None);
        }
        CfProfile::Cold => {
            opts.set_compression_type(DBCompressionType::Lz4);
        }
    }

    opts.set_block_based_table_factory(&block_opts);

    opts
}
