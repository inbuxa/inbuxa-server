/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::sync::Arc;

use rocksdb::{BoundColumnFamily, MultiThreaded, OptimisticTransactionDB};

use crate::{SUBSPACE_BLOBS, SUBSPACE_INDEXES, SUBSPACE_LOGS};

pub mod blob;
pub mod checkpoint; // inbuxa: store-snapshot spec
pub mod main;
pub mod read;
pub mod write;

static CF_LOGS: &str = crate::subspace_name(SUBSPACE_LOGS);
static CF_INDEXES: &str = crate::subspace_name(SUBSPACE_INDEXES);
static CF_BLOBS: &str = crate::subspace_name(SUBSPACE_BLOBS);

pub(crate) trait CfHandle {
    fn subspace_handle(&self, subspace: u8) -> Arc<BoundColumnFamily<'_>>;
}

impl CfHandle for OptimisticTransactionDB<MultiThreaded> {
    #[inline(always)]
    fn subspace_handle(&self, subspace: u8) -> Arc<BoundColumnFamily<'_>> {
        self.cf_handle(crate::subspace_name(subspace)).unwrap()
    }
}

pub struct RocksDbStore {
    db: Arc<OptimisticTransactionDB<MultiThreaded>>,
    worker_pool: rayon::ThreadPool,
}

#[inline(always)]
fn into_error(err: rocksdb::Error) -> trc::Error {
    trc::StoreEvent::RocksdbError.reason(err)
}
