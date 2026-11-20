/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! One write at a time may grow a tenant's counted totals: its objects
//! against the count limits (MT-17) and the disk space its accounts are
//! given (inbuxa-admin#257). Without it, two writes at the same moment could
//! each find room for one more and together pass the limit. The lock lives
//! in the in-memory store, so it holds across a cluster. A write takes it
//! before its tenancy checks and releases it once saved; one left behind by
//! a failed request expires on its own. A write holds at most one tenant's
//! lock, so two can't wait on each other.

use crate::{KV_LOCK_TASK, Server};
use std::time::Duration;

/// How long a lock outlives a request that never releases it.
const LOCK_SECONDS: u64 = 30;
/// How long to wait for another write to the same tenant, in all.
const WAIT_TRIES: u32 = 100;
const WAIT_STEP: Duration = Duration::from_millis(50);

/// What a write that couldn't get the lock is told.
pub const BUSY: &str = "Another change to this tenant's limits is being saved. Try again.";

// The key the disk-quota lock used, kept so nodes on either version share
// one lock during a rolling upgrade
fn key(tenant_id: u32) -> Vec<u8> {
    [b"tenant-disk-quota:".as_slice(), &tenant_id.to_be_bytes()].concat()
}

impl Server {
    /// Takes the tenant's write lock, waiting up to five seconds for a write
    /// that holds it. `false` when it's still held.
    pub async fn lock_tenant_writes(&self, tenant_id: u32) -> trc::Result<bool> {
        let key = key(tenant_id);
        for _ in 0..WAIT_TRIES {
            if self
                .in_memory_store()
                .try_lock(KV_LOCK_TASK, &key, LOCK_SECONDS)
                .await?
            {
                return Ok(true);
            }
            tokio::time::sleep(WAIT_STEP).await;
        }
        Ok(false)
    }

    /// Releases the tenant's write lock. A failure only leaves it to expire.
    pub async fn unlock_tenant_writes(&self, tenant_id: u32) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_TASK, &key(tenant_id))
            .await
        {
            trc::error!(
                err.details("Failed to release a tenant's write lock")
                    .ctx(trc::Key::Id, tenant_id)
            );
        }
    }
}
