/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa-admin#257: one write at a time may grow a tenant's allocated disk
//! space. The lock lives in the in-memory store, so it holds across a
//! cluster: without it, two accounts given quotas at the same moment could
//! each fit the space left and together pass the tenant's limit. Taken
//! before the checks and released once the write is saved; one left behind
//! by a failed request expires on its own.

use common::{KV_LOCK_TASK, Server};
use std::time::Duration;

/// How long a lock outlives a request that never releases it.
const LOCK_SECONDS: u64 = 30;
/// How long to wait for another write to the same tenant, in all.
const WAIT_TRIES: u32 = 100;
const WAIT_STEP: Duration = Duration::from_millis(50);

/// What a write that couldn't get the lock is told.
pub const BUSY: &str = "Another change to this tenant's disk quotas is being saved. Try again.";

fn key(tenant_id: u32) -> Vec<u8> {
    [b"tenant-disk-quota:".as_slice(), &tenant_id.to_be_bytes()].concat()
}

/// Takes the tenant's lock, waiting up to five seconds for a write that
/// holds it. `false` when it's still held.
pub async fn acquire(server: &Server, tenant_id: u32) -> trc::Result<bool> {
    let key = key(tenant_id);
    for _ in 0..WAIT_TRIES {
        if server
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

/// Releases the tenant's lock. A failure only leaves it to expire.
pub async fn release(server: &Server, tenant_id: u32) {
    if let Err(err) = server
        .in_memory_store()
        .remove_lock(KV_LOCK_TASK, &key(tenant_id))
        .await
    {
        trc::error!(
            err.details("Failed to release a tenant's disk-quota lock")
                .ctx(trc::Key::Id, tenant_id)
        );
    }
}
