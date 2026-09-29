/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The compiled rules, kept per node so a message doesn't read the store.
//! A change made on this node applies at once; one made on another node
//! within [`TTL`], when the copy here is next refreshed.

use super::{engine::Compiled, rules};
use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use store::Store;

/// How long a node keeps its copy before reading the rules again.
pub const TTL: Duration = Duration::from_secs(30);

static CACHE: RwLock<Option<(Instant, Arc<Compiled>)>> = RwLock::new(None);

/// Forgets the copy, so the next message reads the rules again.
pub fn invalidate() {
    if let Ok(mut cache) = CACHE.write() {
        *cache = None;
    }
}

/// The enabled rules, compiled. A rule that no longer compiles is left out
/// and reported, once per refresh.
pub async fn compiled(data: &Store) -> trc::Result<Arc<Compiled>> {
    if let Ok(cache) = CACHE.read()
        && let Some((at, compiled)) = cache.as_ref()
        && at.elapsed() < TTL
    {
        return Ok(compiled.clone());
    }
    let (compiled, skipped) = Compiled::new(&rules::all(data).await?);
    for (id, reason) in skipped {
        trc::event!(
            Store(trc::StoreEvent::DataCorruption),
            Id = u64::from(id),
            Reason = reason,
            Details = "Mail rule skipped: it no longer compiles"
        );
    }
    let compiled = Arc::new(compiled);
    if let Ok(mut cache) = CACHE.write() {
        *cache = Some((Instant::now(), compiled.clone()));
    }
    Ok(compiled)
}
