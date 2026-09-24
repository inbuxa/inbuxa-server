/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Readiness that reflects the data store.
//!
//! /healthz/ready used to answer 200 whenever a data store was configured,
//! so a load balancer kept sending traffic to a node through a database
//! outage. It now reads one key from the data store, with a short time
//! limit, and caches the answer for a couple of seconds so probes can't load
//! the database. Liveness stays 200: restarting a node doesn't bring its
//! database back, and an orchestrator that restarts on failed liveness would
//! otherwise restart every node at once.

use crate::Server;
use parking_lot::Mutex;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use store::{ValueKey, write::ValueClass};

/// How long a probe's answer is reused.
pub const READY_CACHE: Duration = Duration::from_secs(2);
/// How long a probe waits for the data store.
pub const READY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
pub struct StoreHealth {
    last: Mutex<Option<(Instant, bool)>>,
    probing: AtomicBool,
}

/// Clears the probing flag even when the request is dropped mid-probe.
struct ProbeGuard<'x>(&'x AtomicBool);

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Server {
    /// Whether the data store answers: a cached result younger than
    /// READY_CACHE, or a fresh read bounded by READY_PROBE_TIMEOUT. While
    /// one probe is running, other callers get the last answer.
    pub async fn is_data_store_ready(&self) -> bool {
        let store = &self.core.storage.data;
        if store.is_none() {
            return false;
        }
        let health = &self.inner.data.store_health;
        let last = *health.last.lock();
        if let Some((at, ready)) = last
            && at.elapsed() < READY_CACHE
        {
            return ready;
        }
        if health.probing.swap(true, Ordering::AcqRel) {
            return last.is_none_or(|(_, ready)| ready);
        }
        let _guard = ProbeGuard(&health.probing);

        let ready = tokio::time::timeout(
            READY_PROBE_TIMEOUT,
            store.get_value::<u64>(ValueKey::from(ValueClass::Property(0))),
        )
        .await
        .is_ok_and(|result| result.is_ok());
        // Say so once per outage, not on every probe
        if !ready && last.is_none_or(|(_, ready)| ready) {
            trc::event!(
                Store(trc::StoreEvent::UnexpectedError),
                Details = "Readiness probe: the data store didn't answer",
                Limit = READY_PROBE_TIMEOUT,
            );
        }
        *health.last.lock() = Some((Instant::now(), ready));
        ready
    }
}
