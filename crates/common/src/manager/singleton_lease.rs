/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: one node at a time does the cluster's singleton work (#437).
//!
//! Every node with the `taskScheduler` role used to queue its own copy of
//! each scheduled maintenance task, and every node with `metricsCalculate`
//! evaluated alerts and sent their emails, so each of those roles had to be
//! on exactly one node. Losing that node paused the work until it came back.
//!
//! Now each role has a lease in the store, taken with a compare-and-swap
//! like the store layout lease. Every node with the role tries for it each
//! minute; the one holding it renews it and does the work, the others wait.
//! A holder that stops renewing loses it when it runs out, and another node
//! with the role takes it over.
//!
//! A node without a cluster coordinator is on its own and needs no lease:
//! the role alone decides, as before.

use crate::{BuildServer, Inner, Server};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use store::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    rand::{RngExt, rng},
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue, now},
};
use trc::{AddContext, ClusterEvent, Collector, MetricType};

/// How long a lease lasts unless renewed.
pub const LEASE_SECONDS: u64 = 180;
/// How often each node with the role tries for its lease.
pub const ROUND: Duration = Duration::from_secs(60);
/// A holder stops acting this long before its lease runs out, so it has
/// stopped by the time another node can take the lease over.
const MARGIN: u64 = 15;

/// The roles only one node of a cluster acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingletonRole {
    /// Queues the scheduled maintenance tasks (`taskScheduler`).
    TaskScheduler,
    /// Calculates the cluster-wide gauges and evaluates alerts
    /// (`metricsCalculate`).
    Metrics,
}

impl SingletonRole {
    pub const ALL: [SingletonRole; 2] = [SingletonRole::TaskScheduler, SingletonRole::Metrics];

    /// Under `X` (cluster-wide singletons) in `_`.
    pub fn key(self) -> &'static [u8] {
        match self {
            SingletonRole::TaskScheduler => b"Xs",
            SingletonRole::Metrics => b"Xm",
        }
    }

    /// The task role's name, as cluster roles list it.
    pub fn name(self) -> &'static str {
        match self {
            SingletonRole::TaskScheduler => "taskScheduler",
            SingletonRole::Metrics => "metricsCalculate",
        }
    }

    fn index(self) -> usize {
        match self {
            SingletonRole::TaskScheduler => 0,
            SingletonRole::Metrics => 1,
        }
    }

    /// Whether this node has the role.
    pub fn assigned(self, server: &Server) -> bool {
        let roles = &server.core.network.roles;
        match self {
            SingletonRole::TaskScheduler => roles.task_scheduler,
            SingletonRole::Metrics => roles.metrics_calculate,
        }
    }
}

/// Which leases this node holds, and until when.
pub struct SingletonLeases {
    /// Says which leases are this process's.
    token: u64,
    held_until: [AtomicU64; 2],
}

impl Default for SingletonLeases {
    fn default() -> Self {
        SingletonLeases {
            token: rng().random(),
            held_until: Default::default(),
        }
    }
}

impl SingletonLeases {
    /// Whether this node holds `role`'s lease with time to spare.
    pub fn holds(&self, role: SingletonRole) -> bool {
        now() + MARGIN < self.held_until[role.index()].load(Ordering::Relaxed)
    }

    fn set(&self, role: SingletonRole, until: u64) {
        self.held_until[role.index()].store(until, Ordering::Relaxed);
    }
}

impl Server {
    /// Whether this node does `role`'s work now: it has the role, and, in a
    /// cluster, holds the role's lease.
    pub fn runs_singleton(&self, role: SingletonRole) -> bool {
        role.assigned(self)
            && (!self.core.storage.has_coordinator()
                || self.inner.data.singleton_leases.holds(role))
    }
}

struct Raw(Vec<u8>);

impl Deserialize for Raw {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Raw(bytes.to_vec()))
    }
}

fn lease_class(role: SingletonRole) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: role.key().to_vec(),
    })
}

/// A lease: the holder's token, when it runs out, then the holder's node id
/// (for the log only; the token says whose it is).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub token: u64,
    pub expires: u64,
    pub node_id: u16,
}

impl Lease {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(18);
        bytes.extend_from_slice(&self.token.to_be_bytes());
        bytes.extend_from_slice(&self.expires.to_be_bytes());
        bytes.extend_from_slice(&self.node_id.to_be_bytes());
        bytes
    }

    /// None for a value that can't be read, which counts as no lease.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Lease {
            token: u64::from_be_bytes(bytes.get(0..8)?.try_into().ok()?),
            expires: u64::from_be_bytes(bytes.get(8..16)?.try_into().ok()?),
            node_id: u16::from_be_bytes(bytes.get(16..18)?.try_into().ok()?),
        })
    }
}

fn is_assert_failure(err: &trc::Error) -> bool {
    matches!(
        err.as_ref(),
        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
    )
}

async fn current(store: &Store, role: SingletonRole) -> trc::Result<Option<Vec<u8>>> {
    Ok(store
        .get_value::<Raw>(ValueKey::from(lease_class(role)))
        .await
        .caused_by(trc::location!())?
        .map(|Raw(bytes)| bytes))
}

/// Who holds `role`'s lease, if it hasn't run out.
pub async fn holder(store: &Store, role: SingletonRole) -> trc::Result<Option<Lease>> {
    Ok(current(store, role)
        .await?
        .and_then(|bytes| Lease::from_bytes(&bytes))
        .filter(|lease| lease.expires > now()))
}

/// One round for `role`: takes the lease if nobody holds it or it ran out,
/// or renews it if it's `token`'s. Returns when it now runs out, or None
/// when another holder has it.
pub async fn try_hold(
    store: &Store,
    role: SingletonRole,
    token: u64,
    node_id: u16,
) -> trc::Result<Option<u64>> {
    let current = current(store, role).await?;
    if let Some(lease) = current.as_deref().and_then(Lease::from_bytes)
        && lease.token != token
        && lease.expires > now()
    {
        return Ok(None);
    }

    let expires = now() + LEASE_SECONDS;
    let mut batch = BatchBuilder::new();
    batch.assert_value(
        lease_class(role),
        current.as_deref().map_or(AssertValue::None, |bytes| {
            AssertValue::Hash(store::xxhash_rust::xxh3::xxh3_64(bytes))
        }),
    );
    batch.set(
        lease_class(role),
        Lease {
            token,
            expires,
            node_id,
        }
        .to_bytes(),
    );
    match store.write(batch.build_all()).await {
        Ok(_) => Ok(Some(expires)),
        // Another node took or renewed it in between
        Err(err) if is_assert_failure(&err) => Ok(None),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

/// Gives `role`'s lease up if it's `token`'s, so another node can take it
/// at its next round instead of waiting for it to run out.
pub async fn release(store: &Store, role: SingletonRole, token: u64) -> trc::Result<()> {
    let Some(bytes) = current(store, role).await? else {
        return Ok(());
    };
    if Lease::from_bytes(&bytes).is_none_or(|lease| lease.token != token) {
        return Ok(());
    }
    let mut batch = BatchBuilder::new();
    batch.assert_value(
        lease_class(role),
        AssertValue::Hash(store::xxhash_rust::xxh3::xxh3_64(&bytes)),
    );
    batch.clear(lease_class(role));
    match store.write(batch.build_all()).await {
        Ok(_) => Ok(()),
        Err(err) if is_assert_failure(&err) => Ok(()),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

/// Keeps this node's singleton leases: each round, every role the node has
/// is tried for, and a role it no longer has is given up.
pub fn spawn_singleton_leases(inner: Arc<Inner>) {
    tokio::spawn(async move {
        loop {
            let server = inner.build_server();
            if server.core.storage.has_coordinator() {
                for role in SingletonRole::ALL {
                    round(&server, role).await;
                }
            }
            tokio::time::sleep(ROUND).await;
        }
    });
}

/// Gives up every lease this node holds, as it stops, so another node with
/// the role, or this one once it's back, takes over at its next round
/// instead of when the lease runs out.
pub async fn release_singleton_leases(server: &Server) {
    let leases = &server.inner.data.singleton_leases;
    for role in SingletonRole::ALL {
        if leases.held_until[role.index()].swap(0, Ordering::Relaxed) == 0 {
            continue;
        }
        match release(server.store(), role, leases.token).await {
            Ok(()) => lost(role, "This node is stopping"),
            Err(err) => {
                // It runs out on its own
                trc::error!(err.details("Failed to give up a singleton role lease"));
            }
        }
    }
}

async fn round(server: &Server, role: SingletonRole) {
    let leases = &server.inner.data.singleton_leases;
    let token = leases.token;
    let store = server.store();
    let was_holding = leases.holds(role);

    if !role.assigned(server) {
        if was_holding {
            leases.set(role, 0);
            lost(role, "The role was taken off this node");
            if let Err(err) = release(store, role, token).await {
                trc::error!(err.details("Failed to give up a singleton role lease"));
            }
        }
        return;
    }

    match try_hold(store, role, token, server.registry().node_id()).await {
        Ok(Some(expires)) => {
            if !was_holding {
                if role == SingletonRole::Metrics {
                    // Carry on from the last holder's firing alerts, so an
                    // alert that's still firing isn't sent again
                    crate::telemetry::alerts::load_firing(store).await;
                }
                trc::event!(
                    Cluster(ClusterEvent::SingletonLeaseTaken),
                    Type = role.name(),
                    Id = server.registry().node_id(),
                    Expires = trc::Value::Timestamp(expires),
                );
            }
            leases.set(role, expires);
        }
        Ok(None) => {
            leases.set(role, 0);
            if was_holding {
                lost(role, "Another node holds the lease");
            }
        }
        // Keeps what it had: the lease runs out on its own if this goes on
        Err(err) => {
            trc::error!(err.details("Failed to renew a singleton role lease"));
        }
    }
}

/// A node that stopped doing the metrics work drops the cluster-wide queue
/// gauges it set, so only the holder shows them (#437). Prometheus reads
/// every node: `cluster.singleton-metrics` says which one holds the role.
pub fn clear_cluster_gauges() {
    for metric in [
        MetricType::ClusterSingletonMetrics,
        MetricType::QueueCount,
        MetricType::QueueOldestMessage,
    ] {
        Collector::update_gauge(metric, 0);
    }
}

fn lost(role: SingletonRole, why: &'static str) {
    if role == SingletonRole::Metrics {
        clear_cluster_gauges();
    }
    trc::event!(
        Cluster(ClusterEvent::SingletonLeaseLost),
        Type = role.name(),
        Reason = why,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lease_reads_back() {
        let lease = Lease {
            token: 7,
            expires: 1_234,
            node_id: 3,
        };
        assert_eq!(Lease::from_bytes(&lease.to_bytes()), Some(lease));
        // A value that can't be read counts as no lease
        assert_eq!(Lease::from_bytes(b"short"), None);
    }

    #[test]
    fn a_node_that_stops_calculating_drops_the_queue_gauges() {
        Collector::update_gauge(MetricType::QueueCount, 12);
        Collector::update_gauge(MetricType::QueueOldestMessage, 1_234);
        Collector::update_gauge(MetricType::ClusterSingletonMetrics, 1);
        lost(SingletonRole::Metrics, "test");
        for metric in [
            MetricType::QueueCount,
            MetricType::QueueOldestMessage,
            MetricType::ClusterSingletonMetrics,
        ] {
            assert_eq!(Collector::read_metric(metric), 0.0, "{metric:?}");
        }
        assert_eq!(
            MetricType::parse("cluster.singleton-metrics"),
            Some(MetricType::ClusterSingletonMetrics)
        );
    }

    #[test]
    fn a_holder_stops_before_its_lease_runs_out() {
        let leases = SingletonLeases::default();
        assert!(!leases.holds(SingletonRole::TaskScheduler));
        leases.set(SingletonRole::TaskScheduler, now() + LEASE_SECONDS);
        assert!(leases.holds(SingletonRole::TaskScheduler));
        assert!(!leases.holds(SingletonRole::Metrics));
        // Inside the margin it no longer acts, though the lease hasn't run out
        leases.set(SingletonRole::TaskScheduler, now() + MARGIN);
        assert!(!leases.holds(SingletonRole::TaskScheduler));
    }
}
