/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! #436: the defaults lease lets one node at a time set up the defaults.
//! Nodes are played by tasks sharing one store.

use common::manager::defaults_lease::{DefaultsLease, LEASE_KEY};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use store::{
    SUBSPACE_INBUXA, Store,
    backend::sqlite::SqliteStore,
    write::{AnyClass, BatchBuilder, ValueClass, now},
};

fn store() -> Store {
    Store::SQLite(SqliteStore::open_memory().unwrap().into())
}

/// A lease another node left, running out at `expires`.
async fn foreign_lease(store: &Store, expires: u64) {
    let mut value = 42u64.to_be_bytes().to_vec();
    value.extend_from_slice(&expires.to_be_bytes());
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_INBUXA,
            key: LEASE_KEY.to_vec(),
        }),
        value,
    );
    store.write(batch.build_all()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn one_node_at_a_time() {
    let store = store();
    let inside = Arc::new(AtomicBool::new(false));
    let turns = Arc::new(AtomicUsize::new(0));

    let nodes = (0..4)
        .map(|_| {
            let (store, inside, turns) = (store.clone(), inside.clone(), turns.clone());
            tokio::spawn(async move {
                for _ in 0..3 {
                    let lease = DefaultsLease::take(&store).await.unwrap();
                    assert!(
                        !inside.swap(true, Ordering::SeqCst),
                        "two nodes held the lease at once"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    inside.store(false, Ordering::SeqCst);
                    turns.fetch_add(1, Ordering::SeqCst);
                    lease.release(&store).await;
                }
            })
        })
        .collect::<Vec<_>>();
    for node in nodes {
        tokio::time::timeout(Duration::from_secs(30), node)
            .await
            .expect("a node never got the lease")
            .unwrap();
    }
    assert_eq!(turns.load(Ordering::SeqCst), 12);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_live_lease_blocks_and_one_run_out_does_not() {
    let store = store();

    // Another node is setting up the defaults: wait
    foreign_lease(&store, now() + 60).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), DefaultsLease::take(&store))
            .await
            .is_err(),
        "took a lease another node holds"
    );

    // That node stopped and its lease ran out: take it at once
    foreign_lease(&store, now() - 1).await;
    let started = Instant::now();
    let lease = DefaultsLease::take(&store).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));

    // Released, the next node gets it at once
    lease.release(&store).await;
    let started = Instant::now();
    DefaultsLease::take(&store)
        .await
        .unwrap()
        .release(&store)
        .await;
    assert!(started.elapsed() < Duration::from_secs(2));
}
