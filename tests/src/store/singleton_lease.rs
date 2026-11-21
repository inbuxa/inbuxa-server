/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! #437: a singleton role's lease has one holder at a time, renews for its
//! holder, and passes to another node once it's given up or runs out.
//! Nodes are played by tokens sharing one store.

use common::manager::singleton_lease::{
    LEASE_SECONDS, Lease, SingletonRole, holder, release, try_hold,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use store::{
    SUBSPACE_INBUXA, Store,
    backend::sqlite::SqliteStore,
    write::{AnyClass, BatchBuilder, ValueClass, now},
};

const SCHEDULER: SingletonRole = SingletonRole::TaskScheduler;

fn store() -> Store {
    Store::SQLite(SqliteStore::open_memory().unwrap().into())
}

/// A lease node `node_id` (token `token`) left, running out at `expires`.
async fn write_lease(store: &Store, token: u64, node_id: u16, expires: u64) {
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_INBUXA,
            key: SCHEDULER.key().to_vec(),
        }),
        Lease {
            token,
            expires,
            node_id,
        }
        .to_bytes(),
    );
    store.write(batch.build_all()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn one_holder_among_many() {
    let store = store();
    let won = Arc::new(AtomicUsize::new(0));

    // Eight nodes try at once: exactly one gets it
    let nodes = (1..=8u64)
        .map(|token| {
            let (store, won) = (store.clone(), won.clone());
            tokio::spawn(async move {
                if try_hold(&store, SCHEDULER, token, token as u16)
                    .await
                    .unwrap()
                    .is_some()
                {
                    won.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect::<Vec<_>>();
    for node in nodes {
        node.await.unwrap();
    }
    assert_eq!(won.load(Ordering::SeqCst), 1, "not exactly one holder");

    // The holder renews it; the others still can't have it
    let lease = holder(&store, SCHEDULER).await.unwrap().unwrap();
    let renewed = try_hold(&store, SCHEDULER, lease.token, lease.node_id)
        .await
        .unwrap()
        .expect("the holder couldn't renew its lease");
    assert!(renewed >= lease.expires);
    for token in (1..=8u64).filter(|token| *token != lease.token) {
        assert_eq!(
            try_hold(&store, SCHEDULER, token, token as u16)
                .await
                .unwrap(),
            None,
            "node {token} took a lease another node holds"
        );
    }

    // The roles have leases of their own
    assert!(
        try_hold(&store, SingletonRole::Metrics, 99, 99)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lease_passes_on_when_it_runs_out_or_is_given_up() {
    let store = store();

    // Node 1 holds it: node 2 waits
    write_lease(&store, 1, 1, now() + LEASE_SECONDS).await;
    assert_eq!(try_hold(&store, SCHEDULER, 2, 2).await.unwrap(), None);

    // Node 1 stopped and its lease ran out: node 2 takes it over
    write_lease(&store, 1, 1, now() - 1).await;
    assert!(holder(&store, SCHEDULER).await.unwrap().is_none());
    let expires = try_hold(&store, SCHEDULER, 2, 2)
        .await
        .unwrap()
        .expect("node 2 didn't take over a lease that ran out");
    assert!(expires >= now() + LEASE_SECONDS - 1);
    assert_eq!(holder(&store, SCHEDULER).await.unwrap().unwrap().node_id, 2);

    // Node 1 comes back: it's node 2's now
    assert_eq!(try_hold(&store, SCHEDULER, 1, 1).await.unwrap(), None);

    // Giving up someone else's lease does nothing
    release(&store, SCHEDULER, 1).await.unwrap();
    assert_eq!(holder(&store, SCHEDULER).await.unwrap().unwrap().token, 2);

    // Node 2 gives it up (the role was taken off it): node 1 takes it at once
    release(&store, SCHEDULER, 2).await.unwrap();
    assert!(holder(&store, SCHEDULER).await.unwrap().is_none());
    assert!(try_hold(&store, SCHEDULER, 1, 1).await.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lease_that_cant_be_read_counts_as_none() {
    let store = store();
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_INBUXA,
            key: SCHEDULER.key().to_vec(),
        }),
        b"short".to_vec(),
    );
    store.write(batch.build_all()).await.unwrap();
    assert!(holder(&store, SCHEDULER).await.unwrap().is_none());
    assert!(try_hold(&store, SCHEDULER, 1, 1).await.unwrap().is_some());
}
