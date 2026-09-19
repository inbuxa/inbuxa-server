/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Read replicas across two nodes, from
//! `docs/spec/features/scale-out-storage.md` (test 11): a write on one node
//! is seen by a read on the other straight away, because the high-water
//! mark is shared (ST-7, step 2). Built with `postgres` and `redis`.

use crate::utils::{
    containers::{PG_REPLICA_CONTAINER, ensure_redis, psql},
    server::TestServerBuilder,
};
use registry::schema::structs::{Coordinator, InMemoryStore, RedisStore};
use std::time::{Duration, Instant};
use store::{
    SerializeInfallible, Store, U64_LEN, ValueKey,
    backend::scaleout::replica::{ReplicaState, ReplicatedStore, replica_read},
    write::{AnyClass, BatchBuilder, ValueClass},
};
use types::collection::{Collection, SyncCollection};

fn replicated(store: &Store) -> std::sync::Arc<ReplicatedStore> {
    match store {
        Store::Replicated(store) => store.clone(),
        other => panic!("the data store isn't replicated: {other:?}"),
    }
}

async fn wait_up(store: &ReplicatedStore, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while store.replicas[0].state() != ReplicaState::Up {
        assert!(
            Instant::now() < deadline,
            "{what}: the replica is {:?}",
            store.replicas[0].state()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn account_key(account_id: u32) -> ValueClass {
    let mut key = b"Rt".to_vec();
    key.extend_from_slice(&account_id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: store::SUBSPACE_PROPERTY,
        key,
    })
}

/// Test 11. `cargo test -p tests --features postgres,redis
/// replica_cluster_tests -- --ignored`, with
/// `STORE=PostgreSqlReplicated`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn replica_cluster_tests() {
    assert_eq!(
        std::env::var("STORE").as_deref(),
        Ok("PostgreSqlReplicated"),
        "run with STORE=PostgreSqlReplicated"
    );
    ensure_redis().await;
    let redis = || RedisStore {
        url: "redis://127.0.0.1".to_string(),
        ..Default::default()
    };

    // Node A is a server; node B is a second replicated store with its own
    // marks, as another node would have. Both share marks through Redis.
    let node_a = TestServerBuilder::new("replica_cluster_a")
        .await
        .with_default_listeners()
        .await
        .with_object(Coordinator::Redis(redis()))
        .await
        .with_object(InMemoryStore::Redis(redis()))
        .await
        .build()
        .await;
    let store_a = replicated(node_a.server.store());
    let shared = store::backend::redis::RedisStore::open_single(redis())
        .await
        .unwrap();
    store_a.share_marks(shared.clone());
    let node_b = crate::utils::storage::build_data_store(
        "PostgreSqlReplicated",
        node_a.temp_dir.path.to_str().unwrap(),
    )
    .await;
    let node_b = Store::build(node_b).await.unwrap();
    let store_b = replicated(&node_b);
    store_b.share_marks(shared);
    wait_up(&store_a, "node A").await;
    wait_up(&store_b, "node B").await;

    // Everything written so far reaches the replica, then replay stops
    tokio::time::sleep(Duration::from_secs(2)).await;
    psql(PG_REPLICA_CONTAINER, "SELECT pg_wal_replay_pause()");

    // Node A writes for the account, which assigns a change id
    let account_id = 1234u32;
    let value = store::rand::random::<u64>();
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Email)
        .log_container_insert(SyncCollection::Email)
        .set(account_key(account_id), value.serialize());
    node_a
        .server
        .store()
        .write(batch.build_all())
        .await
        .unwrap();

    // Node B reads it straight away, in a scope that may use the replica
    let read = replica_read([(account_id, 0)], async {
        node_b
            .get_value::<u64>(ValueKey::from(account_key(account_id)))
            .await
    })
    .await
    .unwrap();
    assert_eq!(
        read,
        Some(value),
        "test 11: node B must see node A's write (the replica is paused)"
    );
    let _ = U64_LEN;

    psql(PG_REPLICA_CONTAINER, "SELECT pg_wal_replay_resume()");
    node_a.temp_dir.delete();
}
