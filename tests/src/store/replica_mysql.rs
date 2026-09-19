/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Read replicas on MySQL, from `docs/spec/features/scale-out-storage.md`
//! (tests 17, 18 and 19), against a source and a replica in containers:
//! one pair replicating with GTIDs, one by binary log position. Built with
//! `mysql`.

use crate::utils::{
    containers::{MYSQL_GTID_PORTS, MYSQL_POS_PORTS, mysql_query},
    server::TestServerBuilder,
};
use registry::schema::structs::{MySqlSettings, MySqlStore, SecretKeyOptional, SecretKeyValue};
use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use store::{
    Store,
    backend::scaleout::replica::{ReplicaState, ReplicatedStore},
};

const GTID_REPLICA: &str = "inbuxa-test-mysql-gtid-replica";
const POSITION_REPLICA: &str = "inbuxa-test-mysql-pos-replica";
const SECRET: &str = "mysql replica test passphrase";

async fn wait_for(store: &ReplicatedStore, state: ReplicaState, within: Duration, what: &str) {
    let deadline = Instant::now() + within;
    while store.replicas[0].state() != state {
        assert!(
            Instant::now() < deadline,
            "{what}: the replica is {:?}, not {state:?}",
            store.replicas[0].state()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn replicated(store: &Store) -> Arc<ReplicatedStore> {
    match store {
        Store::Replicated(store) => store.clone(),
        other => panic!("the data store isn't replicated: {other:?}"),
    }
}

fn message(subject: &str) -> Vec<u8> {
    format!(
        "From: sender@example.org\r\nTo: replica@example.org\r\nSubject: {subject}\r\n\r\nBody.\r\n"
    )
    .into_bytes()
}

fn settings(port: u16, user: &str, secret: &str) -> MySqlSettings {
    MySqlSettings {
        host: "localhost".into(),
        port: port as u64,
        database: "stalwart".into(),
        auth_username: user.to_string().into(),
        auth_secret: SecretKeyOptional::Value(SecretKeyValue {
            secret: secret.into(),
        }),
    }
}

async fn open(primary: u16, replica: MySqlSettings) -> Store {
    store::backend::mysql::MysqlStore::open(MySqlStore {
        host: "localhost".into(),
        port: primary as u64,
        auth_username: "root".to_string().into(),
        auth_secret: SecretKeyOptional::Value(SecretKeyValue {
            secret: "password".into(),
        }),
        database: "stalwart".into(),
        allow_invalid_certs: true,
        read_replicas: registry::types::list::List::from_iter([replica]),
        ..Default::default()
    })
    .await
    .unwrap()
}

/// Test 17: tests 9, 10 and 12 against a source and replica using GTIDs.
/// `cargo test -p tests --features mysql mysql_replica_tests -- --ignored`,
/// with `STORE=MySqlReplicated`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn mysql_replica_tests() {
    assert_eq!(
        std::env::var("STORE").as_deref(),
        Ok("MySqlReplicated"),
        "run with STORE=MySqlReplicated"
    );
    let test = TestServerBuilder::new("mysql_replica_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let store = replicated(test.server.store());
    wait_for(&store, ReplicaState::Up, Duration::from_secs(90), "ST-15").await;

    let admin = test.account("admin");
    let user = admin
        .create_user_account("replica@example.org", SECRET, "Replica", &[], vec![])
        .await;
    let client = user.jmap_client().await;
    let inbox = client
        .mailbox_query(
            jmap_client::mailbox::query::Filter::role(jmap_client::mailbox::Role::Inbox).into(),
            None::<Vec<_>>,
        )
        .await
        .unwrap()
        .take_ids()
        .pop()
        .unwrap();

    // Test 9: reads served by the replica (ST-6)
    let first = client
        .email_import(message("First"), [inbox.clone()], None::<Vec<String>>, None)
        .await
        .unwrap()
        .take_id();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before = store.replicas[0].reads.load(Ordering::Relaxed);
    assert!(
        client
            .email_get(&first, None::<Vec<_>>)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store.replicas[0].reads.load(Ordering::Relaxed) > before,
        "test 17: Email/get on the replica"
    );

    // Test 10: with the replica's applier stopped, a client reads its own
    // writes (ST-7)
    mysql_query(GTID_REPLICA, "STOP REPLICA SQL_THREAD");
    let paused = client
        .email_import(
            message("Paused"),
            [inbox.clone()],
            None::<Vec<String>>,
            None,
        )
        .await
        .unwrap()
        .take_id();
    assert!(
        client
            .email_get(&paused, None::<Vec<_>>)
            .await
            .unwrap()
            .is_some(),
        "test 17: a new message reads back"
    );

    // Test 12: over the lag limit, no reads; back once caught up (ST-10)
    let deadline = Instant::now() + Duration::from_secs(30);
    while store.replicas[0].state() != ReplicaState::Lagging {
        assert!(Instant::now() < deadline, "test 17: never over the limit");
        client
            .email_import(message("Lag"), [inbox.clone()], None::<Vec<String>>, None)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let before = store.replicas[0].reads.load(Ordering::Relaxed);
    assert!(
        client
            .email_get(&first, None::<Vec<_>>)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store.replicas[0].reads.load(Ordering::Relaxed),
        before,
        "test 17: no reads while lagging"
    );
    mysql_query(GTID_REPLICA, "START REPLICA SQL_THREAD");
    wait_for(&store, ReplicaState::Up, Duration::from_secs(30), "test 17").await;

    test.temp_dir.delete();
}

/// Tests 18 and 19: replication by binary log position, where lag comes
/// from `Seconds_Behind_Source`. `cargo test -p tests --features mysql
/// mysql_replica_position_tests -- --ignored`, with
/// `STORE=MySqlReplicatedPosition`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn mysql_replica_position_tests() {
    assert_eq!(
        std::env::var("STORE").as_deref(),
        Ok("MySqlReplicatedPosition"),
        "run with STORE=MySqlReplicatedPosition"
    );
    let test = TestServerBuilder::new("mysql_replica_position_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let store = replicated(test.server.store());
    // Test 18: with the privilege, lag is measured and the replica is used
    wait_for(&store, ReplicaState::Up, Duration::from_secs(90), "test 18").await;
    assert!(
        store.replicas[0].lag_ms.load(Ordering::Relaxed) < 5_000,
        "test 18: Seconds_Behind_Source"
    );

    // Test 18: without REPLICATION CLIENT, the lag can't be measured, so
    // the replica gets no reads
    let plain = replicated(
        &open(
            MYSQL_POS_PORTS.0,
            settings(MYSQL_POS_PORTS.1, "plain", "plain"),
        )
        .await,
    );
    wait_for(
        &plain,
        ReplicaState::Unmeasurable,
        Duration::from_secs(60),
        "test 18: no REPLICATION CLIENT",
    )
    .await;

    // Test 19: applying in parallel without preserving commit order
    mysql_query(POSITION_REPLICA, "STOP REPLICA");
    mysql_query(
        POSITION_REPLICA,
        "SET GLOBAL replica_preserve_commit_order=OFF; SET GLOBAL replica_parallel_workers=4",
    );
    mysql_query(POSITION_REPLICA, "START REPLICA");
    let parallel = replicated(
        &open(
            MYSQL_POS_PORTS.0,
            settings(MYSQL_POS_PORTS.1, "root", "password"),
        )
        .await,
    );
    wait_for(
        &parallel,
        ReplicaState::Excluded,
        Duration::from_secs(60),
        "test 19",
    )
    .await;
    mysql_query(POSITION_REPLICA, "STOP REPLICA");
    mysql_query(
        POSITION_REPLICA,
        "SET GLOBAL replica_parallel_workers=0; SET GLOBAL replica_preserve_commit_order=ON",
    );
    mysql_query(POSITION_REPLICA, "START REPLICA");

    test.temp_dir.delete();
}
