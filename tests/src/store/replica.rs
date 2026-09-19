/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Read-replica acceptance tests, from
//! `docs/spec/features/scale-out-storage.md` (tests 9, 10, 12, 13, 14 and
//! 15), against a PostgreSQL primary with a streaming hot standby in
//! containers. Built with `postgres`.

use crate::utils::{
    containers::{
        PG_PRIMARY_CONTAINER, PG_REPLICA_CONTAINER, PG_REPLICA_PORT, docker, ensure_postgres, psql,
    },
    server::TestServerBuilder,
};
use jmap_client::email;
use registry::schema::structs::{
    Imap, PostgreSqlSettings, PostgreSqlStore, SecretKeyOptional, SecretKeyValue,
};
use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use store::{
    Store,
    backend::scaleout::replica::{ReplicaState, ReplicatedStore},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const SECRET: &str = "replica test user passphrase";

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

fn reads(store: &ReplicatedStore) -> u64 {
    store.replicas[0].reads.load(Ordering::Relaxed)
}

fn message(subject: &str) -> Vec<u8> {
    format!(
        "From: sender@example.org\r\nTo: replica@example.org\r\nSubject: {subject}\r\n\r\nBody of {subject}, with the word zebrafish.\r\n"
    )
    .into_bytes()
}

async fn imap_fetch() -> String {
    let stream = tokio::net::TcpStream::connect("127.0.0.1:9991")
        .await
        .unwrap();
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    lines.next_line().await.unwrap();
    let mut transcript = String::new();
    for (tag, command) in [
        ("a", format!("LOGIN \"replica@example.org\" \"{SECRET}\"")),
        ("b", "SELECT INBOX".to_string()),
        ("c", "FETCH 1 BODY.PEEK[]".to_string()),
        ("d", "LOGOUT".to_string()),
    ] {
        writer
            .write_all(format!("{tag} {command}\r\n").as_bytes())
            .await
            .unwrap();
        while let Ok(Ok(Some(line))) =
            tokio::time::timeout(Duration::from_secs(10), lines.next_line()).await
        {
            transcript.push_str(&line);
            transcript.push('\n');
            if line.starts_with(&format!("{tag} ")) {
                break;
            }
        }
    }
    transcript
}

/// `cargo test -p tests --features postgres replica_tests -- --ignored`,
/// with `STORE=PostgreSqlReplicated`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn replica_tests() {
    assert_eq!(
        std::env::var("STORE").as_deref(),
        Ok("PostgreSqlReplicated"),
        "run with STORE=PostgreSqlReplicated"
    );
    let test = TestServerBuilder::new("replica_tests")
        .await
        .with_default_listeners()
        .await
        .with_object(Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
        .await
        .build()
        .await;
    let replicated: Arc<ReplicatedStore> = match test.server.store() {
        Store::Replicated(store) => store.clone(),
        other => panic!("test 9: the data store isn't replicated: {other:?}"),
    };
    // ST-15: checked and in use
    wait_for(
        &replicated,
        ReplicaState::Up,
        Duration::from_secs(60),
        "ST-15",
    )
    .await;

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

    // Test 9: reads are served by the replica (ST-6)
    let first = client
        .email_import(message("First"), [inbox.clone()], None::<Vec<String>>, None)
        .await
        .unwrap()
        .take_id();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before = reads(&replicated);
    assert!(
        client
            .email_get(&first, None::<Vec<_>>)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        reads(&replicated) > before,
        "test 9: Email/get on the replica"
    );
    let before = reads(&replicated);
    let transcript = imap_fetch().await;
    assert!(
        transcript.contains("Subject: First"),
        "test 9: {transcript}"
    );
    assert!(reads(&replicated) > before, "test 9: FETCH on the replica");

    // Test 15: full-text search through the replicated store (ST-3, ST-6)
    tokio::time::sleep(Duration::from_secs(2)).await;
    let found = client
        .email_query(
            email::query::Filter::text("zebrafish").into(),
            None::<Vec<_>>,
        )
        .await
        .unwrap()
        .take_ids();
    assert!(found.contains(&first), "test 15: {found:?}");

    // Test 10: with replay paused, a client still reads its own writes (ST-7, ST-8)
    let state = client
        .email_changes("n", None)
        .await
        .unwrap()
        .new_state()
        .to_string();
    psql(PG_REPLICA_CONTAINER, "SELECT pg_wal_replay_pause()");
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
        "test 10: a new message reads back"
    );
    let changes = client.email_changes(state, None).await.unwrap();
    assert!(
        changes.created().contains(&paused),
        "test 10: Email/changes"
    );
    let renamed = client
        .mailbox_create("Before", None::<String>, jmap_client::mailbox::Role::None)
        .await
        .unwrap()
        .take_id();
    client.mailbox_rename(&renamed, "After").await.unwrap();
    assert_eq!(
        client
            .mailbox_get(&renamed, None::<Vec<_>>)
            .await
            .unwrap()
            .unwrap()
            .name(),
        Some("After"),
        "test 10: a renamed mailbox"
    );

    // Test 12: over the lag limit, no reads; back once caught up (ST-10, ST-11)
    let deadline = Instant::now() + Duration::from_secs(20);
    while replicated.replicas[0].state() != ReplicaState::Lagging {
        assert!(Instant::now() < deadline, "test 12: never over the limit");
        client
            .email_import(message("Lag"), [inbox.clone()], None::<Vec<String>>, None)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let before = reads(&replicated);
    assert!(
        client
            .email_get(&first, None::<Vec<_>>)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        reads(&replicated),
        before,
        "test 12: no reads while lagging"
    );
    psql(PG_REPLICA_CONTAINER, "SELECT pg_wal_replay_resume()");
    wait_for(
        &replicated,
        ReplicaState::Up,
        Duration::from_secs(20),
        "test 12",
    )
    .await;

    // Test 13: the replica stopped; requests still succeed (ST-12)
    docker("stop", PG_REPLICA_CONTAINER);
    for _ in 0..3 {
        assert!(
            client
                .email_get(&first, None::<Vec<_>>)
                .await
                .unwrap()
                .is_some(),
            "test 13: served while the replica is down"
        );
    }
    wait_for(
        &replicated,
        ReplicaState::Down,
        Duration::from_secs(15),
        "test 13",
    )
    .await;
    docker("start", PG_REPLICA_CONTAINER);
    wait_for(
        &replicated,
        ReplicaState::Up,
        Duration::from_secs(60),
        "test 13: back",
    )
    .await;

    // Test 14: a replica that is writable and unrelated, or the primary
    // itself, is left out (ST-15)
    ensure_postgres().await;
    let setting = |port: u16| PostgreSqlSettings {
        host: "localhost".into(),
        port: port as u64,
        database: "stalwart".into(),
        auth_username: "stalwart".to_string().into(),
        auth_secret: SecretKeyOptional::Value(SecretKeyValue {
            secret: "stalwart".into(),
        }),
        options: None,
    };
    for (port, what) in [
        (5432, "an unrelated database"),
        (5442, "the primary itself"),
    ] {
        let store = store::backend::postgres::PostgresStore::open(PostgreSqlStore {
            host: "localhost".into(),
            port: 5442,
            auth_username: "stalwart".to_string().into(),
            auth_secret: SecretKeyOptional::Value(SecretKeyValue {
                secret: "stalwart".into(),
            }),
            database: "stalwart".into(),
            read_replicas: registry::types::list::List::from_iter([setting(port)]),
            ..Default::default()
        })
        .await
        .unwrap();
        let Store::Replicated(store) = store else {
            panic!("test 14")
        };
        wait_for(
            &store,
            ReplicaState::Excluded,
            Duration::from_secs(20),
            &format!("test 14: {what}"),
        )
        .await;
    }
    let _ = (PG_PRIMARY_CONTAINER, PG_REPLICA_PORT);

    test.temp_dir.delete();
}
