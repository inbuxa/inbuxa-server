/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: the store version mark. A store without it gets it on start, a
//! marked store is left alone, and a store marked by a newer release is
//! refused before anything is written to it. A store opened for the first
//! time has upstream's web interface switched off (docs/spec/import-0.16.md).
//! A store at an older layout version is brought up to this one, by one node
//! at a time (docs/spec/features/store-layout.md). Step 2 -> 3 moves the
//! audit log, journal, holds and undelete notes out of `_`.

use crate::utils::server::TestServerBuilder;
use common::{
    INBUXA_STORE_VERSION, INBUXA_STORE_VERSION_KEY, Server,
    manager::first_party::disable_imported_web_interface,
};
use futures::FutureExt;
use inbuxa_features::audit::{Action, Actor, AuditLog, Outcome, Record, Target, log};
use registry::{
    schema::{prelude::ObjectInner, structs::Application},
    types::map::Map,
};
use std::{panic::AssertUnwindSafe, time::Duration};
use store::{
    Deserialize, InMemoryStore, IterateParams, SUBSPACE_AUDIT, SUBSPACE_HOLDS, SUBSPACE_INBUXA,
    SUBSPACE_JOURNAL, SUBSPACE_UNDELETE, SerializeInfallible, Store, ValueKey,
    dispatch::lookup::KeyValue,
    registry::{bootstrap::Bootstrap, write::RegistryWrite},
    write::{AnyClass, AnyKey, BatchBuilder, InMemoryClass, Operation, ValueClass, ValueOp, now},
};

const UPSTREAM_WEBUI: &str =
    "https://github.com/stalwartlabs/webui/releases/download/v1.0.11/webui.zip";

async fn read_mark(server: &Server) -> Option<u32> {
    server
        .store()
        .get_value::<u32>(AnyKey {
            subspace: SUBSPACE_INBUXA,
            key: INBUXA_STORE_VERSION_KEY.to_vec(),
        })
        .await
        .unwrap()
}

async fn write_mark(server: &Server, version: Option<u32>) {
    let class = ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: INBUXA_STORE_VERSION_KEY.to_vec(),
    });
    let mut batch = BatchBuilder::new();
    match version {
        Some(version) => batch.set(class, version.serialize()),
        None => batch.clear(class),
    };
    server.store().write(batch.build_all()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn store_version() {
    let test = TestServerBuilder::new("store_version")
        .await
        .disable_services()
        .build()
        .await;
    let server = &test.server;

    println!("Running store version tests...");

    // A store from before the mark (or from Stalwart) gets it on start.
    write_mark(server, None).await;
    migration::try_migrate(server).await.unwrap();
    assert_eq!(read_mark(server).await, Some(INBUXA_STORE_VERSION));

    // Starting again leaves it as it is.
    migration::try_migrate(server).await.unwrap();
    assert_eq!(read_mark(server).await, Some(INBUXA_STORE_VERSION));

    // A store marked by a newer release is refused, and the mark stays.
    let newer = INBUXA_STORE_VERSION + 1;
    write_mark(server, Some(newer)).await;
    let result = AssertUnwindSafe(migration::try_migrate(server))
        .catch_unwind()
        .await;
    assert!(result.is_err(), "a store marked newer must be refused");
    assert_eq!(read_mark(server).await, Some(newer));

    // Put back, so the store is usable again.
    write_mark(server, Some(INBUXA_STORE_VERSION)).await;
    migration::try_migrate(server).await.unwrap();

    layout_step_1_2(server).await;
    layout_lease(server).await;
    layout_step_2_3(server).await;
}

/// A counter the way a version 1 store holds it: a row in `y` and an expiry
/// marker in `m`.
async fn seed_v1_counter(store: &Store, key: &[u8], value: i64, expires_at: u64) {
    let mut batch = BatchBuilder::new();
    batch.any_op(Operation::Value {
        class: ValueClass::InMemory(InMemoryClass::Counter(key.to_vec())),
        op: ValueOp::AddAndGet(value),
    });
    batch.any_op(Operation::Value {
        class: ValueClass::InMemory(InMemoryClass::Key(key.to_vec())),
        op: ValueOp::Set(
            [0u64.to_be_bytes(), expires_at.to_be_bytes()]
                .concat()
                .into(),
        ),
    });
    store.write(batch.build_all()).await.unwrap();
}

/// The counter markers left in `m`.
async fn counter_markers(store: &Store) -> usize {
    let mut markers = 0;
    store
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![0u8]))),
                ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![u8::MAX; 10]))),
            ),
            |_, value| {
                if value.get(..8) == Some(&[0u8; 8][..]) {
                    markers += 1;
                }
                Ok(true)
            },
        )
        .await
        .unwrap();
    markers
}

// SL-11, SL-22: a version 1 store's counters on SQL get their expiry in
// their own row and lose their markers; other keys stay; a second run
// changes nothing. On RocksDB and FoundationDB only the mark moves.
async fn layout_step_1_2(server: &Server) {
    let InMemoryStore::Store(memory) = server.in_memory_store().clone() else {
        return;
    };
    let in_memory = server.in_memory_store();
    let sql = memory.counters_keep_expiry();
    let soon = now() + 3;

    seed_v1_counter(&memory, b"layout-live", 5, now() + 3600).await;
    seed_v1_counter(&memory, b"layout-soon", 7, soon).await;
    seed_v1_counter(&memory, b"layout-gone", 9, now() - 10).await;
    in_memory
        .key_set(KeyValue::new(b"layout-key".to_vec(), b"kept".to_vec()).expires(3600))
        .await
        .unwrap();
    assert_eq!(counter_markers(&memory).await, 3);

    write_mark(server, Some(1)).await;
    migration::try_migrate(server).await.unwrap();
    assert_eq!(read_mark(server).await, Some(INBUXA_STORE_VERSION));

    for _ in 0..2 {
        assert_eq!(
            in_memory
                .counter_get(b"layout-live".to_vec())
                .await
                .unwrap(),
            5
        );
        assert_eq!(
            in_memory
                .counter_get(b"layout-soon".to_vec())
                .await
                .unwrap(),
            7
        );
        assert_eq!(
            in_memory
                .key_get::<String>(b"layout-key".to_vec())
                .await
                .unwrap()
                .as_deref(),
            Some("kept")
        );
        if sql {
            assert_eq!(counter_markers(&memory).await, 0, "markers left on SQL");
            assert_eq!(
                in_memory
                    .counter_get(b"layout-gone".to_vec())
                    .await
                    .unwrap(),
                0
            );
        } else {
            assert_eq!(counter_markers(&memory).await, 3, "markers moved off SQL");
        }

        // Again from the start, as after a step stopped half-way
        write_mark(server, Some(1)).await;
        migration::layout::run_steps(server, server.registry().node_id())
            .await
            .unwrap();
        assert_eq!(read_mark(server).await, Some(INBUXA_STORE_VERSION));
    }

    // The purge finds the moved expiry
    tokio::time::sleep(Duration::from_secs(soon + 1 - now().min(soon + 1))).await;
    in_memory.purge_in_memory_store().await.unwrap();
    assert_eq!(
        in_memory
            .counter_get(b"layout-soon".to_vec())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        in_memory
            .counter_get(b"layout-live".to_vec())
            .await
            .unwrap(),
        5
    );

    in_memory.key_delete(b"layout-key".to_vec()).await.unwrap();
    for key in [b"layout-live".as_slice(), b"layout-soon", b"layout-gone"] {
        let mut batch = BatchBuilder::new();
        batch.clear(ValueClass::InMemory(InMemoryClass::Counter(key.to_vec())));
        batch.clear(ValueClass::InMemory(InMemoryClass::Key(key.to_vec())));
        memory.write(batch.build_all()).await.unwrap();
    }
}

async fn write_lease(server: &Server, node_id: u16, expires_at: u64) {
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_INBUXA,
            key: migration::layout::LAYOUT_LEASE_KEY.to_vec(),
        }),
        [node_id.to_be_bytes().as_slice(), &expires_at.to_be_bytes()].concat(),
    );
    server.store().write(batch.build_all()).await.unwrap();
}

async fn lease_held(server: &Server) -> bool {
    server
        .store()
        .get_value::<u64>(AnyKey {
            subspace: SUBSPACE_INBUXA,
            key: migration::layout::LAYOUT_LEASE_KEY.to_vec(),
        })
        .await
        .unwrap()
        .is_some()
}

// SL-3: a node that can't take the lease waits for the mark; a lease that
// ran out is taken over; two nodes starting together both come up.
async fn layout_lease(server: &Server) {
    // Held by another node: wait, then go on once the mark moves
    write_mark(server, Some(1)).await;
    write_lease(server, 900, now() + 600).await;
    let waiting = {
        let server = server.clone();
        tokio::spawn(async move { migration::layout::run_steps(&server, 901).await })
    };
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !waiting.is_finished(),
        "ran the steps under another node's lease"
    );
    assert_eq!(read_mark(server).await, Some(1));
    write_mark(server, Some(INBUXA_STORE_VERSION)).await;
    tokio::time::timeout(Duration::from_secs(15), waiting)
        .await
        .expect("still waiting after the mark moved")
        .unwrap()
        .unwrap();

    // Ran out: taken over, and released after
    write_mark(server, Some(1)).await;
    write_lease(server, 900, now() - 1).await;
    tokio::time::timeout(
        Duration::from_secs(5),
        migration::layout::run_steps(server, 901),
    )
    .await
    .expect("an expired lease was not taken over")
    .unwrap();
    assert_eq!(read_mark(server).await, Some(INBUXA_STORE_VERSION));
    assert!(!lease_held(server).await, "lease not released");

    // Two nodes together
    write_mark(server, Some(1)).await;
    let nodes = [902u16, 903].map(|node_id| {
        let server = server.clone();
        tokio::spawn(async move { migration::layout::run_steps(&server, node_id).await })
    });
    for node in nodes {
        tokio::time::timeout(Duration::from_secs(30), node)
            .await
            .expect("a node never came up")
            .unwrap()
            .unwrap();
    }
    assert_eq!(read_mark(server).await, Some(INBUXA_STORE_VERSION));
    assert!(!lease_held(server).await, "lease not released");
}

async fn applications(server: &Server) -> Vec<(String, bool)> {
    let mut apps = server
        .registry()
        .list::<Application>()
        .await
        .unwrap()
        .into_iter()
        .map(|app| (app.object.resource_url, app.object.enabled))
        .collect::<Vec<_>>();
    apps.sort();
    apps
}

#[tokio::test(flavor = "multi_thread")]
async fn imported_web_interface() {
    // A store brought over from Stalwart: no mark yet, and upstream's web
    // interface listed and on, beside an application of the operator's own.
    let app = |url: &str| Application {
        enabled: true,
        description: "Web interface".to_string(),
        resource_url: url.to_string(),
        url_prefix: Map::new(vec!["/admin".to_string()]),
        ..Default::default()
    };
    let test = TestServerBuilder::new("imported_web_interface")
        .await
        .with_object(app(UPSTREAM_WEBUI))
        .await
        .with_object(app("https://127.0.0.1/own-app.zip"))
        .await
        .disable_services()
        .build()
        .await;
    let server = &test.server;

    println!("Running imported web interface tests...");

    // Starting switched upstream's off and kept the record; the other is on.
    assert_eq!(
        applications(server).await,
        vec![
            ("https://127.0.0.1/own-app.zip".to_string(), true),
            (UPSTREAM_WEBUI.to_string(), false),
        ]
    );

    // Once the store has its version, an operator who switches it back on
    // keeps it on.
    migration::try_migrate(server).await.unwrap();
    let upstream = server
        .registry()
        .list::<Application>()
        .await
        .unwrap()
        .into_iter()
        .find(|app| app.object.resource_url == UPSTREAM_WEBUI)
        .unwrap();
    let mut on = upstream.object.clone();
    on.enabled = true;
    let current = registry::schema::prelude::Object::with_revision(
        ObjectInner::from(upstream.object),
        upstream.revision,
    );
    server
        .registry()
        .write(RegistryWrite::update(
            upstream.id.id(),
            &on.into(),
            &current,
        ))
        .await
        .unwrap();
    let mut bp = Bootstrap::new(server.registry().clone()).await;
    disable_imported_web_interface(&mut bp).await.unwrap();
    assert!(
        applications(server)
            .await
            .contains(&(UPSTREAM_WEBUI.to_string(), true)),
        "a marked store's web interface is left as the operator set it"
    );
}

struct Raw(Vec<u8>);

impl Deserialize for Raw {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Raw(bytes.to_vec()))
    }
}

/// Every row of a subspace, keys as stored.
async fn rows(store: &Store, subspace: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::new();
    store
        .iterate(
            IterateParams::new(
                AnyKey {
                    subspace,
                    key: vec![0u8],
                },
                AnyKey {
                    subspace,
                    key: vec![u8::MAX; 64],
                },
            ),
            |key, value| {
                rows.push((key.to_vec(), value.to_vec()));
                Ok(true)
            },
        )
        .await
        .unwrap();
    rows
}

async fn set_raw(store: &Store, subspace: u8, key: &[u8], value: &[u8]) {
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace,
            key: key.to_vec(),
        }),
        value.to_vec(),
    );
    store.write(batch.build_all()).await.unwrap();
}

async fn clear_raw(store: &Store, subspace: u8, key: &[u8]) {
    let mut batch = BatchBuilder::new();
    batch.clear(ValueClass::Any(AnyClass {
        subspace,
        key: key.to_vec(),
    }));
    store.write(batch.build_all()).await.unwrap();
}

async fn get_raw(store: &Store, subspace: u8, key: &[u8]) -> Option<Vec<u8>> {
    store
        .get_value::<Raw>(AnyKey {
            subspace,
            key: key.to_vec(),
        })
        .await
        .unwrap()
        .map(|Raw(bytes)| bytes)
}

/// The moved subspaces, and the letter each had in `_`.
const MOVED: [(u8, u8); 4] = [
    (SUBSPACE_AUDIT, b'L'),
    (SUBSPACE_JOURNAL, b'J'),
    (SUBSPACE_HOLDS, b'H'),
    (SUBSPACE_UNDELETE, b'U'),
];

/// Puts a version 3 store's moved data back the way version 2 kept it,
/// under its letter in `_`.
async fn back_to_v2(store: &Store) {
    for (subspace, letter) in MOVED {
        for (key, value) in rows(store, subspace).await {
            let mut old = vec![letter];
            old.extend_from_slice(&key);
            set_raw(store, SUBSPACE_INBUXA, &old, &value).await;
            clear_raw(store, subspace, &key).await;
        }
    }
}

/// The rows left in `_` under the moved letters, but for the settings that
/// stay.
async fn left_in_inbuxa(store: &Store) -> Vec<Vec<u8>> {
    rows(store, SUBSPACE_INBUXA)
        .await
        .into_iter()
        .map(|(key, _)| key)
        .filter(|key| {
            MOVED.iter().any(|(_, letter)| key.first() == Some(letter))
                && key.get(..2) != Some(b"Ls")
                && key.get(..2) != Some(b"Jj")
        })
        .collect()
}

fn audit_record(n: u64) -> Record {
    Record {
        at: 1_000 + n,
        actor: Actor::account(7, "admin@example.org", None),
        via: None,
        remote_ip: None,
        action: Action::Update,
        target: Target {
            kind: "x:Domain".into(),
            id: Some(format!("d{n}")),
            name: Some("example.org".into()),
            ..Default::default()
        },
        changes: vec![],
        details: None,
        reason: None,
        outcome: Outcome::success(),
    }
}

// SL-16, SL-17, SL-20, SL-22: a version 2 store's audit log, journal,
// holds and undelete notes move to their own subspaces; settings and other
// features stay in `_`; a second run changes nothing; a run that stopped
// while deleting finishes; an unclaimed key or a copy that doesn't match
// stops the step with nothing deleted.
async fn layout_step_2_3(server: &Server) {
    let store = server.store();
    let node = 3;

    // Version 3 data, written the way this build writes it
    let audit = AuditLog::new();
    let mut ids = Vec::new();
    for n in 0..3 {
        ids.push(audit.append(store, node, &audit_record(n)).await.unwrap());
    }
    set_raw(
        store,
        SUBSPACE_JOURNAL,
        b"c\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01",
        b"{\"journal\":1}",
    )
    .await;
    set_raw(store, SUBSPACE_HOLDS, b"h\x00\x00\x00\x09", b"{\"hold\":9}").await;
    set_raw(
        store,
        SUBSPACE_UNDELETE,
        b"g\x01\x00\x00\x00\x05\x00\x00\x00\x06",
        b"{\"note\":6}",
    )
    .await;
    set_raw(
        store,
        SUBSPACE_UNDELETE,
        b"k\x00\x00\x00\x05",
        b"{\"kept\":5}",
    )
    .await;
    // Settings and another feature's key, which stay in `_`
    set_raw(store, SUBSPACE_INBUXA, b"Ls", b"{\"keepFor\":100}").await;
    set_raw(
        store,
        SUBSPACE_INBUXA,
        b"Jj\x00\x00\x00\x01",
        b"{\"journal\":\"def\"}",
    )
    .await;
    set_raw(store, SUBSPACE_INBUXA, b"Kl\x00\x00\x00\x05", b"lock").await;
    let audit_rows = rows(store, SUBSPACE_AUDIT).await;
    let mut expected = Vec::new();
    for (subspace, _) in MOVED {
        expected.push(rows(store, subspace).await);
    }
    assert_eq!(audit_rows.len(), expected[0].len());
    assert!(!audit_rows.is_empty());

    let moved_rows = |store: Store| async move {
        let mut all = Vec::new();
        for (subspace, _) in MOVED {
            all.push(rows(&store, subspace).await);
        }
        all
    };

    // Brought back to version 2, then up again
    back_to_v2(store).await;
    assert!(rows(store, SUBSPACE_AUDIT).await.is_empty());
    assert_eq!(
        left_in_inbuxa(store).await.len(),
        expected.iter().map(Vec::len).sum::<usize>()
    );
    write_mark(server, Some(2)).await;
    migration::try_migrate(server).await.unwrap();
    assert_eq!(read_mark(server).await, Some(INBUXA_STORE_VERSION));
    assert_eq!(moved_rows(store.clone()).await, expected);
    assert!(left_in_inbuxa(store).await.is_empty(), "left in _");
    assert!(
        get_raw(
            store,
            SUBSPACE_INBUXA,
            migration::fork_subspaces::CHECKED_KEY
        )
        .await
        .is_none()
    );
    assert_eq!(
        get_raw(store, SUBSPACE_INBUXA, b"Ls").await.as_deref(),
        Some(&b"{\"keepFor\":100}"[..])
    );
    assert_eq!(
        get_raw(store, SUBSPACE_INBUXA, b"Jj\x00\x00\x00\x01")
            .await
            .as_deref(),
        Some(&b"{\"journal\":\"def\"}"[..])
    );
    assert_eq!(
        get_raw(store, SUBSPACE_INBUXA, b"Kl\x00\x00\x00\x05")
            .await
            .as_deref(),
        Some(&b"lock"[..])
    );

    // The audit log reads back, its chain whole, and goes on from its head
    for (n, id) in ids.iter().enumerate() {
        assert_eq!(
            log::get(store, *id).await.unwrap(),
            Some(audit_record(n as u64))
        );
    }
    let next = audit.append(store, node, &audit_record(3)).await.unwrap();
    assert_eq!(next.seq, ids[2].seq + 1);
    let report = log::verify(store).await.unwrap();
    let chain = report.iter().find(|chain| chain.node == node).unwrap();
    assert_eq!(chain.broken_at, None, "{chain:?}");
    assert_eq!(chain.entries, 4);
    let mut expected = moved_rows(store.clone()).await;

    // A second run changes nothing
    write_mark(server, Some(2)).await;
    migration::layout::run_steps(server, server.registry().node_id())
        .await
        .unwrap();
    assert_eq!(read_mark(server).await, Some(INBUXA_STORE_VERSION));
    assert_eq!(moved_rows(store.clone()).await, expected);

    // A run that stopped while deleting: copies checked, some originals left
    for (key, value) in &expected[2] {
        let mut old = vec![b'H'];
        old.extend_from_slice(key);
        set_raw(store, SUBSPACE_INBUXA, &old, value).await;
    }
    set_raw(
        store,
        SUBSPACE_INBUXA,
        migration::fork_subspaces::CHECKED_KEY,
        &[1],
    )
    .await;
    write_mark(server, Some(2)).await;
    migration::layout::run_steps(server, server.registry().node_id())
        .await
        .unwrap();
    assert_eq!(moved_rows(store.clone()).await, expected);
    assert!(left_in_inbuxa(store).await.is_empty());
    assert!(
        get_raw(
            store,
            SUBSPACE_INBUXA,
            migration::fork_subspaces::CHECKED_KEY
        )
        .await
        .is_none()
    );

    // A key nobody claims stops the step before it changes anything
    back_to_v2(store).await;
    write_mark(server, Some(2)).await;
    let before = rows(store, SUBSPACE_INBUXA).await;
    set_raw(store, SUBSPACE_INBUXA, b"Zz", b"?").await;
    let err = migration::layout::run_steps(server, server.registry().node_id())
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("Zz"), "{err:?}");
    assert_eq!(read_mark(server).await, Some(2));
    clear_raw(store, SUBSPACE_INBUXA, b"Zz").await;
    assert_eq!(rows(store, SUBSPACE_INBUXA).await, before);
    assert!(rows(store, SUBSPACE_AUDIT).await.is_empty());

    // A copy that doesn't match its originals stops it with nothing deleted
    let (stray, _) = &expected[0][0];
    let mut stray = stray.clone();
    stray.push(0xff);
    set_raw(store, SUBSPACE_AUDIT, &stray, b"stray").await;
    let err = migration::layout::run_steps(server, server.registry().node_id())
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("audit log"), "{err:?}");
    assert_eq!(read_mark(server).await, Some(2));
    assert_eq!(
        rows(store, SUBSPACE_INBUXA).await,
        before,
        "deleted after a mismatch"
    );

    // Put right, it goes through
    clear_raw(store, SUBSPACE_AUDIT, &stray).await;
    migration::layout::run_steps(server, server.registry().node_id())
        .await
        .unwrap();
    assert_eq!(read_mark(server).await, Some(INBUXA_STORE_VERSION));
    expected.iter_mut().for_each(|rows| rows.sort());
    let mut after = moved_rows(store.clone()).await;
    after.iter_mut().for_each(|rows| rows.sort());
    assert_eq!(after, expected);

    // More rows than the step copies at a time, where it copies them itself
    let many = 10_050u32;
    let mut batch = BatchBuilder::new();
    for n in 0..many {
        let mut key = b"Un".to_vec();
        key.extend_from_slice(&n.to_be_bytes());
        batch.set(
            ValueClass::Any(AnyClass {
                subspace: SUBSPACE_INBUXA,
                key,
            }),
            n.to_be_bytes().to_vec(),
        );
        if batch.is_large_batch() {
            store.write(batch.build_all()).await.unwrap();
            batch = BatchBuilder::new();
        }
    }
    store.write(batch.build_all()).await.unwrap();
    write_mark(server, Some(2)).await;
    migration::layout::run_steps(server, server.registry().node_id())
        .await
        .unwrap();
    let notes = rows(store, SUBSPACE_UNDELETE)
        .await
        .into_iter()
        .filter(|(key, _)| key.len() == 5 && key[0] == b'n')
        .collect::<Vec<_>>();
    assert_eq!(notes.len(), many as usize);
    assert!(notes.iter().all(|(key, value)| key[1..] == value[..]));
    assert!(left_in_inbuxa(store).await.is_empty());

    // Clean up
    for (subspace, _) in MOVED {
        for (key, _) in rows(store, subspace).await {
            clear_raw(store, subspace, &key).await;
        }
    }
    for key in [&b"Ls"[..], b"Jj\x00\x00\x00\x01", b"Kl\x00\x00\x00\x05"] {
        clear_raw(store, SUBSPACE_INBUXA, key).await;
    }
}
