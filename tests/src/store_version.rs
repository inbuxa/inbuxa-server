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
//! at a time (docs/spec/features/store-layout.md).

use crate::utils::server::TestServerBuilder;
use common::{
    INBUXA_STORE_VERSION, INBUXA_STORE_VERSION_KEY, Server,
    manager::first_party::disable_imported_web_interface,
};
use futures::FutureExt;
use registry::{
    schema::{prelude::ObjectInner, structs::Application},
    types::map::Map,
};
use std::{panic::AssertUnwindSafe, time::Duration};
use store::{
    InMemoryStore, IterateParams, SUBSPACE_INBUXA, SerializeInfallible, Store, ValueKey,
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
