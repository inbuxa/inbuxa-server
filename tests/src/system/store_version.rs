/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// inbuxa: which stores a start accepts. Either edition's 1.0 schema version
// opens, and the store gets our own mark; an older schema, or a mark newer
// than ours, is refused.

use crate::utils::server::TestServerBuilder;
use common::{
    DATABASE_SCHEMA_OSS_FLAG, DATABASE_SCHEMA_VERSION_BASE, INBUXA_STORE_VERSION, Server,
};
use store::{
    SerializeInfallible, Subspace,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass, key::SystemKind},
};

#[tokio::test(flavor = "multi_thread")]
async fn store_version() {
    let test = TestServerBuilder::new("store_version")
        .await
        .disable_services()
        .build()
        .await;
    let server = &test.server;

    println!("Running store version tests...");
    for schema in [
        DATABASE_SCHEMA_VERSION_BASE,
        DATABASE_SCHEMA_VERSION_BASE | DATABASE_SCHEMA_OSS_FLAG,
    ] {
        // A store from an upstream 1.0 build: no mark of ours
        set(server, SystemKind::SchemaVersion, Some(schema)).await;
        set(server, SystemKind::InbuxaStoreVersion, None).await;
        server.verify_schema_version().await.unwrap();
        assert_eq!(
            get(server, SystemKind::InbuxaStoreVersion).await,
            Some(INBUXA_STORE_VERSION),
            "schema {schema:#x} gets our mark"
        );
        assert_eq!(
            get(server, SystemKind::SchemaVersion).await,
            Some(schema),
            "the edition flag is left as it was"
        );
        server.verify_schema_version().await.unwrap();
    }

    // Written by a later release line
    set(server, SystemKind::InbuxaStoreVersion, Some(INBUXA_STORE_VERSION + 1)).await;
    assert!(server.verify_schema_version().await.is_err());

    // A 0.16 store
    set(server, SystemKind::InbuxaStoreVersion, Some(INBUXA_STORE_VERSION)).await;
    set(server, SystemKind::SchemaVersion, Some(6)).await;
    assert!(server.verify_schema_version().await.is_err());
}

async fn get(server: &Server, kind: SystemKind) -> Option<u32> {
    server
        .store()
        .get_value::<u32>(AnyKey {
            subspace: Subspace::System,
            key: vec![kind as u8],
        })
        .await
        .unwrap()
}

async fn set(server: &Server, kind: SystemKind, value: Option<u32>) {
    let class = ValueClass::Any(AnyClass {
        subspace: Subspace::System,
        key: vec![kind as u8],
    });
    let mut batch = BatchBuilder::new();
    match value {
        Some(value) => batch.set(class, value.serialize()),
        None => batch.clear(class),
    };
    server.store().write_batch(&mut batch).await.unwrap();
}
