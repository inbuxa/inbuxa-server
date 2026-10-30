/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: the store version mark. A store without it gets it on start, a
//! marked store is left alone, and a store marked by a newer release is
//! refused before anything is written to it.

use crate::utils::server::TestServerBuilder;
use common::{INBUXA_STORE_VERSION, INBUXA_STORE_VERSION_KEY, Server};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use store::{
    SUBSPACE_INBUXA, SerializeInfallible,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass},
};

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
}
