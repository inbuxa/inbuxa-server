/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: the store version mark. A store without it gets it on start, a
//! marked store is left alone, and a store marked by a newer release is
//! refused before anything is written to it. A store opened for the first
//! time has upstream's web interface switched off (docs/spec/import-0.16.md).

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
use std::panic::AssertUnwindSafe;
use store::{
    SUBSPACE_INBUXA, SerializeInfallible,
    registry::{bootstrap::Bootstrap, write::RegistryWrite},
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass},
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
