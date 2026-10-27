/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod alerts;
pub mod metrics;
pub mod tracing;
pub mod webhooks;

use crate::utils::server::{TestServer, TestServerBuilder};
use common::telemetry::tracers::store::TracingStore as _;
use registry::schema::structs::{Expression, Jmap, MetricsStore, MtaStageAuth, TracingStore};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
pub async fn telemetry_tests() {
    let mut test = TestServerBuilder::new("telemetry_tests")
        .await
        .with_logging()
        .with_default_listeners()
        .await
        .with_object(MetricsStore::Default)
        .await
        .with_object(TracingStore::Default)
        .await
        .with_object(Jmap {
            max_get_results: 100_000,
            max_query_results: 100_000,
            ..Default::default()
        })
        .await
        .with_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;

    // Create admin account
    let admin = test
        .create_user_account(
            "admin",
            "admin@example.org",
            "these_pretzels_are_making_me_thirsty",
            &[],
            "Admin",
        )
        .await;
    test.account("admin")
        .assign_roles_to_account(admin.id(), &["user", "system"])
        .await;
    test.insert_account(admin);

    alerts::test(&test).await;
    metrics::test(&test).await;
    tracing::test(&test).await;
    webhooks::test(&test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// Purges every stored trace, as `purge_spans` with nothing kept does.
/// inbuxa: 1.0's built-in search index drops traces a whole id bucket (about
/// 18 hours) at a time, so this run's traces stay indexed after the purge
/// until their bucket is past; they are dropped too before a store check.
pub async fn purge_all_traces(test: &TestServer) {
    test.server
        .tracing_store()
        .purge_spans(Duration::from_secs(0), test.server.search_store().into())
        .await
        .unwrap();
    if let Some(index) = test.server.search_store().internal_fts() {
        index.unindex_traces(u64::MAX).await.unwrap();
    }
}
