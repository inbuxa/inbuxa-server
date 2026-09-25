/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! PostgreSQL full-text GIN indexes are built with fastupdate off, and an
//! index made earlier with the default is switched over at startup. With
//! fastupdate on, new entries wait in a pending list that every search scans
//! in full until VACUUM merges it.

use crate::utils::storage::build_data_store;
use registry::schema::structs::DataStore;
use store::{Rows, SearchStore, Store};

const SCHEMA: &str = "gin_fastupdate_test";

#[tokio::test(flavor = "multi_thread")]
pub async fn postgres_gin_fastupdate() {
    println!("Running PostgreSQL GIN fastupdate test...");

    // Work in a schema of our own so the shared search tables are untouched
    let admin = Store::build(build_data_store("PostgreSql", "").await)
        .await
        .expect("Failed to connect to PostgreSQL");
    for query in [
        format!("DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"),
        format!("CREATE SCHEMA {SCHEMA}"),
    ] {
        admin.sql_query::<usize>(&query, vec![]).await.unwrap();
    }
    let DataStore::PostgreSql(mut config) = build_data_store("PostgreSql", "").await else {
        unreachable!()
    };
    config.options = Some(format!("-c search_path={SCHEMA}"));
    let store = Store::build(DataStore::PostgreSql(config))
        .await
        .expect("Failed to connect to PostgreSQL");
    let search = SearchStore::Store(store.clone());

    // A fresh schema
    search.create_indexes().await.unwrap();
    let indexes = gin_indexes(&admin).await;
    assert!(
        indexes.len() >= 4,
        "expected the search GIN indexes, found {indexes:?}"
    );
    for (name, options) in &indexes {
        assert!(
            options.contains("fastupdate=off"),
            "fresh index {name} has options {options:?}"
        );
    }

    // A schema from before the change: the same indexes, made with the
    // default fastupdate=on, and a pending list with something in it
    for (name, _) in &indexes {
        admin
            .sql_query::<usize>(
                &format!("ALTER INDEX {SCHEMA}.{name} RESET (fastupdate)"),
                vec![],
            )
            .await
            .unwrap();
    }
    for (name, options) in gin_indexes(&admin).await {
        assert!(
            !options.contains("fastupdate"),
            "index {name} still has options {options:?}"
        );
    }
    admin
        .sql_query::<usize>(
            &format!(
                "INSERT INTO {SCHEMA}.s_email (accid, docid, subj, body) \
                 SELECT 1, n, to_tsvector('simple', 'pending subject ' || n), \
                 to_tsvector('simple', 'pending body text ' || n) \
                 FROM generate_series(1, 500) n"
            ),
            vec![],
        )
        .await
        .unwrap();
    assert!(
        pending_tuples(&admin, "gin_s_email_body").await > 0,
        "no pending list to merge"
    );

    // Startup on the existing schema switches every index over and merges
    // what was pending
    search.create_indexes().await.unwrap();
    for (name, options) in gin_indexes(&admin).await {
        assert!(
            options.contains("fastupdate=off"),
            "existing index {name} has options {options:?} after startup"
        );
    }
    assert_eq!(pending_tuples(&admin, "gin_s_email_body").await, 0);

    // And a second startup changes nothing
    search.create_indexes().await.unwrap();
    for (name, options) in gin_indexes(&admin).await {
        assert!(options.contains("fastupdate=off"), "{name}: {options:?}");
    }

    admin
        .sql_query::<usize>(&format!("DROP SCHEMA {SCHEMA} CASCADE"), vec![])
        .await
        .unwrap();
}

/// The GIN indexes in the test schema with their reloptions.
async fn gin_indexes(admin: &Store) -> Vec<(String, String)> {
    admin
        .sql_query::<Rows>(
            &format!(
                "SELECT c.relname::text, COALESCE(array_to_string(c.reloptions, ','), '') \
                 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 JOIN pg_am a ON a.oid = c.relam \
                 WHERE n.nspname = '{SCHEMA}' AND c.relkind = 'i' AND a.amname = 'gin' \
                 ORDER BY 1"
            ),
            vec![],
        )
        .await
        .unwrap()
        .rows
        .into_iter()
        .map(|row| {
            let mut values = row.values.into_iter();
            (
                values.next().unwrap().to_str().into_owned(),
                values.next().unwrap().to_str().into_owned(),
            )
        })
        .collect()
}

/// Tuples waiting in a GIN index's pending list (pgstattuple is a contrib
/// extension the test database has).
async fn pending_tuples(admin: &Store, index: &str) -> i64 {
    admin
        .sql_query::<usize>("CREATE EXTENSION IF NOT EXISTS pgstattuple", vec![])
        .await
        .unwrap();
    admin
        .sql_query::<Rows>(
            &format!("SELECT pending_tuples FROM pgstatginindex('{SCHEMA}.{index}'::regclass)"),
            vec![],
        )
        .await
        .unwrap()
        .rows
        .into_iter()
        .next()
        .and_then(|row| row.values.into_iter().next())
        .map(|value| value.to_str().parse::<i64>().unwrap())
        .unwrap()
}
