/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod blob;
pub mod import_export;
pub mod lookup;
pub mod ops;
#[cfg(any(feature = "postgres", feature = "mysql"))]
pub mod pool_timeout; // inbuxa: SQL pools give up instead of hanging
pub mod query;
pub mod registry;
#[cfg(feature = "postgres")]
pub mod replica; // inbuxa: read replicas
#[cfg(feature = "mysql")]
pub mod replica_mysql; // inbuxa: read replicas on MySQL
#[cfg(all(feature = "postgres", feature = "redis"))]
pub mod replica_cluster; // inbuxa: read replicas across nodes
pub mod scaleout; // inbuxa: scale-out storage
#[cfg(feature = "postgres")]
pub mod search_gin; // inbuxa: GIN indexes without a pending list
#[cfg(any(feature = "postgres", feature = "mysql"))]
pub mod sql_timeout;
pub mod task_locks; // inbuxa: task locks across nodes

use crate::utils::server::TestServerBuilder;
use std::io::Read;

#[tokio::test(flavor = "multi_thread")]
pub async fn store_tests() {
    let test = TestServerBuilder::new("store_tests").await.build().await;

    println!("Testing store {}...", std::env::var("STORE").unwrap());

    test.destroy_store().await;

    registry::test(&test).await;
    import_export::test(&test).await;
    ops::test(&test).await;
    #[cfg(any(feature = "postgres", feature = "mysql"))]
    sql_timeout::test(&test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

#[tokio::test(flavor = "multi_thread")]
pub async fn search_tests() {
    let test = TestServerBuilder::new("search_store_tests")
        .await
        .build()
        .await;

    println!(
        "Testing search store {}...",
        std::env::var("SEARCH_STORE").unwrap_or("default".to_string())
    );

    query::test(&test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

pub fn deflate_test_resource(name: &str) -> Vec<u8> {
    let mut csv_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    csv_path.push("resources");
    csv_path.push(name);

    let mut decoder = flate2::bufread::GzDecoder::new(std::io::BufReader::new(
        std::fs::File::open(csv_path).unwrap(),
    ));
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).unwrap();
    result
}
