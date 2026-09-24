/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A database that accepts connections and then says nothing (a hung or
//! half-dead server, a black-holed failover) gives a worker an error within
//! the pool's timeouts. Upstream's pools had none, so the worker waited for
//! good. No database is needed: a local listener that never answers plays
//! the server.

use registry::schema::structs::DataStore;
use std::time::{Duration, Instant};
use store::{Store, ValueKey, write::ValueClass};
use tokio::net::TcpListener;

/// Accepts connections on a local port and never sends a byte.
async fn silent_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    port
}

/// Builds the store and reads a key; both must end, with an error for the
/// read, well within `limit`.
async fn assert_times_out(data_store: DataStore, limit: Duration) {
    let started = Instant::now();
    let result = tokio::time::timeout(limit, async {
        match Store::build(data_store).await {
            Ok(store) => store
                .get_value::<u64>(ValueKey::from(ValueClass::Property(0)))
                .await
                .map(|_| ())
                .map_err(|err| err.to_string()),
            Err(err) => Err(err.to_string()),
        }
    })
    .await;
    let elapsed = started.elapsed();
    match result {
        Ok(Err(err)) => println!("Got {err} after {elapsed:?}"),
        Ok(Ok(())) => panic!("a silent server answered?"),
        Err(_) => panic!("still waiting for a connection after {elapsed:?}"),
    }
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
pub async fn postgres_pool_timeout() {
    use registry::schema::structs::PostgreSqlStore;

    let port = silent_server().await;
    println!("Running PostgreSQL pool timeout test...");
    // The store's own timeout bounds opening a connection, handshake
    // included (tokio-postgres's connect_timeout covers only the TCP connect)
    assert_times_out(
        DataStore::PostgreSql(PostgreSqlStore {
            host: "127.0.0.1".into(),
            port: port as u64,
            database: "none".into(),
            timeout: Some(Duration::from_secs(2).into()),
            use_tls: false,
            ..Default::default()
        }),
        Duration::from_secs(20),
    )
    .await;
}

#[cfg(feature = "mysql")]
#[tokio::test(flavor = "multi_thread")]
pub async fn mysql_pool_timeout() {
    use registry::schema::structs::MySqlStore;

    let port = silent_server().await;
    println!("Running MySQL pool timeout test...");
    // mysql_async has no pool timeout; the store waits 30 s for a connection
    assert_times_out(
        DataStore::MySql(MySqlStore {
            host: "127.0.0.1".into(),
            port: port as u64,
            database: "none".into(),
            use_tls: false,
            ..Default::default()
        }),
        Duration::from_secs(60),
    )
    .await;
}
