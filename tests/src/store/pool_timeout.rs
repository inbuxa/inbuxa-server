/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A database that accepts connections and then says nothing (a hung or
//! half-dead server, a black-holed failover) gives a worker an error within
//! the pool's timeouts. Upstream's pools had none, so the worker waited for
//! good. No database is needed: a local listener that never answers plays
//! the server.
//!
//! inbuxa: the same for a database that stops answering while connections
//! are already open (a paused container): a query on a checked-out
//! connection ends within the query limit, the store works again once the
//! database is back, and /healthz/ready says 503 in between while
//! /healthz/live stays 200. These need the local test databases; a proxy
//! that can stop forwarding plays the pause.

use registry::schema::structs::DataStore;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use store::{
    IterateParams, Store, ValueKey,
    backend::query_timeout::QueryTimeouts,
    write::{BatchBuilder, ValueClass},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

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

/// A TCP proxy to a local port that can stop forwarding, in both
/// directions, while keeping every connection open: a paused server whose
/// kernel still keeps the connections up.
struct PausableProxy {
    port: u16,
    paused: Arc<AtomicBool>,
}

impl PausableProxy {
    async fn start(upstream: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let paused = Arc::new(AtomicBool::new(false));
        let paused_ = paused.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = TcpStream::connect(("127.0.0.1", upstream)).await else {
                    continue;
                };
                let (client_rx, client_tx) = client.into_split();
                let (server_rx, server_tx) = server.into_split();
                tokio::spawn(forward(client_rx, server_tx, paused_.clone()));
                tokio::spawn(forward(server_rx, client_tx, paused_.clone()));
            }
        });
        PausableProxy { port, paused }
    }

    fn pause(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
    }
}

async fn forward(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    paused: Arc<AtomicBool>,
) {
    let mut buf = vec![0u8; 16384];
    loop {
        while paused.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        // Hold what arrived while paused until the pause ends
        while paused.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

const TEST_LIMITS: QueryTimeouts = QueryTimeouts {
    query: Duration::from_secs(2),
    maintenance: Duration::from_secs(3),
};

/// Opens `connections` pooled connections at once, so the operations that
/// follow find one idle and check it out.
async fn warm(store: &Store, connections: usize) {
    let reads = (0..connections).map(|_| async {
        store
            .get_value::<u64>(ValueKey::from(ValueClass::Property(0)))
            .await
            .unwrap();
    });
    futures::future::join_all(reads).await;
}

/// With the database paused, reads, scans and writes on connections the
/// pool already holds end in an error within the query limit; once it is
/// back, the store works again.
async fn assert_queries_time_out(store: Store, proxy: &PausableProxy) {
    store.create_tables().await.unwrap();
    warm(&store, 4).await;
    // mysql_async resets a connection on its way back to the pool; let
    // those finish, or the connections are stuck in the reset when the
    // pause starts and the pool's own wait timeout answers instead
    tokio::time::sleep(Duration::from_secs(1)).await;
    proxy.pause(true);

    let key = || ValueKey::from(ValueClass::Property(0));
    let limit = TEST_LIMITS.query;
    for (what, op) in [("read", 0), ("scan", 1), ("write", 2)] {
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            match op {
                0 => store.get_value::<u64>(key()).await.map(|_| ()),
                1 => {
                    store
                        .iterate(
                            IterateParams::new(
                                ValueKey::from(ValueClass::Property(0)),
                                ValueKey::from(ValueClass::Property(u8::MAX)),
                            ),
                            |_, _| Ok(true),
                        )
                        .await
                }
                _ => {
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(u32::MAX - 7)
                        .with_collection(types::collection::Collection::Email)
                        .with_document(0)
                        .set(ValueClass::Property(0), 1u64.to_be_bytes().to_vec());
                    store.write(batch.build_all()).await.map(|_| ())
                }
            }
        })
        .await;
        let elapsed = started.elapsed();
        match result {
            Ok(Err(err)) => {
                let err = format!("{err:?}");
                println!("Paused database, {what}: {err} after {elapsed:?}");
                assert!(err.contains("Query timed out"), "{what}: {err}");
                assert!(
                    elapsed >= limit && elapsed < limit * 3,
                    "{what} ended after {elapsed:?}"
                );
            }
            Ok(Ok(())) => panic!("{what} succeeded against a paused database"),
            Err(_) => panic!("{what} still waiting after {elapsed:?}"),
        }
    }

    proxy.pause(false);
    tokio::time::timeout(Duration::from_secs(20), store.get_value::<u64>(key()))
        .await
        .expect("still waiting after the database came back")
        .expect("the store didn't recover");
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
pub async fn postgres_query_timeout() {
    println!("Running PostgreSQL query timeout test...");
    let DataStore::PostgreSql(mut config) =
        crate::utils::storage::build_data_store("PostgreSql", "").await
    else {
        unreachable!()
    };
    let proxy = PausableProxy::start(config.port as u16).await;
    config.host = "127.0.0.1".into();
    config.port = proxy.port as u64;
    // New connections through the paused proxy give up as quickly
    config.timeout = Some(TEST_LIMITS.query.into());
    let store = Store::build(DataStore::PostgreSql(config))
        .await
        .unwrap()
        .with_query_timeouts(TEST_LIMITS);
    assert_queries_time_out(store, &proxy).await;
}

#[cfg(feature = "mysql")]
#[tokio::test(flavor = "multi_thread")]
pub async fn mysql_query_timeout() {
    println!("Running MySQL query timeout test...");
    let DataStore::MySql(mut config) = crate::utils::storage::build_data_store("MySql", "").await
    else {
        unreachable!()
    };
    let proxy = PausableProxy::start(config.port as u16).await;
    config.host = "127.0.0.1".into();
    config.port = proxy.port as u64;
    let store = Store::build(DataStore::MySql(config))
        .await
        .unwrap()
        .with_query_timeouts(TEST_LIMITS);
    assert_queries_time_out(store, &proxy).await;
}

/// /healthz/ready follows the data store; /healthz/live doesn't.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
pub async fn postgres_readiness() {
    use crate::utils::server::TestServerBuilder;
    use registry::schema::enums::NetworkListenerProtocol;

    const HTTP_PORT: u16 = 11_320;
    if std::env::var("STORE").as_deref() != Ok("PostgreSql") {
        println!("Skipping the readiness test: it runs with STORE=PostgreSql.");
        return;
    }
    println!("Running readiness test...");

    let test = TestServerBuilder::new("postgres_readiness")
        .await
        .with_listener(NetworkListenerProtocol::Http, "http", HTTP_PORT, true)
        .await
        .build()
        .await;

    // Point the running node's data store at the database through the proxy
    let DataStore::PostgreSql(mut config) =
        crate::utils::storage::build_data_store("PostgreSql", "").await
    else {
        unreachable!()
    };
    let proxy = PausableProxy::start(config.port as u16).await;
    config.host = "127.0.0.1".into();
    config.port = proxy.port as u64;
    config.timeout = Some(TEST_LIMITS.query.into());
    let store = Store::build(DataStore::PostgreSql(config))
        .await
        .unwrap()
        .with_query_timeouts(TEST_LIMITS);
    let inner = &test.server.inner;
    let mut core = inner.shared_core.load_full().as_ref().clone();
    core.storage.data = store;
    inner.shared_core.store(Arc::new(core));

    let health = |path: &'static str| async move {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
            .get(format!("https://127.0.0.1:{HTTP_PORT}/healthz/{path}"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    };
    let wait_for = |path: &'static str, status: u16| async move {
        let started = Instant::now();
        loop {
            let got = health(path).await;
            if got == status {
                println!("/healthz/{path}: {got} after {:?}", started.elapsed());
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "/healthz/{path} still {got}, expected {status}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };

    wait_for("ready", 200).await;
    proxy.pause(true);
    wait_for("ready", 503).await;
    assert_eq!(health("live").await, 200);
    proxy.pause(false);
    wait_for("ready", 200).await;
    assert_eq!(health("live").await, 200);

    if test.is_reset() {
        test.temp_dir.delete();
    }
}
