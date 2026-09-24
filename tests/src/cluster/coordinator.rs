/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A node that starts while its NATS coordinator is down joins the cluster
//! once NATS comes up, without a restart, and reports the coordinator's
//! connection on `/healthz/cluster` as it goes and comes back.

use crate::utils::server::TestServerBuilder;
use coordinator::Coordinator;
use registry::{
    schema::{
        enums::NetworkListenerProtocol,
        structs::{Coordinator as CoordinatorSetting, NatsCoordinator},
    },
    types::map::Map,
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use testcontainers::{
    GenericImage, ImageExt, core::IntoContainerPort, core::WaitFor, runners::AsyncRunner,
};

const HTTP_PORT: u16 = 11_310;
const TOPIC: &str = "inbuxa-coordinator-test";

#[tokio::test(flavor = "multi_thread")]
pub async fn coordinator_reconnect_tests() {
    println!("Running coordinator reconnect tests...");

    // A port with no NATS server behind it, yet
    let nats_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = NatsCoordinator {
        addresses: Map::new(vec![format!("127.0.0.1:{nats_port}")]),
        use_tls: false,
        timeout_connection: 1_000u64.into(),
        ..Default::default()
    };

    // 1. The node starts, without a build error, while NATS is down, and
    // says so
    let test = TestServerBuilder::new("coordinator_reconnect_tests")
        .await
        .with_object(CoordinatorSetting::Nats(config.clone()))
        .await
        .with_listener(NetworkListenerProtocol::Http, "http", HTTP_PORT, true)
        .await
        .build()
        .await;
    let coordinator = test.server.core.storage.coordinator.clone();
    assert!(
        coordinator.is_enabled(),
        "a coordinator, though not connected"
    );
    assert_eq!(coordinator.is_connected(), Some(false));
    assert_eq!(
        cluster_health().await,
        (503, json!({"coordinator": "disconnected"}))
    );

    // A subscription made now, as the broadcast subscriber makes it at
    // startup, has to work once NATS is up
    let mut stream = coordinator.subscribe(TOPIC).await.unwrap();

    // 2. NATS comes up: the node connects on its own
    let nats = GenericImage::new("nats", "latest")
        .with_wait_for(WaitFor::message_on_stderr("Server is ready"))
        .with_mapped_port(nats_port, 4222.tcp())
        .start()
        .await
        .expect("Failed to start NATS container");
    wait_for_health(200, "connected").await;
    let other_node = coordinator::backend::nats::NatsPubSub::open(config.clone())
        .await
        .unwrap();
    wait_until_connected(&other_node).await;
    round_trip(&other_node, &mut stream, b"after startup").await;

    // 3. NATS goes away: the node reports it; and it comes back: the node
    // reconnects and the same subscription carries on
    nats.stop().await.unwrap();
    wait_for_health(503, "disconnected").await;
    nats.start().await.unwrap();
    wait_for_health(200, "connected").await;
    wait_until_connected(&other_node).await;
    round_trip(&other_node, &mut stream, b"after reconnect").await;

    drop(nats);
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

async fn cluster_health() -> (u16, Value) {
    let response = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:{HTTP_PORT}/healthz/cluster"))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

async fn wait_for_health(status: u16, state: &str) {
    let started = Instant::now();
    loop {
        let health = cluster_health().await;
        if health == (status, json!({"coordinator": state})) {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "expected {status} {state}, still {health:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_until_connected(coordinator: &Coordinator) {
    let started = Instant::now();
    while coordinator.is_connected() != Some(true) {
        assert!(started.elapsed() < Duration::from_secs(30), "not connected");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Another node publishes; this one's subscription receives it.
async fn round_trip(from: &Coordinator, stream: &mut coordinator::PubSubStream, payload: &[u8]) {
    from.publish(TOPIC, payload.to_vec()).await.unwrap();
    let message = tokio::time::timeout(Duration::from_secs(10), stream.next())
        .await
        .expect("no message within 10 seconds")
        .expect("subscription ended");
    assert_eq!(message.payload(), payload);
}
