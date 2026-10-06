/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Whether the outside world can reach each node's ports (settings-reorg,
//! Ports: the reachability check).
//!
//! A server can't answer this about itself: a connection to its own public
//! address never leaves the machine, so it passes whatever the firewall in
//! front says. In a cluster the other nodes are outside that machine. Every
//! ten minutes each node resolves every other active node's hostname, as a
//! sender would, and tries a TCP connection to each listener port on each
//! address. What it saw goes in the shared in-memory store for an hour, under
//! (target, prober), so whichever node the admin asks can report it all.
//!
//! A single server has no one outside to ask. It reports only whether each
//! port is listening, and says so.
//!
//! A connection is all that's tried: nothing is sent, so no protocol logs a
//! session and no rate limit counts it.

use crate::{KV_PORT_REACHABILITY, Server};
use registry::schema::{enums::ClusterNodeStatus, structs::NetworkListener};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};
use store::{dispatch::lookup::KeyValue, write::now};

/// How often each node probes the others.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(600);
/// How long one node's view of another is kept: long enough to span a missed round.
const KEEP_FOR: u64 = 3600;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probe {
    pub port: u16,
    pub address: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Unix seconds.
    pub checked_at: u64,
    pub probes: Vec<Probe>,
    /// The hostname didn't resolve, so nothing could be tried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The ports a sender or client could reach: every listener's port, leaving
/// out listeners bound only to loopback, which are private by design.
pub fn public_ports<'x>(listeners: impl IntoIterator<Item = &'x NetworkListener>) -> Vec<u16> {
    listeners
        .into_iter()
        .flat_map(|l| l.bind.iter())
        .map(|addr| addr.0)
        .filter(|addr| !addr.ip().is_loopback())
        .map(|addr| addr.port())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn key(target: &str, prober: &str) -> Vec<u8> {
    format!("{target}\n{prober}").into_bytes()
}

async fn connect(address: SocketAddr) -> Result<(), String> {
    match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(address)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err("no answer within 5 seconds".into()),
    }
}

/// Tries each port on each address `hostname` resolves to.
pub async fn probe_host(hostname: &str, ports: &[u16]) -> Report {
    let checked_at = now();
    let addresses = match tokio::net::lookup_host((hostname, 0)).await {
        Ok(found) => found.map(|a| a.ip()).collect::<BTreeSet<_>>(),
        Err(err) => {
            return Report {
                checked_at,
                probes: vec![],
                error: Some(format!("{hostname} doesn't resolve: {err}")),
            };
        }
    };
    let tries = addresses.iter().flat_map(|ip| {
        ports.iter().map(move |port| {
            let address = SocketAddr::new(*ip, *port);
            async move {
                let result = connect(address).await;
                Probe {
                    port: *port,
                    address: ip.to_string(),
                    ok: result.is_ok(),
                    error: result.err(),
                }
            }
        })
    });
    Report {
        checked_at,
        probes: futures::future::join_all(tries).await,
        error: None,
    }
}

async fn listeners(server: &Server) -> trc::Result<Vec<NetworkListener>> {
    Ok(server
        .registry()
        .list::<NetworkListener>()
        .await?
        .into_iter()
        .map(|l| l.object)
        .collect())
}

/// Where to knock to see a port listening on this machine: the bound
/// address, or loopback of the same family for a wildcard bind.
pub fn local_targets<'x>(
    listeners: impl IntoIterator<Item = &'x NetworkListener>,
) -> Vec<SocketAddr> {
    listeners
        .into_iter()
        .flat_map(|l| l.bind.iter())
        .map(|addr| addr.0)
        .filter(|addr| !addr.ip().is_loopback())
        .map(|addr| match addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => {
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port())
            }
            IpAddr::V6(ip) if ip.is_unspecified() => {
                SocketAddr::new(Ipv6Addr::LOCALHOST.into(), addr.port())
            }
            _ => addr,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// One round: this node probes every other active node and records what it saw.
pub async fn probe_peers(server: &Server) -> trc::Result<()> {
    let nodes = server.registry().cluster_node_list().await?;
    let me = server.registry().node_id() as u64;
    let Some(prober) = nodes
        .iter()
        .find(|n| n.node_id == me)
        .map(|n| n.hostname.clone())
    else {
        return Ok(());
    };
    let ports = public_ports(&listeners(server).await?);
    for target in nodes.iter().filter(|n| {
        n.node_id != me && n.status == ClusterNodeStatus::Active && n.hostname != prober
    }) {
        let report = probe_host(&target.hostname, &ports).await;
        server
            .in_memory_store()
            .key_set(
                KeyValue::with_prefix(
                    KV_PORT_REACHABILITY,
                    key(&target.hostname, &prober),
                    serde_json::to_vec(&report).unwrap_or_default(),
                )
                .expires(KEEP_FOR),
            )
            .await?;
    }
    Ok(())
}

/// What `GET /api/ports/check` answers.
pub async fn report(server: &Server) -> trc::Result<Value> {
    let listeners = listeners(server).await?;
    let ports = public_ports(&listeners);
    let nodes = if server.core.storage.coordinator.is_enabled() {
        server.registry().cluster_node_list().await?
    } else {
        vec![]
    };
    let active = nodes
        .iter()
        .filter(|n| n.status == ClusterNodeStatus::Active)
        .collect::<Vec<_>>();

    if active.len() < 2 {
        // No one outside to ask: only whether each port is listening here.
        let started = Instant::now();
        let listening = futures::future::join_all(local_targets(&listeners).into_iter().map(
            |address| async move {
                let result = connect(address).await;
                json!({ "port": address.port(), "address": address.ip().to_string(), "listening": result.is_ok() })
            },
        ))
        .await;
        return Ok(json!({
            "mode": "local",
            "ports": ports,
            "listening": listening,
            "ms": started.elapsed().as_millis() as u64,
        }));
    }

    let mut out = Vec::new();
    for target in &active {
        let mut seen_by = Vec::new();
        for prober in active.iter().filter(|p| p.node_id != target.node_id) {
            let stored = server
                .in_memory_store()
                .key_get::<String>(KeyValue::<()>::build_key(
                    KV_PORT_REACHABILITY,
                    key(&target.hostname, &prober.hostname),
                ))
                .await?;
            let report = stored.and_then(|raw| serde_json::from_str::<Report>(&raw).ok());
            seen_by.push(json!({ "prober": prober.hostname, "report": report }));
        }
        out.push(json!({ "hostname": target.hostname, "seenBy": seen_by }));
    }
    Ok(json!({
        "mode": "cluster",
        "ports": ports,
        "intervalSeconds": PROBE_INTERVAL.as_secs(),
        "nodes": out,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(binds: &[&str]) -> NetworkListener {
        NetworkListener {
            bind: registry::schema::prelude::Map::new(
                binds.iter().map(|b| b.parse().unwrap()).collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn public_ports_leave_out_loopback_only_listeners() {
        let listeners = [
            listener(&["[::]:25"]),
            listener(&["0.0.0.0:993", "[::]:993"]),
            listener(&["127.0.0.1:8080"]),
            listener(&["203.0.113.5:465"]),
        ];
        assert_eq!(public_ports(listeners.iter()), vec![25, 465, 993]);
        assert_eq!(
            local_targets(listeners.iter())
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["127.0.0.1:993", "203.0.113.5:465", "[::1]:25", "[::1]:993"]
        );
    }

    #[tokio::test]
    async fn probe_host_reports_open_and_closed_ports() {
        let open = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = open.local_addr().unwrap().port();
        let closed_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let report = probe_host("127.0.0.1", &[open_port, closed_port]).await;
        assert_eq!(report.error, None);
        let ok = |port| report.probes.iter().find(|p| p.port == port).unwrap().ok;
        assert!(ok(open_port));
        assert!(!ok(closed_port));
    }

    #[tokio::test]
    async fn probe_host_says_when_a_name_does_not_resolve() {
        let report = probe_host("does-not-exist.invalid", &[25]).await;
        assert!(report.probes.is_empty());
        assert!(report.error.unwrap().contains("doesn't resolve"));
    }
}
