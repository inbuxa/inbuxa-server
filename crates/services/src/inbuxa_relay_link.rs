/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The relay link service (docs/spec/features/relay.md, "The link
//! service"): on every node, a link to every enabled inbuxa Relay.
//!
//! The node dials the relay; the relay never dials in. A relay waiting to
//! join gets `Relay/join` on a connection that can't check its key yet, and
//! its proof decides whether its key is pinned (RL-7, RL-8). After that the
//! node only talks to that key, over a WebSocket (RFC 8887), and keeps the
//! relay's settings and recipient set the same as this server's: in full
//! when the link comes up, then as changes, every few seconds.
//!
//! Push is asked for `Relay` and `Inbound`, which puts the relay in live
//! mode (RL-12). Every message the relay takes is claimed, unsealed, and
//! judged by this server's own inbound pipeline with the relay's session
//! (RL-23): a live one gets this server's verdict before the sender is
//! answered, a held one is delivered, or reported to a sender who passed
//! SPF or DMARC (RL-17, RL-18). A message taken is recorded before the
//! relay is told, so one offered again isn't delivered twice (RL-16).
//!
//! The relay's own events become this server's `relay.*` trace events, so
//! they reach the log, webhooks and OpenTelemetry, and its TLS results go
//! into this server's TLS-RPT reports. On a cluster only the
//! linked node with the lowest id takes them. A node with no link to a
//! joined relay for an hour says so with `relay.link-down` (RL-T23).

use crate::{
    inbuxa_relay_certificates::order_relay_certificates, task_manager::dns::queue_relay_dns,
};
use common::{
    BuildServer, Inner, Server,
    config::server::{DEFAULT_TLS_TIMEOUT, ServerProtocol},
    network::{ServerInstance, TcpAcceptor, limiter::ConcurrencyLimiter},
};
use futures::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use inbuxa_features::{
    masked_email,
    relay::{
        self as relays, DownstreamKeys, JoinState, Relay,
        link::{
            JoinRecorded, LinkState, LocalDomain, NODE_CERT_RENEW_AFTER, NodeCertificate, NodeLink,
            RecipientPlan, forget_ingested, is_inbound_id, issue_node_certificate, pushed_settings,
            record_ingested, record_join, set_status, was_ingested,
        },
        outbound::{self, Call, HandOver, Handed, Linked, Refused, Sender},
    },
};
use inbuxa_relay_proto::{
    CAPABILITY, CORE_CAPABILITY, PROTOCOL_VERSION, b64,
    jmap::{ClientFrame, Invocation, Request, ServerFrame, Session, method},
    pin::{Pin, pins_match, spki_pin},
    recipient::{RecipientDomain, RecipientHash},
    seal, token,
    types::{
        Address, Capability, Delivered, DeliveryStatus, Envelope, Inbound, InboundState,
        Outbound as ProtoOutbound, RELAY_SINGLETON, RelayEvent as ProtoRelayEvent, RelaySettings,
        RelayStatus, Reply, Verdict,
    },
};
use registry::schema::{
    prelude::ObjectType,
    structs::{Domain, SubAddressing},
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use serde_json::{Value, json};
use smtp::{
    core::Relayed,
    inbound::relayed::{RelayedMessage, RelayedOutcome, ingest_relayed},
    outbound::relay::{Applied, RelayedStatus, apply_relayed, report_relayed_tls},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use store::{registry::RegistryQuery, write::now};
use tokio::{
    net::TcpStream,
    sync::{mpsc, watch},
    task::JoinHandle,
    time::MissedTickBehavior,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

/// How often the list of relays is read again.
const SCAN: Duration = Duration::from_secs(10);
/// How often a linked relay is brought up to date, and asked how it is.
const SYNC: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const CALL_TIMEOUT: Duration = Duration::from_secs(60);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// How often the link is pinged, so NAT and firewalls keep it open (RL-5).
const PING_EVERY: Duration = Duration::from_secs(30);
/// Pongs that may go missing before the link is taken as dead.
const PONGS_MISSED_MAX: u32 = 2;
/// After a join that can't go on, wait this long, or for a change.
const JOIN_FAILED_WAIT: Duration = Duration::from_secs(300);
/// Status is written when it changes, and at least this often.
const STATUS_EVERY: u64 = 60;
/// More recipient changes than this go as a full `Recipient/replace`.
const MAX_DELTA: usize = 2_000;
/// The relay's only account.
const ACCOUNT_ID: &str = "relay";
/// Any name: the relay is known by its key, never its name (RL-6).
const SERVER_NAME: &str = "relay.invalid";
/// Messages one link takes at once.
const TAKE_MAX: usize = 8;
/// How long a claimed message is this node's (RL-15).
const LEASE_SECONDS: u64 = 300;
/// How often messages taken long ago are forgotten (RL-16).
const FORGET_EVERY: u64 = 3_600;
/// No link this long to a joined relay raises `relay.link-down`.
const LINK_DOWN_ALERT: u64 = 3_600;

pub fn spawn_relay_links(inner: Arc<Inner>) {
    tokio::spawn(async move {
        let certs = Arc::new(NodeCertificates::default());
        // Relayed mail's sessions: port 25's, but no listener's
        let instance = Arc::new(ServerInstance {
            id: "relay".to_string(),
            protocol: ServerProtocol::Smtp,
            acceptor: TcpAcceptor::Plain,
            limiter: ConcurrencyLimiter::new(100),
            tls_timeout: DEFAULT_TLS_TIMEOUT,
            shutdown_rx: watch::channel(false).1,
            proxy_networks: vec![],
            span_id_gen: Arc::new(SnowflakeIdGenerator::new()),
        });
        let mut links: HashMap<u32, Running> = HashMap::new();
        let mut forgot_at = 0;
        loop {
            let server = inner.build_server();
            if let Err(err) = reconcile(&inner, &server, &certs, &instance, &mut links).await {
                trc::error!(err.details("Failed to start relay links"));
            }
            if now() >= forgot_at + FORGET_EVERY {
                forgot_at = now();
                if let Err(err) = forget_taken(&server).await {
                    trc::error!(err.details("Failed to forget relayed messages taken"));
                }
            }
            let woken = tokio::select! {
                _ = tokio::time::sleep(SCAN) => false,
                _ = relays::CHANGED.notified() => true,
            };
            if woken {
                for link in links.values() {
                    link.wake.send_modify(|n| *n = n.wrapping_add(1));
                }
            }
        }
    });
}

struct Running {
    handle: JoinHandle<()>,
    /// Where the link goes: a change starts it again.
    target: (String, u16),
    wake: watch::Sender<u64>,
}

/// Starts a link for every enabled relay, and stops those for relays gone,
/// turned off, or moved.
async fn reconcile(
    inner: &Arc<Inner>,
    server: &Server,
    certs: &Arc<NodeCertificates>,
    instance: &Arc<ServerInstance>,
    links: &mut HashMap<u32, Running>,
) -> trc::Result<()> {
    let data = server.store();
    let all = match relays::keys(data).await? {
        Some(_) => relays::all(data).await?,
        None => Vec::new(),
    };
    // Which relays outbound mail goes through (RL-20, RL-24)
    server.inner.data.relay_senders.set_relays(&all);
    // The domains' MX and SPF records, when the relays in them changed (RL-25)
    if let Some(hash) = relays::dns::dns_change(data, &all).await? {
        queue_relay_dns(server).await?;
        relays::dns::record_dns(data, hash).await?;
    }
    // Their certificates, ordered when missing or running out (RL-27)
    order_relay_certificates(inner, &all).await;
    let wanted: HashMap<u32, (String, u16)> = all
        .into_iter()
        .filter(|relay| relay.enabled)
        .map(|relay| (relay.id, (relay.address.clone(), relay.link_port)))
        .collect();
    links.retain(|id, link| match wanted.get(id) {
        Some(target) if *target == link.target && !link.handle.is_finished() => true,
        // Moved: start over at the new address
        Some(_) => {
            link.handle.abort();
            false
        }
        // Gone or turned off: the link sees it, says so, and ends
        None => {
            link.wake.send_modify(|n| *n = n.wrapping_add(1));
            false
        }
    });
    for (id, target) in wanted {
        if links.contains_key(&id) {
            continue;
        }
        let (wake, woken) = watch::channel(0);
        let handle = tokio::spawn(run_link(
            inner.clone(),
            id,
            certs.clone(),
            instance.clone(),
            woken,
        ));
        links.insert(
            id,
            Running {
                handle,
                target,
                wake,
            },
        );
    }
    Ok(())
}

/// RL-16: a relay's messages are remembered for its `heldMaxAge` and a day.
async fn forget_taken(server: &Server) -> trc::Result<()> {
    let data = server.store();
    for relay in relays::all(data).await? {
        let keep = (u64::from(relay.settings.held_max_age) + 1) * 86_400;
        forget_ingested(data, relay.id, now().saturating_sub(keep)).await?;
    }
    Ok(())
}

/// This node's link certificate, made again once it is old.
#[derive(Default)]
struct NodeCertificates(Mutex<Option<Arc<NodeCertificate>>>);

impl NodeCertificates {
    fn get(&self, keys: &DownstreamKeys, node_id: u64) -> trc::Result<Arc<NodeCertificate>> {
        let now = now();
        let mut current = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cert) = current.as_ref()
            && cert.issued_at + NODE_CERT_RENEW_AFTER > now
        {
            return Ok(cert.clone());
        }
        let cert = Arc::new(issue_node_certificate(keys, node_id, now)?);
        *current = Some(cert.clone());
        Ok(cert)
    }
}

/// Why a link went down, and how the node shows it.
struct LinkError {
    state: LinkState,
    message: String,
}

impl LinkError {
    fn down(message: impl Into<String>) -> Self {
        LinkError {
            state: LinkState::Down,
            message: message.into(),
        }
    }

    fn join_failed(message: impl Into<String>) -> Self {
        LinkError {
            state: LinkState::JoinFailed,
            message: message.into(),
        }
    }
}

impl From<trc::Error> for LinkError {
    fn from(err: trc::Error) -> Self {
        LinkError::down(format!("This server failed: {err}"))
    }
}

/// One relay's link, for as long as the relay is enabled.
async fn run_link(
    inner: Arc<Inner>,
    relay_id: u32,
    certs: Arc<NodeCertificates>,
    instance: Arc<ServerInstance>,
    mut woken: watch::Receiver<u64>,
) {
    let mut backoff = BACKOFF_MIN;
    let mut status = StatusWriter::new(inner.build_server().core.network.node_id);
    loop {
        let server = inner.build_server();
        let data = server.store().clone();
        let relay = match relays::get(&data, relay_id).await {
            Ok(Some(relay)) if relay.enabled => relay,
            Ok(Some(_)) => {
                status
                    .set(
                        &data,
                        relay_id,
                        LinkState::Down,
                        Some("The relay is turned off.".into()),
                    )
                    .await;
                return;
            }
            Ok(None) => return,
            Err(err) => {
                trc::error!(err.details("Failed to read a relay"));
                tokio::time::sleep(backoff).await;
                continue;
            }
        };
        let outcome = match link_keys(&server, &certs).await {
            Ok((keys, cert)) => match relay.join.state(now()) {
                JoinState::Waiting => {
                    status.set(&data, relay_id, LinkState::Joining, None).await;
                    join(&data, &relay, &cert).await
                }
                JoinState::Expired => Err(LinkError::join_failed(
                    "The join token ran out before the relay joined. Start a new join.",
                )),
                JoinState::Joined => {
                    session(
                        &server,
                        &instance,
                        &relay,
                        &keys,
                        &cert,
                        &mut woken,
                        &mut status,
                    )
                    .await
                }
            },
            Err(err) => Err(err),
        };
        let wait = match outcome {
            Ok(()) => {
                backoff = BACKOFF_MIN;
                Duration::ZERO
            }
            Err(err) => {
                let wait = if err.state == LinkState::JoinFailed {
                    JOIN_FAILED_WAIT
                } else {
                    backoff
                };
                status
                    .set(&data, relay_id, err.state, Some(err.message))
                    .await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
                wait
            }
        };
        if relay.join.state(now()) == JoinState::Joined {
            status.alert_if_down(relay.relay_id(), &relay.settings.hostname);
        }
        if !wait.is_zero() {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = woken.changed() => {}
            }
        }
    }
}

async fn link_keys(
    server: &Server,
    certs: &NodeCertificates,
) -> Result<(DownstreamKeys, Arc<NodeCertificate>), LinkError> {
    let keys = relays::keys(server.store())
        .await?
        .ok_or_else(|| LinkError::down("This server has no relay keys yet."))?;
    let cert = certs.get(&keys, server.core.network.node_id)?;
    Ok((keys, cert))
}

/// Writes this node's view of a link when it changes, and at least every
/// [`STATUS_EVERY`] seconds while it holds.
struct StatusWriter {
    current: NodeLink,
    written_at: u64,
    /// Since when this node has had no link, if it hasn't.
    unlinked_since: Option<u64>,
    /// `relay.link-down` was raised for this outage, for this relay.
    alerted: Option<(String, String)>,
}

impl StatusWriter {
    fn new(node_id: u64) -> Self {
        StatusWriter {
            current: NodeLink {
                node_id,
                ..Default::default()
            },
            written_at: 0,
            unlinked_since: None,
            alerted: None,
        }
    }

    /// RL-T23: an hour with no link to a joined relay is said once, and
    /// so is its end.
    fn alert_if_down(&mut self, relay_id: String, hostname: &str) {
        let Some(since) = self.unlinked_since else {
            return;
        };
        if self.alerted.is_none() && now() >= since + LINK_DOWN_ALERT {
            trc::event!(
                Relay(trc::RelayEvent::LinkDown),
                Id = relay_id.clone(),
                Hostname = hostname.to_string(),
                Reason = self.current.last_error.clone().unwrap_or_default(),
                Elapsed = trc::Value::Duration(now().saturating_sub(since) * 1000),
            );
            self.alerted = Some((relay_id, hostname.to_string()));
        }
    }

    async fn set(
        &mut self,
        data: &store::Store,
        relay_id: u32,
        state: LinkState,
        error: Option<String>,
    ) {
        let now = now();
        if state != self.current.state {
            self.current.since = now;
        }
        if state == LinkState::Linked {
            self.unlinked_since = None;
            if let Some((id, hostname)) = self.alerted.take() {
                trc::event!(Relay(trc::RelayEvent::LinkUp), Id = id, Hostname = hostname);
            }
        } else if self.unlinked_since.is_none() {
            self.unlinked_since = Some(now);
        }
        let changed = state != self.current.state || error != self.current.last_error;
        self.current.state = state;
        if error.is_some() || state == LinkState::Linked {
            self.current.last_error = error;
        }
        self.write(data, relay_id, changed, now).await;
    }

    async fn seen(
        &mut self,
        data: &store::Store,
        relay_id: u32,
        relay: Option<RelayStatus>,
        recipients: u64,
    ) {
        let now = now();
        let changed = relay != self.current.relay || Some(recipients) != self.current.recipients;
        self.current.last_seen = Some(now);
        if relay.is_some() {
            self.current.relay = relay;
        }
        self.current.recipients = Some(recipients);
        self.write(data, relay_id, changed, now).await;
    }

    async fn write(&mut self, data: &store::Store, relay_id: u32, changed: bool, now: u64) {
        if !changed && now < self.written_at + STATUS_EVERY {
            return;
        }
        self.current.updated_at = now;
        match set_status(data, relay_id, &self.current).await {
            Ok(()) => self.written_at = now,
            Err(err) => {
                trc::error!(err.details("Failed to record a relay link"));
            }
        }
    }
}

// ---- TLS ------------------------------------------------------------------

/// Checks the relay's certificate against its pinned key, or, while it
/// joins, takes any key and keeps it for the proof (RL-7).
#[derive(Debug)]
struct RelayKey {
    pin: Option<Pin>,
    seen: Mutex<Option<Pin>>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for RelayKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let pin = x509_parser::parse_x509_certificate(end_entity)
            .map(|(_, cert)| spki_pin(cert.tbs_certificate.subject_pki.raw))
            .map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        if let Some(pinned) = &self.pin
            && !pins_match(pinned, &pin)
        {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(pin);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // The link is TLS 1.3 only
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Dials one relay: TLS 1.3, this node's link certificate, and the relay's
/// key checked against `pin` when there is one.
struct Dialer {
    address: String,
    port: u16,
    connector: TlsConnector,
    key: Arc<RelayKey>,
}

impl Dialer {
    fn new(relay: &Relay, cert: &NodeCertificate, pin: Option<Pin>) -> Result<Self, LinkError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let key = Arc::new(RelayKey {
            pin,
            seen: Mutex::new(None),
            algorithms: provider.signature_verification_algorithms,
        });
        let private_key = PrivateKeyDer::try_from(cert.key_der.clone())
            .map_err(|err| LinkError::down(format!("The node's link key is unreadable: {err}")))?;
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|err| LinkError::down(err.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(key.clone())
            .with_client_auth_cert(
                vec![
                    CertificateDer::from(cert.cert_der.clone()),
                    CertificateDer::from(cert.ca_der.clone()),
                ],
                private_key,
            )
            .map_err(|err| LinkError::down(err.to_string()))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Dialer {
            address: relay.address.trim().to_string(),
            port: relay.link_port,
            connector: TlsConnector::from(Arc::new(config)),
            key,
        })
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>, LinkError> {
        let host = self.address.trim_start_matches('[').trim_end_matches(']');
        let connect = async {
            let tcp = TcpStream::connect((host, self.port)).await?;
            self.connector
                .connect(
                    ServerName::try_from(SERVER_NAME).expect("a valid name"),
                    tcp,
                )
                .await
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Ok(Ok(tls)) => Ok(tls),
            Ok(Err(err)) => Err(LinkError::down(match self.key.pin {
                Some(_) if err.to_string().contains("ApplicationVerificationFailure") => {
                    "The relay answered with another key than the one pinned at join. \
                     If it was reset, start a new join."
                        .to_string()
                }
                _ => format!("Could not reach the relay: {err}"),
            })),
            Err(_) => Err(LinkError::down("Could not reach the relay in time.")),
        }
    }

    fn seen_pin(&self) -> Option<Pin> {
        *self.key.seen.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One HTTP/1.1 request on its own connection.
    async fn http(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), LinkError> {
        let tls = self.connect().await?;
        let failed =
            |err: &dyn std::fmt::Display| LinkError::down(format!("The relay failed: {err}"));
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| failed(&e))?;
        tokio::spawn(conn);
        let request = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", SERVER_NAME)
            .header("Content-Type", content_type)
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| failed(&e))?;
        let exchange = async {
            let response = sender.send_request(request).await.map_err(|e| failed(&e))?;
            let status = response.status().as_u16();
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|e| failed(&e))?
                .to_bytes()
                .to_vec();
            Ok((status, body))
        };
        tokio::time::timeout(CALL_TIMEOUT, exchange)
            .await
            .map_err(|_| LinkError::down("The relay didn't answer in time."))?
    }

    /// The relay's JMAP session, refused if its link protocol is one this
    /// server doesn't speak (RL-28).
    async fn check_session(&self) -> Result<Capability, LinkError> {
        let (status, body) = self
            .http("GET", "/jmap/session", "application/json", Vec::new())
            .await?;
        if status != 200 {
            return Err(LinkError::down(format!(
                "The relay answered {status} for its session."
            )));
        }
        let capability = serde_json::from_slice::<Session>(&body)
            .ok()
            .and_then(|session| session.capabilities.get(CAPABILITY).cloned())
            .and_then(|value| serde_json::from_value::<Capability>(value).ok())
            .ok_or_else(|| LinkError::down("The relay's session is unreadable."))?;
        if capability.protocol_version != PROTOCOL_VERSION {
            return Err(LinkError::down(format!(
                "The relay speaks link protocol {} and this server speaks {}: \
                 update whichever is older.",
                capability.protocol_version, PROTOCOL_VERSION
            )));
        }
        Ok(capability)
    }

    async fn api(&self, calls: Vec<Invocation>) -> Result<Vec<Invocation>, LinkError> {
        let request = Request {
            using: vec![CORE_CAPABILITY.into(), CAPABILITY.into()],
            method_calls: calls,
            created_ids: None,
        };
        let body = serde_json::to_vec(&request).unwrap_or_default();
        let (status, body) = self
            .http("POST", "/jmap/api", "application/json", body)
            .await?;
        if status != 200 {
            return Err(LinkError::down(format!(
                "The relay answered {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        serde_json::from_slice::<inbuxa_relay_proto::jmap::Response>(&body)
            .map(|response| response.method_responses)
            .map_err(|_| LinkError::down("The relay's answer is unreadable."))
    }

    /// Uploads `body`; the blob's id.
    async fn upload(&self, body: Vec<u8>) -> Result<String, LinkError> {
        let (status, body) = self
            .http(
                "POST",
                "/jmap/upload/relay",
                "application/octet-stream",
                body,
            )
            .await?;
        if status != 200 && status != 201 {
            return Err(LinkError::down(format!(
                "The relay refused an upload ({status})."
            )));
        }
        serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v["blobId"].as_str().map(str::to_string))
            .ok_or_else(|| LinkError::down("The relay's upload answer is unreadable."))
    }
}

// ---- Joining --------------------------------------------------------------

/// Joins a relay waiting with its token (relay spec, "Joining and reset",
/// step 4): one call, `Relay/join`, on a connection whose key is checked by
/// the answer instead.
async fn join(data: &store::Store, relay: &Relay, cert: &NodeCertificate) -> Result<(), LinkError> {
    let Some(secret) = relay.join.secret else {
        return Ok(());
    };
    let dialer = Dialer::new(relay, cert, None)?;
    let nonce = relays::random_key();
    let responses = dialer
        .api(vec![Invocation::new(
            method::RELAY_JOIN,
            json!({"accountId": ACCOUNT_ID, "nonce": b64::encode(&nonce)}),
            "j",
        )])
        .await?;
    let seen = dialer
        .seen_pin()
        .ok_or_else(|| LinkError::down("The relay showed no key."))?;
    let answer = responses
        .into_iter()
        .next()
        .ok_or_else(|| LinkError::down("The relay didn't answer the join."))?;
    if answer.name() == "error" {
        // Another node may have joined it a moment ago: read the relay again
        return Err(LinkError::down(format!(
            "The relay refused the join: {}",
            answer.args()["description"].as_str().unwrap_or("no reason")
        )));
    }
    let proof = answer.args()["proof"]
        .as_str()
        .and_then(b64::decode)
        .unwrap_or_default();
    let claimed = answer.args()["relayPin"].as_str().and_then(b64::decode);
    if claimed.as_deref() != Some(&seen[..])
        || !token::verify_join_proof(&secret, &nonce, &seen, &proof)
    {
        return Err(LinkError::join_failed(
            "The relay's answer didn't prove it holds this relay's token. \
             Reset the relay and start a new join.",
        ));
    }
    // Whichever way it went, the relay is read again: joined by this node
    // or another, or given a new token meanwhile
    let _: JoinRecorded = record_join(data, relay.id, &secret, seen, now()).await?;
    Ok(())
}

// ---- The linked session ---------------------------------------------------

/// A WebSocket to the relay, with the changes it pushed meanwhile.
struct Ws {
    stream: WebSocketStream<TlsStream<TcpStream>>,
    next_id: u64,
    /// Pings sent since the last pong.
    pongs_missed: u32,
    relay_changed: bool,
    inbound_changed: bool,
    events_changed: bool,
    outbound_changed: bool,
}

impl Ws {
    async fn open(dialer: &Dialer) -> Result<Ws, LinkError> {
        let tls = dialer.connect().await?;
        let request = tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(format!("wss://{SERVER_NAME}/jmap/ws"))
            .header("Host", SERVER_NAME)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("Sec-WebSocket-Protocol", "jmap")
            .body(())
            .map_err(|err| LinkError::down(err.to_string()))?;
        let (stream, _) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_tungstenite::client_async(request, tls),
        )
        .await
        .map_err(|_| LinkError::down("The relay's WebSocket didn't open in time."))?
        .map_err(|err| LinkError::down(format!("The relay's WebSocket didn't open: {err}")))?;
        Ok(Ws {
            stream,
            next_id: 0,
            pongs_missed: 0,
            relay_changed: false,
            inbound_changed: false,
            events_changed: false,
            outbound_changed: false,
        })
    }

    async fn send(&mut self, frame: &ClientFrame) -> Result<(), LinkError> {
        let text = serde_json::to_string(frame).unwrap_or_default();
        self.stream
            .send(Message::Text(text.into()))
            .await
            .map_err(|err| LinkError::down(format!("The link dropped: {err}")))
    }

    /// The next frame from the relay, `None` once it has gone.
    async fn frame(&mut self) -> Result<ServerFrame, LinkError> {
        loop {
            match self.stream.next().await {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(frame) = serde_json::from_str::<ServerFrame>(&text) {
                        return Ok(frame);
                    }
                }
                Some(Ok(Message::Pong(_))) => self.pongs_missed = 0,
                Some(Ok(Message::Ping(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Binary(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    return Err(LinkError::down("The relay closed the link."));
                }
                Some(Err(err)) => return Err(LinkError::down(format!("The link dropped: {err}"))),
            }
        }
    }

    /// Pings the relay, or fails once too many pongs have gone missing.
    async fn ping(&mut self) -> Result<(), LinkError> {
        if self.pongs_missed >= PONGS_MISSED_MAX {
            return Err(LinkError::down("The relay stopped answering pings."));
        }
        self.pongs_missed += 1;
        self.stream
            .send(Message::Ping(Bytes::new()))
            .await
            .map_err(|err| LinkError::down(format!("The link dropped: {err}")))
    }

    fn note(&mut self, frame: &ServerFrame) {
        if let ServerFrame::StateChange { changed, .. } = frame {
            for types in changed.values() {
                self.relay_changed |= types.contains_key("Relay");
                self.inbound_changed |= types.contains_key("Inbound");
                self.events_changed |= types.contains_key("RelayEvent");
                self.outbound_changed |= types.contains_key("Outbound");
            }
        }
    }

    /// Sends `calls` and waits for their answers.
    async fn call(&mut self, calls: Vec<Invocation>) -> Result<Vec<Invocation>, LinkError> {
        self.next_id += 1;
        let id = format!("r{}", self.next_id);
        self.send(&ClientFrame::Request {
            id: Some(id.clone()),
            request: Request {
                using: vec![CORE_CAPABILITY.into(), CAPABILITY.into()],
                method_calls: calls,
                created_ids: None,
            },
        })
        .await?;
        let wait = async {
            loop {
                let frame = self.frame().await?;
                match frame {
                    ServerFrame::Response {
                        request_id,
                        response,
                    } if request_id.as_deref() == Some(id.as_str()) => {
                        return Ok(response.method_responses);
                    }
                    ServerFrame::RequestError {
                        request_id, detail, ..
                    } if request_id.as_deref() == Some(id.as_str()) => {
                        return Err(LinkError::down(format!(
                            "The relay refused a request: {}",
                            detail.unwrap_or_default()
                        )));
                    }
                    other => self.note(&other),
                }
            }
        };
        tokio::time::timeout(CALL_TIMEOUT, wait)
            .await
            .map_err(|_| LinkError::down("The relay didn't answer in time."))?
    }

    /// One call on the relay's account, whose answer must not be an error.
    async fn ok(&mut self, name: &str, mut args: Value) -> Result<Value, LinkError> {
        if args.get("accountId").is_none() {
            args["accountId"] = ACCOUNT_ID.into();
        }
        let answer = self
            .call(vec![Invocation::new(name, args, "c")])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| LinkError::down(format!("The relay didn't answer {name}.")))?;
        if answer.name() == "error" {
            return Err(LinkError::down(format!(
                "The relay refused {name}: {}",
                answer.args()["description"]
                    .as_str()
                    .or(answer.args()["type"].as_str())
                    .unwrap_or("no reason")
            )));
        }
        Ok(Value::Object(answer.1))
    }
}

/// What this node last sent the relay on this link.
#[derive(Default)]
struct Sent {
    /// The relay's domains were read, and its recipients sent in full.
    started: bool,
    settings: Option<RelaySettings>,
    domains: BTreeMap<String, RecipientDomain>,
    hashes: BTreeSet<RecipientHash>,
}

/// The relay linked: kept up to date until the link drops, the relay is
/// turned off, moved or joined again, or this node stops.
async fn session(
    server: &Server,
    instance: &Arc<ServerInstance>,
    relay: &Relay,
    keys: &DownstreamKeys,
    cert: &NodeCertificate,
    woken: &mut watch::Receiver<u64>,
    status: &mut StatusWriter,
) -> Result<(), LinkError> {
    let data = server.store();
    let pin = relay.join.relay_pin;
    let dialer = Arc::new(Dialer::new(relay, cert, pin)?);
    dialer.check_session().await?;
    let mut ws = Ws::open(&dialer).await?;
    // Inbound too: live mode (RL-12)
    ws.send(&ClientFrame::WebSocketPushEnable {
        data_types: Some(vec![
            "Relay".into(),
            "Inbound".into(),
            "RelayEvent".into(),
            "Outbound".into(),
        ]),
        push_state: None,
    })
    .await?;
    let mut sent = Sent::default();
    let mut relay = relay.clone();
    sync(server, &relay, keys, &dialer, &mut ws, &mut sent).await?;
    status.set(data, relay.id, LinkState::Linked, None).await;
    refresh_status(&mut ws, data, &relay, &sent, status).await?;

    let (answers_tx, mut answers) = mpsc::unbounded_channel();
    let mut taker = Taker {
        server: server.clone(),
        instance: instance.clone(),
        dialer: dialer.clone(),
        relay_id: relay.id,
        relay_name: relay.name.clone(),
        secret: keys.sealing_secret,
        taking: HashSet::new(),
        answers: answers_tx,
    };
    taker.take(&mut ws).await?;
    take_events(&mut ws, server, &relay, status.current.node_id).await?;

    // Outbound mail can go through this link now (RL-24), until it drops
    let _sending = Sending::up(server, &relay, dialer.clone());
    let mut follower = Follower::default();
    follower
        .follow(&mut ws, server, &relay, status.current.node_id)
        .await?;

    let mut tick = tokio::time::interval(SYNC);
    tick.reset();
    let mut ping = tokio::time::interval(PING_EVERY);
    // A long call must not let pings pile up and count as missed
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ping.reset();
    loop {
        tokio::select! {
            frame = ws.frame() => {
                let frame = frame?;
                ws.note(&frame);
                if ws.relay_changed {
                    refresh_status(&mut ws, data, &relay, &sent, status).await?;
                }
                if ws.inbound_changed {
                    taker.take(&mut ws).await?;
                }
                if ws.events_changed {
                    take_events(&mut ws, server, &relay, status.current.node_id).await?;
                }
                if ws.outbound_changed {
                    follower.follow(&mut ws, server, &relay, status.current.node_id).await?;
                }
                continue;
            }
            Some(answer) = answers.recv() => {
                taker.answer(&mut ws, answer).await?;
                taker.take(&mut ws).await?;
                continue;
            }
            _ = ping.tick() => {
                ws.ping().await?;
                continue;
            }
            _ = tick.tick() => {}
            changed = woken.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
            }
        }
        // The relay as it is now: a new join, a move or off ends this link
        match relays::get(data, relay.id).await? {
            Some(now_relay)
                if now_relay.enabled
                    && now_relay.join.relay_pin == pin
                    && now_relay.address == relay.address
                    && now_relay.link_port == relay.link_port =>
            {
                relay = now_relay;
            }
            _ => return Ok(()),
        }
        sync(server, &relay, keys, &dialer, &mut ws, &mut sent).await?;
        refresh_status(&mut ws, data, &relay, &sent, status).await?;
        taker.relay_name = relay.name.clone();
        taker.take(&mut ws).await?;
        take_events(&mut ws, server, &relay, status.current.node_id).await?;
        follower
            .follow(&mut ws, server, &relay, status.current.node_id)
            .await?;
    }
}

// ---- Relay events -----------------------------------------------------------

/// The relay's events, as this server's trace events, then acknowledged so
/// the relay can forget them. One node takes them: the lowest linked one.
async fn take_events(
    ws: &mut Ws,
    server: &Server,
    relay: &Relay,
    node_id: u64,
) -> Result<(), LinkError> {
    ws.events_changed = false;
    if !first_linked(server.store(), relay.id, node_id).await? {
        return Ok(());
    }
    let answer = ws.ok(method::RELAY_EVENT_GET, json!({})).await?;
    let mut ids = Vec::new();
    for event in answer["list"].as_array().into_iter().flatten() {
        if let Ok(event) = serde_json::from_value::<ProtoRelayEvent>(event.clone()) {
            trace_event(relay, &event);
            // The relay's sessions count in this server's TLS-RPT reports
            if event.kind == "outbound.tls" {
                report_relayed_tls(server, &event.data).await;
            }
            ids.push(event.id);
        }
    }
    if !ids.is_empty() {
        ws.ok(method::RELAY_EVENT_SET, json!({"destroy": ids}))
            .await?;
    }
    Ok(())
}

/// Whether this node is the lowest linked to the relay, which takes what
/// only one node should: events, and outbound statuses.
async fn first_linked(data: &store::Store, relay_id: u32, node_id: u64) -> trc::Result<bool> {
    Ok(relays::link::statuses(data, relay_id)
        .await?
        .iter()
        .filter(|link| {
            link.state == LinkState::Linked && link.updated_at + 3 * STATUS_EVERY >= now()
        })
        .map(|link| link.node_id)
        .min()
        .is_none_or(|first| first >= node_id))
}

/// One relay event, as a `relay.*` trace event naming the relay.
fn trace_event(relay: &Relay, event: &ProtoRelayEvent) {
    let id = relay.relay_id();
    let hostname = relay.settings.hostname.clone();
    let data = &event.data;
    let text = |key: &str| {
        data.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let number = |key: &str| data.get(key).and_then(Value::as_u64).unwrap_or_default();
    match event.kind.as_str() {
        "smtp.session" => trc::event!(
            Relay(trc::RelayEvent::Session),
            Id = id,
            Hostname = hostname,
            RemoteIp = text("remoteIp"),
            Tls = data.get("tls").and_then(Value::as_bool).unwrap_or_default(),
            Total = number("accepted"),
            TotalFailures = number("refusedRecipients"),
        ),
        "inbound.accepted" => trc::event!(
            Relay(trc::RelayEvent::MessageAccepted),
            Id = id,
            Hostname = hostname,
            Details = text("id"),
            Type = text("mode"),
            Size = number("size"),
        ),
        "inbound.refused" => trc::event!(
            Relay(trc::RelayEvent::MessageRefused),
            Id = id,
            Hostname = hostname,
            Details = text("id"),
            Code = number("code"),
        ),
        "inbound.expired" => trc::event!(
            Relay(trc::RelayEvent::MessageExpired),
            Id = id,
            Hostname = hostname,
            Details = text("id"),
            Value = text("receivedAt"),
        ),
        "relay.joined" => {
            trc::event!(Relay(trc::RelayEvent::Joined), Id = id, Hostname = hostname,)
        }
        "recipients.replaced" => trc::event!(
            Relay(trc::RelayEvent::RecipientsReplaced),
            Id = id,
            Hostname = hostname,
            Total = number("count"),
        ),
        kind => trc::event!(
            Relay(trc::RelayEvent::Event),
            Id = id,
            Hostname = hostname,
            Type = kind.to_string(),
            Details = Value::Object(data.clone()).to_string(),
        ),
    }
}

// ---- Outbound mail ----------------------------------------------------------

/// Hands messages to the relay over this node's link (RL-24): the message
/// as an upload, then `Outbound/set` create.
struct LinkSender {
    dialer: Arc<Dialer>,
}

impl Sender for LinkSender {
    fn hand_over(&self, message: Vec<u8>, envelope: Envelope) -> HandOver<'_> {
        Box::pin(async move {
            let blob_id = self
                .dialer
                .upload(message)
                .await
                .map_err(|err| Refused::Temporary(err.message))?;
            let answer = self
                .dialer
                .api(vec![Invocation::new(
                    method::OUTBOUND_SET,
                    json!({
                        "accountId": ACCOUNT_ID,
                        "create": {"m": {"blobId": blob_id, "envelope": envelope}},
                    }),
                    "c",
                )])
                .await
                .map_err(|err| Refused::Temporary(err.message))?
                .into_iter()
                .next()
                .ok_or_else(|| Refused::Temporary("The relay didn't answer.".into()))?;
            let args = answer.args();
            if let Some(id) = args["created"]["m"]["id"].as_str() {
                return Ok(id.to_string());
            }
            Err(refusal(&args["notCreated"]["m"]))
        })
    }

    fn call(&self, method: &'static str, mut args: Value) -> Call<'_> {
        Box::pin(async move {
            if args.get("accountId").is_none() {
                args["accountId"] = ACCOUNT_ID.into();
            }
            let answer = self
                .dialer
                .api(vec![Invocation::new(method, args, "c")])
                .await
                .map_err(|err| err.message)?
                .into_iter()
                .next()
                .ok_or_else(|| format!("The relay didn't answer {method}."))?;
            if answer.name() == "error" {
                return Err(format!(
                    "The relay refused {method}: {}",
                    answer.args()["description"]
                        .as_str()
                        .or(answer.args()["type"].as_str())
                        .unwrap_or("no reason")
                ));
            }
            Ok(Value::Object(answer.1))
        })
    }
}

/// A relay's `notCreated` for a message, as this server's refusal.
fn refusal(error: &Value) -> Refused {
    let description = error["description"].as_str().unwrap_or("no reason given");
    match error["type"].as_str().unwrap_or_default() {
        "tooLarge" => Refused::Permanent(format!("552 5.3.4 {description}")),
        "forbiddenFrom" => Refused::Permanent(format!("550 5.7.1 {description}")),
        "invalidProperties" => Refused::Permanent(format!("550 5.5.2 {description}")),
        kind => Refused::Temporary(format!("{kind}: {description}")),
    }
}

/// This node's link, offered for outbound mail while it is up.
struct Sending {
    inner: Arc<Inner>,
    linked: Arc<Linked>,
}

impl Sending {
    fn up(server: &Server, relay: &Relay, dialer: Arc<Dialer>) -> Self {
        let linked = Arc::new(Linked {
            relay_id: relay.id,
            name: relay.name.clone(),
            sender: Box::new(LinkSender { dialer }),
        });
        server.inner.data.relay_senders.link_up(linked.clone());
        Sending {
            inner: server.inner.clone(),
            linked,
        }
    }
}

impl Drop for Sending {
    fn drop(&mut self) {
        self.inner.data.relay_senders.link_down(&self.linked);
    }
}

/// How many messages one `Outbound/get` asks for.
const FOLLOW_BATCH: usize = 200;

/// Follows the messages handed to the relay, from any node, until each
/// has a final status (RL-24): the lowest linked node does, and records
/// the relay's replies in this server's queue, which sends the DSNs.
#[derive(Default)]
struct Follower {
    /// Each message's statuses as last recorded, to skip ones unchanged.
    recorded: HashMap<String, BTreeMap<String, DeliveryStatus>>,
}

impl Follower {
    async fn follow(
        &mut self,
        ws: &mut Ws,
        server: &Server,
        relay: &Relay,
        node_id: u64,
    ) -> Result<(), LinkError> {
        ws.outbound_changed = false;
        let data = server.store();
        if !first_linked(data, relay.id, node_id).await? {
            self.recorded.clear();
            return Ok(());
        }
        let handed: HashMap<String, Handed> = outbound::handed(data, relay.id)
            .await?
            .into_iter()
            .map(|h| (h.id.clone(), h))
            .collect();
        self.recorded.retain(|id, _| handed.contains_key(id));
        let ids: Vec<&String> = handed.keys().collect();
        for batch in ids.chunks(FOLLOW_BATCH) {
            let answer = ws.ok(method::OUTBOUND_GET, json!({"ids": batch})).await?;
            let mut done = Vec::new();
            for found in answer["list"].as_array().into_iter().flatten() {
                let Ok(found) = serde_json::from_value::<ProtoOutbound>(found.clone()) else {
                    continue;
                };
                let Some(handed) = handed.get(&found.id) else {
                    continue;
                };
                if self.recorded.get(&found.id) == Some(&found.delivery_status) {
                    continue;
                }
                let statuses = relayed_statuses(handed, &found);
                let finished = statuses.iter().all(|(_, s)| {
                    matches!(
                        s,
                        RelayedStatus::Delivered { .. } | RelayedStatus::Refused { .. }
                    )
                });
                match apply_relayed(
                    server,
                    handed.queue_id,
                    &handed.queue_name,
                    &relay.name,
                    &statuses,
                )
                .await
                {
                    Applied::Done if finished => done.push(found.id.clone()),
                    Applied::Done => {
                        self.recorded
                            .insert(found.id.clone(), found.delivery_status.clone());
                    }
                    // Cancelled here: the relay stops too
                    Applied::Gone => done.push(found.id.clone()),
                    Applied::Locked => {}
                }
            }
            // Gone from the relay (a reset, or kept past seven days): the
            // queue hands the recipients over again
            for id in answer["notFound"].as_array().into_iter().flatten() {
                let Some(handed) = id.as_str().and_then(|id| handed.get(id)) else {
                    continue;
                };
                let lost: Vec<(String, RelayedStatus)> = handed
                    .recipients
                    .iter()
                    .map(|r| (r.clone(), RelayedStatus::Lost))
                    .collect();
                match apply_relayed(
                    server,
                    handed.queue_id,
                    &handed.queue_name,
                    &relay.name,
                    &lost,
                )
                .await
                {
                    Applied::Done | Applied::Gone => {
                        outbound::forget_handed(data, relay.id, std::slice::from_ref(&handed.id))
                            .await?;
                    }
                    Applied::Locked => {}
                }
            }
            if !done.is_empty() {
                let answer = ws
                    .ok(method::OUTBOUND_SET, json!({"destroy": done}))
                    .await?;
                // One being tried right now is cleared next time
                let busy: HashSet<&str> = answer["notDestroyed"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(_, e)| e["type"] == "forbidden")
                    .map(|(id, _)| id.as_str())
                    .collect();
                let forget: Vec<String> = done
                    .into_iter()
                    .filter(|id| !busy.contains(id.as_str()))
                    .collect();
                for id in &forget {
                    self.recorded.remove(id);
                }
                outbound::forget_handed(data, relay.id, &forget).await?;
            }
        }
        Ok(())
    }
}

/// What the relay says of each recipient a message was handed over for.
fn relayed_statuses(handed: &Handed, found: &ProtoOutbound) -> Vec<(String, RelayedStatus)> {
    handed
        .recipients
        .iter()
        .filter_map(|address| {
            let status = found.delivery_status.get(address)?;
            let reply = status.smtp_reply.clone();
            let mx = status.mx.clone();
            Some((
                address.clone(),
                match status.delivered {
                    Delivered::Yes | Delivered::Unknown => RelayedStatus::Delivered { reply, mx },
                    Delivered::No => RelayedStatus::Refused { reply, mx },
                    Delivered::Queued => RelayedStatus::Queued { reply, mx },
                },
            ))
        })
        .collect()
}

// ---- Inbound mail -----------------------------------------------------------

/// Takes the relay's messages for this node: a few at a time, each judged in
/// its own task, each answered on the link when judged.
struct Taker {
    server: Server,
    instance: Arc<ServerInstance>,
    dialer: Arc<Dialer>,
    relay_id: u32,
    relay_name: String,
    secret: [u8; 32],
    /// Claimed and still being judged.
    taking: HashSet<String>,
    answers: mpsc::UnboundedSender<Answer>,
}

/// What a judged message's answer to the relay is.
struct Answer {
    id: String,
    action: Action,
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Taken: the relay deletes it, and a live sender hears 250.
    Destroy,
    /// A live message refused: the relay gives the sender this reply.
    Verdict(Verdict),
    /// Not now: the lease runs out and it is offered again (RL-16).
    Leave,
}

impl Taker {
    /// Claims what the relay holds, up to [`TAKE_MAX`] at once.
    async fn take(&mut self, ws: &mut Ws) -> Result<(), LinkError> {
        ws.inbound_changed = false;
        let room = TAKE_MAX.saturating_sub(self.taking.len());
        if room == 0 {
            return Ok(());
        }
        let claimed = ws
            .ok(
                method::INBOUND_CLAIM,
                json!({"limit": room, "leaseSeconds": LEASE_SECONDS}),
            )
            .await?;
        let ids: Vec<&str> = claimed["ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if ids.is_empty() {
            return Ok(());
        }
        let got = ws.ok(method::INBOUND_GET, json!({"ids": ids})).await?;
        for inbound in got["list"].as_array().into_iter().flatten() {
            let Ok(inbound) = serde_json::from_value::<Inbound>(inbound.clone()) else {
                continue;
            };
            if !is_inbound_id(&inbound.id)
                || !is_inbound_id(&inbound.blob_id)
                || !self.taking.insert(inbound.id.clone())
            {
                continue;
            }
            let job = Job {
                server: self.server.clone(),
                instance: self.instance.clone(),
                dialer: self.dialer.clone(),
                relay_id: self.relay_id,
                relay_name: self.relay_name.clone(),
                secret: self.secret,
            };
            let answers = self.answers.clone();
            tokio::spawn(async move {
                let id = inbound.id.clone();
                let action = Box::pin(job.judge(inbound)).await;
                let _ = answers.send(Answer { id, action });
            });
        }
        Ok(())
    }

    /// Tells the relay what became of one message.
    async fn answer(&mut self, ws: &mut Ws, answer: Answer) -> Result<(), LinkError> {
        self.taking.remove(&answer.id);
        match answer.action {
            Action::Destroy => {
                ws.ok(method::INBOUND_SET, json!({"destroy": [answer.id]}))
                    .await?;
            }
            Action::Verdict(verdict) => {
                // Refused as `notUpdated` if it stopped waiting meanwhile:
                // then it is held, comes back when the lease runs out, and
                // is judged as held
                ws.ok(
                    method::INBOUND_SET,
                    json!({"update": {answer.id: {"verdict": verdict}}}),
                )
                .await?;
            }
            Action::Leave => {}
        }
        Ok(())
    }
}

/// Everything one message's judging needs, apart from the link.
struct Job {
    server: Server,
    instance: Arc<ServerInstance>,
    dialer: Arc<Dialer>,
    relay_id: u32,
    relay_name: String,
    secret: [u8; 32],
}

impl Job {
    async fn judge(self, inbound: Inbound) -> Action {
        let data = self.server.store().clone();
        // RL-16: offered again after this server took it
        match was_ingested(&data, self.relay_id, &inbound.id).await {
            Ok(true) => return Action::Destroy,
            Ok(false) => {}
            Err(err) => {
                trc::error!(err.details("Failed to read the relayed messages taken"));
                return Action::Leave;
            }
        }
        let live = inbound.state == InboundState::Pending;

        let message = match self.fetch(&inbound).await {
            Ok(message) => message,
            Err(reason) => {
                trc::error!(
                    trc::EventType::Server(trc::ServerEvent::ThreadError)
                        .reason(reason)
                        .details("Failed to take a relayed message")
                        .id(inbound.id.clone())
                );
                return Action::Leave;
            }
        };

        let input = relayed_message(&self.relay_name, &inbound, !live, message);
        let outcome = Box::pin(ingest_relayed(
            self.server.clone(),
            self.instance.clone(),
            input,
        ))
        .await;
        let action = action_for(&outcome, live);
        if action == Action::Destroy
            && let Err(err) = record_ingested(&data, self.relay_id, &inbound.id, now()).await
        {
            trc::error!(err.details("Failed to record a relayed message as taken"));
        }
        action
    }

    /// The message, downloaded and unsealed (RL-21).
    async fn fetch(&self, inbound: &Inbound) -> Result<Vec<u8>, String> {
        let (status, sealed) = self
            .dialer
            .http(
                "GET",
                &format!("/jmap/download/relay/{}/msg", inbound.blob_id),
                "application/octet-stream",
                Vec::new(),
            )
            .await
            .map_err(|err| err.message)?;
        if status != 200 {
            return Err(format!(
                "The relay answered {status} for a held message's download."
            ));
        }
        seal::open(&self.secret, inbound.id.as_bytes(), &sealed)
            .map_err(|err| format!("A relayed message didn't unseal: {err}"))
    }
}

/// The relay's session, as this server's pipeline takes it (RL-23).
fn relayed_message(relay: &str, inbound: &Inbound, held: bool, message: Vec<u8>) -> RelayedMessage {
    let address = |address: &Address| {
        (
            address.email.clone(),
            address
                .parameters
                .iter()
                .flatten()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        )
    };
    let session = &inbound.session;
    RelayedMessage {
        relayed: Relayed {
            relay: relay.to_string(),
            held,
            tls: session
                .tls
                .as_ref()
                .map(|tls| (tls.version.clone(), tls.cipher.clone())),
            dmarc_pass: false,
        },
        local_ip: session.local_ip,
        remote_ip: session.remote_ip,
        remote_port: session.remote_port,
        helo: session.helo.clone(),
        mail_from: address(&inbound.envelope.mail_from),
        rcpt_to: inbound.envelope.rcpt_to.iter().map(address).collect(),
        message,
    }
}

/// What the relay is told, from what this server answered.
fn action_for(outcome: &RelayedOutcome, live: bool) -> Action {
    match outcome {
        RelayedOutcome::Accepted { .. } => Action::Destroy,
        RelayedOutcome::Refused { reply, .. } if live => Action::Verdict(verdict_for(reply)),
        // Held and refused for good: reported to the sender if it may be
        // (RL-18), and gone
        RelayedOutcome::Refused { reply, .. } if reply.starts_with('5') => Action::Destroy,
        // Held and refused for now: tried again after the lease
        RelayedOutcome::Refused { .. } => Action::Leave,
    }
}

/// A live message's verdict: this server's reply, as the relay gives it.
fn verdict_for(reply: &str) -> Verdict {
    let mut parts = reply.splitn(3, ' ');
    let code = parts.next().and_then(|code| code.parse::<u16>().ok());
    let class = code.map_or(4, |code| code / 100);
    let (enhanced, text) = match parts.next() {
        Some(esc)
            if esc.split('.').count() == 3
                && esc.split('.').all(|p| p.parse::<u16>().is_ok())
                && esc.starts_with(char::from(b'0' + class as u8)) =>
        {
            (
                esc.to_string(),
                parts.next().unwrap_or_default().to_string(),
            )
        }
        Some(word) => (
            format!("{class}.0.0"),
            [word, parts.next().unwrap_or_default()].join(" "),
        ),
        None => (format!("{class}.0.0"), String::new()),
    };
    // Not a reply at all: its words, as a temporary failure
    let text = if code.is_none() {
        reply.to_string()
    } else {
        text
    };
    let text: String = text
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(400)
        .collect();
    let text = if text.is_empty() {
        "Refused".to_string()
    } else {
        text
    };
    let verdict = match (code, class) {
        (Some(code), 5) => Verdict::Reject(Reply {
            code,
            enhanced,
            text,
        }),
        (Some(code), 4) => Verdict::Tempfail(Reply {
            code,
            enhanced,
            text,
        }),
        _ => Verdict::Tempfail(Reply {
            code: 451,
            enhanced: "4.3.0".into(),
            text,
        }),
    };
    if verdict.is_valid() {
        verdict
    } else {
        Verdict::Tempfail(Reply {
            code: 451,
            enhanced: "4.3.0".into(),
            text: "Try again later".into(),
        })
    }
}

/// Asks the relay how it is, and records it.
async fn refresh_status(
    ws: &mut Ws,
    data: &store::Store,
    relay: &Relay,
    sent: &Sent,
    status: &mut StatusWriter,
) -> Result<(), LinkError> {
    ws.relay_changed = false;
    let answer = ws
        .ok(method::RELAY_GET, json!({"ids": [RELAY_SINGLETON]}))
        .await?;
    let relay_status = answer["list"][0]
        .get("status")
        .cloned()
        .and_then(|value| serde_json::from_value::<RelayStatus>(value).ok());
    status
        .seen(data, relay.id, relay_status, sent.hashes.len() as u64)
        .await;
    Ok(())
}

/// Brings the relay's settings, domains and recipients level with this
/// server's, sending only what changed since the last time.
async fn sync(
    server: &Server,
    relay: &Relay,
    keys: &DownstreamKeys,
    dialer: &Dialer,
    ws: &mut Ws,
    sent: &mut Sent,
) -> Result<(), LinkError> {
    let (local, addresses) = local_recipients(server).await?;
    let plan = RecipientPlan::new(relay, &local, &addresses);
    if plan.domains.is_empty() {
        return Err(LinkError::down(
            "The relay has no domain to serve: none of its domains is on this server.",
        ));
    }

    // Settings, whole, when they changed
    let settings = pushed_settings(relay, keys, &plan);
    if sent.settings.as_ref() != Some(&settings) {
        let patch = serde_json::to_value(&settings).unwrap_or_default();
        let answer = ws
            .ok(
                method::RELAY_SET,
                json!({"update": {RELAY_SINGLETON: patch}}),
            )
            .await?;
        if let Some(error) = answer["notUpdated"][RELAY_SINGLETON].as_object() {
            return Err(LinkError::down(format!(
                "The relay refused its settings: {}",
                error
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("no reason")
            )));
        }
        sent.settings = Some(settings);
    }

    // Domains: on a new link, whatever the relay holds that isn't served
    // goes; after that, only changes
    if !sent.started {
        let answer = ws.ok(method::RECIPIENT_DOMAIN_GET, json!({})).await?;
        for domain in answer["list"].as_array().into_iter().flatten() {
            if let Ok(domain) = serde_json::from_value::<RecipientDomain>(domain.clone()) {
                sent.domains.insert(domain.domain.clone(), domain);
            }
        }
    }
    let create: serde_json::Map<String, Value> = plan
        .domains
        .iter()
        .filter(|(name, domain)| sent.domains.get(*name) != Some(*domain))
        .map(|(name, domain)| {
            (
                name.clone(),
                serde_json::to_value(domain).unwrap_or_default(),
            )
        })
        .collect();
    let destroy: Vec<&String> = sent
        .domains
        .keys()
        .filter(|name| !plan.domains.contains_key(*name))
        .collect();
    if !create.is_empty() || !destroy.is_empty() {
        ws.ok(
            method::RECIPIENT_DOMAIN_SET,
            json!({"create": create, "destroy": destroy}),
        )
        .await?;
        sent.domains = plan.domains.clone();
    }

    // Recipients: in full on a new link or after many changes, else as
    // changes
    let hashes: BTreeSet<RecipientHash> = plan.hashes(&relay.recipient_key).into_iter().collect();
    let added: Vec<&RecipientHash> = hashes.difference(&sent.hashes).collect();
    let removed: Vec<&RecipientHash> = sent.hashes.difference(&hashes).collect();
    if !sent.started || added.len() + removed.len() > MAX_DELTA {
        let mut file = Vec::with_capacity(hashes.len() * 32);
        for hash in &hashes {
            file.extend_from_slice(hash);
        }
        let blob_id = dialer.upload(file).await?;
        ws.ok(method::RECIPIENT_REPLACE, json!({"blobId": blob_id}))
            .await?;
    } else if !added.is_empty() || !removed.is_empty() {
        let create: serde_json::Map<String, Value> = added
            .iter()
            .enumerate()
            .map(|(i, hash)| (format!("h{i}"), json!({"hash": b64::encode(*hash)})))
            .collect();
        let destroy: Vec<String> = removed.iter().map(|hash| b64::encode(*hash)).collect();
        ws.ok(
            method::RECIPIENT_SET,
            json!({"create": create, "destroy": destroy}),
        )
        .await?;
    }
    sent.hashes = hashes;
    sent.started = true;
    Ok(())
}

// ---- This server's recipients ---------------------------------------------

/// This server's domains, and every address it takes mail for: accounts and
/// groups with their aliases, mailing lists, and live masked addresses.
/// Each address counts at every name of its domain.
///
/// A domain whose recipients an external directory answers for has only
/// the addresses this server has seen from it.
async fn local_recipients(server: &Server) -> trc::Result<(Vec<LocalDomain>, Vec<String>)> {
    let registry = server.registry();
    let mut names: HashMap<u32, Vec<String>> = HashMap::new();
    let mut local = Vec::new();
    for id in registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Domain))
        .await?
    {
        let Some(domain) = registry.object::<Domain>(id).await? else {
            continue;
        };
        if !domain.is_enabled {
            continue;
        }
        let mut domain_names = vec![domain.name.trim_end_matches('.').to_ascii_lowercase()];
        domain_names.extend(
            domain
                .aliases
                .iter()
                .map(|alias| alias.trim_end_matches('.').to_ascii_lowercase()),
        );
        local.push(LocalDomain {
            names: domain_names.clone(),
            catch_all: domain.catch_all_address.is_some() || domain.allow_relaying,
            subaddress_separator: match domain.sub_addressing {
                SubAddressing::Disabled => None,
                SubAddressing::Enabled | SubAddressing::Custom(_) => Some("+".into()),
            },
        });
        names.insert(id.document_id(), domain_names);
    }

    let mut addresses = Vec::new();
    let mut add = |local_part: &str, domain_id: u32| {
        for name in names.get(&domain_id).into_iter().flatten() {
            addresses.push(format!("{}@{name}", local_part.to_lowercase()));
        }
    };
    for id in registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Account))
        .await?
    {
        if let Some(account) = server.try_account(id.document_id()).await? {
            for address in account.addresses.iter() {
                add(&address.local_part, address.domain_id);
            }
        }
    }
    for id in registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::MailingList))
        .await?
    {
        if let Some(list) = server.try_list(id.document_id()).await? {
            for address in list.addresses.iter() {
                add(&address.local_part, address.domain_id);
            }
        }
    }
    for mask in masked_email::ops::all(server.store(), registry).await? {
        if mask.accepts_mail() {
            addresses.push(mask.object.email.to_lowercase());
        }
    }
    Ok((local, addresses))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(code: u16, enhanced: &str, text: &str) -> Reply {
        Reply {
            code,
            enhanced: enhanced.into(),
            text: text.into(),
        }
    }

    #[test]
    fn verdicts() {
        assert_eq!(
            verdict_for("550 5.7.1 Message rejected due to excessive spam score."),
            Verdict::Reject(reply(
                550,
                "5.7.1",
                "Message rejected due to excessive spam score."
            ))
        );
        assert_eq!(
            verdict_for("450 4.4.6 Too many Received headers."),
            Verdict::Tempfail(reply(450, "4.4.6", "Too many Received headers."))
        );
        // No enhanced code, or one of the wrong class: the class's own
        assert_eq!(
            verdict_for("554 no thanks"),
            Verdict::Reject(reply(554, "5.0.0", "no thanks"))
        );
        assert_eq!(
            verdict_for("451 5.7.1 odd"),
            Verdict::Tempfail(reply(451, "4.0.0", "5.7.1 odd"))
        );
        // Anything else is a temporary failure, never a 250
        assert_eq!(
            verdict_for("garbage"),
            Verdict::Tempfail(reply(451, "4.3.0", "garbage"))
        );
        assert!(verdict_for("550 5.1.1").is_valid());
    }

    #[test]
    fn link_down_alert() {
        let alert = |status: &mut StatusWriter| status.alert_if_down("a".into(), "mx1.example.com");
        let mut status = StatusWriter::new(7);
        // Never unlinked, or not for an hour yet: nothing
        alert(&mut status);
        assert!(status.alerted.is_none());
        status.unlinked_since = Some(now() - LINK_DOWN_ALERT + 60);
        alert(&mut status);
        assert!(status.alerted.is_none());
        // An hour: once
        status.unlinked_since = Some(now() - LINK_DOWN_ALERT);
        alert(&mut status);
        let first = status.alerted.clone();
        assert!(first.is_some());
        alert(&mut status);
        assert_eq!(status.alerted, first);
    }

    #[test]
    fn actions() {
        let accepted = RelayedOutcome::Accepted {
            refused: vec![("joe@example.com".into(), "550 5.1.1 No".into())],
        };
        let refused = |reply: &str| RelayedOutcome::Refused {
            reply: reply.into(),
            refused: vec![],
        };
        assert_eq!(action_for(&accepted, true), Action::Destroy);
        assert_eq!(action_for(&accepted, false), Action::Destroy);
        assert!(matches!(
            action_for(&refused("550 5.7.1 Spam"), true),
            Action::Verdict(Verdict::Reject(_))
        ));
        // Held: refused for good is reported and gone, for now is retried
        assert_eq!(action_for(&refused("550 5.1.1 No"), false), Action::Destroy);
        assert_eq!(
            action_for(&refused("451 4.3.0 Later"), false),
            Action::Leave
        );
    }
}
