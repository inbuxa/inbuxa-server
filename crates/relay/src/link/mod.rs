/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The link (RL-5): JMAP over HTTP/1.1 and WebSocket (RFC 8887), behind
//! pinned mutual TLS. The downstream dials in; nothing here dials out.
//!
//! Routes: `GET /jmap/session`, `POST /jmap/api`, `GET /jmap/ws`,
//! `POST /jmap/upload/relay` and `GET /jmap/download/relay/<blobId>`.

pub mod jmap;
pub mod tls;

use crate::app::App;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, Limited, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Frame, Incoming},
    header,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use inbuxa_relay_proto::{
    CAPABILITY, CORE_CAPABILITY, PROTOCOL_VERSION,
    jmap::{
        self as proto, Account, ClientFrame, ServerFrame, Session, WEBSOCKET_CAPABILITY,
        websocket_capability,
    },
    types::{Capability, type_name},
};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::TcpListener};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, handshake::derive_accept_key, protocol::Role},
};

/// Largest upload: a recipient file for about two million addresses.
pub const MAX_BLOB_SIZE: u64 = 64 * 1024 * 1024;
/// Largest JMAP request.
const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024;
/// TLS handshakes a minute from one address.
const HANDSHAKES_PER_MINUTE: u32 = 30;

type Body = UnsyncBoxBody<Bytes, std::io::Error>;

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn json_response(status: StatusCode, value: &impl serde::Serialize) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(full(serde_json::to_vec(value).expect("serializes")))
        .expect("response")
}

fn problem(status: StatusCode, kind: &str, detail: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/problem+json")
        .body(full(
            serde_json::to_vec(&serde_json::json!({
                "type": kind, "status": status.as_u16(), "detail": detail
            }))
            .expect("serializes"),
        ))
        .expect("response")
}

pub fn is_blob_id(id: &str) -> bool {
    id.len() == 25 && id.starts_with('b') && id[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn new_blob_id() -> String {
    let mut id = crate::spool::new_id();
    id.replace_range(0..1, "b");
    id
}

#[derive(Default)]
struct Handshakes {
    ips: HashMap<IpAddr, (u64, u32)>,
}

impl Handshakes {
    fn allow(&mut self, ip: IpAddr, now: u64) -> bool {
        let minute = now / 60;
        if self.ips.len() > 10_000 {
            self.ips.retain(|_, (m, _)| *m == minute);
        }
        let entry = self.ips.entry(ip).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        entry.1 += 1;
        entry.1 <= HANDSHAKES_PER_MINUTE
    }
}

/// Runs the link listener until the process ends.
pub async fn serve(app: Arc<App>, listener: TcpListener) -> std::io::Result<()> {
    let config = {
        let identity = app.identity.lock().expect("identity");
        tls::server_config(
            &identity.link_key_pem,
            &identity.link_cert_pem,
            identity.ca_pin,
        )
        .map_err(std::io::Error::other)?
    };
    let acceptor = TlsAcceptor::from(Arc::new(config));
    if let Ok(addr) = listener.local_addr() {
        eprintln!("inbuxa-relay: link listening on {addr}");
    }
    let handshakes = Arc::new(Mutex::new(Handshakes::default()));
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("inbuxa-relay: link accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Dropped before TLS, with no reply (RL-33)
        if !app.link_allows(peer.ip()) {
            continue;
        }
        let now = inbuxa_relay_proto::time::now();
        if !handshakes.lock().expect("handshakes").allow(peer.ip(), now) {
            continue;
        }
        let app = app.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let tls =
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                    Ok(Ok(tls)) => tls,
                    // No client certificate, the wrong CA, or a timeout: the
                    // peer gets a TLS alert and nothing more.
                    _ => return,
                };
            let conn = app.conn_id();
            let caller = jmap::Caller {
                conn,
                peer: peer.ip().to_canonical(),
            };
            let service = {
                let app = app.clone();
                service_fn(move |req| {
                    let app = app.clone();
                    async move { Ok::<_, std::convert::Infallible>(route(app, caller, req).await) }
                })
            };
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30))
                .serve_connection(TokioIo::new(tls), service)
                .with_upgrades()
                .await;
            let released = app.spool.lock().expect("spool").release_conn(conn);
            if released {
                app.inbound_changed();
            }
        });
    }
}

async fn route(app: Arc<App>, caller: jmap::Caller, req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path().to_string();
    match (req.method(), path.as_str()) {
        (&Method::GET, "/jmap/session" | "/.well-known/jmap") => session(&app, &req),
        (&Method::POST, "/jmap/api") => api(app, caller, req).await,
        (&Method::GET, "/jmap/ws") => websocket(app, caller, req),
        (&Method::POST, "/jmap/upload/relay") => upload(app, req).await,
        (&Method::GET, p) if p.starts_with("/jmap/download/relay/") => {
            download(app, &p["/jmap/download/relay/".len()..]).await
        }
        _ => problem(StatusCode::NOT_FOUND, "about:blank", "not found"),
    }
}

fn base_url(req: &Request<Incoming>) -> String {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .filter(|h| h.bytes().all(|b| b.is_ascii_graphic()))
        .unwrap_or("relay.invalid");
    format!("https://{host}")
}

fn session(app: &App, req: &Request<Incoming>) -> Response<Body> {
    let base = base_url(req);
    let capability = Capability {
        protocol_version: PROTOCOL_VERSION,
        relay_version: crate::app::VERSION.into(),
        max_blob_size: MAX_BLOB_SIZE,
        features: vec![],
    };
    let ws_url = format!("{}/jmap/ws", base.replacen("https://", "wss://", 1));
    let core = serde_json::json!({
        "maxSizeUpload": MAX_BLOB_SIZE,
        "maxConcurrentUpload": 4,
        "maxSizeRequest": MAX_REQUEST_SIZE,
        "maxConcurrentRequests": 8,
        "maxCallsInRequest": jmap::MAX_CALLS,
        "maxObjectsInGet": 5000,
        "maxObjectsInSet": 5000,
        "collationAlgorithms": [],
    });
    let capability = serde_json::to_value(capability).expect("serializes");
    let session = Session {
        capabilities: BTreeMap::from([
            (CORE_CAPABILITY.to_string(), core),
            (CAPABILITY.to_string(), capability.clone()),
            (
                WEBSOCKET_CAPABILITY.to_string(),
                websocket_capability(&ws_url),
            ),
        ]),
        accounts: BTreeMap::from([(
            jmap::ACCOUNT_ID.to_string(),
            Account {
                name: app.identity.lock().expect("identity").relay_id.clone(),
                is_personal: false,
                is_read_only: false,
                account_capabilities: BTreeMap::from([(CAPABILITY.to_string(), capability)]),
            },
        )]),
        primary_accounts: BTreeMap::from([(CAPABILITY.to_string(), jmap::ACCOUNT_ID.to_string())]),
        username: "downstream".into(),
        api_url: format!("{base}/jmap/api"),
        download_url: format!("{base}/jmap/download/{{accountId}}/{{blobId}}"),
        upload_url: format!("{base}/jmap/upload/{{accountId}}"),
        event_source_url: String::new(),
        state: "1".into(),
    };
    json_response(StatusCode::OK, &session)
}

async fn api(app: Arc<App>, caller: jmap::Caller, req: Request<Incoming>) -> Response<Body> {
    let body = match Limited::new(req.into_body(), MAX_REQUEST_SIZE)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                proto::request_error::LIMIT,
                "the request is too large",
            );
        }
    };
    let request: proto::Request = match serde_json::from_slice::<serde_json::Value>(&body) {
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                proto::request_error::NOT_JSON,
                "not JSON",
            );
        }
        Ok(value) => match serde_json::from_value(value) {
            Ok(request) => request,
            Err(e) => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    proto::request_error::NOT_REQUEST,
                    &e.to_string(),
                );
            }
        },
    };
    match jmap::handle(&app, &caller, request) {
        Ok(response) => json_response(StatusCode::OK, &response),
        Err(e) => problem(
            StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST),
            e.kind,
            &e.detail,
        ),
    }
}

async fn upload(app: Arc<App>, req: Request<Incoming>) -> Response<Body> {
    let body = match Limited::new(req.into_body(), MAX_BLOB_SIZE as usize)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                proto::request_error::LIMIT,
                "the upload is too large",
            );
        }
    };
    let blob_id = new_blob_id();
    let path = app.paths.blobs().join(&blob_id);
    if let Err(e) = tokio::fs::write(&path, &body).await {
        app.set_error(format!("could not store an upload: {e}"));
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "about:blank",
            "could not store the upload",
        );
    }
    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "accountId": jmap::ACCOUNT_ID,
            "blobId": blob_id,
            "type": "application/octet-stream",
            "size": body.len(),
        }),
    )
}

/// Downloads a held message: the sealed stream, exactly as stored.
async fn download(app: Arc<App>, rest: &str) -> Response<Body> {
    let blob_id = rest.split('/').next().unwrap_or("");
    if !crate::spool::is_valid_id(blob_id) || !app.spool.lock().expect("spool").contains(blob_id) {
        return problem(StatusCode::NOT_FOUND, "about:blank", "no such blob");
    }
    let path = app.spool.lock().expect("spool").msg_path(blob_id);
    let file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(_) => return problem(StatusCode::NOT_FOUND, "about:blank", "no such blob"),
    };
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let stream = futures_util::stream::unfold(file, |mut file| async move {
        let mut buf = vec![0u8; 64 * 1024];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(Frame::data(Bytes::from(buf))), file))
            }
            Err(e) => Some((Err(e), file)),
        }
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, len)
        .header(header::CACHE_CONTROL, "no-store")
        .body(StreamBody::new(stream).boxed_unsync())
        .expect("response")
}

fn websocket(app: Arc<App>, caller: jmap::Caller, mut req: Request<Incoming>) -> Response<Body> {
    let headers = req.headers();
    let is_upgrade = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let protocols_ok = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|p| p.trim() == "jmap");
    let Some(key) = headers.get(header::SEC_WEBSOCKET_KEY).cloned() else {
        return problem(
            StatusCode::BAD_REQUEST,
            "about:blank",
            "not a WebSocket request",
        );
    };
    if !is_upgrade || !protocols_ok {
        return problem(
            StatusCode::BAD_REQUEST,
            "about:blank",
            "a WebSocket with the jmap subprotocol is required",
        );
    }
    let accept = derive_accept_key(key.as_bytes());
    let upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let Ok(upgraded) = upgrade.await else {
            return;
        };
        let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
        run_websocket(app, caller, ws).await;
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header(header::SEC_WEBSOCKET_ACCEPT, accept)
        .header(header::SEC_WEBSOCKET_PROTOCOL, "jmap")
        .body(full(Bytes::new()))
        .expect("response")
}

/// Push settings for one WebSocket.
struct PushState {
    /// `None` when push is off; `Some(None)` for every type.
    types: Option<Option<Vec<String>>>,
    live: bool,
}

impl PushState {
    fn wants(&self, type_name: &str) -> bool {
        match &self.types {
            None => false,
            Some(None) => true,
            Some(Some(types)) => types.iter().any(|t| t == type_name),
        }
    }
}

async fn run_websocket<S>(app: Arc<App>, caller: jmap::Caller, ws: WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    app.link_clients.fetch_add(1, Ordering::Relaxed);
    app.relay_changed();
    let (mut sink, mut stream) = ws.split();
    let mut changes = app.push.subscribe();
    let mut push = PushState {
        types: None,
        live: false,
    };
    let idle = Duration::from_secs(120);
    loop {
        tokio::select! {
            frame = tokio::time::timeout(idle, stream.next()) => {
                let message = match frame {
                    Ok(Some(Ok(message))) => message,
                    // Closed, broken, or silent past two pings.
                    _ => break,
                };
                let text = match message {
                    Message::Text(text) => text.to_string(),
                    Message::Ping(data) => {
                        if sink.send(Message::Pong(data)).await.is_err() { break; }
                        continue;
                    }
                    Message::Pong(_) => continue,
                    Message::Close(_) => break,
                    Message::Binary(_) | Message::Frame(_) => {
                        let reply = ServerFrame::RequestError {
                            request_id: None,
                            kind: proto::request_error::NOT_JSON.into(),
                            status: 400,
                            detail: Some("frames are JSON text".into()),
                        };
                        if send(&mut sink, &reply).await.is_err() { break; }
                        continue;
                    }
                };
                if text.len() > MAX_REQUEST_SIZE {
                    break;
                }
                let reply = match serde_json::from_str::<ClientFrame>(&text) {
                    Err(e) => Some(ServerFrame::RequestError {
                        request_id: None,
                        kind: proto::request_error::NOT_REQUEST.into(),
                        status: 400,
                        detail: Some(e.to_string()),
                    }),
                    Ok(ClientFrame::Request { id, request }) => {
                        Some(match jmap::handle(&app, &caller, request) {
                            Ok(response) => ServerFrame::Response { request_id: id, response },
                            Err(e) => ServerFrame::RequestError {
                                request_id: id,
                                kind: e.kind.into(),
                                status: e.status,
                                detail: Some(e.detail),
                            },
                        })
                    }
                    Ok(ClientFrame::WebSocketPushEnable { data_types, .. }) => {
                        push.types = Some(data_types);
                        set_live(&app, &mut push);
                        // Send the current states, so the client starts level.
                        Some(state_change(&app, &push))
                    }
                    Ok(ClientFrame::WebSocketPushDisable) => {
                        push.types = None;
                        set_live(&app, &mut push);
                        None
                    }
                };
                if let Some(reply) = reply
                    && send(&mut sink, &reply).await.is_err()
                {
                    break;
                }
            }
            change = changes.recv() => {
                match change {
                    Ok(change) if push.wants(change.type_name) => {
                        let frame = ServerFrame::StateChange {
                            changed: BTreeMap::from([(
                                jmap::ACCOUNT_ID.to_string(),
                                BTreeMap::from([(change.type_name.to_string(), change.state)]),
                            )]),
                            push_state: None,
                        };
                        if send(&mut sink, &frame).await.is_err() { break; }
                    }
                    Ok(_) => {}
                    // Missed some: send every state again.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        if push.types.is_some() && send(&mut sink, &state_change(&app, &push)).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    push.types = None;
    set_live(&app, &mut push);
    app.link_clients.fetch_sub(1, Ordering::Relaxed);
    if app.spool.lock().expect("spool").release_conn(caller.conn) {
        app.inbound_changed();
    }
    app.relay_changed();
}

fn set_live(app: &App, push: &mut PushState) {
    let live = push.wants(type_name::INBOUND);
    if live != push.live {
        push.live = live;
        if live {
            app.live_clients.fetch_add(1, Ordering::Relaxed);
        } else {
            app.live_clients.fetch_sub(1, Ordering::Relaxed);
        }
        app.relay_changed();
    }
}

fn state_change(app: &App, push: &PushState) -> ServerFrame {
    let states = jmap::states(app)
        .into_iter()
        .filter(|(t, _)| push.wants(t))
        .map(|(t, s)| (t.to_string(), s))
        .collect();
    ServerFrame::StateChange {
        changed: BTreeMap::from([(jmap::ACCOUNT_ID.to_string(), states)]),
        push_state: None,
    }
}

async fn send<S>(sink: &mut S, frame: &ServerFrame) -> Result<(), ()>
where
    S: futures_util::Sink<Message> + Unpin,
{
    let text = serde_json::to_string(frame).expect("frame serializes");
    sink.send(Message::Text(text.into())).await.map_err(|_| ())
}
