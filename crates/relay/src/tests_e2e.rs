/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! End to end, over real sockets: a test downstream joins the relay, sets
//! it up over the link, and mail goes through the door in held and live
//! mode (spec acceptance tests RL-T1 to RL-T9).

use crate::{
    app::App,
    link::{
        self,
        tls::{cert_pin, tests::test_ca},
    },
    smtp,
    state::{Identity, Paths},
};
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use inbuxa_relay_proto::{
    b64, recipient, seal, time,
    token::{self, JoinToken},
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

/// Takes any server certificate, and keeps it so the test can pin it, as
/// the downstream does at join.
#[derive(Debug, Default)]
struct Capture(Mutex<Option<Vec<u8>>>);

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.0.lock().unwrap() = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &link::tls::provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        link::tls::provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct Downstream {
    connector: TlsConnector,
    capture: Arc<Capture>,
    addr: std::net::SocketAddr,
}

impl Downstream {
    fn new(ca: &link::tls::tests::TestCa, addr: std::net::SocketAddr) -> Self {
        let capture = Arc::new(Capture::default());
        let config = rustls::ClientConfig::builder_with_provider(link::tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(capture.clone())
            .with_client_auth_cert(
                vec![
                    CertificateDer::from(ca.node_cert_der.clone()),
                    CertificateDer::from(ca.ca_der.clone()),
                ],
                PrivateKeyDer::try_from(ca.node_key_der.clone()).unwrap(),
            )
            .unwrap();
        Downstream {
            connector: TlsConnector::from(Arc::new(config)),
            capture,
            addr,
        }
    }

    async fn tls(&self) -> std::io::Result<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(self.addr).await?;
        self.connector
            .connect(ServerName::try_from("relay.invalid").unwrap(), tcp)
            .await
    }

    async fn ws(&self) -> Result<Ws, String> {
        let tls = self.tls().await.map_err(|e| e.to_string())?;
        let request = tokio_tungstenite::tungstenite::http::Request::builder()
            .uri("wss://relay.invalid/jmap/ws")
            .header("Host", "relay.invalid")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("Sec-WebSocket-Protocol", "jmap")
            .body(())
            .unwrap();
        let (ws, _) = tokio_tungstenite::client_async(request, tls)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Ws {
            ws,
            changes: vec![],
            next: 0,
        })
    }

    async fn http(&self, method: &str, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
        let tls = self.tls().await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "relay.invalid")
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, body)
    }
}

struct Ws {
    ws: WebSocketStream<TlsStream<TcpStream>>,
    /// StateChanges seen, as `type:state`.
    changes: Vec<String>,
    next: u64,
}

impl Ws {
    async fn frame(&mut self) -> Value {
        let msg = tokio::time::timeout(Duration::from_secs(10), self.ws.next())
            .await
            .expect("a frame within 10 s")
            .expect("open")
            .expect("ok");
        let Message::Text(text) = msg else {
            panic!("not text: {msg:?}")
        };
        serde_json::from_str(&text).unwrap()
    }

    fn note(&mut self, frame: &Value) {
        if frame["@type"] == "StateChange" {
            for (t, s) in frame["changed"]["relay"].as_object().unwrap() {
                self.changes.push(format!("{t}:{}", s.as_str().unwrap()));
            }
        }
    }

    async fn send(&mut self, value: Value) {
        self.ws
            .send(Message::Text(value.to_string().into()))
            .await
            .unwrap();
    }

    /// One method call; returns `(name, args)` of the response.
    async fn call(&mut self, method: &str, mut args: Value) -> (String, Value) {
        args["accountId"] = json!("relay");
        self.next += 1;
        let id = format!("r{}", self.next);
        self.send(json!({
            "@type": "Request",
            "id": id,
            "using": ["urn:ietf:params:jmap:core", "urn:inbuxa:jmap:relay"],
            "methodCalls": [[method, args, "c0"]],
        }))
        .await;
        loop {
            let frame = self.frame().await;
            self.note(&frame);
            if frame["@type"] == "Response" && frame["requestId"] == id {
                let call = &frame["methodResponses"][0];
                return (call[0].as_str().unwrap().to_string(), call[1].clone());
            }
            assert_ne!(frame["@type"], "RequestError", "{frame}");
        }
    }

    async fn ok(&mut self, method: &str, args: Value) -> Value {
        let (name, args) = self.call(method, args).await;
        assert_eq!(name, method, "{args}");
        args
    }

    /// Waits for a StateChange naming `type_name`.
    async fn wait_change(&mut self, type_name: &str) {
        let prefix = format!("{type_name}:");
        let seen = self.changes.len();
        if self.changes[..seen].iter().any(|c| c.starts_with(&prefix)) {
            self.changes.clear();
            return;
        }
        loop {
            let frame = self.frame().await;
            self.note(&frame);
            if self.changes.iter().any(|c| c.starts_with(&prefix)) {
                self.changes.clear();
                return;
            }
        }
    }
}

struct Smtp {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl Smtp {
    async fn connect(port: u16) -> Smtp {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (r, w) = tcp.into_split();
        let mut s = Smtp {
            reader: BufReader::new(r),
            writer: w,
        };
        assert!(s.reply().await.starts_with("220 relay.test"));
        s
    }

    /// The whole reply, lines joined by `\n`.
    async fn reply(&mut self) -> String {
        let mut out = String::new();
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
                .await
                .expect("a reply")
                .unwrap();
            assert!(n > 0, "closed");
            let line = line.trim_end().to_string();
            let more = line.as_bytes().get(3) == Some(&b'-');
            out.push_str(&line);
            if !more {
                return out;
            }
            out.push('\n');
        }
    }

    async fn cmd(&mut self, line: &str) -> String {
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .unwrap();
        self.reply().await
    }

    async fn send_message(&mut self, rcpt: &str, body: &str) -> String {
        assert!(
            self.cmd("MAIL FROM:<sender@example.org>")
                .await
                .starts_with("250")
        );
        assert!(
            self.cmd(&format!("RCPT TO:<{rcpt}>"))
                .await
                .starts_with("250")
        );
        assert!(self.cmd("DATA").await.starts_with("354"));
        self.writer.write_all(body.as_bytes()).await.unwrap();
        self.cmd(".").await
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_end_to_end() {
    let dir = std::env::temp_dir().join(format!("inbuxa-relay-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let paths = Paths::new(&dir);

    // inbuxa-admin makes a token; the relay host joins with it.
    let ca = test_ca(true);
    let ca_pin = cert_pin(&ca.ca_der).unwrap();
    let token = JoinToken::issue("r1", ca_pin, time::now());
    crate::join(&paths, &token.encode()).unwrap();
    assert!(crate::join(&paths, &token.encode()).is_err(), "joined once");

    let identity = Identity::load(&paths).unwrap().unwrap();
    let app = Arc::new(App::open(Paths::new(&dir), identity).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let link_addr = listener.local_addr().unwrap();
    tokio::spawn(link::serve(app.clone(), listener));
    tokio::spawn(smtp::serve(app.clone()));

    // RL-T8: a client from another CA gets no further than TLS.
    let stranger = Downstream::new(&test_ca(true), link_addr);
    assert!(stranger.ws().await.is_err());

    let down = Downstream::new(&ca, link_addr);
    let mut ws = down.ws().await.unwrap();

    // Before the join, nothing but Relay/join.
    let (name, args) = ws.call("Inbound/get", json!({})).await;
    assert_eq!(
        (name.as_str(), args["type"].as_str()),
        ("error", Some("forbidden"))
    );

    // RL-T9 / RL-8: the join proof.
    let nonce = [7u8; 32];
    let joined = ws
        .ok("Relay/join", json!({ "nonce": b64::encode(&nonce) }))
        .await;
    let relay_cert = down.capture.0.lock().unwrap().clone().unwrap();
    let relay_pin = cert_pin(&relay_cert).unwrap();
    assert_eq!(joined["relayPin"], json!(b64::encode(&relay_pin)));
    let proof = b64::decode(joined["proof"].as_str().unwrap()).unwrap();
    assert!(token::verify_join_proof(
        &token.secret,
        &nonce,
        &relay_pin,
        &proof
    ));
    let (name, _) = ws
        .call("Relay/join", json!({ "nonce": b64::encode(&nonce) }))
        .await;
    assert_eq!(name, "error", "a second join fails");

    // The first settings complete the join.
    let (secret, public) = seal::generate_keypair();
    let recipient_key = [3u8; 32];
    let smtp_port = free_port();
    let set = ws
        .ok(
            "Relay/set",
            json!({ "update": { "singleton": {
                "hostname": "relay.test",
                "smtpListen": [format!("127.0.0.1:{smtp_port}")],
                "domains": ["example.com"],
                "sealingKey": b64::encode(&public),
                "recipientKey": b64::encode(&recipient_key),
                "liveVerdictTimeout": 2,
            }}}),
        )
        .await;
    assert_eq!(set["updated"], json!({ "singleton": null }), "{set}");
    let bad = ws
        .ok(
            "Relay/set",
            json!({ "update": { "singleton": { "liveVerdictTimeout": 500 }}}),
        )
        .await;
    assert!(bad["notUpdated"]["singleton"].is_object());
    assert!(
        Identity::load(&paths)
            .unwrap()
            .unwrap()
            .join_secret
            .is_none()
    );

    // Recipients: a domain rule, and the set by upload and replace.
    ws.ok(
        "RecipientDomain/set",
        json!({ "create": { "d": { "domain": "example.com", "subaddressSeparator": "+" }}}),
    )
    .await;
    let file: Vec<u8> = ["john@example.com", "jane@example.com"]
        .iter()
        .flat_map(|a| recipient::hash(&recipient_key, a))
        .collect();
    let (status, body) = down.http("POST", "/jmap/upload/relay", file).await;
    assert_eq!(status, 201);
    let blob: Value = serde_json::from_slice(&body).unwrap();
    let replaced = ws
        .ok("Recipient/replace", json!({ "blobId": blob["blobId"] }))
        .await;
    assert_eq!(replaced["count"], 2);

    // Port 25 opens once configured.
    let mut opened = false;
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", smtp_port)).await.is_ok() {
            opened = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(opened, "port 25 opened");
    tokio::time::sleep(Duration::from_millis(400)).await;

    // RL-T1, RL-T2: the door, in held mode.
    let mut s = Smtp::connect(smtp_port).await;
    let ehlo = s.cmd("EHLO mx.example.org").await;
    assert!(ehlo.contains("STARTTLS") && ehlo.contains("PIPELINING"));
    assert!(!ehlo.contains("AUTH"));
    assert!(
        s.cmd("AUTH PLAIN AGJvYgBzZWNyZXQ=")
            .await
            .starts_with("502")
    );
    assert!(
        s.cmd("MAIL FROM:<sender@example.org>")
            .await
            .starts_with("250")
    );
    assert!(
        s.cmd("RCPT TO:<nobody@example.com>")
            .await
            .starts_with("550 5.1.1")
    );
    assert!(
        s.cmd("RCPT TO:<john@example.net>")
            .await
            .starts_with("550 5.7.1")
    );
    assert!(
        s.cmd("RCPT TO:<John+news@example.com>")
            .await
            .starts_with("250")
    );
    assert!(s.cmd("DATA").await.starts_with("354"));
    let body = "Subject: test\r\n\r\nMARKER-e2e-0451\r\n..dot line\r\n";
    s.writer.write_all(body.as_bytes()).await.unwrap();
    let done = s.cmd(".").await;
    assert!(done.starts_with("250 2.0.0 Accepted i"), "{done}");
    let id = done.rsplit(' ').next().unwrap().to_string();

    // STARTTLS, with the self-signed certificate the relay uses until the
    // downstream sends one.
    let tcp = TcpStream::connect(("127.0.0.1", smtp_port)).await.unwrap();
    let mut plain = BufReader::new(tcp);
    let mut line = String::new();
    plain.read_line(&mut line).await.unwrap();
    plain
        .get_mut()
        .write_all(b"EHLO mx.example.org\r\n")
        .await
        .unwrap();
    loop {
        line.clear();
        plain.read_line(&mut line).await.unwrap();
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }
    plain.get_mut().write_all(b"STARTTLS\r\n").await.unwrap();
    line.clear();
    plain.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("220"), "{line}");
    let config = rustls::ClientConfig::builder_with_provider(link::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Capture::default()))
        .with_no_client_auth();
    let tls = TlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from("relay.test").unwrap(),
            plain.into_inner(),
        )
        .await
        .unwrap();
    let mut tls = BufReader::new(tls);
    tls.get_mut()
        .write_all(b"EHLO mx.example.org\r\n")
        .await
        .unwrap();
    let mut ehlo = String::new();
    loop {
        line.clear();
        tls.read_line(&mut line).await.unwrap();
        ehlo.push_str(&line);
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }
    assert!(
        ehlo.starts_with("250-relay.test") && !ehlo.contains("STARTTLS"),
        "{ehlo}"
    );
    tls.get_mut().write_all(b"QUIT\r\n").await.unwrap();

    // Handing it down: claim, download, open, destroy.
    let claimed = ws.ok("Inbound/claim", json!({ "limit": 10 })).await;
    assert_eq!(claimed["ids"], json!([id]));
    let got = ws.ok("Inbound/get", json!({ "ids": [id] })).await;
    let inbound = &got["list"][0];
    assert_eq!(inbound["state"], "claimed");
    assert_eq!(
        inbound["envelope"]["rcptTo"][0]["email"],
        "John+news@example.com"
    );
    assert_eq!(inbound["session"]["remoteIp"], "127.0.0.1");
    assert_eq!(inbound["session"]["helo"], "mx.example.org");
    let on_disk = std::fs::read(app.paths.spool_in().join(format!("{id}.msg"))).unwrap();
    assert!(
        !on_disk.windows(15).any(|w| w == b"MARKER-e2e-0451"),
        "RL-T7"
    );
    let (status, sealed) = down
        .http("GET", &format!("/jmap/download/relay/{id}/msg"), vec![])
        .await;
    assert_eq!(status, 200);
    let opened = seal::open(&secret, id.as_bytes(), &sealed).unwrap();
    assert_eq!(
        String::from_utf8(opened).unwrap(),
        "Subject: test\r\n\r\nMARKER-e2e-0451\r\n.dot line\r\n"
    );
    let destroyed = ws.ok("Inbound/set", json!({ "destroy": [id] })).await;
    assert_eq!(destroyed["destroyed"], json!([id]));
    assert!(!app.paths.spool_in().join(format!("{id}.msg")).exists());

    // Live mode: push on, then the downstream refuses a message (RL-T3).
    ws.send(json!({ "@type": "WebSocketPushEnable", "dataTypes": null }))
        .await;
    ws.wait_change("Inbound").await;
    let sender = tokio::spawn(async move {
        let mut s = Smtp::connect(smtp_port).await;
        s.cmd("EHLO mx.example.org").await;
        let first = s
            .send_message("jane@example.com", "Subject: spam\r\n\r\nbuy\r\n")
            .await;
        let second = s
            .send_message("jane@example.com", "Subject: slow\r\n\r\nwait\r\n")
            .await;
        (first, second)
    });
    ws.wait_change("Inbound").await;
    let pending = ws.ok("Inbound/query", json!({})).await;
    let live_id = pending["ids"][0].as_str().unwrap().to_string();
    let got = ws.ok("Inbound/get", json!({ "ids": [live_id] })).await;
    assert_eq!(got["list"][0]["state"], "pending");
    ws.ok("Inbound/claim", json!({})).await;
    // Claimed, it still waits for its verdict
    let got = ws.ok("Inbound/get", json!({ "ids": [live_id] })).await;
    assert_eq!(got["list"][0]["state"], "pending");
    assert!(got["list"][0]["claimedUntil"].is_string());
    let verdict = ws
        .ok(
            "Inbound/set",
            json!({ "update": { live_id.clone(): { "verdict": {
                "type": "reject", "code": 550, "enhanced": "5.7.1", "text": "Spam"
            }}}}),
        )
        .await;
    assert_eq!(
        verdict["updated"],
        json!({ live_id.clone(): null }),
        "{verdict}"
    );

    // RL-T4: no verdict for the second, so it is held after the timeout.
    let (first, second) = tokio::time::timeout(Duration::from_secs(15), sender)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first, "550 5.7.1 Spam");
    assert!(second.starts_with("250 2.0.0 Accepted"), "{second}");
    let held_id = second.rsplit(' ').next().unwrap().to_string();
    assert!(
        !app.spool.lock().unwrap().contains(&live_id),
        "refused mail is gone"
    );
    let got = ws.ok("Inbound/get", json!({ "ids": [held_id] })).await;
    assert_eq!(got["list"][0]["state"], "held");

    // Outbound: handed over as an upload (RL-19), never from a sender
    // outside the relay's domains (RL-T10), and cancelled while queued.
    let (status, body) = down
        .http(
            "POST",
            "/jmap/upload/relay",
            b"Subject: out\r\n\r\nhello\r\n".to_vec(),
        )
        .await;
    assert_eq!(status, 201);
    let blob: Value = serde_json::from_slice(&body).unwrap();
    let envelope = |from: &str| json!({ "mailFrom": { "email": from }, "rcptTo": [{ "email": "bob@example.org" }] });
    let set = ws
        .ok(
            "Outbound/set",
            json!({ "create": {
                "a": { "blobId": blob["blobId"], "envelope": envelope("jane@example.com") },
                "b": { "blobId": blob["blobId"], "envelope": envelope("jane@example.org") },
            }}),
        )
        .await;
    assert_eq!(set["notCreated"]["b"]["type"], "forbiddenFrom", "{set}");
    let out_id = set["created"]["a"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        set["created"]["a"]["deliveryStatus"]["bob@example.org"]["delivered"],
        "queued"
    );
    ws.wait_change("Outbound").await;
    let got = ws.ok("Outbound/get", json!({ "ids": [out_id] })).await;
    assert_eq!(got["list"][0]["size"], 23);
    let eml = app.paths.spool_out().join(format!("{out_id}.eml"));
    assert!(eml.exists());
    let relay = ws.ok("Relay/get", json!({})).await;
    assert_eq!(relay["list"][0]["status"]["spool"]["outbound"], 1);
    let again = ws
        .ok(
            "Outbound/set",
            json!({
                "create": { "c": { "blobId": blob["blobId"], "envelope": envelope("jane@example.com") }},
                "update": { out_id.clone(): { "attempts": 9 }},
            }),
        )
        .await;
    assert_eq!(
        again["notCreated"]["c"]["type"], "invalidProperties",
        "an upload is used once"
    );
    assert_eq!(again["notUpdated"][&out_id]["type"], "forbidden");
    let gone = ws.ok("Outbound/set", json!({ "destroy": [out_id] })).await;
    assert_eq!(gone["destroyed"], json!([out_id]));
    assert!(!eml.exists());

    // Events went up the link.
    let events = ws.ok("RelayEvent/get", json!({})).await;
    let kinds: Vec<&str> = events["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .collect();
    for kind in [
        "relay.joined",
        "inbound.accepted",
        "inbound.refused",
        "smtp.session",
    ] {
        assert!(kinds.contains(&kind), "{kind} in {kinds:?}");
    }

    drop(ws);
    std::fs::remove_dir_all(dir).unwrap();
}
