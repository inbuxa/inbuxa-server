/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The delivery engine against a scripted MX on localhost, with DNS
//! answers fixed by the test.

use super::{
    route::{LookupError, Mx, Resolve},
    run,
};
use crate::{
    app::App,
    state::{Identity, Paths},
};
use inbuxa_outbound_tls::{
    Mode, MxPattern, Policy, Tlsa, TlsaEntry, TlsaMatching, dnssec::TlsaResult,
};
use inbuxa_relay_proto::{
    time,
    token::JoinToken,
    types::{Address, Delivered, Envelope, Outbound, RelaySettings},
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2_shim::sha256;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

/// SHA-256, from the crypto the relay already links.
mod sha2_shim {
    pub fn sha256(data: &[u8]) -> Vec<u8> {
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
            .as_ref()
            .to_vec()
    }
}

#[derive(Default)]
struct Fixed {
    port: u16,
    mx: HashMap<String, Mx>,
    secure: bool,
    tlsa: Option<Arc<Tlsa>>,
    sts: Option<Arc<Policy>>,
}

impl Resolve for Fixed {
    async fn mx(&self, domain: &str) -> Result<Mx, LookupError> {
        self.mx
            .get(domain)
            .cloned()
            .ok_or_else(|| LookupError::Permanent("the domain doesn't exist".into()))
    }

    async fn addresses(&self, _: &str, _: bool) -> Result<(Vec<IpAddr>, bool), LookupError> {
        Ok((vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], self.secure))
    }

    async fn tlsa(&self, _: &str) -> Result<TlsaResult, LookupError> {
        Ok(match &self.tlsa {
            Some(t) => TlsaResult::Secure(t.clone()),
            None => TlsaResult::Missing,
        })
    }

    async fn mta_sts(&self, _: &str) -> Option<Arc<Policy>> {
        self.sts.clone()
    }

    fn port(&self) -> u16 {
        self.port
    }
}

/// What the scripted MX saw.
#[derive(Default)]
struct Seen {
    messages: Vec<(bool, Vec<u8>)>,
}

/// An MX on localhost: STARTTLS with a self-signed certificate for
/// `mx.test`; `bob` is taken, `nobody` refused, `later` deferred.
async fn scripted_mx() -> (u16, Arc<Mutex<Seen>>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["mx.test".into()]).unwrap();
    let der = cert.cert.der().to_vec();
    let spki = x509_parser::parse_x509_certificate(&der)
        .unwrap()
        .1
        .tbs_certificate
        .subject_pki
        .raw
        .to_vec();
    let config = rustls::ServerConfig::builder_with_provider(crate::link::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (acceptor, seen) = (acceptor.clone(), seen2.clone());
            tokio::spawn(async move {
                let mut conn = BufReader::new(tcp);
                conn.get_mut()
                    .write_all(b"220 mx.test ready\r\n")
                    .await
                    .unwrap();
                if let Some(true) = talk(&mut conn, &seen, false).await {
                    let tls = acceptor.accept(conn.into_inner()).await;
                    if let Ok(tls) = tls {
                        let mut conn = BufReader::new(tls);
                        talk(&mut conn, &seen, true).await;
                    }
                }
            });
        }
    });
    (port, seen, spki)
}

/// Returns `Some(true)` when the client asked for STARTTLS.
async fn talk<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut BufReader<S>,
    seen: &Mutex<Seen>,
    tls: bool,
) -> Option<bool> {
    let mut line = String::new();
    loop {
        line.clear();
        if conn.read_line(&mut line).await.ok()? == 0 {
            return None;
        }
        let upper = line.to_ascii_uppercase();
        let reply: &[u8] = if upper.starts_with("EHLO") {
            if tls {
                b"250-mx.test\r\n250-SIZE 1000000\r\n250 8BITMIME\r\n"
            } else {
                b"250-mx.test\r\n250-STARTTLS\r\n250 SIZE 1000000\r\n"
            }
        } else if upper.starts_with("STARTTLS") {
            conn.get_mut().write_all(b"220 go ahead\r\n").await.ok()?;
            return Some(true);
        } else if upper.starts_with("MAIL") {
            b"250 2.1.0 ok\r\n"
        } else if upper.starts_with("RCPT") {
            if upper.contains("NOBODY@") {
                b"550 5.1.1 no such user\r\n"
            } else if upper.contains("LATER@") {
                b"451 4.2.0 try later\r\n"
            } else {
                b"250 2.1.5 ok\r\n"
            }
        } else if upper.starts_with("DATA") {
            conn.get_mut().write_all(b"354 go\r\n").await.ok()?;
            let mut body = Vec::new();
            loop {
                let mut l = Vec::new();
                conn.read_until(b'\n', &mut l).await.ok()?;
                if l == b".\r\n" || l.is_empty() {
                    break;
                }
                body.extend_from_slice(&l);
            }
            seen.lock().unwrap().messages.push((tls, body));
            b"250 2.0.0 queued as X1\r\n"
        } else if upper.starts_with("QUIT") {
            conn.get_mut().write_all(b"221 bye\r\n").await.ok()?;
            return None;
        } else {
            b"500 5.5.1 what\r\n"
        };
        conn.get_mut().write_all(reply).await.ok()?;
    }
}

async fn relay(name: &str) -> (Arc<App>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "inbuxa-relay-deliver-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let paths = Paths::new(&dir);
    let token = JoinToken::issue("r1", [1; 32], time::now());
    crate::join(&paths, &token.encode()).unwrap();
    let identity = Identity::load(&paths).unwrap().unwrap();
    let app = Arc::new(App::open(Paths::new(&dir), identity).unwrap());
    app.settings.send_replace(Some(Arc::new(RelaySettings {
        hostname: "relay.test".into(),
        domains: vec!["example.com".into()],
        sealing_key: Some([1; 32]),
        recipient_key: Some([2; 32]),
        outbound_retry: vec![60],
        ..Default::default()
    })));
    (app, dir)
}

fn hand_over(app: &App, to: &[&str], body: &[u8]) -> String {
    hand_over_from(app, Address::new("jane@example.com"), to, body)
}

fn hand_over_from(app: &App, from: Address, to: &[&str], body: &[u8]) -> String {
    let blob = app.paths.blobs().join(crate::spool::new_id());
    std::fs::write(&blob, body).unwrap();
    let settings = app.settings().unwrap();
    app.outbox
        .lock()
        .unwrap()
        .create(
            &blob,
            "b",
            Envelope {
                mail_from: from,
                rcpt_to: to.iter().map(|t| Address::new(*t)).collect(),
            },
            &settings,
            false,
            time::now(),
        )
        .unwrap()
}

/// Waits until the message has been tried at least once.
async fn tried(app: &App, id: &str) -> Outbound {
    for _ in 0..200 {
        if let Some(out) = app.outbox.lock().unwrap().get(id)
            && out.attempts > 0
        {
            return out;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{id} was never tried");
}

fn events(app: &App, kind: &str) -> Vec<serde_json::Map<String, serde_json::Value>> {
    let events = app.events.lock().unwrap();
    events
        .get(None)
        .0
        .into_iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.data)
        .collect()
}

fn hosts(port: u16) -> Fixed {
    Fixed {
        port,
        mx: HashMap::from([
            (
                "example.org".to_string(),
                Mx::Hosts {
                    hosts: vec!["mx.test".into()],
                    secure: false,
                },
            ),
            ("null.example".to_string(), Mx::Null),
        ]),
        ..Default::default()
    }
}

#[tokio::test]
async fn delivers_with_opportunistic_tls_and_per_recipient_status() {
    let (port, seen, _) = scripted_mx().await;
    let (app, dir) = relay("plain").await;
    let id = hand_over(
        &app,
        &[
            "bob@example.org",
            "nobody@example.org",
            "later@example.org",
            "x@null.example",
            "y@missing.example",
        ],
        b"Subject: hi\r\n\r\n.dot line\r\nend",
    );
    tokio::spawn(run(app.clone(), Arc::new(hosts(port))));
    app.outbound_wake.notify_one();
    let out = tried(&app, &id).await;

    let status = |rcpt: &str| out.delivery_status[rcpt].clone();
    assert_eq!(status("bob@example.org").delivered, Delivered::Yes);
    assert_eq!(
        status("bob@example.org").smtp_reply,
        "250 2.0.0 queued as X1"
    );
    // RL-T11: the remote server's own reply.
    assert_eq!(status("nobody@example.org").delivered, Delivered::No);
    assert_eq!(
        status("nobody@example.org").smtp_reply,
        "550 5.1.1 no such user"
    );
    assert_eq!(status("later@example.org").delivered, Delivered::Queued);
    assert_eq!(
        status("later@example.org").smtp_reply,
        "451 4.2.0 try later"
    );
    assert_eq!(status("x@null.example").delivered, Delivered::No);
    assert!(
        status("x@null.example")
            .smtp_reply
            .starts_with("556 5.1.10")
    );
    assert_eq!(status("y@missing.example").delivered, Delivered::No);
    assert!(
        out.next_attempt_at.is_some(),
        "one recipient is still queued"
    );

    let messages = &seen.lock().unwrap().messages;
    assert_eq!(messages.len(), 1);
    let (tls, body) = &messages[0];
    assert!(tls, "STARTTLS was offered, so it was used");
    assert_eq!(body, b"Subject: hi\r\n\r\n..dot line\r\nend\r\n");

    let attempts = events(&app, "outbound.attempt");
    assert_eq!(attempts[0]["delivered"], 1);
    assert_eq!(attempts[0]["refused"], 1);
    assert_eq!(attempts[0]["deferred"], 1);
    assert!(attempts[0]["tls"]["version"].is_string());
    let tls = events(&app, "outbound.tls");
    assert_eq!(tls[0]["policyType"], "no-policy-found");
    assert_eq!(tls[0]["result"], "success");

    // Only the relay may give up on a message mid-send; afterwards the
    // downstream can clear it.
    assert_eq!(
        app.outbox.lock().unwrap().destroy(&id),
        crate::outbound::Destroyed::Yes
    );
    std::fs::remove_dir_all(dir).unwrap();
}

fn tlsa(data: Vec<u8>) -> Arc<Tlsa> {
    Arc::new(Tlsa {
        entries: vec![TlsaEntry {
            is_end_entity: true,
            is_spki: true,
            matching: TlsaMatching::Sha256,
            data,
        }],
        has_end_entities: true,
        has_intermediates: false,
    })
}

/// RL-T12, first half: DANE against the MX's real key, then a wrong one.
#[tokio::test]
async fn dane_is_enforced() {
    let (port, seen, spki) = scripted_mx().await;

    let (app, dir) = relay("dane-ok").await;
    let id = hand_over(&app, &["bob@example.org"], b"Subject: dane\r\n\r\nhi\r\n");
    let resolve = Fixed {
        secure: true,
        tlsa: Some(tlsa(sha256(&spki))),
        mx: HashMap::from([(
            "example.org".to_string(),
            Mx::Hosts {
                hosts: vec!["mx.test".into()],
                secure: true,
            },
        )]),
        ..hosts(port)
    };
    tokio::spawn(run(app.clone(), Arc::new(resolve)));
    app.outbound_wake.notify_one();
    let out = tried(&app, &id).await;
    assert_eq!(
        out.delivery_status["bob@example.org"].delivered,
        Delivered::Yes
    );
    let tls = events(&app, "outbound.tls");
    assert_eq!(tls[0]["policyType"], "tlsa");
    assert_eq!(tls[0]["result"], "success");
    assert!(
        tls[0]["policyStrings"][0]
            .as_str()
            .unwrap()
            .starts_with("3 1 1 ")
    );
    std::fs::remove_dir_all(dir).unwrap();

    let (app, dir) = relay("dane-bad").await;
    let id = hand_over(&app, &["bob@example.org"], b"Subject: dane\r\n\r\nhi\r\n");
    let resolve = Fixed {
        secure: true,
        tlsa: Some(tlsa(vec![0; 32])),
        mx: HashMap::from([(
            "example.org".to_string(),
            Mx::Hosts {
                hosts: vec!["mx.test".into()],
                secure: true,
            },
        )]),
        ..hosts(port)
    };
    tokio::spawn(run(app.clone(), Arc::new(resolve)));
    app.outbound_wake.notify_one();
    let out = tried(&app, &id).await;
    let status = &out.delivery_status["bob@example.org"];
    assert_eq!(status.delivered, Delivered::Queued);
    assert!(
        status.smtp_reply.starts_with("451 4.4.1 "),
        "{}",
        status.smtp_reply
    );
    let tls = events(&app, "outbound.tls");
    assert_eq!(tls[0]["policyType"], "tlsa");
    assert_eq!(tls[0]["result"], "validation-failure");
    assert_eq!(
        seen.lock().unwrap().messages.len(),
        1,
        "only the first went"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// RL-T12, second half: MTA-STS enforce with a certificate no CA signed,
/// and with an MX host the policy doesn't list.
#[tokio::test]
async fn mta_sts_enforce_is_enforced() {
    let (port, seen, _) = scripted_mx().await;
    for (name, pattern) in [
        ("sts-cert", MxPattern::Equals("mx.test".into())),
        ("sts-mx", MxPattern::Equals("other.test".into())),
    ] {
        let (app, dir) = relay(name).await;
        let id = hand_over(&app, &["bob@example.org"], b"Subject: sts\r\n\r\nhi\r\n");
        let resolve = Fixed {
            sts: Some(Arc::new(Policy {
                id: "1".into(),
                mode: Mode::Enforce,
                mx: vec![pattern].into_boxed_slice(),
                max_age: 86_400,
            })),
            ..hosts(port)
        };
        tokio::spawn(run(app.clone(), Arc::new(resolve)));
        app.outbound_wake.notify_one();
        let out = tried(&app, &id).await;
        let status = &out.delivery_status["bob@example.org"];
        assert_eq!(status.delivered, Delivered::Queued, "{name}");
        let tls = events(&app, "outbound.tls");
        assert_eq!(tls[0]["policyType"], "sts", "{name}");
        assert_ne!(tls[0]["result"], "success", "{name}");
        assert!(
            tls[0]["policyStrings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l == "mode: enforce"),
            "{name}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    assert!(seen.lock().unwrap().messages.is_empty());
}

#[tokio::test]
async fn requiretls_needs_a_verified_certificate() {
    // The scripted MX's certificate is self-signed: fine for opportunistic
    // TLS, not for REQUIRETLS (RFC 8689)
    let (port, seen, _) = scripted_mx().await;
    let (app, dir) = relay("requiretls").await;
    let mut from = Address::new("jane@example.com");
    from.parameters = Some([("REQUIRETLS".to_string(), None)].into());
    let id = hand_over_from(
        &app,
        from,
        &["bob@example.org"],
        b"Subject: r\r\n\r\nhi\r\n",
    );
    tokio::spawn(run(app.clone(), Arc::new(hosts(port))));
    app.outbound_wake.notify_one();
    let out = tried(&app, &id).await;
    let status = &out.delivery_status["bob@example.org"];
    assert_eq!(status.delivered, Delivered::Queued);
    assert!(status.smtp_reply.starts_with("451 4."), "{status:?}");
    let tls = events(&app, "outbound.tls");
    assert_eq!(tls[0]["policyType"], "no-policy-found");
    assert_ne!(tls[0]["result"], "success");
    // Not tried again in the clear either
    assert!(seen.lock().unwrap().messages.is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn expiry_refuses_what_is_still_queued() {
    let (port, _, _) = scripted_mx().await;
    let (app, dir) = relay("expiry").await;
    let id = hand_over(&app, &["later@example.org"], b"Subject: x\r\n\r\nx\r\n");
    tokio::spawn(run(app.clone(), Arc::new(hosts(port))));
    app.outbound_wake.notify_one();
    let out = tried(&app, &id).await;
    assert_eq!(
        out.delivery_status["later@example.org"].delivered,
        Delivered::Queued
    );
    let gone = app
        .outbox
        .lock()
        .unwrap()
        .expire(time::now() + 4 * 86_400)
        .unwrap();
    assert_eq!(gone, vec![(id.clone(), 1)]);
    let out = app.outbox.lock().unwrap().get(&id).unwrap();
    let status = &out.delivery_status["later@example.org"];
    assert_eq!(status.delivered, Delivered::No);
    assert_eq!(
        status.smtp_reply, "451 4.2.0 try later",
        "the last real reply"
    );
    assert!(out.next_attempt_at.is_none());
    assert_eq!(
        app.outbox
            .lock()
            .unwrap()
            .sweep_finished(time::now() + 12 * 86_400, super::FINISHED_KEEP),
        1
    );
    std::fs::remove_dir_all(dir).unwrap();
}
