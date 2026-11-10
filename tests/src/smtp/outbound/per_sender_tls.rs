/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// Per-sender "require TLS": a `require-tls` MtaTlsStrategy picked by a
// `sender == ...` row in the outbound strategy's TLS rule. Note that
// test_mode accepts any certificate for MX delivery, so these cover STARTTLS
// and the handshake, not certificate verification.

use crate::{
    smtp::{
        inbound::TestMessage,
        session::{TestSession, VerifyResponse},
    },
    utils::{
        dns::DnsCache,
        server::{TestServer, TestServerBuilder},
    },
};
use mail_auth::{DnssecStatus, MX};
use registry::{
    schema::{
        enums::MtaRequiredOrOptional,
        structs::{
            Expression, ExpressionMatch, MtaConnectionStrategy, MtaDeliverySchedule,
            MtaOutboundStrategy, MtaTlsStrategy, MtaVirtualQueue,
        },
    },
    types::list::List,
};
use smtp::queue::Status;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use store::write::now;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

/// The recipe's TLS rule, plus a `late@` row placed after the retry row to
/// show what happens when the sender rule isn't first.
async fn setup_local(local: &TestServer, ehlo: &str) {
    let admin = local.account("admin");
    admin.mta_no_auth().await;
    admin.mta_allow_relaying().await;
    admin
        .registry_create_object(MtaOutboundStrategy {
            tls: Expression {
                match_: List::from_iter([
                    ExpressionMatch {
                        if_: "sender == 'secure@test.org'".into(),
                        then: "'require-tls'".into(),
                    },
                    ExpressionMatch {
                        if_: "retry_num > 0 && last_error == 'tls'".into(),
                        then: "'no-tls'".into(),
                    },
                    ExpressionMatch {
                        if_: "sender == 'late@test.org'".into(),
                        then: "'require-tls'".into(),
                    },
                ]),
                else_: "'default'".into(),
            },
            connection: Expression {
                else_: "'plain'".into(),
                ..Default::default()
            },
            schedule: Expression {
                else_: "'default'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    let queue_id = admin
        .registry_create_object(MtaVirtualQueue {
            name: "default".into(),
            threads_per_node: 25,
            description: None,
        })
        .await;
    admin
        .registry_create_object(MtaDeliverySchedule {
            name: "default".into(),
            queue_id,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaConnectionStrategy {
            name: "plain".into(),
            ehlo_hostname: ehlo.to_string().into(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaTlsStrategy {
            name: "no-tls".into(),
            allow_invalid_certs: true,
            start_tls: MtaRequiredOrOptional::Disable,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaTlsStrategy {
            name: "require-tls".into(),
            allow_invalid_certs: false,
            start_tls: MtaRequiredOrOptional::Require,
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;

    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(60),
    );
    local.server.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(60),
    );
}

async fn send(local: &TestServer, from: &str) {
    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message(from, &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
}

fn status_name<T, E>(status: &Status<T, E>) -> &'static str {
    match status {
        Status::Scheduled => "scheduled",
        Status::Completed(_) => "completed",
        Status::TemporaryFailure(_) => "temporary",
        Status::PermanentFailure(_) => "permanent",
    }
}

/// Delivers the queued message once, then makes it due again and delivers it
/// a second time. Returns the recipient status after each attempt (None when
/// the message left the queue).
async fn two_attempts(local: &mut TestServer) -> Vec<String> {
    let mut seen = Vec::new();
    local
        .expect_message_for_queue_then_deliver("default")
        .await
        .try_deliver(local.server.clone());
    for attempt in 0..2 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let queued = local.read_queued_messages().await;
        let Some(mut msg) = queued
            .into_iter()
            .find(|m| !m.message.return_path.is_empty())
        else {
            seen.push("gone".to_string());
            for m in local
                .read_queued_messages()
                .await
                .into_iter()
                .filter(|m| m.message.return_path.is_empty())
            {
                let lines = m.read_lines(local).await;
                seen.push(format!(
                    "DSN: {}",
                    lines
                        .iter()
                        .filter(|l| l.contains("Action:")
                            || l.contains("(TLS")
                            || l.contains("(host"))
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" | ")
                ));
            }
            break;
        };
        let rcpt = &msg.message.recipients[0];
        seen.push(format!("{} {:?}", status_name(&rcpt.status), rcpt.status));
        if attempt == 1 {
            break;
        }
        let prev_due = msg.message.recipients[0].retry.due;
        msg.message.recipients[0].retry.due = now();
        let queue_id = msg.queue_id;
        msg.save_changes(&local.server, prev_due.into(), None).await;
        local
            .delivery_attempt_for_queue(queue_id, "default")
            .await
            .try_deliver(local.server.clone());
    }
    seen
}

async fn remote_server(name: &str, port: u16) -> TestServer {
    let mut remote = TestServerBuilder::new(name)
        .await
        .with_http_listener(port)
        .await
        .with_smtp_listener(9925)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let remote_admin = remote.account("admin");
    remote_admin.mta_no_auth().await;
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin.mta_all_extensions().await;
    remote_admin.mta_add_all_headers().await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;
    remote
}

/// Receiving server offers STARTTLS but the handshake fails (test-mode
/// `badtls` hook: the remote hangs up right after "220 Ready to start TLS").
#[tokio::test]
#[serial_test::serial]
async fn per_sender_require_tls_handshake_fails() {
    let mut local = TestServerBuilder::new("smtp_per_sender_tls_local")
        .await
        .with_http_listener(19234)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let mut remote = remote_server("smtp_per_sender_tls_remote", 19235).await;
    setup_local(&local, "badtls.test.org").await;
    local.reload_core();
    local.expect_reload_settings().await;

    // 1. secure@ (rule first): both attempts fail temporarily, the message
    //    stays queued, nothing reaches the remote.
    send(&local, "secure@test.org").await;
    let seen = two_attempts(&mut local).await;
    println!("secure@ attempts: {seen:#?}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        remote.try_read_event().await.is_none(),
        "remote got secure@ mail"
    );
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(seen.iter().all(|s| s.starts_with("temporary")), "{seen:?}");
    local.clear_queue().await;

    // 2. late@ (rule below the retry row): the retry falls back to no-tls
    //    and the message goes out in plain text.
    send(&local, "late@test.org").await;
    let seen = two_attempts(&mut local).await;
    println!("late@ attempts: {seen:#?}");
    assert!(seen[0].starts_with("temporary"), "{seen:?}");
    assert_eq!(seen[1], "gone", "{seen:?}");
    remote
        .expect_message()
        .await
        .read_lines(&remote)
        .await
        .assert_contains("From: ")
        .assert_contains("Received: from ")
        .assert_not_contains("using TLS");
    remote.clear_queue().await;
    local.clear_queue().await;

    // 3. Any other sender keeps the normal behaviour (same as 2).
    send(&local, "john@test.org").await;
    let seen = two_attempts(&mut local).await;
    println!("john@ attempts: {seen:#?}");
    assert_eq!(seen.last().unwrap(), "gone", "{seen:?}");
    remote
        .expect_message()
        .await
        .read_lines(&remote)
        .await
        .assert_contains("Received: from ")
        .assert_not_contains("using TLS");
}

/// Receiving server offers working STARTTLS: secure@ goes out encrypted.
#[tokio::test]
#[serial_test::serial]
async fn per_sender_require_tls_good() {
    let mut local = TestServerBuilder::new("smtp_per_sender_tls_good")
        .await
        .with_http_listener(19237)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let mut remote = remote_server("smtp_per_sender_tls_good_remote", 19238).await;
    setup_local(&local, "mx.test.org").await;
    local.reload_core();
    local.expect_reload_settings().await;

    send(&local, "secure@test.org").await;
    let seen = two_attempts(&mut local).await;
    println!("secure@ attempts (good TLS): {seen:#?}");
    assert_eq!(seen[0], "gone", "{seen:?}");
    let lines = remote.expect_message().await.read_lines(&remote).await;
    println!(
        "remote Received: {:?}",
        lines
            .iter()
            .filter(|l| l.to_ascii_lowercase().contains("tls")
                || l.starts_with("Received")
                || l.contains("cipher"))
            .collect::<Vec<_>>()
    );
    lines.assert_contains("using TLSv1.3 with cipher");
}

/// A fake MX that never advertises STARTTLS. Records every command it sees.
async fn spawn_plain_mx(log: Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:9925").await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let (rd, mut wr) = stream.into_split();
                let mut rd = BufReader::new(rd);
                wr.write_all(b"220 mx.foobar.org ESMTP\r\n").await.ok();
                let mut line = String::new();
                let mut in_data = false;
                loop {
                    line.clear();
                    if rd.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    if in_data {
                        if line == ".\r\n" {
                            in_data = false;
                            log.lock().unwrap().push("DATA-COMPLETE".into());
                            wr.write_all(b"250 2.0.0 queued\r\n").await.ok();
                        }
                        continue;
                    }
                    let cmd = line.trim_end().to_string();
                    log.lock().unwrap().push(cmd.clone());
                    let upper = cmd.to_ascii_uppercase();
                    let reply: &[u8] = if upper.starts_with("EHLO") {
                        b"250-mx.foobar.org\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n"
                    } else if upper.starts_with("DATA") {
                        in_data = true;
                        b"354 go ahead\r\n"
                    } else if upper.starts_with("QUIT") {
                        wr.write_all(b"221 bye\r\n").await.ok();
                        return;
                    } else if upper.starts_with("STARTTLS") {
                        b"502 5.5.1 not here\r\n"
                    } else {
                        b"250 2.0.0 ok\r\n"
                    };
                    wr.write_all(reply).await.ok();
                }
            });
        }
    });
}

/// Receiving server doesn't offer STARTTLS at all: a sender that requires TLS
/// gets an immediate bounce, everyone else is delivered in plain text.
#[tokio::test]
#[serial_test::serial]
async fn per_sender_require_tls_no_starttls() {
    let mut local = TestServerBuilder::new("smtp_per_sender_tls_plain")
        .await
        .with_http_listener(19236)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    setup_local(&local, "mx.test.org").await;
    local.reload_core();
    local.expect_reload_settings().await;

    let log = Arc::new(Mutex::new(Vec::new()));
    spawn_plain_mx(log.clone()).await;

    // secure@: bounced on the first attempt, DATA never sent.
    send(&local, "secure@test.org").await;
    let seen = two_attempts(&mut local).await;
    println!("secure@ attempts (no STARTTLS): {seen:#?}");
    let mx_log = log.lock().unwrap().clone();
    assert!(!mx_log.iter().any(|l| l == "DATA-COMPLETE"), "{mx_log:?}");
    assert!(
        !mx_log.iter().any(|l| l.starts_with("MAIL FROM")),
        "{mx_log:?}"
    );
    assert_eq!(seen[0], "gone", "{seen:?}");
    let dsn = local
        .read_queued_messages()
        .await
        .into_iter()
        .find(|m| m.message.return_path.is_empty())
        .expect("no DSN for secure@");
    dsn.read_lines(&local)
        .await
        .assert_contains("To: secure@test.org")
        .assert_contains("STARTTLS not advertised")
        .assert_contains("Action: failed");
    local.clear_queue().await;
    log.lock().unwrap().clear();

    // john@: delivered in plain text, as today.
    send(&local, "john@test.org").await;
    let seen = two_attempts(&mut local).await;
    println!("john@ attempts (no STARTTLS): {seen:#?}");
    let mx_log = log.lock().unwrap().clone();
    assert!(mx_log.iter().any(|l| l == "DATA-COMPLETE"), "{mx_log:?}");
}
