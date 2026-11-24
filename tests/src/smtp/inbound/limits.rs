/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    smtp::session::{TestServerInstance, TestSession, VerifyResponse},
    utils::server::TestServerBuilder,
};
use common::network::{ServerInstance, SessionStream};
use registry::{
    schema::structs::{Expression, ExpressionMatch, MtaInboundSession},
    types::list::List,
};
use smtp::core::{Session, SessionData, SessionParameters, State};
use std::{
    borrow::Cow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
};

#[tokio::test]
async fn limits() {
    let mut test = TestServerBuilder::new("smtp_inbound_limits_test")
        .await
        .with_http_listener(19013)
        .await
        .disable_services()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    admin
        .registry_create_object(MtaInboundSession {
            max_duration: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.3'".into(),
                    then: "500ms".into(),
                }]),
                else_: "60m".into(),
            },
            timeout: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "500ms".into(),
                }]),
                else_: "30m".into(),
            },
            transfer_limit: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1'".into(),
                    then: "10".into(),
                }]),
                else_: "1024".into(),
            },
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();

    // Exceed max line length
    let (mut session, _tx) = test.new_mta_session_with_shutdown();
    session.data.remote_ip_str = "10.0.0.1".into();
    let mut buf = vec![b'A'; 4097];
    session.ingest(&buf).await.unwrap();
    session.ingest(b"\r\n").await.unwrap();
    session.response().assert_code("554 5.3.4");

    // Invalid command
    buf.extend_from_slice(b"\r\n");
    session.ingest(&buf).await.unwrap();
    session.response().assert_code("500 5.5.1");

    // Exceed transfer quota
    session.eval_session_params().await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn().await;
    session.response().assert_code("452 4.7.28");

    // Loitering
    session.data.remote_ip_str = "10.0.0.3".into();
    session.data.valid_until = Instant::now();
    session.eval_session_params().await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn().await;
    session.response().assert_code("421 4.3.2");

    // Timeout
    session.data.remote_ip_str = "10.0.0.2".into();
    session.data.valid_until = Instant::now();
    session.eval_session_params().await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn().await;
    session.response().assert_code("221 2.0.0");

    // inbuxa: SMTP-3: a client that never reads its replies is dropped once
    // a reply has stood still for the session timeout
    let mut session = Session {
        state: State::default(),
        instance: Arc::new(ServerInstance::test_with_shutdown(watch::channel(false).1)),
        server: test.server.clone(),
        stream: StalledIo {
            rx_buf: b"NOOP\r\n".to_vec(),
        },
        data: SessionData::new(
            "10.0.0.2".parse().unwrap(),
            0,
            "10.0.0.2".parse().unwrap(),
            0,
            Default::default(),
            0,
        ),
        params: SessionParameters::default(),
        hostname: "localhost".into(),
    };
    session.eval_session_params().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(10), session.handle_conn())
            .await
            .is_ok(),
        "the session was still writing to a client that doesn't read 10 s later"
    );
}

/// inbuxa: a client that sends what it has and then never reads
struct StalledIo {
    rx_buf: Vec<u8>,
}

impl AsyncRead for StalledIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.rx_buf.is_empty() {
            buf.put_slice(&std::mem::take(&mut self.rx_buf));
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl AsyncWrite for StalledIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Pending
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Pending
    }
}

impl SessionStream for StalledIo {
    fn is_tls(&self) -> bool {
        false
    }

    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>) {
        ("".into(), "".into())
    }
}
