/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    smtp::session::{TestSession, VerifyResponse},
    utils::server::TestServerBuilder,
};
use common::auth::{AccountCache, AccountInfo};
use mail_auth::SpfOutput;
use smtp::core::SessionAddress;
use std::sync::Arc;

#[tokio::test]
async fn basic_commands() {
    let test = TestServerBuilder::new("smtp_basic_test")
        .await
        .with_http_listener(19002)
        .await
        .disable_services()
        .build()
        .await;

    let mut session = test.new_mta_session();

    // STARTTLS should be available on clear text connections
    session.stream.tls = false;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("STARTTLS");
    session.data.mail_from = Some(SessionAddress::new("attacker@evil.tld".to_string()));
    session
        .data
        .rcpt_to
        .push(SessionAddress::new("victim@foobar.org".to_string()));
    session.data.spf_ehlo = Some(SpfOutput::default());
    session.data.authenticated_as = Some(AccountInfo {
        account_id: u32::MAX,
        addresses: vec!["attacker@evil.tld".to_string()],
        account: Arc::new(AccountCache {
            name: "attacker".into(),
            ..Default::default()
        }),
    });
    session.data.bytes_left = 12345;
    session.data.rcpt_errors = 2;
    session.data.auth_errors = 1;

    assert!(!session.ingest(b"STARTTLS\r\n").await.unwrap());
    session.response().assert_contains("220 2.0.0");

    assert!(session.data.mail_from.is_none());
    assert!(session.data.rcpt_to.is_empty());
    assert!(session.data.helo_domain.is_empty());
    assert!(session.data.spf_ehlo.is_none());
    assert!(session.data.authenticated_as.is_none());

    assert_eq!(session.data.bytes_left, 12345);
    assert_eq!(session.data.rcpt_errors, 2);
    assert_eq!(session.data.auth_errors, 1);

    // STARTTLS should not be offered on TLS connections
    session.stream.tls = true;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("STARTTLS");
    session.cmd("STARTTLS", "504 5.7.4").await;

    // Test NOOP
    session.cmd("NOOP", "250").await;

    // Test RSET
    session.cmd("RSET", "250").await;

    // Test HELP
    session.cmd("HELP QUIT", "250").await;

    // Test LHLO on SMTP channel
    session.cmd("LHLO domain.org", "502").await;

    // inbuxa: an AUTH line the parser refuses is answered once, and the
    // rest of it is not read as another command, also when it arrives in
    // pieces
    for (line, code) in [
        (&b"AUTH \tRSET\r\n"[..], "501 5.5.2"),
        (b"AUTH  RSET\r\n", "554 5.7.8"),
    ] {
        session.ingest(line).await.unwrap();
        let response = session.response();
        assert_eq!(
            response.len(),
            1,
            "{} got {response:?}",
            String::from_utf8_lossy(line).escape_debug()
        );
        response.assert_code(code);
    }
    session.ingest(b"AUTH \tRS").await.unwrap();
    session.ingest(b"ET\r\nNOOP\r\n").await.unwrap();
    let response = session.response();
    assert_eq!(response.len(), 2, "{response:?}");
    response
        .assert_contains("501 5.5.2")
        .assert_contains("250 2.0.0");

    // Test QUIT
    session.ingest(b"QUIT\r\n").await.unwrap_err();
    session.response().assert_code("221");
}
