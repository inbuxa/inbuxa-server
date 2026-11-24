/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::utils::{server::TestServer, smtp::SmtpConnection};

use super::{AssertResult, ImapConnection, Type};
use imap_proto::ResponseType;
use std::time::Duration;

const SLEEP: Duration = Duration::from_millis(200);

pub async fn test(
    imap: &mut ImapConnection,
    imap_check: &mut ImapConnection,
    is_cluster_test: bool,
) {
    println!("Running IDLE tests...");

    // Switch connection to IDLE mode
    imap_check.send("CREATE Parmeggiano").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check.send("SELECT Parmeggiano").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check.send("NOOP").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check.send("IDLE").await;
    imap_check
        .assert_read(Type::Continuation, ResponseType::Ok)
        .await;

    // Expect a new mailbox update
    imap.send("CREATE Provolone").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    if is_cluster_test {
        tokio::time::sleep(SLEEP).await;
    }
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("LIST () \"/\" \"Provolone\"");

    // Insert a message in the new folder and expect an update
    let message = "From: test@domain.com\nSubject: Test\n\nTest message\n";
    imap.send(&format!("APPEND Provolone {{{}}}", message.len()))
        .await;
    imap.assert_read(Type::Continuation, ResponseType::Ok).await;
    imap.send_untagged(message).await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    if is_cluster_test {
        tokio::time::sleep(SLEEP).await;
    }
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("STATUS \"Provolone\"")
        .assert_contains("MESSAGES 1")
        .assert_contains("UNSEEN 1")
        .assert_contains("UIDNEXT 2");

    // Change message to Seen and expect an update
    imap.send("SELECT Provolone").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("STORE 1:* +FLAGS (\\Seen)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    if is_cluster_test {
        tokio::time::sleep(SLEEP).await;
    }
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("STATUS \"Provolone\"")
        .assert_contains("MESSAGES 1")
        .assert_contains("UNSEEN 0")
        .assert_contains("UIDNEXT 2");

    // Delete message and expect an update
    imap.send("STORE 1:* +FLAGS (\\Deleted)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("CLOSE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    if is_cluster_test {
        tokio::time::sleep(SLEEP).await;
    }
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("STATUS \"Provolone\"")
        .assert_contains("MESSAGES 0")
        .assert_contains("UNSEEN 0")
        .assert_contains("UIDNEXT 2");

    // Delete folder and expect an update
    imap.send("DELETE Provolone").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    if is_cluster_test {
        tokio::time::sleep(SLEEP).await;
    }
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("LIST (\\NonExistent) \"/\" \"Provolone\"");

    // Add a message to Inbox and expect an update
    imap.send(&format!("APPEND Parmeggiano {{{}}}", message.len()))
        .await;
    imap.assert_read(Type::Continuation, ResponseType::Ok).await;
    imap.send_untagged(message).await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    if is_cluster_test {
        tokio::time::sleep(SLEEP).await;
    }
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 1")
        .assert_contains("UNSEEN 1");
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 EXISTS");
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 FETCH (FLAGS () UID 1)");

    // Delete message and expect an update
    imap.send("SELECT Parmeggiano").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    imap.send("STORE 1 +FLAGS (\\Deleted)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    if is_cluster_test {
        tokio::time::sleep(SLEEP).await;
    }
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 FETCH (FLAGS (\\Deleted) UID 1)");

    imap.send("UID EXPUNGE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 1 EXPUNGE")
        .assert_contains("* 0 EXISTS");
    if is_cluster_test {
        tokio::time::sleep(SLEEP).await;
    }
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 0")
        .assert_contains("UNSEEN 0");
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 EXPUNGE");
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 0 EXISTS");

    // Test SMTP delivery notifications
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "X-Spam-Status: No\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    if is_cluster_test {
        tokio::time::sleep(SLEEP).await;
    }
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("STATUS \"INBOX\"")
        .assert_contains(if is_cluster_test {
            "MESSAGES 1"
        } else {
            "MESSAGES 11"
        });

    // Stop IDLE mode
    imap_check.send_raw("DONE").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;

    imap_check.send("NOOP").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
}

// inbuxa: a message that arrives between two commands is announced with
// EXISTS before the data of the next FETCH or STORE, and changes that were
// found but not reported yet are sent as soon as IDLE starts.
pub async fn test_pending_changes(imap: &mut ImapConnection, imap_check: &mut ImapConnection) {
    println!("Running pending change tests...");

    let message = "From: test@domain.com\nSubject: Pending\n\nTest message\n";
    imap.send_ok("CREATE Fontina").await;
    imap.send_ok("SELECT Fontina").await;
    imap_check.send_ok("SELECT Fontina").await;

    // FETCH announces the new message before its data
    imap.append("Fontina", message).await;
    imap_check.send("UID FETCH 1:* (FLAGS)").await;
    let lines = imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    let exists = lines.iter().position(|line| line == "* 1 EXISTS");
    let fetch = lines.iter().position(|line| line.starts_with("* 1 FETCH"));
    assert!(
        matches!((exists, fetch), (Some(exists), Some(fetch)) if exists < fetch),
        "expected * 1 EXISTS before the FETCH data: {lines:?}"
    );

    // STORE announces it before the tagged reply
    imap.append("Fontina", message).await;
    imap_check.send("STORE 1 +FLAGS (\\Flagged)").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 2 EXISTS");

    // With an expunge pending, FETCH reports nothing and IDLE sends both
    imap.send_ok("UID STORE 1 +FLAGS (\\Deleted)").await;
    imap.send_ok("UID EXPUNGE 1").await;
    imap.append("Fontina", message).await;
    imap_check.send("UID FETCH 1:* (FLAGS)").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("EXPUNGE");
    imap_check.send("IDLE").await;
    imap_check
        .assert_read(Type::Continuation, ResponseType::Ok)
        .await;
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 EXPUNGE");
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 2 EXISTS");
    imap_check.send_raw("DONE").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;

    imap_check.send_ok("UNSELECT").await;
    imap.send_ok("UNSELECT").await;
    imap.send_ok("DELETE Fontina").await;
}

// inbuxa: once CONDSTORE is enabled, the STATUS sent during IDLE for another
// mailbox carries HIGHESTMODSEQ (RFC 7162 3.1); without it, it does not.
pub async fn test_condstore_status(test: &TestServer) {
    println!("Running IDLE CONDSTORE status tests...");

    let account = test.account("jdoe@example.com");
    let mut imap = account.imap_client().await;
    imap.send_ok("CREATE Gorgonzola").await;

    let mut condstore = account.imap_client().await;
    condstore.send_ok("ENABLE CONDSTORE").await;
    let mut plain = account.imap_client().await;
    for idle in [&mut condstore, &mut plain] {
        idle.send("IDLE").await;
        idle.assert_read(Type::Continuation, ResponseType::Ok).await;
    }

    imap.append(
        "Gorgonzola",
        "From: test@domain.com\nSubject: Modseq\n\nTest message\n",
    )
    .await;
    condstore
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("STATUS \"Gorgonzola\"")
        .assert_contains("MESSAGES 1")
        .assert_contains("HIGHESTMODSEQ ");
    plain
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("STATUS \"Gorgonzola\"")
        .assert_contains("MESSAGES 1")
        .assert_not_contains("HIGHESTMODSEQ");

    for idle in [&mut condstore, &mut plain] {
        idle.send_raw("DONE").await;
        idle.assert_read(Type::Tagged, ResponseType::Ok).await;
    }
    imap.send_ok("DELETE Gorgonzola").await;
}

// inbuxa: #607: with CONDSTORE on, the flag changes sent during IDLE carry
// MODSEQ (RFC 7162 3.2); without it, they do not.
pub async fn test_condstore_fetch(test: &TestServer) {
    println!("Running IDLE CONDSTORE flag change tests...");

    let account = test.account("jdoe@example.com");
    let mut imap = account.imap_client().await;
    imap.send_ok("CREATE Taleggio").await;
    imap.append(
        "Taleggio",
        "From: test@domain.com\nSubject: Modseq\n\nTest message\n",
    )
    .await;
    imap.send_ok("SELECT Taleggio").await;

    let mut condstore = account.imap_client().await;
    condstore.send_ok("ENABLE CONDSTORE").await;
    let mut plain = account.imap_client().await;
    for idle in [&mut condstore, &mut plain] {
        idle.send_ok("SELECT Taleggio").await;
        idle.send("IDLE").await;
        idle.assert_read(Type::Continuation, ResponseType::Ok).await;
    }

    imap.send_ok("STORE 1 +FLAGS (\\Flagged)").await;
    condstore
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 FETCH (")
        .assert_contains("FLAGS (\\Flagged)")
        .assert_contains("MODSEQ (");
    plain
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 FETCH (")
        .assert_contains("FLAGS (\\Flagged)")
        .assert_not_contains("MODSEQ");

    for idle in [&mut condstore, &mut plain] {
        idle.send_raw("DONE").await;
        idle.assert_read(Type::Tagged, ResponseType::Ok).await;
        idle.send_ok("UNSELECT").await;
    }
    imap.send_ok("UNSELECT").await;
    imap.send_ok("DELETE Taleggio").await;
}
