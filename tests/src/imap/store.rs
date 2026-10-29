/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{AssertResult, ImapConnection, Type};
use crate::utils::server::TestServer;
use imap_proto::ResponseType;

pub async fn test(imap: &mut ImapConnection, _imap_check: &mut ImapConnection, test: &TestServer) {
    println!("Running STORE tests...");

    // Select INBOX
    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("10 EXISTS")
        .assert_contains("[UIDNEXT 11]");

    // Set all messages to flag "Seen"
    imap.send("UID STORE 1:10 +FLAGS.SILENT (\\Seen)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("FLAGS", 0);

    // Check that the flags were set
    imap.send("UID FETCH 1:* (Flags)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("\\Seen", 10);

    // Check status
    imap.send("STATUS INBOX (UIDNEXT MESSAGES UNSEEN)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 10")
        .assert_contains("UNSEEN 0")
        .assert_contains("UIDNEXT 11");

    // Remove Seen flag from all messages
    imap.send("UID STORE 1:10 -FLAGS (\\Seen)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("FLAGS", 10)
        .assert_count("Seen", 0);

    // Check that the flags were removed
    imap.send("UID FETCH 1:* (Flags)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("\\Seen", 0);
    imap.send("STATUS INBOX (UIDNEXT MESSAGES UNSEEN)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 10")
        .assert_contains("UNSEEN 10")
        .assert_contains("UIDNEXT 11");

    // Store using saved searches
    test.wait_for_tasks().await;
    imap.send("SEARCH RETURN (SAVE) FROM nathaniel").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("UID STORE $ +FLAGS (\\Answered)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("FLAGS", 3);

    // Remove Answered flag
    imap.send("UID STORE 1:* -FLAGS (\\Answered)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("FLAGS", 3)
        .assert_count("Answered", 0);

    // inbuxa: a keyword that is not an atom (here stored from a literal, as
    // JMAP or Sieve could) is never written into FLAGS, so it cannot inject
    // a response
    for op in ["+", "-"] {
        imap.send(&format!("UID STORE 1 {op}FLAGS (custom {{16}}"))
            .await;
        imap.assert_read(Type::Continuation, ResponseType::Ok).await;
        imap.send_untagged("x)\r\n* 99 EXPUNGE)").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .assert_count("99 EXPUNGE", 0);
        imap.send("UID FETCH 1 (FLAGS)").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .assert_count("99 EXPUNGE", 0)
            .assert_count("custom", if op == "+" { 1 } else { 0 });
    }
}
