/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{AssertResult, ImapConnection, Type, resources_dir};
use crate::utils::{server::TestServer, smtp::SmtpConnection};
use futures::StreamExt;
use imap_proto::ResponseType;
use jmap_client::{
    DataType,
    event_source::{Changes, PushNotification},
};
use std::{fs, io, time::Duration};
use tokio::{sync::mpsc, time::Instant};

pub async fn test(imap: &mut ImapConnection, _imap_check: &mut ImapConnection, test: &TestServer) {
    println!("Running APPEND tests...");

    // Invalid APPEND commands
    imap.send("APPEND \"Does not exist\" {1+}\r\na").await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("TRYCREATE");

    // inbuxa: a message of more than 65,535 parts is refused, since its part
    // ids don't fit the stored structure
    let mut message =
        String::from("From: a@example.org\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n");
    for _ in 0..65_536 {
        message.push_str("--b\r\n\r\nx\r\n");
    }
    message.push_str("--b--\r\n");
    assert_append_message(imap, "INBOX", &message, ResponseType::No).await;

    // Import test messages
    let mut entries = fs::read_dir(resources_dir())
        .unwrap()
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()
        .unwrap();

    entries.sort();

    let mut expected_uid = 1;
    for file_name in entries.into_iter().take(20) {
        if file_name.extension().is_none_or(|e| e != "txt") {
            continue;
        }
        let raw_message = fs::read(&file_name).unwrap();

        imap.send(&format!(
            "APPEND INBOX (Flag_{}) {{{}}}",
            file_name
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .split_once('.')
                .unwrap()
                .0,
            raw_message.len()
        ))
        .await;
        imap.assert_read(Type::Continuation, ResponseType::Ok).await;
        imap.send_untagged(std::str::from_utf8(&raw_message).unwrap())
            .await;
        let result = imap
            .assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_response_code();
        let mut code = result.split(' ');
        assert_eq!(code.next(), Some("APPENDUID"));
        assert_ne!(code.next(), Some("0"));
        assert_eq!(code.next(), Some(expected_uid.to_string().as_str()));
        expected_uid += 1;
    }

    test.wait_for_tasks().await;
}

pub async fn assert_append_message(
    imap: &mut ImapConnection,
    folder: &str,
    message: &str,
    expected_response: ResponseType,
) -> Vec<String> {
    imap.send(&format!("APPEND \"{}\" {{{}}}", folder, message.len()))
        .await;
    imap.assert_read(Type::Continuation, ResponseType::Ok).await;
    imap.send_untagged(message).await;
    imap.assert_read(Type::Tagged, expected_response).await
}

fn build_message(message: usize, in_reply_to: Option<usize>, thread_num: usize) -> String {
    if let Some(in_reply_to) = in_reply_to {
        format!(
            "Message-ID: <{}@domain>\nReferences: <{}@domain>\nSubject: re: T{}\n\nreply\n",
            message, in_reply_to, thread_num
        )
    } else {
        format!(
            "Message-ID: <{}@domain>\nSubject: T{}\n\nmsg\n",
            message, thread_num
        )
    }
}

pub fn build_messages() -> Vec<String> {
    let mut messages = Vec::new();
    for parent in 0..3 {
        messages.push(build_message(parent, None, parent));
        for child in 0..3 {
            messages.push(build_message(
                ((parent + 1) * 10) + child,
                parent.into(),
                parent,
            ));
        }
    }
    messages
}

// inbuxa: mail a client adds over IMAP (APPEND, COPY, MOVE) is not a
// delivery, so it doesn't push EmailDelivery (RFC 8621, section 1.5);
// mail that arrives by LMTP still does
pub async fn test_no_delivery_push(test: &TestServer) {
    println!("Running IMAP new-mail push tests...");

    let account = test.account("jdoe@example.com");
    let account_id = account.id_string();
    let client = account.jmap_client().await;
    let mut changes = client
        .event_source(Some([DataType::EmailDelivery]), false, 1.into(), None)
        .await
        .unwrap();
    let (event_tx, mut event_rx) = mpsc::channel::<Changes>(100);
    tokio::spawn(async move {
        while let Some(change) = changes.next().await {
            let PushNotification::StateChange(changes) = change.unwrap() else {
                continue;
            };
            if event_tx.send(changes).await.is_err() {
                break;
            }
        }
    });
    // A first ping shows the subscription is in place
    match tokio::time::timeout(Duration::from_millis(2000), event_rx.recv()).await {
        Ok(Some(changes)) if changes.changes("ping").is_some() => {}
        result => panic!("Expected a ping, got {result:?}"),
    }

    let mut imap = account.imap_client().await;
    imap.send_ok("CREATE \"Push Drafts\"").await;
    imap.send_ok("CREATE \"Push Copies\"").await;
    imap.append(
        "Push Drafts",
        "From: jdoe@example.com\r\nSubject: Push draft\r\n\r\nNot sent yet.\r\n",
    )
    .await;
    assert_no_delivery_push(&mut event_rx, account_id, "APPEND").await;
    imap.send_ok("SELECT \"Push Drafts\"").await;
    imap.send_ok("COPY 1 \"Push Copies\"").await;
    assert_no_delivery_push(&mut event_rx, account_id, "COPY").await;
    imap.send_ok("MOVE 1 \"Push Copies\"").await;
    assert_no_delivery_push(&mut event_rx, account_id, "MOVE").await;

    // Mail that arrives is still pushed
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: Push delivery\r\n",
            "\r\n",
            "This one arrived."
        ),
    )
    .await;
    lmtp.quit().await;
    let deadline = Instant::now() + Duration::from_millis(3000);
    loop {
        match tokio::time::timeout_at(deadline, event_rx.recv()).await {
            Ok(Some(changes)) => {
                if let Some(mut types) = changes.changes(account_id) {
                    assert!(types.any(|(t, _)| *t == DataType::EmailDelivery));
                    break;
                }
            }
            result => panic!("No EmailDelivery push after an LMTP delivery: {result:?}"),
        }
    }

    // Clean up
    imap.send_ok("SELECT INBOX").await;
    imap.send("UID SEARCH SUBJECT \"Push delivery\"").await;
    let found = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let uid = found
        .iter()
        .find_map(|line| line.strip_prefix("* SEARCH "))
        .expect("delivered message not found")
        .trim()
        .to_string();
    imap.send_ok(&format!("UID MOVE {uid} \"Push Copies\""))
        .await;
    imap.send_ok("UNSELECT").await;
    imap.send_ok("DELETE \"Push Drafts\"").await;
    imap.send_ok("DELETE \"Push Copies\"").await;
}

async fn assert_no_delivery_push(
    event_rx: &mut mpsc::Receiver<Changes>,
    account_id: &str,
    command: &str,
) {
    // Changes are pushed at most once a second, so two seconds of pings
    // only means nothing was pushed
    let deadline = Instant::now() + Duration::from_millis(2000);
    while let Ok(Some(changes)) = tokio::time::timeout_at(deadline, event_rx.recv()).await {
        if let Some(types) = changes.changes(account_id) {
            panic!(
                "{command} pushed {:?} to an EmailDelivery subscriber",
                types.map(|(t, _)| t).collect::<Vec<_>>()
            );
        }
    }
}
