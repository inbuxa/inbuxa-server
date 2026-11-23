/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use email::mailbox::INBOX_ID;
use futures::StreamExt;
use jmap_client::{
    DataType,
    core::set::SetObject,
    email::EmailBodyPart,
    event_source::{Changes, PushNotification},
    mailbox::Role,
};
use std::time::Duration;
use store::ahash::AHashSet;
use tokio::sync::mpsc;
use types::id::Id;

use crate::utils::{server::TestServer, smtp::SmtpConnection};

pub async fn test(test: &TestServer) {
    println!("Running EventSource tests...");

    // Create test account
    let account = test.account("jdoe@example.com");
    let client = account.jmap_client().await;

    // inbuxa: an email in another account, for the Email/copy check below
    let jane = test.account("jane.smith@example.com");
    let mut admin_client = test.account("admin@example.com").jmap_client().await;
    let jane_email_id = admin_client
        .set_default_account_id(jane.id_string())
        .email_import(
            concat!(
                "From: jane.smith@example.com\r\n",
                "To: jdoe@example.com\r\n",
                "Subject: TPS Report (copied)\r\n",
                "\r\n",
                "Here is my copy."
            )
            .as_bytes()
            .to_vec(),
            [Id::from(INBOX_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap()
        .take_id();

    let mut changes = client
        .event_source(None::<Vec<_>>, false, 1.into(), None)
        .await
        .unwrap();

    let (event_tx, mut event_rx) = mpsc::channel::<Changes>(100);

    tokio::spawn(async move {
        while let Some(change) = changes.next().await {
            if let Err(_err) = event_tx
                .send(match change.unwrap() {
                    PushNotification::StateChange(changes) => changes,
                    PushNotification::CalendarAlert(_) => unreachable!(),
                })
                .await
            {
                //println!("Error sending event: {}", _err);
                break;
            }
        }
    });

    assert_ping(&mut event_rx).await;

    // Create mailbox and expect state change
    let mailbox_id = client
        .mailbox_create("EventSource Test", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();
    assert_state(&mut event_rx, account.id_string(), &[DataType::Mailbox]).await;

    // Multiple changes should be grouped and delivered in intervals
    for num in 0..5 {
        client
            .mailbox_update_sort_order(&mailbox_id, num)
            .await
            .unwrap();
    }
    assert_state(&mut event_rx, account.id_string(), &[DataType::Mailbox]).await;
    assert_ping(&mut event_rx).await; // Pings are only received in cfg(test)

    // Ingest email and expect state change
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    lmtp.quit().await;

    assert_state(
        &mut event_rx,
        account.id_string(),
        &[
            DataType::EmailDelivery,
            DataType::Email,
            DataType::Thread,
            DataType::Mailbox,
        ],
    )
    .await;
    assert_ping(&mut event_rx).await;

    // inbuxa: mail a client adds is not a delivery, so an import, a draft
    // saved with Email/set and an Email/copy change Email, Thread and
    // Mailbox but not EmailDelivery (RFC 8621, section 1.5)
    client
        .email_import(
            concat!(
                "From: bill@example.com\r\n",
                "To: jdoe@example.com\r\n",
                "Subject: TPS Report (imported)\r\n",
                "\r\n",
                "Did you get the memo?"
            )
            .as_bytes()
            .to_vec(),
            [Id::from(INBOX_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap();
    assert_state(
        &mut event_rx,
        account.id_string(),
        &[DataType::Email, DataType::Thread, DataType::Mailbox],
    )
    .await;
    assert_ping(&mut event_rx).await;

    let mut request = client.build();
    let create_id = request
        .set_email()
        .create()
        .mailbox_ids([Id::from(INBOX_ID).to_string()])
        .keywords(["$draft"])
        .from(["jdoe@example.com"])
        .to(["bill@example.com"])
        .subject("Re: TPS Report (draft)")
        .body_value("t".to_string(), "Working on it.")
        .text_body(EmailBodyPart::new().part_id("t"))
        .create_id()
        .unwrap();
    request
        .send_set_email()
        .await
        .unwrap()
        .created(&create_id)
        .unwrap();
    assert_state(
        &mut event_rx,
        account.id_string(),
        &[DataType::Email, DataType::Thread, DataType::Mailbox],
    )
    .await;
    assert_ping(&mut event_rx).await;

    admin_client
        .set_default_account_id(account.id_string())
        .email_copy(
            jane.id_string(),
            &jane_email_id,
            [Id::from(INBOX_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap();
    assert_state(
        &mut event_rx,
        account.id_string(),
        &[DataType::Email, DataType::Thread, DataType::Mailbox],
    )
    .await;
    assert_ping(&mut event_rx).await;
    test.account("admin@example.com")
        .destroy_all_mailboxes_for_account(jane.id().document_id())
        .await;

    // Destroy mailbox
    client.mailbox_destroy(&mailbox_id, true).await.unwrap();
    assert_state(&mut event_rx, account.id_string(), &[DataType::Mailbox]).await;

    // Destroy Inbox
    client
        .mailbox_destroy(&Id::from(INBOX_ID).to_string(), true)
        .await
        .unwrap();
    assert_state(
        &mut event_rx,
        account.id_string(),
        &[DataType::Email, DataType::Thread, DataType::Mailbox],
    )
    .await;
    assert_ping(&mut event_rx).await;
    assert_ping(&mut event_rx).await;

    test.destroy_all_mailboxes(account).await;
    test.assert_is_empty().await;
}

async fn assert_state(
    event_rx: &mut mpsc::Receiver<Changes>,
    account_id: &str,
    state: &[DataType],
) {
    match tokio::time::timeout(Duration::from_millis(700), event_rx.recv()).await {
        Ok(Some(changes)) => {
            assert_eq!(
                changes
                    .changes(account_id)
                    .unwrap()
                    .map(|x| x.0)
                    .collect::<AHashSet<&DataType>>(),
                state.iter().collect::<AHashSet<&DataType>>()
            );
        }
        result => {
            panic!("Timeout waiting for event {:?}: {:?}", state, result);
        }
    }
}

async fn assert_ping(event_rx: &mut mpsc::Receiver<Changes>) {
    match tokio::time::timeout(Duration::from_millis(1100), event_rx.recv()).await {
        Ok(Some(changes)) => {
            assert!(changes.changes("ping").is_some(),);
        }
        _ => {
            panic!("Did not receive ping.");
        }
    }
}
