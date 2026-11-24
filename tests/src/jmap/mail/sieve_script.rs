/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    jmap::mail::submission::{MockMessage, assert_message_delivery, spawn_mock_smtp_server},
    utils::{dns::DnsCache, server::TestServer, smtp::SmtpConnection},
};
use ::email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::{INBOX_ID, JUNK_ID},
};
use jmap_client::{
    email, mailbox,
    sieve::query::{Comparator, Filter},
};
use mail_auth::{common::parse::TxtRecordParser, spf::Spf};
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{Expression, SenderAuth, SieveUserScript, SpamTag, SpamTagScore},
    },
    types::float::Float,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    str::FromStr,
    time::{Duration, Instant},
};
use store::{
    query::log::{Change, Query},
    write::LogCollection,
};
use types::{collection::SyncCollection, id::Id};

pub async fn test(test: &TestServer) {
    println!("Running Sieve tests...");

    // Create a global script
    let admin = test.account("admin@example.com");
    admin
        .registry_create_object(SieveUserScript {
            contents: "require \"reject\";\nreject \"Rejected from a global script.\";\nstop;\n"
                .into(),
            description: None,
            is_active: true,
            name: "common".into(),
        })
        .await;
    admin.reload_settings().await;

    let server = test.server.clone();
    let account = test.account("jdoe@example.com");
    let client = account.jmap_client().await;

    // Validate scripts
    client
        .sieve_script_validate(get_script("validate_ok"))
        .await
        .unwrap();
    // A script that doesn't compile is the invalidSieve of RFC 9661, from
    // SieveScript/validate and SieveScript/set alike (jmap-client only knows
    // the draft's name, so the responses are read as JSON)
    let account_id = account.id_string();
    let blob_id = client
        .upload(None, get_script("validate_error"), None)
        .await
        .unwrap()
        .blob_id()
        .to_string();
    let response = account
        .jmap_method_call(
            "SieveScript/validate",
            serde_json::json!({"accountId": account_id, "blobId": blob_id}),
        )
        .await;
    assert_eq!(
        response
            .method_response()
            .pointer("/error/type")
            .and_then(|v| v.as_str()),
        Some("invalidSieve"),
        "{response:?}"
    );
    let response = account
        .jmap_method_call(
            "SieveScript/set",
            serde_json::json!({"accountId": account_id, "create": {
                "bad": {"name": "does_not_compile", "blobId": blob_id}
            }}),
        )
        .await;
    assert_eq!(
        response
            .method_response()
            .pointer("/notCreated/bad/type")
            .and_then(|v| v.as_str()),
        Some("invalidSieve"),
        "{response:?}"
    );

    // Create 5 Sieve scripts, all deactivated.
    let mut script_ids = Vec::new();
    for i in 0..5 {
        script_ids.push(
            client
                .sieve_script_create(
                    format!("script_{}", i + 1),
                    format!("require \"fileinto\"; fileinto \"{}\";", i + 1).into_bytes(),
                    false,
                )
                .await
                .unwrap()
                .take_id(),
        );
    }

    let response = client
        .sieve_script_query(Filter::is_active(false).into(), [Comparator::name()].into())
        .await
        .unwrap();
    assert_eq!(response.ids().len(), 5);
    for (pos, id) in response.ids().iter().enumerate() {
        let script = client
            .sieve_script_get(id, None::<Vec<_>>)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(script.name().unwrap(), format!("script_{}", pos + 1));
        assert_eq!(
            String::from_utf8(client.download(script.blob_id().unwrap()).await.unwrap()).unwrap(),
            format!("require \"fileinto\"; fileinto \"{}\";", pos + 1)
        );
    }

    // Activate last script twice and then the first script
    for _ in 0..2 {
        client
            .sieve_script_activate(script_ids.last().unwrap())
            .await
            .unwrap();
        assert_eq!(
            client
                .sieve_script_query(Filter::is_active(true).into(), [Comparator::name()].into())
                .await
                .unwrap()
                .ids(),
            vec![script_ids.last().unwrap().to_string()]
        );
    }
    client
        .sieve_script_activate(script_ids.first().unwrap())
        .await
        .unwrap();
    assert_eq!(
        client
            .sieve_script_query(Filter::is_active(true).into(), [Comparator::name()].into())
            .await
            .unwrap()
            .ids(),
        vec![script_ids.first().unwrap().to_string()]
    );

    // Destroying an active script should not work, and the error is the
    // sieveIsActive of RFC 9661 (jmap-client only knows the draft's name,
    // so the response is read as JSON)
    let account_id = account.id_string();
    let response = account
        .jmap_method_call(
            "SieveScript/set",
            json!({"accountId": account_id, "destroy": [&script_ids[0]]}),
        )
        .await;
    assert_eq!(
        response
            .method_response()
            .pointer(&format!("/notDestroyed/{}/type", script_ids[0]))
            .and_then(|v| v.as_str()),
        Some("sieveIsActive"),
        "{response:?}"
    );

    // Activating another script reports the old one as inactive and the new
    // one as active, moves the SieveScript state, and logs both as updated
    // (the server has no SieveScript/changes, so the log is read directly)
    let get_state = async || {
        account
            .jmap_method_call(
                "SieveScript/get",
                json!({"accountId": account_id, "ids": []}),
            )
            .await
            .method_response()["state"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let sieve_changes = async |query: Query| {
        server
            .store()
            .changes(
                account.id().document_id(),
                LogCollection::Sync(SyncCollection::SieveScript),
                query,
            )
            .await
            .unwrap()
    };
    let state = get_state().await;
    let last_change_id = sieve_changes(Query::All).await.to_change_id;
    let response = account
        .jmap_method_call(
            "SieveScript/set",
            json!({"accountId": account_id, "onSuccessActivateScript": &script_ids[1]}),
        )
        .await;
    assert_eq!(
        response.updated(&script_ids[0]),
        &json!({"isActive": false}),
        "{response:?}"
    );
    assert_eq!(
        response.updated(&script_ids[1]),
        &json!({"isActive": true}),
        "{response:?}"
    );
    assert_ne!(
        response.method_response()["oldState"],
        response.method_response()["newState"],
        "{response:?}"
    );
    assert_ne!(get_state().await, state);
    let changes = sieve_changes(Query::Since(last_change_id)).await;
    let mut updated = changes
        .changes
        .iter()
        .filter_map(|change| match change {
            Change::UpdateItem(id) => Some(*id),
            _ => None,
        })
        .collect::<Vec<_>>();
    updated.sort();
    let mut expected = script_ids[..2]
        .iter()
        .map(|id| Id::from_str(id).unwrap().document_id() as u64)
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(updated, expected, "{changes:?}");

    // When part of the call fails, nothing is activated and nothing is
    // reported as active
    let response = account
        .jmap_method_call(
            "SieveScript/set",
            json!({
                "accountId": account_id,
                "update": {
                    &script_ids[2]: {"name": "script_3"},
                    &script_ids[3]: {"name": "vacation"}
                },
                "onSuccessActivateScript": &script_ids[2]
            }),
        )
        .await;
    response.not_updated(&script_ids[3]);
    assert_eq!(
        response.updated(&script_ids[2]),
        &Value::Null,
        "{response:?}"
    );
    assert_eq!(
        client
            .sieve_script_query(Filter::is_active(true).into(), [Comparator::name()].into())
            .await
            .unwrap()
            .ids(),
        vec![script_ids[1].to_string()]
    );

    // Deactivating reports the script as inactive
    let response = account
        .jmap_method_call(
            "SieveScript/set",
            json!({"accountId": account_id, "onSuccessDeactivateScript": true}),
        )
        .await;
    assert_eq!(
        response.updated(&script_ids[1]),
        &json!({"isActive": false}),
        "{response:?}"
    );

    // A script destroyed in the same call is not activated, and the active
    // script stays active
    client.sieve_script_activate(&script_ids[0]).await.unwrap();
    let response = account
        .jmap_method_call(
            "SieveScript/set",
            json!({
                "accountId": account_id,
                "destroy": [&script_ids[4]],
                "onSuccessActivateScript": &script_ids[4]
            }),
        )
        .await;
    assert_eq!(
        response.method_response()["destroyed"],
        json!([&script_ids[4]]),
        "{response:?}"
    );
    assert_eq!(
        response
            .method_response()
            .pointer(&format!("/updated/{}", script_ids[4])),
        None,
        "{response:?}"
    );
    assert_eq!(
        client
            .sieve_script_query(Filter::is_active(true).into(), [Comparator::name()].into())
            .await
            .unwrap()
            .ids(),
        vec![script_ids[0].to_string()]
    );

    // Deactivate all scripts
    client.sieve_script_deactivate().await.unwrap();
    assert_eq!(
        client
            .sieve_script_query(Filter::is_active(true).into(), [Comparator::name()].into())
            .await
            .unwrap()
            .ids(),
        Vec::<String>::new()
    );

    // Connect to LMTP service
    let mut lmtp = SmtpConnection::connect().await;

    // Run mailbox, fileinto, flags tests
    client
        .sieve_script_create("test_mailbox", get_script("test_mailbox"), true)
        .await
        .unwrap();
    lmtp.ingest(
        "bill@remote.org",
        &["jdoe@example.com"],
        concat!(
            "From: bill@remote.org\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;

    // Make sure all folders were created
    let mailbox_names = "My/Nested/Mailbox/with/multiple/levels/Folder"
        .split('/')
        .collect::<Vec<_>>();
    let mut mailbox_ids = Vec::new();
    for &mailbox in &mailbox_names {
        let mut response = client
            .mailbox_query(mailbox::query::Filter::name(mailbox).into(), None::<Vec<_>>)
            .await
            .unwrap();
        assert!(
            !response.ids().is_empty(),
            "Mailbox {} was not created.",
            mailbox
        );
        mailbox_ids.extend(response.take_ids());
    }
    assert_eq!(mailbox_ids.len(), mailbox_names.len());

    // Make sure the message was delivered to the right folders
    let message_ids = client
        .email_query(None::<email::query::Filter>, None::<Vec<_>>)
        .await
        .unwrap()
        .take_ids();
    assert_eq!(message_ids.len(), 1, "too many messages {:?}", message_ids);
    let email = client
        .email_get(
            message_ids.last().unwrap(),
            [email::Property::MailboxIds, email::Property::Keywords].into(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        email.keywords().len(),
        2,
        "Expected 2 keywords, found {:?}.",
        email.keywords()
    );
    for keyword in ["$important", "$seen"] {
        if !email.keywords().contains(&keyword) {
            panic!("Keyword {} not found in {:?}.", keyword, email.keywords());
        }
    }
    assert_eq!(
        email.mailbox_ids().len(),
        3,
        "Expected 3 mailbox ids, found {:?}.",
        email.mailbox_ids()
    );
    let drafts_id = client
        .mailbox_query(
            mailbox::query::Filter::name("Drafts").into(),
            None::<Vec<_>>,
        )
        .await
        .unwrap()
        .take_ids()
        .pop()
        .expect("Drafts mailbox not found.");
    assert!(
        email.mailbox_ids().contains(&drafts_id.as_str()),
        "Drafts mailbox {} not found in {:?}.",
        drafts_id,
        email.mailbox_ids()
    );
    for mailbox_pos in [mailbox_ids.len() - 1, mailbox_ids.len() - 2] {
        if !email
            .mailbox_ids()
            .contains(&mailbox_ids[mailbox_pos].as_str())
        {
            panic!(
                "Mailbox {} ({}) not found in {:?}.",
                mailbox_names[mailbox_pos],
                mailbox_ids[mailbox_pos],
                email.keywords()
            );
        }
    }

    // Run discard and duplicate tests
    client
        .sieve_script_create(
            "test_discard_reject",
            get_script("test_discard_reject"),
            true,
        )
        .await
        .unwrap();
    lmtp.ingest(
        "bill@remote.org",
        &["jdoe@example.com"],
        concat!(
            "From: bill@remote.org\r\n",
            "Bcc: Undisclosed recipients;\r\n",
            "Message-ID: <1234@example.com>\r\n",
            "Subject: Holidays\r\n",
            "\r\n",
            "Remember to file your TPS reports before ",
            "going on holidays."
        ),
    )
    .await;
    assert_eq!(
        client
            .email_query(None::<email::query::Filter>, None::<Vec<_>>)
            .await
            .unwrap()
            .ids()
            .len(),
        1,
        "Discard failed."
    );

    // Let one sec duplicate ids expire
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Start mock SMTP server
    let (mut smtp_rx, smtp_settings) = spawn_mock_smtp_server();
    server.ipv4_add(
        "localhost",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    // inbuxa: a rejection goes back only to a return path this server
    // verified. Here LMTP checks SPF: remote.org passes, foobar.com fails
    admin
        .registry_update_setting(
            SenderAuth {
                spf_from_verify: Expression {
                    else_: "relaxed".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            &[Property::SpfFromVerify],
        )
        .await;
    admin.reload_settings().await;
    for (domain, record) in [
        ("remote.org", &b"v=spf1 ip4:127.0.0.1 -all"[..]),
        ("foobar.com", &b"v=spf1 -all"[..]),
    ] {
        server.txt_add(
            domain,
            Spf::parse(record).unwrap(),
            Instant::now() + Duration::from_secs(3600),
        );
    }
    let mut lmtp = SmtpConnection::connect().await;

    // Run reject and duplicate check tests
    lmtp.ingest(
        "bill@remote.org",
        &["jdoe@example.com"],
        concat!(
            "From: bill@remote.org\r\n",
            "Bcc: Undisclosed recipients;\r\n",
            "Message-ID: <1234@example.com>\r\n",
            "Subject: Holidays\r\n",
            "\r\n",
            "Remember to file your T.P.S. reports before ",
            "going on holidays."
        ),
    )
    .await;

    assert_eq!(
        client
            .email_query(None::<email::query::Filter>, None::<Vec<_>>)
            .await
            .unwrap()
            .ids()
            .len(),
        1,
        "Reject failed."
    );

    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new("<>", ["<bill@remote.org>"], "@No soup for you"),
    )
    .await;

    // Run include tests
    client
        .sieve_script_create("test_include_this", get_script("test_include_this"), false)
        .await
        .unwrap();
    client
        .sieve_script_create("test_include", get_script("test_include"), true)
        .await
        .unwrap();
    lmtp.ingest(
        "bill@remote.org",
        &["jdoe@example.com"],
        concat!(
            "From: bill@remote.org\r\n",
            "Bcc: Undisclosed recipients;\r\n",
            "Message-ID: <1234@example.com>\r\n",
            "Subject: Holidays\r\n",
            "\r\n",
            "Remember to file your T.P.S. reports before ",
            "going on holidays."
        ),
    )
    .await;

    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new(
            "<>",
            ["<bill@remote.org>"],
            "@Rejected from an included script",
        ),
    )
    .await;

    client
        .sieve_script_create(
            "Test Script",
            concat!(
                "require \"reject\";\n",
                "reject \"Rejected from a mixed-case included script.\";\n",
                "stop;\n"
            )
            .as_bytes()
            .to_vec(),
            false,
        )
        .await
        .unwrap();
    client
        .sieve_script_create("test_include_case", get_script("test_include_case"), true)
        .await
        .unwrap();
    lmtp.ingest(
        "bill@remote.org",
        &["jdoe@example.com"],
        concat!(
            "From: bill@remote.org\r\n",
            "Bcc: Undisclosed recipients;\r\n",
            "Message-ID: <5678@example.com>\r\n",
            "Subject: Holidays\r\n",
            "\r\n",
            "Remember to file your T.P.S. reports before ",
            "going on holidays."
        ),
    )
    .await;

    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new(
            "<>",
            ["<bill@remote.org>"],
            "@Rejected from a mixed-case included script",
        ),
    )
    .await;

    // Run include global tests
    client
        .sieve_script_create(
            "test_include_global",
            get_script("test_include_global"),
            true,
        )
        .await
        .unwrap();
    lmtp.ingest(
        "bill@remote.org",
        &["jdoe@example.com"],
        concat!(
            "From: bill@remote.org\r\n",
            "Bcc: Undisclosed recipients;\r\n",
            "Message-ID: <1234@example.com>\r\n",
            "Subject: Holidays\r\n",
            "\r\n",
            "Remember to file your T.P.S. reports before ",
            "going on holidays."
        ),
    )
    .await;

    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new(
            "<>",
            ["<bill@remote.org>"],
            "@Rejected from a global script",
        ),
    )
    .await;

    // inbuxa: mail from a sender that failed SPF is rejected without a
    // rejection notice (it would go to whoever was forged), and isn't stored
    client
        .sieve_script_create(
            "test_reject_forged",
            concat!(
                "require \"reject\";\r\n",
                "reject \"Not accepted here.\";\r\n"
            )
            .as_bytes()
            .to_vec(),
            true,
        )
        .await
        .unwrap();
    let stored = client
        .email_query(None::<email::query::Filter>, None::<Vec<_>>)
        .await
        .unwrap()
        .ids()
        .len();
    for sender in ["victim@foobar.com", ""] {
        lmtp.ingest(
            sender,
            &["jdoe@example.com"],
            concat!(
                "From: victim@foobar.com\r\n",
                "To: jdoe@example.com\r\n",
                "Subject: Backscatter\r\n",
                "\r\n",
                "Bounce this to the forged sender."
            ),
        )
        .await;
    }
    // the next rejection to arrive is the one for the verified sender
    lmtp.ingest(
        "bill@remote.org",
        &["jdoe@example.com"],
        concat!(
            "From: bill@remote.org\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: Verified\r\n",
            "\r\n",
            "Reject this one with a notice."
        ),
    )
    .await;
    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new("<>", ["<bill@remote.org>"], "@Not accepted here"),
    )
    .await;
    assert_eq!(
        client
            .email_query(None::<email::query::Filter>, None::<Vec<_>>)
            .await
            .unwrap()
            .ids()
            .len(),
        stored,
        "A rejected message was stored."
    );

    // Run enclose + redirect tests
    client
        .sieve_script_create(
            "test_redirect_enclose",
            get_script("test_redirect_enclose"),
            true,
        )
        .await
        .unwrap();
    lmtp.ingest(
        "bill@remote.org",
        &["jdoe@example.com"],
        concat!(
            "From: bill@remote.org\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new(
            "<jdoe@example.com>",
            ["<jane@remote.org>"],
            "@Attached you'll find",
        ),
    )
    .await;
    assert_eq!(
        client
            .email_query(None::<email::query::Filter>, None::<Vec<_>>)
            .await
            .unwrap()
            .ids()
            .len(),
        1,
        "Redirected message was stored."
    );

    // Run notify + editheader + notify + fcc tests
    client
        .sieve_script_create("test_notify_fcc", get_script("test_notify_fcc"), true)
        .await
        .unwrap();
    smtp_settings.lock().do_stop = true;
    lmtp.ingest(
        "bill@remote.org",
        &["jdoe@example.com"],
        concat!(
            "From: bill@remote.org\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: Urgently I need those TPS Reports\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;

    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new(
            "<jdoe@example.com>",
            ["<sms_gateway@remote.org>"],
            "@It's TPS-o-clock",
        ),
    )
    .await;

    let mut request = client.build();
    request.get_email().properties([
        email::Property::MailboxIds,
        email::Property::Keywords,
        email::Property::Subject,
    ]);
    let emails = request.send_get_email().await.unwrap().take_list();

    assert_eq!(
        emails.len(),
        3,
        "Two new messages were expected: {:#?}.",
        emails
    );

    'outer: for (subject, folder, keywords) in [
        ("It's TPS-o-clock", "Notifications", ""),
        (
            "Urgently I need those **censored** Reports",
            "Inbox",
            "$seen",
        ),
    ] {
        for email in &emails {
            if email.subject().unwrap().eq(subject) {
                if !keywords.is_empty() && !email.keywords().contains(&keywords) {
                    panic!("Keyword {:?} not found in: {:#?}", keywords, email);
                }

                let mailbox_id = client
                    .mailbox_query(
                        mailbox::query::Filter::name(folder.to_string()).into(),
                        None::<Vec<_>>,
                    )
                    .await
                    .unwrap()
                    .take_ids()
                    .pop()
                    .unwrap_or_else(|| panic!("Mailbox {:?} not found", folder));

                if !email.mailbox_ids().contains(&mailbox_id.as_str()) {
                    panic!(
                        "Mailbox {:?} ({}) not found in: {:#?}",
                        folder, mailbox_id, email
                    );
                }

                continue 'outer;
            }
        }
        panic!("Email {:?} not found in: {:#?}", subject, emails);
    }

    // inbuxa: #542: a redirect to a local account keeps the spam verdict of
    // the recipient whose script redirected it: the copy goes to the
    // target's Junk, not its Inbox
    let gtube_score = admin
        .registry_create_object(SpamTag::Score(SpamTagScore {
            score: Float::new(1000.0),
            tag: "GTUBE_TEST".to_string(),
        }))
        .await;
    admin.reload_settings().await;
    client
        .sieve_script_create(
            "test_redirect_local",
            b"redirect \"bill@example.com\";".to_vec(),
            true,
        )
        .await
        .unwrap();
    let bill = test.account("bill@example.com");
    let bill_id = bill.id().document_id();
    let in_mailbox = |mailbox_id: u32| {
        let server = server.clone();
        async move {
            server
                .get_cached_messages(bill_id)
                .await
                .unwrap()
                .in_mailbox(mailbox_id)
                .count()
        }
    };
    let bill_inbox = in_mailbox(INBOX_ID).await;
    let bill_junk = in_mailbox(JUNK_ID).await;
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "spammer@remote.org",
        &["jdoe@example.com"],
        concat!(
            "From: spammer@remote.org\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n",
            "\r\n",
            "Redirected spam."
        ),
    )
    .await;
    lmtp.quit().await;
    let started = Instant::now();
    while in_mailbox(INBOX_ID).await + in_mailbox(JUNK_ID).await == bill_inbox + bill_junk {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the redirected message didn't arrive"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        (in_mailbox(INBOX_ID).await, in_mailbox(JUNK_ID).await),
        (bill_inbox, bill_junk + 1),
        "the redirected spam wasn't filed in the target's Junk"
    );
    admin
        .registry_destroy(ObjectType::SpamTag, [gtube_score])
        .await
        .assert_destroyed(&[gtube_score]);
    admin.reload_settings().await;
    test.destroy_all_mailboxes(bill).await;

    // Remove test data
    client.sieve_script_deactivate().await.unwrap();
    let mut request = client.build();
    request.query_sieve_script();
    for id in request.send_query_sieve_script().await.unwrap().take_ids() {
        client.sieve_script_destroy(&id).await.unwrap();
    }
    test.destroy_all_mailboxes(account).await;
    admin
        .registry_destroy_all(ObjectType::SieveUserScript)
        .await;
    admin
        .registry_update_setting(SenderAuth::default(), &[Property::SpfFromVerify])
        .await;
    admin.reload_settings().await;
    test.assert_is_empty().await;
}

fn get_script(name: &str) -> Vec<u8> {
    let mut script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    script_path.push("resources");
    script_path.push("jmap");
    script_path.push("sieve");
    script_path.push(format!("{}.sieve", name));
    fs::read(script_path).unwrap()
}
