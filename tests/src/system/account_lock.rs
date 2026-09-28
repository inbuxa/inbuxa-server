/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Account lock with delegation acceptance tests, from
//! `inbuxa-drafts/specs/audit-hold-lock.md` (AL-1 to AL-12; tests 10 to 15
//! of its list). Each check names the requirement or test number.

use crate::{
    jmap::mail::submission::{
        MockMessage, assert_message_delivery, expect_nothing, spawn_mock_smtp_server,
    },
    utils::{
        account::Account,
        dns::DnsCache,
        server::{TestServer, TestServerBuilder},
        smtp::SmtpConnection,
    },
};
use registry::{
    schema::{
        enums::MtaProtocol,
        structs::{
            Expression, ExpressionMatch, Imap, MtaOutboundStrategy, MtaRoute, MtaRouteRelay,
            MtaStageAuth,
        },
    },
    types::list::List,
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:mail",
    "urn:ietf:params:jmap:submission",
    "urn:ietf:params:jmap:calendars",
    "urn:ietf:params:jmap:contacts",
    "urn:ietf:params:jmap:filenode",
    "urn:inbuxa:jmap",
];

const OWNER_SECRET: &str = "owner-secret-4471";
const DELEGATE_SECRET: &str = "delegate-secret-9902";

impl Account {
    async fn call(&self, method: &str, arguments: Value) -> (String, Value) {
        let response = self.jmap_request(USING, json!([[method, arguments, "0"]])).await;
        let call = response
            .0
            .pointer("/methodResponses/0")
            .cloned()
            .unwrap_or_else(|| panic!("{method}: {}", response.0));
        (call[0].as_str().unwrap_or_default().to_string(), call[1].clone())
    }

    async fn lock_set(&self, arguments: Value) -> Value {
        let mut arguments = arguments;
        arguments["accountId"] = self.id_string().into();
        let (name, response) = self.call("inbuxa:AccountLock/set", arguments).await;
        assert_eq!(name, "inbuxa:AccountLock/set", "{response}");
        response
    }

    async fn session_status(&self) -> u16 {
        self.http_get_raw(&format!("{}/jmap/session", self.base_url()), None)
            .await
            .status
    }
}

fn message(from: &str, subject: &str) -> String {
    format!("From: {from}\r\nTo: owner@example.com\r\nSubject: {subject}\r\n\r\nHello.\r\n")
}

pub async fn test(test: &mut TestServer) {
    println!("Running account lock tests...");
    let admin = test.account("admin@example.com");
    let owner = admin
        .create_user_account("owner@example.com", OWNER_SECRET, "Owner", &[], vec![])
        .await;
    let delegate = admin
        .create_user_account("delegate@example.com", DELEGATE_SECRET, "Delegate", &[], vec![])
        .await;
    let owner_id = owner.id_string().to_string();

    // Mail leaving the server goes to the mock
    let (mut smtp_rx, _smtp_settings) = spawn_mock_smtp_server();
    test.server.ipv4_add(
        "localhost",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(60),
    );

    // The owner set a vacation reply before leaving
    owner
        .jmap_client()
        .await
        .vacation_response_enable("Away", "I'm away.".into(), None::<String>)
        .await
        .unwrap();
    // Control: before the lock, the vacation reply goes out, so its absence
    // later means the lock stopped it
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "dave@remote.org",
        &["owner@example.com"],
        &message("dave@remote.org", "Before the lock"),
    )
    .await;
    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new("<owner@example.com>", ["<dave@remote.org>"], "@Away"),
    )
    .await;

    let right_password = owner.session_status().await;
    assert_eq!(right_password, 200, "the owner can sign in before the lock");
    let wrong = Account::new("owner@example.com", "wrong-password", &[], "", owner.id());
    let wrong_password = wrong.session_status().await;

    // AU-12: no lock without a reason
    let response = admin
        .lock_set(json!({"create": {"l": {"accountId": owner_id,
            "delegates": [{"accountId": delegate.id_string(), "access": "read"}]}}}))
        .await;
    assert_eq!(
        response["notCreated"]["l"]["type"], "invalidProperties",
        "AU-12: {response}"
    );

    // AL-12: nobody locks themselves
    let response = admin
        .lock_set(json!({"create": {"l": {"accountId": admin.id_string(), "reason": "test"}}}))
        .await;
    assert_eq!(response["notCreated"]["l"]["type"], "forbidden", "AL-12: {response}");

    // AL-8: send-as needs more than read
    let response = admin
        .lock_set(json!({"create": {"l": {"accountId": owner_id, "reason": "Left",
            "delegates": [{"accountId": delegate.id_string(), "access": "read", "sendAs": true}]}}}))
        .await;
    assert_eq!(
        response["notCreated"]["l"]["type"], "invalidProperties",
        "AL-8: {response}"
    );

    // Lock, with a read-only delegate (AL-1)
    let response = admin
        .lock_set(json!({"create": {"l": {"accountId": owner_id,
            "reason": "Left the company; mail to be reviewed",
            "delegates": [{"accountId": delegate.id_string(), "access": "read"}]}}}))
        .await;
    assert_eq!(response["created"]["l"]["id"], owner_id.as_str(), "AL-1: {response}");

    // AL-2: the right password fails as a wrong one does
    let right_password = owner.session_status().await;
    assert_ne!(right_password, 200, "AL-2: a locked account signed in");
    assert_eq!(
        right_password, wrong_password,
        "AL-2: the right password is told apart from a wrong one"
    );

    // Test 11, AL-4: mail keeps arriving, and nothing is sent: no vacation
    lmtp.ingest(
        "bill@remote.org",
        &["owner@example.com"],
        &message("bill@remote.org", "Quarterly report"),
    )
    .await;
    expect_nothing(&mut smtp_rx).await;

    // AL-7: the delegate sees the account, read-only, marked as delegated
    let session = delegate.jmap_session_object().await.0;
    let entry = &session["accounts"][owner_id.as_str()];
    assert_eq!(entry["isPersonal"], false, "AL-7: {session}");
    assert_eq!(entry["isReadOnly"], true, "AL-6: {entry}");
    let delegation = &entry["accountCapabilities"]["urn:inbuxa:jmap"]["delegation"];
    assert_eq!(delegation["locked"], true, "AL-7: {entry}");
    assert_eq!(delegation["access"], "read", "AL-7");
    assert_eq!(delegation["sendAs"], false, "AL-7");

    // AL-7: the whole account, not only mail: even a kind the owner holds
    // none of (no files here) reads as empty rather than refused
    for (method, arguments) in [
        ("FileNode/query", json!({"accountId": owner_id})),
        ("Calendar/get", json!({"accountId": owner_id, "ids": null})),
        ("AddressBook/get", json!({"accountId": owner_id, "ids": null})),
    ] {
        let (name, response) = delegate.call(method, arguments).await;
        assert_eq!(name, method, "AL-7: {method} refused to the delegate: {response}");
    }

    // The delegate reads the mail that arrived
    let (_, found) = delegate
        .call(
            "Email/query",
            json!({"accountId": owner_id, "filter": {"text": "Quarterly"}}),
        )
        .await;
    let email_id = found["ids"][0]
        .as_str()
        .unwrap_or_else(|| panic!("AL-4: the mail didn't arrive: {found}"))
        .to_string();

    // Test 12, AL-6: read means nothing changes, not even $seen
    let (_, response) = delegate
        .call(
            "Email/set",
            json!({"accountId": owner_id, "update": {email_id.as_str(): {"keywords/$seen": true}}}),
        )
        .await;
    assert!(
        response["notUpdated"][email_id.as_str()].is_object(),
        "test 12: a read delegate changed a keyword: {response}"
    );

    // AU-12: changing delegates needs a reason
    let response = admin
        .lock_set(json!({"update": {owner_id.as_str(): {"delegates": [
            {"accountId": delegate.id_string(), "access": "organize"}]}}}))
        .await;
    assert_eq!(
        response["notUpdated"][owner_id.as_str()]["type"], "invalidProperties",
        "AU-12: {response}"
    );
    let response = admin
        .lock_set(json!({"reason": "Manager files the mail",
            "update": {owner_id.as_str(): {"delegates": [
            {"accountId": delegate.id_string(), "access": "organize"}]}}}))
        .await;
    assert!(
        response["updated"].get(owner_id.as_str()).is_some(),
        "AL-5: {response}"
    );

    // Test 12, AL-6, AL-7: organize makes folders it can see, moves mail,
    // never deletes it
    let (_, mailboxes) = delegate
        .call("Mailbox/get", json!({"accountId": owner_id, "ids": null}))
        .await;
    let inbox = mailboxes["list"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["role"] == "inbox")
        .unwrap_or_else(|| panic!("AL-7: no inbox seen: {mailboxes}"))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, created) = delegate
        .call(
            "Mailbox/set",
            json!({"accountId": owner_id, "create": {"f": {"name": "Reviewed", "parentId": inbox}}}),
        )
        .await;
    let folder = created["created"]["f"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("AL-6: organize couldn't make a folder: {created}"))
        .to_string();
    let (_, mailboxes) = delegate
        .call("Mailbox/get", json!({"accountId": owner_id, "ids": [folder]}))
        .await;
    assert_eq!(
        mailboxes["list"].as_array().map(Vec::len),
        Some(1),
        "AL-7: the delegate can't see the folder it made: {mailboxes}"
    );
    let (_, moved) = delegate
        .call(
            "Email/set",
            json!({"accountId": owner_id, "update": {email_id.as_str(): {
                "mailboxIds": {folder.as_str(): true}}}}),
        )
        .await;
    assert!(
        moved["updated"].get(email_id.as_str()).is_some(),
        "test 12: organize couldn't move mail: {moved}"
    );
    let (_, destroyed) = delegate
        .call(
            "Email/set",
            json!({"accountId": owner_id, "destroy": [email_id]}),
        )
        .await;
    assert_eq!(
        destroyed["notDestroyed"][email_id.as_str()]["type"], "forbidden",
        "test 12: organize deleted mail: {destroyed}"
    );

    // AL-8: no sending without send-as
    let (name, _) = delegate
        .call("Identity/get", json!({"accountId": owner_id, "ids": null}))
        .await;
    assert_eq!(name, "error", "AL-8: identities of a locked account without send-as");

    // Test 11, AL-4: a Sieve reject is kept instead, and nobody is answered
    admin
        .jmap_client()
        .await
        .set_default_account_id(owner_id.clone())
        .sieve_script_create(
            "rejector",
            "require \"reject\";\r\nreject \"Not here.\";\r\n",
            true,
        )
        .await
        .unwrap();
    lmtp.ingest(
        "carol@remote.org",
        &["owner@example.com"],
        &message("carol@remote.org", "Invoice 77"),
    )
    .await;
    expect_nothing(&mut smtp_rx).await;
    let (_, kept) = delegate
        .call(
            "Email/query",
            json!({"accountId": owner_id, "filter": {"text": "Invoice"}}),
        )
        .await;
    assert_eq!(
        kept["ids"].as_array().map(Vec::len),
        Some(1),
        "AL-4: the rejected message wasn't kept: {kept}"
    );

    // AL-5: a delegation ends at its `until`, not at the next daily sweep
    let soon = store::write::now() + 3;
    let response = admin
        .lock_set(json!({"reason": "Handover ends shortly",
            "update": {owner_id.as_str(): {"delegates": [
            {"accountId": delegate.id_string(), "access": "organize",
             "until": chrono::DateTime::from_timestamp(soon as i64, 0).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)}]}}}))
        .await;
    assert!(
        response["updated"].get(owner_id.as_str()).is_some(),
        "AL-5: {response}"
    );
    let (_, before) = delegate
        .call("Mailbox/get", json!({"accountId": owner_id, "ids": null}))
        .await;
    assert!(
        before["list"].as_array().is_some_and(|l| !l.is_empty()),
        "AL-5: the delegate lost the account before its end: {before}"
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    let session = delegate.jmap_session_object().await.0;
    assert!(
        session["accounts"].get(owner_id.as_str()).is_none(),
        "AL-5: the delegation outlived its end in the session: {session}"
    );
    let (_, after) = delegate
        .call("Mailbox/get", json!({"accountId": owner_id, "ids": null}))
        .await;
    assert!(
        after["list"].as_array().is_none_or(|l| l.is_empty()),
        "AL-5: the delegate still reaches the folders after its end: {after}"
    );

    // AL-10: unlocking needs a reason, then restores everything
    let response = admin
        .lock_set(json!({"destroy": [owner_id]}))
        .await;
    assert_eq!(
        response["notDestroyed"][owner_id.as_str()]["type"], "invalidProperties",
        "AU-12: {response}"
    );
    let response = admin
        .lock_set(json!({"reason": "Review done", "destroy": [owner_id]}))
        .await;
    assert_eq!(response["destroyed"][0], owner_id.as_str(), "AL-10: {response}");
    assert_eq!(owner.session_status().await, 200, "AL-10: the owner can sign in");
    let session = delegate.jmap_session_object().await.0;
    assert!(
        session["accounts"].get(owner_id.as_str()).is_none(),
        "test 15: the delegate kept the account: {session}"
    );

    // AL-9, AU-12: every step is recorded, with its reason
    let (_, query) = admin
        .call(
            "inbuxa:AuditEvent/query",
            json!({"accountId": admin.id_string(), "filter": {"targetKind": "inbuxa:AccountLock"}}),
        )
        .await;
    let (_, records) = admin
        .call(
            "inbuxa:AuditEvent/get",
            json!({"accountId": admin.id_string(), "ids": query["ids"]}),
        )
        .await;
    let reasons = records["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["outcome"]["status"] == "success")
        .filter_map(|r| r["reason"].as_str())
        .collect::<Vec<_>>();
    for reason in [
        "Left the company; mail to be reviewed",
        "Manager files the mail",
        "Review done",
    ] {
        assert!(reasons.contains(&reason), "AU-12: {reason} missing from {reasons:?}");
    }
    let (_, query) = admin
        .call(
            "inbuxa:AuditEvent/query",
            json!({"accountId": admin.id_string(),
                "filter": {"actorId": delegate.id_string(), "accountId": owner_id}}),
        )
        .await;
    assert!(
        query["ids"].as_array().is_some_and(|ids| ids.len() >= 2),
        "AL-9: the delegate's access and changes weren't recorded: {query}"
    );
}

/// Runs these tests alone: `cargo test -p tests account_lock_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn account_lock_tests() {
    let mut test = TestServerBuilder::new("account_lock_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.com").await;
    admin
        .registry_create_object(Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaOutboundStrategy {
            route: Expression {
                match_: List::from_iter([
                    ExpressionMatch {
                        if_: "rcpt_domain == 'example.com'".into(),
                        then: "'local'".into(),
                    },
                    ExpressionMatch {
                        if_: "rcpt_domain == 'remote.org'".into(),
                        then: "'mock-smtp'".into(),
                    },
                ]),
                else_: "'mx'".to_string(),
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaRoute::Relay(MtaRouteRelay {
            address: "127.0.0.1".into(),
            port: 9999,
            allow_invalid_certs: true,
            implicit_tls: false,
            name: "mock-smtp".into(),
            protocol: MtaProtocol::Smtp,
            ..Default::default()
        }))
        .await;
    admin.reload_settings().await;
    test.insert_account(admin);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
