/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
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
    smtp::session::TestSession,
    utils::{
        account::Account,
        dns::DnsCache,
        server::{TestServer, TestServerBuilder},
        smtp::SmtpConnection,
    },
};
use registry::{
    schema::{
        enums::{MtaProtocol, Permission},
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
        let response = self
            .jmap_request(USING, json!([[method, arguments, "0"]]))
            .await;
        let call = response
            .0
            .pointer("/methodResponses/0")
            .cloned()
            .unwrap_or_else(|| panic!("{method}: {}", response.0));
        (
            call[0].as_str().unwrap_or_default().to_string(),
            call[1].clone(),
        )
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
        .create_user_account(
            "delegate@example.com",
            DELEGATE_SECRET,
            "Delegate",
            &[],
            vec![],
        )
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
    assert_eq!(
        response["notCreated"]["l"]["type"], "forbidden",
        "AL-12: {response}"
    );

    lock_needs_the_accounts_permissions(admin).await;

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
    assert_eq!(
        response["created"]["l"]["id"],
        owner_id.as_str(),
        "AL-1: {response}"
    );

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
        (
            "AddressBook/get",
            json!({"accountId": owner_id, "ids": null}),
        ),
    ] {
        let (name, response) = delegate.call(method, arguments).await;
        assert_eq!(
            name, method,
            "AL-7: {method} refused to the delegate: {response}"
        );
    }

    // AL-6: reading adds nothing, not even at the top of empty Files
    let (_, response) = delegate
        .call(
            "FileNode/set",
            json!({"accountId": owner_id, "create": {"f": {"name": "Notes", "parentId": null}}}),
        )
        .await;
    assert!(
        response["created"].get("f").is_none(),
        "AL-6: a read delegate added a file: {response}"
    );

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
        response["notUpdated"][owner_id.as_str()]["type"],
        "invalidProperties",
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

    // AL-7: organize adds at the top of the locked account's Files, which
    // held none, and sees what it made
    let (_, response) = delegate
        .call(
            "FileNode/set",
            json!({"accountId": owner_id, "create": {"f": {"name": "Handover notes", "parentId": null}}}),
        )
        .await;
    let folder_id = response["created"]["f"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("AL-7: organize couldn't add to empty Files: {response}"))
        .to_string();
    let (_, response) = delegate
        .call(
            "FileNode/get",
            json!({"accountId": owner_id, "ids": [folder_id]}),
        )
        .await;
    assert_eq!(
        response["list"].as_array().map(Vec::len),
        Some(1),
        "AL-7: the delegate can't see the folder it made: {response}"
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
        .call(
            "Mailbox/get",
            json!({"accountId": owner_id, "ids": [folder]}),
        )
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
        destroyed["notDestroyed"][email_id.as_str()]["type"],
        "forbidden",
        "test 12: organize deleted mail: {destroyed}"
    );

    // AL-8: no sending without send-as
    let (name, _) = delegate
        .call("Identity/get", json!({"accountId": owner_id, "ids": null}))
        .await;
    assert_eq!(
        name, "error",
        "AL-8: identities of a locked account without send-as"
    );

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
    let response = admin.lock_set(json!({"destroy": [owner_id]})).await;
    assert_eq!(
        response["notDestroyed"][owner_id.as_str()]["type"],
        "invalidProperties",
        "AU-12: {response}"
    );
    let response = admin
        .lock_set(json!({"reason": "Review done", "destroy": [owner_id]}))
        .await;
    assert_eq!(
        response["destroyed"][0],
        owner_id.as_str(),
        "AL-10: {response}"
    );
    assert_eq!(
        owner.session_status().await,
        200,
        "AL-10: the owner can sign in"
    );
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
        assert!(
            reasons.contains(&reason),
            "AU-12: {reason} missing from {reasons:?}"
        );
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

    shared_mailbox(test, admin, &mut smtp_rx, &mut lmtp).await;
    shared_mailbox_filters(admin, &mut smtp_rx, &mut lmtp).await;
}

/// AL-12: a lock reaches only an account whose every permission the caller
/// holds, as changing that account does. Otherwise a role that may only lock
/// accounts could lock out an administrator and take over its mail.
async fn lock_needs_the_accounts_permissions(admin: &Account) {
    let helpdesk = admin
        .create_user_account(
            "helpdesk@example.com",
            "helpdesk-secret-5530",
            "Helpdesk",
            &[],
            vec![
                Permission::SysAccountLockGet,
                Permission::SysAccountLockCreate,
                Permission::SysAccountLockUpdate,
                Permission::SysAccountLockDestroy,
            ],
        )
        .await;
    let boss = admin
        .create_user_account("boss@example.com", "boss-secret-6124", "Boss", &[], vec![])
        .await;
    admin
        .assign_roles_to_account(boss.id(), &["user", "system"])
        .await;
    let leaver = admin
        .create_user_account(
            "leaver@example.com",
            "leaver-secret-2208",
            "Leaver",
            &[],
            vec![],
        )
        .await;
    let to_self = json!([{"accountId": helpdesk.id_string(), "access": "full", "sendAs": true}]);

    // Locking an administrator, and handing its mail to the caller, is refused
    let response = helpdesk
        .lock_set(json!({"create": {"l": {"accountId": boss.id_string(),
            "reason": "Left", "delegates": to_self}}}))
        .await;
    assert_eq!(
        response["notCreated"]["l"]["type"], "forbidden",
        "AL-12: a lock-only role locked an administrator: {response}"
    );
    assert_eq!(
        boss.session_status().await,
        200,
        "AL-12: the administrator was locked"
    );

    // So are changing and ending an administrator's lock
    let response = admin
        .lock_set(json!({"create": {"l": {"accountId": boss.id_string(), "reason": "Away"}}}))
        .await;
    assert_eq!(
        response["created"]["l"]["id"],
        boss.id_string(),
        "AL-12: {response}"
    );
    let response = helpdesk
        .lock_set(json!({"reason": "Review", "update": {boss.id_string(): {"delegates": to_self}}}))
        .await;
    assert_eq!(
        response["notUpdated"][boss.id_string()]["type"],
        "forbidden",
        "AL-12: a lock-only role took over an administrator's lock: {response}"
    );
    let response = helpdesk
        .lock_set(json!({"reason": "Back", "destroy": [boss.id_string()]}))
        .await;
    assert_eq!(
        response["notDestroyed"][boss.id_string()]["type"],
        "forbidden",
        "AL-12: a lock-only role ended an administrator's lock: {response}"
    );
    let response = admin
        .lock_set(json!({"reason": "Back", "destroy": [boss.id_string()]}))
        .await;
    assert_eq!(
        response["destroyed"][0],
        boss.id_string(),
        "AL-12: {response}"
    );

    // An account with no more than the caller's permissions is still in reach
    let response = helpdesk
        .lock_set(json!({"create": {"l": {"accountId": leaver.id_string(), "reason": "Left"}}}))
        .await;
    assert_eq!(
        response["created"]["l"]["id"],
        leaver.id_string(),
        "AL-12: {response}"
    );
    let response = helpdesk
        .lock_set(json!({"reason": "Rehired", "destroy": [leaver.id_string()]}))
        .await;
    assert_eq!(
        response["destroyed"][0],
        leaver.id_string(),
        "AL-12: {response}"
    );
}

/// MA-S (specs/multi-account.md): a shared mailbox is a lock of its own
/// kind. No reason is needed, more people fit, its Sieve replies go out,
/// only what is sent as it is recorded, and it sends only as itself.
async fn shared_mailbox(
    test: &TestServer,
    admin: &Account,
    smtp_rx: &mut tokio::sync::mpsc::Receiver<crate::jmap::mail::submission::MockMessage>,
    lmtp: &mut SmtpConnection,
) {
    println!("Running shared mailbox tests...");
    let support = admin
        .create_user_account(
            "support@example.com",
            "support-secret-3317",
            "Support",
            &[],
            vec![],
        )
        .await;
    let agent = admin
        .create_user_account(
            "agent@example.com",
            "agent-secret-5520",
            "Agent",
            &[],
            vec![],
        )
        .await;
    let support_id = support.id_string().to_string();

    // An automatic acknowledgement, set up while it could still sign in
    support
        .jmap_client()
        .await
        .vacation_response_enable("Received", "We'll get back to you.".into(), None::<String>)
        .await
        .unwrap();

    // More people than a lock may have
    let mut delegates =
        vec![json!({"accountId": agent.id_string(), "access": "organize", "sendAs": true})];
    for n in 0..11 {
        let name: &'static str = Box::leak(format!("desk{n}@example.com").into_boxed_str());
        let desk = admin
            .create_user_account(name, "desk-secret-7781", "Desk", &[], vec![])
            .await;
        delegates.push(json!({"accountId": desk.id_string(), "access": "read"}));
    }

    // No reason needed
    let response = admin
        .lock_set(
            json!({"create": {"s": {"accountId": support_id, "kind": "sharedMailbox",
            "delegates": delegates}}}),
        )
        .await;
    assert_eq!(
        response["created"]["s"]["id"],
        support_id.as_str(),
        "MA-S1: {response}"
    );
    let (_, got) = admin
        .call(
            "inbuxa:AccountLock/get",
            json!({"accountId": admin.id_string(), "ids": [support_id]}),
        )
        .await;
    assert_eq!(got["list"][0]["kind"], "sharedMailbox", "MA-S1: {got}");

    // Nobody signs in to it
    assert_ne!(
        support.session_status().await,
        200,
        "MA-S1: a shared mailbox signed in"
    );

    // It says what it is to the people in it
    let session = agent.jmap_session_object().await.0;
    let delegation = &session["accounts"][support_id.as_str()]["accountCapabilities"]["urn:inbuxa:jmap"]
        ["delegation"];
    assert_eq!(delegation["kind"], "sharedMailbox", "MA-S: {session}");
    assert_eq!(
        delegation["locked"], true,
        "MA-S: front ends that know no kind still see a lock"
    );

    // Its Sieve replies go out, where a lock's are held back
    lmtp.ingest(
        "carol@remote.org",
        &["support@example.com"],
        // Addressed to it: a vacation reply answers only mail sent to it
        "From: carol@remote.org\r\nTo: support@example.com\r\nSubject: My order\r\n\r\nHello.\r\n",
    )
    .await;
    assert_message_delivery(
        smtp_rx,
        MockMessage::new("<support@example.com>", ["<carol@remote.org>"], "@Received"),
    )
    .await;

    // The agent answers as support@: sent, and recorded as the agent
    let (_, mailboxes) = agent
        .call(
            "Mailbox/get",
            json!({"accountId": support_id, "ids": null, "properties": ["role"]}),
        )
        .await;
    let drafts = mailboxes["list"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["role"] == "drafts")
        .unwrap_or_else(|| panic!("no Drafts: {mailboxes}"))["id"]
        .clone();
    let (_, identities) = agent
        .call(
            "Identity/get",
            json!({"accountId": support_id, "ids": null}),
        )
        .await;
    let identity = identities["list"][0]["id"].clone();
    let send = |reply_to: Option<&str>, subject: &str| {
        let mut email = json!({
            "mailboxIds": {drafts.as_str().unwrap(): true},
            "from": [{"email": "support@example.com"}],
            "to": [{"email": "carol@remote.org"}],
            "subject": subject,
            "bodyValues": {"t": {"value": "Thanks for writing."}},
            "textBody": [{"partId": "t", "type": "text/plain"}]
        });
        if let Some(reply_to) = reply_to {
            email["replyTo"] = json!([{"email": reply_to}]);
        }
        json!([
            ["Email/set", {"accountId": support_id, "create": {"m": email}}, "e"],
            ["EmailSubmission/set", {"accountId": support_id,
                "create": {"s": {"identityId": identity, "emailId": "#m"}}}, "s"]
        ])
    };
    let response = agent
        .jmap_request(USING, send(None, "Re: My order"))
        .await
        .0;
    assert!(
        response.pointer("/methodResponses/1/1/created/s").is_some(),
        "MA-S3: the answer didn't go out: {response}"
    );
    assert_message_delivery(
        smtp_rx,
        MockMessage::new(
            "<support@example.com>",
            ["<carol@remote.org>"],
            "@Re: My order",
        ),
    )
    .await;

    // MA-S3: a reply can't be steered to the agent's own address
    let response = agent
        .jmap_request(
            USING,
            send(Some("agent@example.com"), "Write to me directly"),
        )
        .await
        .0;
    assert_eq!(
        response.pointer("/methodResponses/1/1/notCreated/s/type"),
        Some(&json!("forbiddenFrom")),
        "MA-S3: {response}"
    );
    expect_nothing(smtp_rx).await;

    // MA-D0a: the send names the agent; AL-9's per-change records don't
    // apply in a shared mailbox
    let (_, query) = admin
        .call(
            "inbuxa:AuditEvent/query",
            json!({"accountId": admin.id_string(),
                "filter": {"actorId": agent.id_string(), "accountId": support_id}}),
        )
        .await;
    let (_, records) = admin
        .call(
            "inbuxa:AuditEvent/get",
            json!({"accountId": admin.id_string(), "ids": query["ids"]}),
        )
        .await;
    let kinds = records["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["target"]["kind"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert_eq!(kinds, ["EmailSubmission"], "MA-D0a: {records}");

    // Over SMTP submission too: the agent signs in as itself and sends as
    // support@, a desk without sendAs can't, and the send is recorded
    let smtp_session = || {
        let mut session = test.new_mta_session();
        session.stream.tls = true;
        session
    };
    let mut session = smtp_session();
    session.eval_session_params().await;
    session.ehlo("agent.example.com").await;
    session
        .auth_plain("agent@example.com", "agent-secret-5520", "235 2.7.0")
        .await;
    session
        .send_message(
            "support@example.com",
            &["carol@remote.org"],
            "From: support@example.com\r\nTo: carol@remote.org\r\nSubject: Re: Over SMTP\r\n\r\nThanks.\r\n",
            "250",
        )
        .await;
    assert_message_delivery(
        smtp_rx,
        MockMessage::new(
            "<support@example.com>",
            ["<carol@remote.org>"],
            "@Re: Over SMTP",
        ),
    )
    .await;
    // MA-S3: and the reply still can't be steered to the agent
    session
        .send_message(
            "support@example.com",
            &["carol@remote.org"],
            "From: support@example.com\r\nReply-To: agent@example.com\r\nTo: carol@remote.org\r\nSubject: Write to me\r\n\r\nHi.\r\n",
            "550 5.7.1",
        )
        .await;
    expect_nothing(smtp_rx).await;
    let mut session = smtp_session();
    session.eval_session_params().await;
    session.ehlo("desk.example.com").await;
    session
        .auth_plain("desk0@example.com", "desk-secret-7781", "235 2.7.0")
        .await;
    session.mail_from("support@example.com", "501 5.5.4").await;
    session.mail_from("desk0@example.com", "250").await;
    let (_, query) = admin
        .call(
            "inbuxa:AuditEvent/query",
            json!({"accountId": admin.id_string(),
                "filter": {"actorId": agent.id_string(), "accountId": support_id}}),
        )
        .await;
    let (_, records) = admin
        .call(
            "inbuxa:AuditEvent/get",
            json!({"accountId": admin.id_string(), "ids": query["ids"]}),
        )
        .await;
    let mut kinds = records["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["target"]["kind"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    kinds.sort();
    assert_eq!(
        kinds,
        ["EmailSubmission", "QueuedMessage"],
        "MA-D0a over SMTP: {records}"
    );

    // Ending it needs no reason either
    let response = admin.lock_set(json!({"destroy": [support_id]})).await;
    assert_eq!(
        response["destroyed"][0],
        support_id.as_str(),
        "MA-S: {response}"
    );
}

/// #643 (MA-S): a shared mailbox's full members manage its filters, which
/// may only sort unless an administrator saves them; read and organize
/// members can't, the session says so, and every change is recorded.
async fn shared_mailbox_filters(
    admin: &Account,
    smtp_rx: &mut tokio::sync::mpsc::Receiver<crate::jmap::mail::submission::MockMessage>,
    lmtp: &mut SmtpConnection,
) {
    println!("Running shared mailbox filter tests...");
    let helpdesk = admin
        .create_user_account(
            "frontdesk@example.com",
            "frontdesk-secret-6613",
            "Help desk",
            &[],
            vec![],
        )
        .await;
    let mut members = Vec::new();
    for (name, access) in [
        ("filer@example.com", "full"),
        ("sorter@example.com", "organize"),
        ("reader@example.com", "read"),
    ] {
        let member = admin
            .create_user_account(name, "member-secret-2290", "Member", &[], vec![])
            .await;
        members.push((member, access));
    }
    let helpdesk_id = helpdesk.id_string().to_string();
    // A folder to sort into, made while it could still sign in
    let billing_id = helpdesk
        .jmap_client()
        .await
        .mailbox_create("Billing", None::<String>, jmap_client::mailbox::Role::None)
        .await
        .unwrap()
        .take_id();
    let response = admin
        .lock_set(
            json!({"create": {"h": {"accountId": helpdesk_id, "kind": "sharedMailbox",
            "delegates": members.iter().map(|(member, access)|
                json!({"accountId": member.id_string(), "access": access})).collect::<Vec<_>>()}}}),
        )
        .await;
    assert_eq!(
        response["created"]["h"]["id"],
        helpdesk_id.as_str(),
        "#643: {response}"
    );
    let (filer, _) = &members[0];

    // Session honesty: filters are offered to the full member only
    for (member, access) in &members {
        let session = member.jmap_session_object().await.0;
        let offered = session["accounts"][helpdesk_id.as_str()]["accountCapabilities"]
            .get(SIEVE)
            .is_some();
        assert_eq!(
            offered,
            *access == "full",
            "#643: {access} member's session: {session}"
        );
    }

    // Read and organize members get Forbidden, as before
    for (member, access) in &members[1..] {
        for (method, arguments) in [
            (
                "SieveScript/get",
                json!({"accountId": helpdesk_id, "ids": null}),
            ),
            ("SieveScript/query", json!({"accountId": helpdesk_id})),
            (
                "SieveScript/set",
                json!({"accountId": helpdesk_id, "destroy": ["a"]}),
            ),
        ] {
            let response = sieve_call(member, method, arguments).await;
            assert_eq!(
                (response[0].as_str(), response[1]["type"].as_str()),
                (Some("error"), Some("forbidden")),
                "#643: {access} member, {method}: {response}"
            );
        }
        let response = member
            .http_post_raw(
                &format!("{}/jmap/upload/{}/", member.base_url(), helpdesk_id),
                "application/sieve",
                b"keep;".to_vec(),
            )
            .await;
        assert_ne!(response.status, 200, "#643: {access} member uploaded");
    }

    // The full member saves and activates a sorting script
    let sorting = "require [\"fileinto\", \"imap4flags\"];\r\n\
        if header :contains \"subject\" \"Invoice\" {\r\n  \
        fileinto :flags \"\\\\Flagged\" \"Billing\";\r\n  stop;\r\n}\r\n";
    let blob_id = sieve_upload(filer, &helpdesk_id, sorting).await;
    let response = sieve_call(
        filer,
        "SieveScript/validate",
        json!({"accountId": helpdesk_id, "blobId": blob_id}),
    )
    .await;
    assert_eq!(response[0], "SieveScript/validate", "#643: {response}");
    assert!(response[1]["error"].is_null(), "#643: {response}");
    let response = sieve_call(
        filer,
        "SieveScript/set",
        json!({"accountId": helpdesk_id,
            "create": {"s": {"name": "Sort", "blobId": blob_id}},
            "onSuccessActivateScript": "#s"}),
    )
    .await;
    assert_eq!(
        response[1]["created"]["s"]["isActive"], true,
        "#643: the full member's sorting script: {response}"
    );
    let sort_id = response[1]["created"]["s"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let sort_blob = response[1]["created"]["s"]["blobId"]
        .as_str()
        .unwrap()
        .to_string();

    // It reads the script back, and its text
    let response = sieve_call(
        filer,
        "SieveScript/get",
        json!({"accountId": helpdesk_id, "ids": null}),
    )
    .await;
    assert_eq!(
        response[1]["list"][0]["id"],
        sort_id.as_str(),
        "#643: {response}"
    );
    let download = filer
        .http_get_raw(
            &format!(
                "{}/jmap/download/{}/{}/sort.sieve",
                filer.base_url(),
                helpdesk_id,
                sort_blob
            ),
            None,
        )
        .await;
    assert_eq!(
        download.body,
        sorting.as_bytes(),
        "#643: download {}",
        download.status
    );

    // Mail to the shared address is sorted by it
    lmtp.ingest(
        "carol@remote.org",
        &["frontdesk@example.com"],
        "From: carol@remote.org\r\nTo: frontdesk@example.com\r\nSubject: Invoice 3141\r\n\r\nPlease pay.\r\n",
    )
    .await;
    let response = sieve_call(
        filer,
        "Email/query",
        json!({"accountId": helpdesk_id, "filter": {"inMailbox": billing_id}}),
    )
    .await;
    assert_eq!(
        response[1]["ids"].as_array().map(Vec::len),
        Some(1),
        "#643: the invoice wasn't filed: {response}"
    );

    // Sort only: forwarding and automatic replies are refused, whatever
    // the require line says, and the active script stays as it was
    for script in [
        "redirect \"elsewhere@remote.org\";",
        "require \"copy\";\r\nredirect :copy \"elsewhere@remote.org\";",
        "require \"vacation\";\r\nvacation \"We're closed.\";",
        "require \"enotify\";\r\nnotify \"mailto:elsewhere@remote.org\";",
        "require \"reject\";\r\nreject \"Not here.\";",
        "require [\"fileinto\", \"ereject\"];\r\nif false { ereject \"No.\"; }\r\nfileinto \"Billing\";",
    ] {
        let blob_id = sieve_upload(filer, &helpdesk_id, script).await;
        let response = sieve_call(
            filer,
            "SieveScript/set",
            json!({"accountId": helpdesk_id,
                "create": {"f": {"name": "Forward", "blobId": blob_id}},
                "update": {sort_id.as_str(): {"blobId": blob_id}},
                "onSuccessActivateScript": "#f"}),
        )
        .await;
        for error in [
            &response[1]["notCreated"]["f"],
            &response[1]["notUpdated"][sort_id.as_str()],
        ] {
            assert_eq!(error["type"], "forbidden", "#643: {script}: {response}");
            assert_eq!(
                error["description"],
                "Forwarding and automatic replies on a shared mailbox can only be saved by an administrator.",
                "#643: {script}: {response}"
            );
        }
    }
    let response = sieve_call(
        filer,
        "SieveScript/get",
        json!({"accountId": helpdesk_id, "ids": null}),
    )
    .await;
    let list = response[1]["list"].as_array().unwrap();
    assert_eq!(list.len(), 1, "#643: {response}");
    assert_eq!(list[0]["isActive"], true, "#643: {response}");
    assert_eq!(list[0]["blobId"], sort_blob.as_str(), "#643: {response}");
    expect_nothing(smtp_rx).await;

    // An administrator adds a forward to the active script. Its member may
    // then edit the other rules and remove the forward, but not change it
    let require = "require [\"fileinto\", \"imap4flags\", \"copy\"];\r\n";
    let invoices = "if header :contains \"subject\" \"Invoice\" {\r\n  \
        fileinto :flags \"\\\\Flagged\" \"Billing\";\r\n  stop;\r\n}\r\n";
    let receipts = "if header :contains \"subject\" \"Receipt\" { fileinto \"Billing\"; }\r\n";
    let forward = |to: &str| format!("redirect :copy \"{to}\";\r\n");
    let response = sieve_save(
        admin,
        &helpdesk_id,
        &sort_id,
        format!("{require}{}{invoices}", forward("old-desk@remote.org")),
    )
    .await;
    assert!(
        response[1]["updated"].get(sort_id.as_str()).is_some(),
        "#643: the administrator's forward: {response}"
    );
    let response = sieve_save(
        filer,
        &helpdesk_id,
        &sort_id,
        format!(
            "{require}{}{receipts}{invoices}",
            forward("old-desk@remote.org")
        ),
    )
    .await;
    let kept_blob = response[1]["updated"][sort_id.as_str()]["blobId"]
        .as_str()
        .unwrap_or_else(|| panic!("#643: another rule, the forward kept: {response}"))
        .to_string();
    let response = sieve_save(
        filer,
        &helpdesk_id,
        &sort_id,
        format!(
            "{require}{}{receipts}{invoices}",
            forward("new-desk@remote.org")
        ),
    )
    .await;
    assert_eq!(
        response[1]["notUpdated"][sort_id.as_str()]["description"],
        "Forwarding and automatic replies on a shared mailbox can only be saved by an administrator.",
        "#643: the forward's address changed: {response}"
    );
    let response = sieve_call(
        filer,
        "SieveScript/get",
        json!({"accountId": helpdesk_id, "ids": [sort_id]}),
    )
    .await;
    assert_eq!(
        response[1]["list"][0]["blobId"],
        kept_blob.as_str(),
        "#643: {response}"
    );
    let response = sieve_save(
        filer,
        &helpdesk_id,
        &sort_id,
        format!("{require}{receipts}{invoices}"),
    )
    .await;
    assert!(
        response[1]["updated"].get(sort_id.as_str()).is_some(),
        "#643: the forward removed: {response}"
    );

    // A member doesn't turn on a script that forwards; an administrator
    // does, and the member may turn it off and delete it
    let blob_id = sieve_upload(admin, &helpdesk_id, "redirect \"elsewhere@remote.org\";").await;
    let response = sieve_call(
        admin,
        "SieveScript/set",
        json!({"accountId": helpdesk_id,
            "create": {"a": {"name": "Forward to the old desk", "blobId": blob_id}}}),
    )
    .await;
    let forward_id = response[1]["created"]["a"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("#643: the administrator's script: {response}"))
        .to_string();
    for arguments in [
        json!({"accountId": helpdesk_id, "onSuccessActivateScript": forward_id}),
        json!({"accountId": helpdesk_id, "update": {forward_id.as_str(): {"isActive": true}}}),
    ] {
        let response = sieve_call(filer, "SieveScript/set", arguments).await;
        let error = &response[1]["notUpdated"][forward_id.as_str()];
        assert_eq!(error["type"], "forbidden", "#643: {response}");
        assert_eq!(
            error["description"],
            "Filters that forward or answer mail on a shared mailbox can only be turned on by an administrator.",
            "#643: {response}"
        );
    }
    let response = sieve_call(
        filer,
        "SieveScript/get",
        json!({"accountId": helpdesk_id, "ids": [sort_id, forward_id]}),
    )
    .await;
    assert_eq!(
        response[1]["list"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| (s["id"].as_str().unwrap().to_string(), s["isActive"] == true))
            .collect::<Vec<_>>(),
        [(sort_id.clone(), true), (forward_id.clone(), false)],
        "#643: {response}"
    );
    let response = sieve_call(
        admin,
        "SieveScript/set",
        json!({"accountId": helpdesk_id, "onSuccessActivateScript": forward_id}),
    )
    .await;
    assert_eq!(
        response[1]["updated"][forward_id.as_str()]["isActive"],
        true,
        "#643: {response}"
    );
    let response = sieve_call(
        filer,
        "SieveScript/set",
        json!({"accountId": helpdesk_id, "onSuccessDeactivateScript": true}),
    )
    .await;
    assert_eq!(
        response[1]["updated"][forward_id.as_str()]["isActive"],
        false,
        "#643: {response}"
    );
    let response = sieve_call(
        filer,
        "SieveScript/set",
        json!({"accountId": helpdesk_id, "destroy": [forward_id]}),
    )
    .await;
    assert_eq!(
        response[1]["destroyed"][0],
        forward_id.as_str(),
        "#643: {response}"
    );

    // Every change is in the audit log, with who made it and where
    let records = sieve_records(admin, filer, &helpdesk_id).await;
    let seen = |action: &str, details: Option<&str>, status: &str| {
        records.iter().any(|r| {
            r["action"] == action
                && details.is_none_or(|d| r["details"] == d)
                && r["outcome"]["status"] == status
                && r["target"]["accountId"] == helpdesk_id.as_str()
                && r["actor"]["accountId"] == filer.id_string()
        })
    };
    for (action, details, status) in [
        ("create", None, "success"),
        ("update", Some("Activated"), "success"),
        ("update", Some("Deactivated"), "success"),
        ("destroy", None, "success"),
        // The refused forwarding scripts and the activations asked for
        ("create", None, "refused"),
        ("update", None, "refused"),
        ("update", Some("Activated"), "refused"),
    ] {
        assert!(
            seen(action, details, status),
            "#643: no {action} {details:?} {status} record: {records:?}"
        );
    }
    assert!(
        sieve_records(admin, admin, &helpdesk_id)
            .await
            .iter()
            .any(|r| r["action"] == "create" && r["outcome"]["status"] == "success"),
        "#643: the administrator's script wasn't recorded"
    );

    let response = admin.lock_set(json!({"destroy": [helpdesk_id]})).await;
    assert_eq!(
        response["destroyed"][0],
        helpdesk_id.as_str(),
        "#643: {response}"
    );
}

const SIEVE: &str = "urn:ietf:params:jmap:sieve";

async fn sieve_call(account: &Account, method: &str, arguments: Value) -> Value {
    let using = [USING, &[SIEVE]].concat();
    let response = account
        .jmap_request(&using, json!([[method, arguments, "0"]]))
        .await
        .0;
    response
        .pointer("/methodResponses/0")
        .cloned()
        .unwrap_or_else(|| panic!("{method}: {response}"))
}

/// Replaces a script's text.
async fn sieve_save(account: &Account, account_id: &str, script_id: &str, script: String) -> Value {
    let blob_id = sieve_upload(account, account_id, &script).await;
    sieve_call(
        account,
        "SieveScript/set",
        json!({"accountId": account_id, "update": {script_id: {"blobId": blob_id}}}),
    )
    .await
}

async fn sieve_upload(account: &Account, account_id: &str, script: &str) -> String {
    let response = account
        .http_post_raw(
            &format!("{}/jmap/upload/{account_id}/", account.base_url()),
            "application/sieve",
            script.as_bytes().to_vec(),
        )
        .await;
    assert_eq!(
        response.status,
        200,
        "#643: upload: {}",
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice::<Value>(&response.body).unwrap()["blobId"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The audit records of `actor`'s changes to `account_id`'s scripts.
async fn sieve_records(admin: &Account, actor: &Account, account_id: &str) -> Vec<Value> {
    let (_, query) = admin
        .call(
            "inbuxa:AuditEvent/query",
            json!({"accountId": admin.id_string(), "filter": {"actorId": actor.id_string(),
                "accountId": account_id, "targetKind": "SieveScript"}}),
        )
        .await;
    let (_, records) = admin
        .call(
            "inbuxa:AuditEvent/get",
            json!({"accountId": admin.id_string(), "ids": query["ids"]}),
        )
        .await;
    records["list"].as_array().cloned().unwrap_or_default()
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
