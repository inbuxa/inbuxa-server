/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Undelete acceptance tests, from `docs/spec/features/undelete.md`. Each
//! check names the test number or the requirement it covers.

use crate::utils::{
    account::Account,
    webdav::DummyWebDavClient,
    imap::{ImapConnection, Type},
    jmap::{JmapResponse, JmapUtils},
    pop3::{self, Pop3Connection},
    server::{TestServer, TestServerBuilder},
    smtp::SmtpConnection,
};
use email::{
    mailbox::{INBOX_ID, TRASH_ID},
    message::delete::EmailDeletion,
};
use imap_proto::ResponseType;
use jmap_client::client::{Client, Credentials};
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{DataRetention, Expression, Imap, Jmap, MtaStageAuth, MtaStageRcpt, Task},
    },
    types::duration::Duration,
};
use hyper::StatusCode;
use serde_json::{Value, json};
use store::{
    Deserialize, IterateParams, ValueKey,
    query::acl::AclQuery,
    write::{TaskQueueClass, ValueClass},
};
use types::id::Id;

const SECRET: &str = "undelete test user passphrase";
const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:lunch-1\r\nDTSTAMP:20260918T100000Z\r\nDTSTART:20260918T120000Z\r\nDTEND:20260918T130000Z\r\nSUMMARY:Lunch\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
const CARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:jane-1\r\nFN:Jane Doe\r\nEND:VCARD\r\n";
const DAY: u64 = 86_400;

pub async fn test(test: &mut TestServer) {
    println!("Running undelete tests...");
    let admin = test.account("admin@example.org");
    // Inside system_tests the quota suite leaves a 1-second upload lifetime,
    // which a script upload can outlive before its set
    admin
        .registry_update_setting(
            Jmap::default(),
            &[
                Property::UploadQuota,
                Property::MaxUploadCount,
                Property::UploadTtl,
            ],
        )
        .await;
    admin.reload_settings().await;
    let user = admin
        .create_user_account("undelete@example.org", SECRET, "Undelete", &[], vec![])
        .await;
    let client = user.jmap_client().await;

    // Acceptance test 1: archiving off keeps nothing
    admin.set_retention(None).await;
    let id = import(&client, "Off", &[INBOX_ID], &[]).await;
    client.email_destroy(&id).await.unwrap();
    test.wait_for_tasks().await;
    assert!(user.archived().await.is_empty(), "test 1");

    // Acceptance test 2: each way of deleting keeps one copy, 30 days out.
    // No settings reload: the change applies at once (UD-6a).
    admin.set_retention(Some(30 * DAY)).await;

    // JMAP
    let id = import(&client, "Via JMAP", &[INBOX_ID], &[]).await;
    client.email_destroy(&id).await.unwrap();
    // IMAP expunge
    import(&client, "Via IMAP", &[INBOX_ID], &[]).await;
    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    imap.authenticate("undelete@example.org", SECRET).await;
    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("SEARCH SUBJECT \"Via IMAP\"").await;
    let found = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let seq = found
        .iter()
        .find_map(|line| line.strip_prefix("* SEARCH "))
        .map(|s| s.trim().to_string())
        .expect("IMAP message");
    imap.send(&format!("STORE {seq} +FLAGS (\\Deleted)")).await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("EXPUNGE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    // POP3 delete: the newest message is the last in the maildrop
    import(&client, "Via POP3", &[INBOX_ID], &[]).await;
    let mut pop = Pop3Connection::connect().await;
    pop.authenticate("undelete@example.org", SECRET).await;
    pop.send("STAT").await;
    let message = pop.assert_read(pop3::ResponseType::Ok).await[0]
        .split_whitespace()
        .nth(1)
        .expect("POP3 count")
        .to_string();
    pop.send(&format!("DELE {message}")).await;
    pop.assert_read(pop3::ResponseType::Ok).await;
    pop.send("QUIT").await;
    pop.assert_read(pop3::ResponseType::Ok).await;
    // Automatic Trash emptying
    import(&client, "Via Trash emptying", &[TRASH_ID], &[]).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    test.server
        .emails_auto_expunge(user.id().document_id(), 0)
        .await
        .unwrap();
    test.wait_for_tasks().await;

    let archived = user.archived().await;
    for subject in ["Via JMAP", "Via IMAP", "Via POP3", "Via Trash emptying"] {
        let item = archived
            .iter()
            .find(|item| item["subject"] == subject)
            .unwrap_or_else(|| panic!("test 2: {subject} not archived: {archived:?}"));
        let span = seconds(&item["archivedUntil"]) - seconds(&item["archivedAt"]);
        assert!(
            (30 * DAY as i64 - 60..=30 * DAY as i64 + 60).contains(&span),
            "test 2: {subject} kept for {span}s"
        );
        assert_eq!(item["status"], "archived", "status is returned");
        assert_eq!(item["accountId"], user.id_string(), "accountId is returned");
    }
    assert_eq!(archived.len(), 4, "test 2: {archived:?}");

    // Acceptance test 3: moving to Trash keeps nothing
    let id = import(&client, "Moved", &[INBOX_ID], &[]).await;
    user.email_set_mailboxes(&id, &[TRASH_ID]).await;
    test.wait_for_tasks().await;
    assert_eq!(user.archived().await.len(), 4, "test 3");

    // Acceptance test 13: archived copies don't count toward quota
    let used = test
        .server
        .get_used_quota_account(user.id().document_id())
        .await
        .unwrap();

    // Acceptance test 4: restore puts a message back in both of its
    // mailboxes with its keywords (UD-8)
    let label = user.create_mailbox("Label").await;
    let id = import(
        &client,
        "Two labels",
        &[INBOX_ID, label],
        &["$seen", "$flagged"],
    )
    .await;
    client.email_destroy(&id).await.unwrap();
    test.wait_for_tasks().await;
    assert_eq!(
        test.server
            .get_used_quota_account(user.id().document_id())
            .await
            .unwrap(),
        used,
        "test 13"
    );
    let item = user.archived_with_subject("Two labels").await;
    user.request_restore(item.object_id()).await;
    test.wait_for_tasks().await;
    let restored = user.email_with_subject("Two labels").await;
    assert_eq!(
        restored["mailboxIds"],
        json!({Id::from(INBOX_ID).to_string(): true, Id::from(label).to_string(): true}),
        "test 4: {restored}"
    );
    assert_eq!(
        restored["keywords"],
        json!({"$seen": true, "$flagged": true}),
        "test 4"
    );
    // Acceptance test 7: a new id, and the record is gone (UD-9)
    assert_ne!(restored.id(), id, "test 7");
    assert!(
        user.archived()
            .await
            .iter()
            .all(|i| i["subject"] != "Two labels"),
        "test 7"
    );

    // Acceptance test 5: its mailbox gone, a message comes back to Inbox
    let gone = user.create_mailbox("Gone").await;
    let id = import(&client, "Lost label", &[gone], &[]).await;
    client.email_destroy(&id).await.unwrap();
    user.destroy_mailbox(gone).await;
    test.wait_for_tasks().await;
    let item = user.archived_with_subject("Lost label").await;
    user.request_restore(item.object_id()).await;
    test.wait_for_tasks().await;
    assert_eq!(
        user.email_with_subject("Lost label").await["mailboxIds"],
        json!({Id::from(INBOX_ID).to_string(): true}),
        "test 5"
    );

    // Acceptance test 9: asking twice restores once (UD-11)
    let item = user.archived_with_subject("Via JMAP").await;
    user.request_restore(item.object_id()).await;
    // The second ask may find it already restored, which is fine
    user.jmap_method_call(
        "x:ArchivedItem/set",
        json!({
            "accountId": user.id_string(),
            "update": {item.object_id().to_string(): {"status": "requestRestore"}}
        }),
    )
    .await;
    test.wait_for_tasks().await;
    assert_eq!(user.count_with_subject("Via JMAP").await, 1, "test 9");

    // Acceptance test 10: the user destroys an archived item for good (UD-12)
    let item = user.archived_with_subject("Via IMAP").await;
    user.registry_destroy(ObjectType::ArchivedItem, [item.object_id()])
        .await
        .assert_destroyed(&[item.object_id()]);
    assert!(
        user.archived()
            .await
            .iter()
            .all(|i| i["subject"] != "Via IMAP"),
        "test 10"
    );

    // Acceptance test 11: lowering retention doesn't move deadlines (UD-5)
    let before = user.archived_with_subject("Via POP3").await["archivedUntil"].clone();
    admin.set_retention(Some(7 * DAY)).await;
    assert_eq!(
        user.archived_with_subject("Via POP3").await["archivedUntil"],
        before,
        "test 11"
    );

    // /changes (a fork addition)
    let since = user.archive_state().await;
    let id = import(&client, "For changes", &[INBOX_ID], &[]).await;
    client.email_destroy(&id).await.unwrap();
    test.wait_for_tasks().await;
    let changes = user
        .jmap_method_call(
            "x:ArchivedItem/changes",
            json!({"accountId": user.id_string(), "sinceState": since}),
        )
        .await;
    assert_eq!(
        changes.method_response()["created"]
            .as_array()
            .map(|a| a.len()),
        Some(1),
        "/changes: {changes:?}"
    );

    // /query filters (a fork addition)
    let found = user
        .registry_query_ids(
            ObjectType::ArchivedItem,
            [(Property::Text, "changes")],
            Vec::<&str>::new(),
        )
        .await;
    assert_eq!(found.len(), 1, "query text");

    // Acceptance test 15: nobody else sees the archive (UD-7)
    let other = admin
        .create_user_account("other@example.org", SECRET, "Other", &[], vec![])
        .await;
    assert_eq!(
        other
            .jmap_method_call(
                "x:ArchivedItem/get",
                json!({"accountId": user.id_string(), "ids": null}),
            )
            .await
            .method_response()
            .text_field("type"),
        "forbidden",
        "test 15"
    );

    // Acceptance test 6: a file, event, contact and script each come back to
    // the right place (UD-1, UD-8)
    let dav = DummyWebDavClient::new(
        user.id().document_id(),
        "undelete@example.org",
        SECRET,
        "undelete@example.org",
    );
    let home = "undelete%40example.org";
    dav.mkcol("MKCOL", &format!("/dav/file/{home}/Folder/"), [], [])
        .await
        .with_status(StatusCode::CREATED);
    let file = format!("/dav/file/{home}/Folder/notes.txt");
    let event = format!("/dav/cal/{home}/default/lunch.ics");
    let card = format!("/dav/card/{home}/default/jane.vcf");
    for (path, body) in [
        (&file, "Some notes.".to_string()),
        (&event, EVENT.to_string()),
        (&card, CARD.to_string()),
    ] {
        dav.request("PUT", path, body)
            .await
            .with_status(StatusCode::CREATED);
    }
    let script = client
        .sieve_script_create("Filters", b"keep;".to_vec(), true)
        .await
        .unwrap()
        .take_id();
    for path in [&file, &event, &card] {
        dav.request("DELETE", path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    client.sieve_script_deactivate().await.unwrap();
    client.sieve_script_destroy(&script).await.unwrap();
    test.wait_for_tasks().await;
    // A new file takes the old name, so the restored one is renamed
    dav.request("PUT", &file, "Newer notes.")
        .await
        .with_status(StatusCode::CREATED);
    for kind in ["FileNode", "CalendarEvent", "ContactCard", "SieveScript"] {
        let item = user
            .archived()
            .await
            .into_iter()
            .find(|item| item["@type"] == kind)
            .unwrap_or_else(|| panic!("test 6: no archived {kind}"));
        user.request_restore(item.object_id()).await;
    }
    test.wait_for_tasks().await;
    dav.request("GET", &format!("/dav/file/{home}/Folder/notes%20%28restored%29.txt"), "")
        .await
        .with_status(StatusCode::OK)
        .with_body("Some notes.");
    dav.request("GET", &event, "")
        .await
        .with_status(StatusCode::OK);
    dav.request("GET", &card, "").await.with_status(StatusCode::OK);
    let restored = client
        .sieve_script_query(
            jmap_client::sieve::query::Filter::name("Filters").into(),
            None::<Vec<_>>,
        )
        .await
        .unwrap();
    let restored = client
        .sieve_script_get(restored.ids().first().expect("test 6: script"), None::<Vec<_>>)
        .await
        .unwrap()
        .unwrap();
    assert!(!restored.is_active(), "test 6: a restored script is inactive");
    assert!(
        user.archived()
            .await
            .iter()
            .all(|item| item["@type"] == "Email"),
        "test 6: records removed"
    );

    // Acceptance test 8: a restore past the account's quota is refused, and
    // the item stays archived (UD-10)
    let used = test
        .server
        .get_used_quota_account(user.id().document_id())
        .await
        .unwrap();
    admin
        .registry_update_object(
            ObjectType::Account,
            user.id(),
            json!({ Property::Quotas: {"maxDiskQuota": used} }),
        )
        .await;
    let item = user.archived_with_subject("Via POP3").await;
    user.request_restore(item.object_id()).await;
    test.wait_for_tasks_skip_failures().await;
    assert_eq!(user.count_with_subject("Via POP3").await, 0, "test 8");
    assert_eq!(
        user.archived_with_subject("Via POP3").await["status"],
        "archived",
        "test 8: still archived"
    );
    // The refused restore stays in the queue as failed
    admin.registry_destroy_all(ObjectType::Task).await;
    admin
        .registry_update_object(
            ObjectType::Account,
            user.id(),
            json!({ Property::Quotas: {} }),
        )
        .await;

    // Acceptance test 12: past its deadline an item isn't restorable
    admin.set_retention(Some(1)).await;
    let id = import(&client, "Short-lived", &[INBOX_ID], &[]).await;
    client.email_destroy(&id).await.unwrap();
    test.wait_for_tasks().await;
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert!(
        user.archived()
            .await
            .iter()
            .all(|item| item["subject"] != "Short-lived"),
        "test 12"
    );

    // Acceptance test 14: a deleted account is kept: it can't sign in or
    // receive mail, its name stays held, and an admin restores it whole,
    // shares both ways included (UD-15 to UD-17a)
    admin
        .registry_update_setting(
            MtaStageRcpt {
                wait_on_fail: Expression {
                    else_: "1ms".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            &[Property::WaitOnFail],
        )
        .await;
    admin.reload_settings().await;
    admin.set_account_retention(Some(30 * DAY)).await;
    let gone = admin
        .create_user_account("gone@example.org", SECRET, "Gone", &[], vec![])
        .await;
    let gone_id = gone.id();
    import(&gone.jmap_client().await, "Kept with the account", &[INBOX_ID], &[]).await;
    share_inbox(&gone, user.id()).await;
    share_inbox(&user, gone_id).await;
    assert!(has_access(test, user.id(), gone_id).await, "test 14: shared");
    assert!(has_access(test, gone_id, user.id()).await, "test 14: shared");

    admin
        .registry_destroy(ObjectType::Account, [gone_id])
        .await
        .assert_destroyed(&[gone_id]);
    assert!(
        matches!(
            Client::new()
                .credentials(Credentials::basic("gone@example.org", SECRET))
                .accept_invalid_certs(true)
                .follow_redirects(["127.0.0.1"])
                .connect(&gone.base_url())
                .await,
            Err(jmap_client::Error::Problem(err)) if err.status() == Some(401)
        ),
        "test 14: can't sign in"
    );
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.mail_from("sender@remote.example.org", 2).await;
    let reply = lmtp.rcpt_to("gone@example.org", 5).await;
    assert!(
        reply.iter().any(|line| line.starts_with("550 5.1.2")),
        "test 14: mail refused, {reply:?}"
    );
    assert!(!has_access(test, user.id(), gone_id).await, "test 14: suspended");
    assert!(!has_access(test, gone_id, user.id()).await, "test 14: suspended");
    assert!(pending_destroy(test, gone_id).await, "test 14: destruction due");

    // Its name is held (UD-16)
    let domain_id = admin
        .jmap_method_call(
            "x:Account/get",
            json!({"ids": [user.id_string()], "properties": ["domainId"]}),
        )
        .await
        .list()[0]["domainId"]
        .clone();
    let response = admin
        .jmap_method_call(
            "x:Account/set",
            json!({"create": {"i0": {"@type": "User", "name": "gone", "domainId": domain_id}}}),
        )
        .await;
    assert_eq!(
        response.not_created(0)["type"],
        "primaryKeyViolation",
        "test 14: name held"
    );

    // Listed for admins only (UD-17)
    let listed = admin.deleted_accounts().await;
    assert_eq!(listed.len(), 1, "test 14: listed");
    assert_eq!(listed[0]["id"], gone_id.to_string());
    assert_eq!(listed[0]["name"], "gone");
    assert_eq!(listed[0]["addresses"], json!(["gone@example.org"]));
    assert_eq!(
        seconds(&listed[0]["keptUntil"]) - seconds(&listed[0]["deletedAt"]),
        (30 * DAY) as i64
    );
    let response = user
        .jmap_request(
            &["urn:ietf:params:jmap:core", "urn:inbuxa:jmap"],
            json!([["inbuxa:DeletedAccount/get", {"accountId": user.id_string(), "ids": null}, "0"]]),
        )
        .await;
    assert_eq!(
        response.0.pointer("/methodResponses/0/0"),
        Some(&json!("error")),
        "test 14: not for users"
    );

    // Restored with the same id, its mail and its shares
    let response = admin
        .deleted_account_set(json!({"update": {gone_id.to_string(): {"restore": true, "password": SECRET}}}))
        .await;
    response.updated_id(gone_id);
    assert_eq!(gone.count_with_subject("Kept with the account").await, 1, "test 14: data intact");
    assert!(has_access(test, user.id(), gone_id).await, "test 14: reinstated");
    assert!(has_access(test, gone_id, user.id()).await, "test 14: reinstated");
    assert!(!pending_destroy(test, gone_id).await, "test 14: destruction off");
    assert!(admin.deleted_accounts().await.is_empty());
    test.wait_for_tasks().await;

    // Destroyed for good: the task runs now and the name is free
    admin
        .registry_destroy(ObjectType::Account, [gone_id])
        .await
        .assert_destroyed(&[gone_id]);
    admin
        .deleted_account_set(json!({"destroy": [gone_id.to_string()]}))
        .await
        .assert_destroyed(&[gone_id]);
    test.wait_for_tasks().await;
    assert!(admin.deleted_accounts().await.is_empty(), "test 14: gone");
    assert!(!pending_destroy(test, gone_id).await);
    admin.set_account_retention(None).await;
    let again = admin
        .create_user_account("gone@example.org", SECRET, "Gone", &[], vec![])
        .await;
    assert_eq!(again.count_with_subject("Kept with the account").await, 0);
    admin.destroy_account(again).await;
    admin
        .registry_update_setting(MtaStageRcpt::default(), &[Property::WaitOnFail])
        .await;
    admin.reload_settings().await;

    // Clean up
    admin.set_retention(None).await;
    for item in user.archived().await {
        user.registry_destroy(ObjectType::ArchivedItem, [item.object_id()])
            .await;
    }
    admin.destroy_account(other).await;
    admin.destroy_account(user).await;
    test.wait_for_tasks().await;
}

/// Runs the undelete tests alone:
/// `cargo test -p tests undelete_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn undelete_tests() {
    let mut test = TestServerBuilder::new("undelete_tests")
        .await
        .with_default_listeners()
        .await
        .with_object(Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
        .await
        .with_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// Acceptance test 16 (compat): archived items written before the cutover
/// read back unchanged through `x:ArchivedItem`, and restore.
///
/// INBUXA held no archived items (spec, observed 1), so the items to check
/// are made on a copy of its data, through the Enterprise server, before the
/// copy is opened here:
///
/// - `INBUXA_COMPAT_ADMIN`: `name:password` of a server-level administrator
///   in that data;
/// - `INBUXA_COMPAT_ARCHIVED`: a JSON file of `x:ArchivedItem/get` results
///   recorded against the Enterprise server, each with its `id` and
///   `accountId`;
///
/// and the data itself in place of the test store: run with `NO_INSERT=1`
/// and the store's `TMPDIR`/`STORE` pointing at the copy, so it isn't reset.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn undelete_compat() {
    let admin = std::env::var("INBUXA_COMPAT_ADMIN").expect("INBUXA_COMPAT_ADMIN");
    let items: Vec<Value> = serde_json::from_slice(
        &std::fs::read(std::env::var("INBUXA_COMPAT_ARCHIVED").expect("INBUXA_COMPAT_ARCHIVED"))
            .expect("archived items file"),
    )
    .expect("archived items JSON");
    assert!(
        std::env::var("NO_INSERT").is_ok(),
        "NO_INSERT must be set, or the copy of INBUXA's data is wiped"
    );

    let test = TestServerBuilder::new("undelete_compat")
        .await
        .with_default_listeners()
        .await
        .build_with_opts(false)
        .await;
    let (name, secret) = admin.split_once(':').expect("name:password");
    let admin = Account::new(
        Box::leak(name.to_string().into_boxed_str()),
        Box::leak(secret.to_string().into_boxed_str()),
        &[],
        "Compat admin",
        Id::from(u32::MAX),
    );

    admin.assert_authenticates("INBUXA_COMPAT_ADMIN").await;

    for recorded in &items {
        let id = recorded["id"].as_str().unwrap();
        let account = recorded["accountId"].as_str().unwrap();

        // Reads back unchanged: every recorded property, same value
        let response = admin
            .jmap_method_call(
                "x:ArchivedItem/get",
                json!({"accountId": account, "ids": [id]}),
            )
            .await;
        let stored = &response.method_response()["list"][0];
        for (property, value) in recorded.as_object().unwrap() {
            assert_eq!(&stored[property], value, "{id} {property}: {response:?}");
        }

        // Restores: the record goes once the item is back (UD-9)
        admin
            .jmap_method_call(
                "x:ArchivedItem/set",
                json!({"accountId": account, "update": {id: {"status": "requestRestore"}}}),
            )
            .await
            .updated(id);
    }
    test.wait_for_tasks_skip_failures().await;
    for recorded in &items {
        let id = recorded["id"].as_str().unwrap();
        let response = admin
            .jmap_method_call(
                "x:ArchivedItem/get",
                json!({"accountId": recorded["accountId"], "ids": [id]}),
            )
            .await;
        assert_eq!(
            response.method_response()["notFound"],
            json!([id]),
            "{id} not restored"
        );
    }
}

fn seconds(value: &Value) -> i64 {
    value
        .as_str()
        .and_then(|s| s.parse::<registry::types::datetime::UTCDateTime>().ok())
        .map(|d| d.timestamp())
        .unwrap_or_default()
}

async fn import(client: &Client, subject: &str, mailboxes: &[u32], keywords: &[&str]) -> String {
    client
        .email_import(
            format!(
                "From: sender@example.org\r\nTo: undelete@example.org\r\nSubject: {subject}\r\n\r\nBody of {subject}.\r\n"
            )
            .into_bytes(),
            mailboxes.iter().map(|id| Id::from(*id).to_string()),
            if keywords.is_empty() {
                None
            } else {
                Some(keywords.to_vec())
            },
            None,
        )
        .await
        .unwrap()
        .take_id()
}

/// Shares `owner`'s Inbox with `grantee`, read-only.
async fn share_inbox(owner: &Account, grantee: Id) {
    owner
        .jmap_method_call(
            "Mailbox/set",
            json!({
                "accountId": owner.id_string(),
                "update": {
                    Id::from(INBOX_ID).to_string(): {
                        "shareWith": { grantee.to_string(): { "mayReadItems": true } }
                    }
                }
            }),
        )
        .await
        .updated_id(Id::from(INBOX_ID));
}

/// Whether `grantee` may reach anything of `owner`'s.
async fn has_access(test: &TestServer, grantee: Id, owner: Id) -> bool {
    test.server
        .store()
        .acl_query(AclQuery::HasAccess {
            grant_account_id: grantee.document_id(),
        })
        .await
        .unwrap()
        .iter()
        .any(|item| item.to_account_id == owner.document_id())
}

/// Whether a `DestroyAccount` task for the account is queued.
async fn pending_destroy(test: &TestServer, account: Id) -> bool {
    let mut found = false;
    test.server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task { id: 0 })),
                ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task { id: u64::MAX })),
            )
            .ascending(),
            |_, value| {
                if let Task::DestroyAccount(task) = Task::deserialize(value)? {
                    found |= task.account_id == account;
                }
                Ok(!found)
            },
        )
        .await
        .unwrap();
    found
}

impl Account {
    async fn set_account_retention(&self, keep_for: Option<u64>) {
        self.registry_update_setting(
            DataRetention {
                archive_deleted_accounts_for: keep_for
                    .map(|secs| Duration::from_millis(secs * 1000)),
                ..Default::default()
            },
            &[Property::ArchiveDeletedAccountsFor],
        )
        .await;
    }

    async fn deleted_accounts(&self) -> Vec<Value> {
        self.jmap_request(
            &["urn:ietf:params:jmap:core", "urn:inbuxa:jmap"],
            json!([["inbuxa:DeletedAccount/get", {"accountId": self.id_string(), "ids": null}, "0"]]),
        )
        .await
        .list()
        .to_vec()
    }

    async fn deleted_account_set(&self, mut args: Value) -> JmapResponse {
        args["accountId"] = json!(self.id_string());
        self.jmap_request(
            &["urn:ietf:params:jmap:core", "urn:inbuxa:jmap"],
            json!([["inbuxa:DeletedAccount/set", args, "0"]]),
        )
        .await
    }

    async fn set_retention(&self, keep_for: Option<u64>) {
        self.registry_update_setting(
            DataRetention {
                archive_deleted_items_for: keep_for.map(|secs| Duration::from_millis(secs * 1000)),
                ..Default::default()
            },
            &[Property::ArchiveDeletedItemsFor],
        )
        .await;
    }

    async fn archived(&self) -> Vec<Value> {
        self.jmap_method_call(
            "x:ArchivedItem/get",
            json!({"accountId": self.id_string(), "ids": null}),
        )
        .await
        .method_response()["list"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    async fn archived_with_subject(&self, subject: &str) -> Value {
        let archived = self.archived().await;
        archived
            .into_iter()
            .find(|item| item["subject"] == subject)
            .unwrap_or_else(|| panic!("{subject} isn't archived"))
    }

    async fn archive_state(&self) -> String {
        self.jmap_method_call(
            "x:ArchivedItem/get",
            json!({"accountId": self.id_string(), "ids": []}),
        )
        .await
        .method_response()["state"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    async fn request_restore(&self, id: Id) {
        self.registry_update_object(
            ObjectType::ArchivedItem,
            id,
            json!({ Property::Status: "requestRestore" }),
        )
        .await;
    }

    async fn emails_with_subject(&self, subject: &str) -> Vec<Value> {
        let response = self
            .jmap_method_calls(json!([
                ["Email/query", {
                    "accountId": self.id_string(),
                    "filter": {"subject": subject}
                }, "q"],
                ["Email/get", {
                    "accountId": self.id_string(),
                    "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                    "properties": ["id", "subject", "mailboxIds", "keywords"]
                }, "g"]
            ]))
            .await;
        response.0["methodResponses"][1][1]["list"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|email| email["subject"] == subject)
            .collect()
    }

    async fn email_with_subject(&self, subject: &str) -> Value {
        self.emails_with_subject(subject)
            .await
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("no email with subject {subject}"))
    }

    async fn count_with_subject(&self, subject: &str) -> usize {
        self.emails_with_subject(subject).await.len()
    }

    async fn email_set_mailboxes(&self, id: &str, mailboxes: &[u32]) {
        let ids = mailboxes
            .iter()
            .map(|id| (Id::from(*id).to_string(), Value::Bool(true)))
            .collect::<serde_json::Map<_, _>>();
        self.jmap_method_call(
            "Email/set",
            json!({"accountId": self.id_string(), "update": {id: {"mailboxIds": ids}}}),
        )
        .await
        .updated(id);
    }

    async fn create_mailbox(&self, name: &str) -> u32 {
        let response = self
            .jmap_method_call(
                "Mailbox/set",
                json!({"accountId": self.id_string(), "create": {"i0": {"name": name}}}),
            )
            .await;
        response.created_id(0).document_id()
    }

    async fn destroy_mailbox(&self, id: u32) {
        self.jmap_method_call(
            "Mailbox/set",
            json!({
                "accountId": self.id_string(),
                "destroy": [Id::from(id).to_string()],
                "onDestroyRemoveEmails": true
            }),
        )
        .await;
    }
}
