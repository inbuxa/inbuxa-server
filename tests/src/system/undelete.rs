/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Undelete acceptance tests, from `docs/spec/features/undelete.md`. Each
//! check names the test number or the requirement it covers.

use crate::utils::{
    account::Account,
    imap::{ImapConnection, Type},
    jmap::JmapUtils,
    pop3::{self, Pop3Connection},
    server::{TestServer, TestServerBuilder},
};
use email::{
    mailbox::{INBOX_ID, TRASH_ID},
    message::delete::EmailDeletion,
};
use imap_proto::ResponseType;
use jmap_client::client::Client;
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{DataRetention, Expression, Imap, MtaStageAuth},
    },
    types::duration::Duration,
};
use serde_json::{Value, json};
use types::id::Id;

const SECRET: &str = "undelete test user passphrase";
const DAY: u64 = 86_400;

pub async fn test(test: &mut TestServer) {
    println!("Running undelete tests...");
    let admin = test.account("admin@example.org");
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

impl Account {
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

    async fn inbox_ids(&self) -> Vec<String> {
        self.jmap_method_call(
            "Email/query",
            json!({
                "accountId": self.id_string(),
                "filter": {"inMailbox": Id::from(INBOX_ID).to_string()}
            }),
        )
        .await
        .method_response()["ids"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .map(|id| id.as_str().unwrap().to_string())
                    .collect()
            })
            .unwrap_or_default()
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
