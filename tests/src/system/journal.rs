/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Journaling (journaling spec, phase 2): journals over JMAP, the copy
//! taken as mail is queued with its whole envelope, the report around the
//! untouched message, retention, purge, and a chain that shows tampering.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
    smtp::SmtpConnection,
};
use inbuxa_features::journal::{
    Direction,
    entries::{self, Entry, EntryId},
    report,
};
use registry::schema::structs::{Expression, MtaStageAuth};
use serde_json::{Value, json};
use store::{Deserialize, write::BatchBuilder};

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:mail",
    "urn:ietf:params:jmap:submission",
    "urn:inbuxa:jmap",
];

async fn call(account: &Account, method: &str, mut arguments: Value) -> (String, Value) {
    if arguments.get("accountId").is_none() {
        arguments["accountId"] = account.id_string().into();
    }
    let response = account
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

/// Sends a message whose headers name `to`, to the envelope `rcpt_to`.
async fn send(
    sender: &Account,
    identity: &str,
    mailbox: &str,
    to: &[&str],
    rcpt_to: &[&str],
    subject: &str,
) -> Value {
    let (_, response) = call(
        sender,
        "Email/set",
        json!({"create": {"e": {
            "mailboxIds": {mailbox: true},
            "from": [{"email": sender.name()}],
            "to": to.iter().map(|a| json!({"email": a})).collect::<Vec<_>>(),
            "subject": subject,
            "bodyValues": {"b": {"value": "The body."}},
            "textBody": [{"partId": "b", "type": "text/plain"}]
        }}}),
    )
    .await;
    let email = response["created"]["e"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("draft: {response}"))
        .to_string();
    call(
        sender,
        "EmailSubmission/set",
        json!({"create": {"s": {
            "emailId": email,
            "identityId": identity,
            "envelope": {
                "mailFrom": {"email": sender.name()},
                "rcptTo": rcpt_to.iter().map(|a| json!({"email": a})).collect::<Vec<_>>()
            }
        }}}),
    )
    .await
    .1
}

async fn all_entries(test: &TestServer) -> Vec<(EntryId, Entry)> {
    entries::list(test.server.store(), 0, u64::MAX, 10_000)
        .await
        .unwrap()
}

async fn entry_for(test: &TestServer, subject: &str) -> Option<(EntryId, Entry)> {
    all_entries(test)
        .await
        .into_iter()
        .find(|(_, e)| e.subject == subject)
}

async fn report_of(test: &TestServer, entry: &Entry) -> Vec<u8> {
    let hash = entry.blob_hash().expect("blob hash");
    test.server
        .blob_store()
        .get_blob(hash.as_slice(), 0..usize::MAX)
        .await
        .unwrap()
        .expect("report blob")
}

pub async fn test(test: &mut TestServer) {
    println!("Running journaling tests...");
    let admin = test.account("admin@example.com");
    let sender = admin
        .create_user_account(
            "journal-sender@example.com",
            "journal-sender-secret-7101",
            "Journal sender",
            &[],
            vec![],
        )
        .await;
    let other = admin
        .create_user_account(
            "journal-other@example.com",
            "journal-other-secret-7102",
            "Journal other",
            &[],
            vec![],
        )
        .await;
    let (_, response) = call(
        &sender,
        "Identity/set",
        json!({"create": {"i": {"name": "Sender", "email": "journal-sender@example.com"}}}),
    )
    .await;
    let identity = response["created"]["i"]["id"].as_str().unwrap().to_string();
    let (_, response) = call(
        &sender,
        "Mailbox/set",
        json!({"create": {"m": {"name": "Journal drafts"}}}),
    )
    .await;
    let mailbox = response["created"]["m"]["id"].as_str().unwrap().to_string();

    // Nothing is journaled while there are no journals
    let response = send(
        &sender,
        &identity,
        &mailbox,
        &["journal-other@example.com"],
        &["journal-other@example.com"],
        "Before any journal",
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
    assert!(all_entries(test).await.is_empty());

    // Journals: checked when written, the server's own properties refused
    let (_, response) = call(
        &admin,
        "inbuxa:Journal/set",
        json!({"create": {
            "short": {"name": "Short", "enabled": true, "direction": "any",
                      "scope": {"everyone": true}, "retentionDays": 29},
            "both": {"name": "Both", "enabled": true, "direction": "any",
                     "scope": {"everyone": true, "accounts": [sender.id_string()]},
                     "retentionDays": 365},
            "none": {"name": "None", "enabled": true, "direction": "any",
                     "scope": {}, "retentionDays": 365},
            "server": {"name": "Mine", "enabled": true, "direction": "any",
                       "scope": {"everyone": true}, "retentionDays": 365,
                       "createdBy": "me"},
            "all": {"name": "Everything", "enabled": true, "direction": "any",
                    "scope": {"everyone": true}, "retentionDays": 365},
            "out": {"name": "Sender's outgoing", "enabled": true, "direction": "outgoing",
                    "scope": {"accounts": [sender.id_string()]}, "retentionDays": 3650}
        }}),
    )
    .await;
    for refused in ["short", "both", "none", "server"] {
        assert_eq!(
            response["notCreated"][refused]["type"], "invalidProperties",
            "{refused}: {response}"
        );
    }
    assert_eq!(
        response["notCreated"]["short"]["properties"],
        json!(["retentionDays"])
    );
    assert_eq!(
        response["notCreated"]["both"]["properties"],
        json!(["scope"])
    );
    let everything = response["created"]["all"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let outgoing = response["created"]["out"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, response) = call(&admin, "inbuxa:Journal/get", json!({"ids": null})).await;
    let list = response["list"].as_array().unwrap();
    assert_eq!(list.len(), 2, "{response}");
    assert_eq!(list[0]["name"], "Everything");
    assert_eq!(list[0]["createdBy"], "admin@example.com");
    assert_eq!(list[1]["scope"]["accounts"], json!([sender.id_string()]));
    // Each node reads journals again within 30 seconds; this one at once
    inbuxa_features::journal::invalidate();

    // Internal mail with a Bcc recipient: one entry, the whole envelope
    let response = send(
        &sender,
        &identity,
        &mailbox,
        &["journal-sender@example.com"],
        &["journal-sender@example.com", "journal-other@example.com"],
        "Internal with Bcc",
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
    let (_, entry) = entry_for(test, "Internal with Bcc")
        .await
        .expect("journaled");
    assert_eq!(entry.direction, Direction::Internal);
    assert_eq!(entry.sender, "journal-sender@example.com");
    assert!(entry.authenticated);
    assert_eq!(entry.recipients.len(), 2, "{entry:?}");
    assert_eq!(
        entry.journals.len(),
        1,
        "internal isn't outgoing: {entry:?}"
    );
    assert!(!entry.held);
    assert_eq!(entry.expires_at, entry.at + 365 * 86_400);
    let bytes = report_of(test, &entry).await;
    assert_eq!(entries::sha256(&bytes), entry.sha256);
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("Direction: internal\r\n"), "{text}");
    assert!(
        text.contains("To: journal-sender@example.com\r\n"),
        "{text}"
    );
    assert!(
        text.contains("Bcc: journal-other@example.com\r\n"),
        "{text}"
    );
    let original = report::original(&bytes).expect("original part");
    let original = String::from_utf8_lossy(original);
    assert!(
        original.contains("Subject: Internal with Bcc"),
        "{original}"
    );
    assert!(original.contains("The body."), "{original}");
    assert!(!original.contains("Bcc:"), "the original is as sent");

    // Outgoing: both journals take it, and it's kept for the longer
    let response = send(
        &sender,
        &identity,
        &mailbox,
        &["someone@elsewhere.org"],
        &["someone@elsewhere.org"],
        "Leaving",
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
    let (leaving_id, entry) = entry_for(test, "Leaving").await.expect("journaled");
    assert_eq!(entry.direction, Direction::Outgoing);
    assert_eq!(entry.journals.len(), 2, "{entry:?}");
    assert_eq!(entry.expires_at, entry.at + 3650 * 86_400);

    // Incoming from outside
    admin
        .registry_create_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "someone@elsewhere.org",
        &["journal-other@example.com"],
        "From: someone@elsewhere.org\r\nTo: journal-other@example.com\r\nSubject: Arriving\r\n\r\nHi.\r\n",
    )
    .await;
    let (_, entry) = entry_for(test, "Arriving").await.expect("journaled");
    assert_eq!(entry.direction, Direction::Incoming);
    assert!(!entry.authenticated);
    assert_eq!(entry.accounts, vec![other.id().document_id()]);

    // The chain checks out, reports included
    let store = test.server.store();
    let blobs = test.server.blob_store();
    let reports = entries::verify(store, Some(blobs)).await.unwrap();
    assert!(reports.iter().all(|r| r.broken_at.is_none()), "{reports:?}");
    let journaled = all_entries(test).await.len() as u64;
    assert!(reports.iter().map(|r| r.entries).sum::<u64>() >= journaled);

    // An entry changed in the store shows; put back, it checks out again
    let key = entries::content_key(leaving_id);
    let stored = store
        .get_value::<Raw>(key.clone())
        .await
        .unwrap()
        .expect("stored entry")
        .0;
    let mut forged: Entry = serde_json::from_slice(&stored).unwrap();
    forged.recipients = vec!["nobody@elsewhere.org".into()];
    let mut batch = BatchBuilder::new();
    batch.set(key.class.clone(), serde_json::to_vec(&forged).unwrap());
    store.write(batch.build_all()).await.unwrap();
    let reports = entries::verify(store, None).await.unwrap();
    let broken = reports
        .iter()
        .find(|r| r.broken_at.is_some())
        .expect("broken");
    assert_eq!(
        broken.broken_at.as_deref(),
        Some(leaving_id.to_string().as_str())
    );
    assert!(
        broken
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("changed")
    );
    let mut batch = BatchBuilder::new();
    batch.set(key.class.clone(), stored.clone());
    store.write(batch.build_all()).await.unwrap();
    assert!(
        entries::verify(store, None)
            .await
            .unwrap()
            .iter()
            .all(|r| r.broken_at.is_none())
    );

    // An entry removed without a purge shows too
    let mut batch = BatchBuilder::new();
    batch.clear(key.class.clone());
    store.write(batch.build_all()).await.unwrap();
    let reports = entries::verify(store, None).await.unwrap();
    assert!(
        reports.iter().any(|r| r
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("before its time")),
        "{reports:?}"
    );
    let mut batch = BatchBuilder::new();
    batch.set(key.class.clone(), stored);
    store.write(batch.build_all()).await.unwrap();

    // Retention: nothing is due yet; a year on, what's kept for a hold
    // stays, the rest goes, and the chain still checks out
    let now = store::write::now();
    let purged = entries::purge(store, now, |_| false).await.unwrap();
    assert_eq!(purged.removed, 0);
    let sender_id = sender.id().document_id();
    let later = now + 400 * 86_400;
    let purged = entries::purge(store, later, |e| e.accounts.contains(&sender_id))
        .await
        .unwrap();
    assert!(purged.removed >= 1, "{purged:?}");
    assert!(purged.kept_for_hold >= 1, "{purged:?}");
    assert!(entry_for(test, "Arriving").await.is_none(), "purged");
    assert!(entry_for(test, "Internal with Bcc").await.is_some(), "held");
    assert!(entry_for(test, "Leaving").await.is_some(), "ten years");
    let reports = entries::verify(store, Some(blobs)).await.unwrap();
    assert!(reports.iter().all(|r| r.broken_at.is_none()), "{reports:?}");
    assert!(reports.iter().map(|r| r.purged).sum::<u64>() >= 1);

    // Once the hold is gone the held entry goes too
    let purged = entries::purge(store, later, |_| false).await.unwrap();
    assert!(purged.removed >= 1, "{purged:?}");
    assert!(entry_for(test, "Internal with Bcc").await.is_none());
    assert!(
        entries::verify(store, Some(blobs))
            .await
            .unwrap()
            .iter()
            .all(|r| r.broken_at.is_none())
    );

    // Changing a journal's retention doesn't touch what it has taken
    let before = entry_for(test, "Leaving").await.unwrap().1.expires_at;
    let (_, response) = call(
        &admin,
        "inbuxa:Journal/set",
        json!({"update": {outgoing.clone(): {"retentionDays": 30}}}),
    )
    .await;
    assert!(response["updated"].get(&outgoing).is_some(), "{response}");
    assert_eq!(
        entry_for(test, "Leaving").await.unwrap().1.expires_at,
        before
    );

    // Journals turned off or removed take nothing more; entries stay
    let (_, response) = call(
        &admin,
        "inbuxa:Journal/set",
        json!({"update": {everything.clone(): {"enabled": false}}, "destroy": [outgoing]}),
    )
    .await;
    assert!(response["updated"].get(&everything).is_some(), "{response}");
    assert_eq!(response["destroyed"].as_array().map(|d| d.len()), Some(1));
    inbuxa_features::journal::invalidate();
    let count = all_entries(test).await.len();
    let response = send(
        &sender,
        &identity,
        &mailbox,
        &["journal-other@example.com"],
        &["journal-other@example.com"],
        "After the journals",
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
    assert_eq!(all_entries(test).await.len(), count);
    assert!(entry_for(test, "Leaving").await.is_some());

    // Every change to a journal is in the audit log
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:Journal"}}),
    )
    .await;
    assert!(
        response["ids"].as_array().map_or(0, |ids| ids.len()) >= 4,
        "{response}"
    );
}

struct Raw(Vec<u8>);

impl Deserialize for Raw {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Raw(bytes.to_vec()))
    }
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn journal_tests() {
    let mut test = TestServerBuilder::new("journal_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.com").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
