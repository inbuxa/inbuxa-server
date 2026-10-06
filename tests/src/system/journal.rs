/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
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
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{CustomRoles, Expression, MtaStageAuth, Role, UserRoles},
};
use registry::types::map::Map;
use serde_json::{Value, json};
use std::str::FromStr;
use store::{Deserialize, write::BatchBuilder};

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:mail",
    "urn:ietf:params:jmap:submission",
    "urn:inbuxa:jmap",
    "urn:inbuxa:jmap:registry",
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
            "none": {"name": "Nowhere", "enabled": true, "direction": "any",
                     "scope": {"everyone": true}, "retentionDays": 365, "builtIn": false},
            "badaddr": {"name": "Bad archive", "enabled": true, "direction": "any",
                        "scope": {"everyone": true}, "retentionDays": 365,
                        "archiveAddress": "not an address"},
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
    for refused in ["short", "both", "none", "badaddr", "server"] {
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
    assert_eq!(
        response["notCreated"]["none"]["properties"],
        json!(["builtIn"])
    );
    assert_eq!(
        response["notCreated"]["badaddr"]["properties"],
        json!(["archiveAddress"])
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

/// Phase 3: journals only rules send mail to, recipients a rule added,
/// reports sent to an outside archive, and what happens when the archive
/// doesn't take one.
pub async fn archive(test: &mut TestServer) {
    println!("Running journal archive tests...");
    let admin = test.account("admin@example.com");
    let sender = admin
        .create_user_account(
            "archive-sender@example.com",
            "archive-sender-secret-7201",
            "Archive sender",
            &[],
            vec![],
        )
        .await;
    let vault = admin
        .create_user_account(
            "journal-vault@example.com",
            "journal-vault-secret-7202",
            "Journal vault",
            &[],
            vec![],
        )
        .await;
    let (_, response) = call(
        &sender,
        "Identity/set",
        json!({"create": {"i": {"name": "Sender", "email": "archive-sender@example.com"}}}),
    )
    .await;
    let identity = response["created"]["i"]["id"].as_str().unwrap().to_string();
    let (_, response) = call(
        &sender,
        "Mailbox/set",
        json!({"create": {"m": {"name": "Archive drafts"}}}),
    )
    .await;
    let mailbox = response["created"]["m"]["id"].as_str().unwrap().to_string();

    let (_, response) = call(
        &admin,
        "inbuxa:Journal/set",
        json!({"create": {
            "rules": {"name": "Only what rules send", "enabled": true, "direction": "any",
                      "scope": {}, "retentionDays": 30},
            "local": {"name": "To the vault", "enabled": true, "direction": "outgoing",
                      "scope": {"accounts": [sender.id_string()]}, "retentionDays": 30,
                      "builtIn": false, "archiveAddress": "journal-vault@example.com"},
            "remote": {"name": "To an outside archive", "enabled": true, "direction": "internal",
                       "scope": {"accounts": [sender.id_string()]}, "retentionDays": 30,
                       "builtIn": false, "archiveAddress": "vault@elsewhere.org"}
        }}),
    )
    .await;
    let id = |name: &str| {
        response["created"][name]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: {response}"))
            .to_string()
    };
    let (rules_only, local, remote) = (id("rules"), id("local"), id("remote"));
    let number = |id: &str| types::id::Id::from_str(id).unwrap().document_id();
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"create": {"r": {
            "name": "Copy and journal", "kind": "transport", "direction": "outgoing",
            "conditions": [{"type": "words", "words": ["journal-me"]}],
            "actions": [
                {"type": "addRecipient", "address": "journal-vault@example.com"},
                {"type": "journal", "journal": rules_only.clone()}
            ]
        }}}),
    )
    .await;
    let rule = response["created"]["r"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    inbuxa_features::journal::invalidate();

    // A rule sends it to a journal whose scope takes nobody, and says who
    // it added
    let response = send(
        &sender,
        &identity,
        &mailbox,
        &["archive-sender@example.com"],
        &["archive-sender@example.com"],
        "Marked journal-me",
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
    let entry = all_entries(test)
        .await
        .into_iter()
        .map(|(_, e)| e)
        .find(|e| e.subject == "Marked journal-me" && e.journals.contains(&number(&rules_only)))
        .expect("journaled by the rule");
    assert_eq!(entry.journals, vec![number(&rules_only)], "{entry:?}");
    let text = String::from_utf8_lossy(&report_of(test, &entry).await).into_owned();
    assert!(
        text.contains("Added by rule: Copy and journal -> journal-vault@example.com\r\n"),
        "{text}"
    );
    assert!(!text.contains("Bcc:"), "{text}");

    // The same message went to the outside archive, which can't be reached
    // from here: once it leaves the queue (given up on, or deleted), it's
    // kept in the built-in journal
    let fallback = |entries: &[(EntryId, Entry)]| {
        entries
            .iter()
            .any(|(_, e)| e.subject == "Marked journal-me" && e.journals == vec![number(&remote)])
    };
    let mut deleted = false;
    for _ in 0..100 {
        if fallback(&all_entries(test).await) {
            break;
        }
        let (_, response) = call(&admin, "x:QueuedMessage/get", json!({"ids": null})).await;
        if let Some(queued) = response["list"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m.to_string().contains("vault@elsewhere.org"))
        {
            let queued_id = queued["id"].as_str().unwrap().to_string();
            let (_, response) = call(
                &admin,
                "x:QueuedMessage/set",
                json!({"destroy": [queued_id.clone()]}),
            )
            .await;
            deleted = response["destroyed"] == json!([queued_id]);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let kept: Vec<Entry> = all_entries(test)
        .await
        .into_iter()
        .map(|(_, e)| e)
        .filter(|e| e.subject == "Marked journal-me")
        .collect();
    assert_eq!(kept.len(), 2, "{kept:?}");
    assert!(kept.iter().any(|e| e.journals == vec![number(&remote)]));
    let (_, response) = call(
        &admin,
        "inbuxa:Journal/get",
        json!({"ids": [remote.clone()]}),
    )
    .await;
    let failures = &response["list"][0]["archiveFailures"];
    assert_eq!(failures["count"], 1, "{response}");
    assert_eq!(
        failures["lastReason"],
        if deleted {
            "it wasn't delivered before leaving the queue"
        } else {
            "the archive refused it"
        },
        "{response}"
    );
    let (_, response) = call(
        &admin,
        "inbuxa:Journal/get",
        json!({"ids": [local.clone()]}),
    )
    .await;
    assert_eq!(response["list"][0]["archiveFailures"]["count"], 0);

    // Delivered to an archive here: the report arrives, and nothing goes
    // into the built-in journal for that journal
    let response = send(
        &sender,
        &identity,
        &mailbox,
        &["someone@elsewhere.org"],
        &["someone@elsewhere.org"],
        "To the vault",
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
    let mut arrived = Vec::new();
    for _ in 0..100 {
        let (_, response) = call(
            &vault,
            "Email/query",
            json!({"filter": {"subject": "Journal report: To the vault"}}),
        )
        .await;
        arrived = response["ids"].as_array().cloned().unwrap_or_default();
        if !arrived.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(arrived.len(), 1, "the report arrived");
    assert!(entry_for(test, "To the vault").await.is_none());
    assert!(
        all_entries(test)
            .await
            .iter()
            .all(|(_, e)| !e.subject.starts_with("Journal report")),
        "reports aren't journaled"
    );
    let (_, response) = call(
        &admin,
        "inbuxa:Journal/get",
        json!({"ids": [local.clone()]}),
    )
    .await;
    assert_eq!(response["list"][0]["archiveFailures"]["count"], 0);

    call(&admin, "inbuxa:MailRule/set", json!({"destroy": [rule]})).await;
    call(
        &admin,
        "inbuxa:Journal/set",
        json!({"destroy": [rules_only, local, remote]}),
    )
    .await;
    inbuxa_features::journal::invalidate();
}

/// Phase 4: searching, reading and exporting over JMAP, by a Compliance
/// Officer, each recorded; administrators set journals up but don't read
/// them; the chain check.
pub async fn search(test: &mut TestServer) {
    println!("Running journal search tests...");
    let admin = test.account("admin@example.com");
    let sender = admin
        .create_user_account(
            "search-sender@example.com",
            "search-sender-secret-7301",
            "Search sender",
            &[],
            vec![],
        )
        .await;
    let (_, response) = call(
        &sender,
        "Identity/set",
        json!({"create": {"i": {"name": "Sender", "email": "search-sender@example.com"}}}),
    )
    .await;
    let identity = response["created"]["i"]["id"].as_str().unwrap().to_string();
    let (_, response) = call(
        &sender,
        "Mailbox/set",
        json!({"create": {"m": {"name": "Search drafts"}}}),
    )
    .await;
    let mailbox = response["created"]["m"]["id"].as_str().unwrap().to_string();
    let (_, response) = call(
        &admin,
        "inbuxa:Journal/set",
        json!({"create": {"s": {"name": "Search sender", "enabled": true, "direction": "any",
            "scope": {"accounts": [sender.id_string()]}, "retentionDays": 30}}}),
    )
    .await;
    let journal_id = response["created"]["s"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    inbuxa_features::journal::invalidate();
    for subject in ["Budget draft", "Budget final", "Lunch"] {
        let response = send(
            &sender,
            &identity,
            &mailbox,
            &["someone@elsewhere.org"],
            &["someone@elsewhere.org"],
            subject,
        )
        .await;
        assert!(response["created"].get("s").is_some(), "{response}");
    }

    // Administrators set journals up but don't read them
    let (name, response) = call(
        &admin,
        "inbuxa:JournalEntry/query",
        json!({"filter": {"sender": "search-sender"}}),
    )
    .await;
    assert_eq!(name, "error", "{response}");

    // A Compliance Officer does
    let mut officer_role = None;
    for id in admin
        .registry_query_ids(
            ObjectType::Role,
            Vec::<(&str, &str)>::new(),
            Vec::<&str>::new(),
        )
        .await
    {
        let role = admin.registry_get::<Role>(id).await;
        if role.description == "Compliance Officer" && role.member_tenant_id.is_none() {
            officer_role = Some(id);
        }
    }
    let officer = admin
        .create_user_account(
            "journal-officer@example.com",
            "journal-officer-secret-7302",
            "Officer",
            &[],
            vec![],
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            officer.id(),
            json!({Property::Roles: UserRoles::Custom(CustomRoles {
                role_ids: Map::new(vec![officer_role.expect("the officer role")]),
            })}),
        )
        .await;
    let (_, response) = call(
        &officer,
        "inbuxa:JournalEntry/query",
        json!({"filter": {"sender": "search-sender", "text": "budget"}, "calculateTotal": true}),
    )
    .await;
    assert_eq!(response["total"], 2, "{response}");
    let ids = response["ids"].clone();
    let (_, response) = call(&officer, "inbuxa:JournalEntry/get", json!({"ids": ids})).await;
    let list = response["list"].as_array().unwrap();
    assert_eq!(list.len(), 2, "{response}");
    assert_eq!(list[0]["subject"], "Budget final", "newest first");
    assert_eq!(list[0]["direction"], "outgoing");
    assert_eq!(list[0]["journalIds"], json!([journal_id]));
    assert!(list[0]["report"].is_null(), "only when asked for");
    let first = list[0]["id"].as_str().unwrap().to_string();
    let (_, response) = call(
        &officer,
        "inbuxa:JournalEntry/get",
        json!({"ids": [first.clone()], "properties": ["subject", "report"]}),
    )
    .await;
    let report = response["list"][0]["report"].as_str().unwrap_or_default();
    assert!(
        report.contains("Subject: Journal report: Budget final"),
        "{response}"
    );
    assert!(report.contains("Sender: search-sender@example.com\r\n"));
    let (_, response) = call(
        &officer,
        "inbuxa:JournalEntry/query",
        json!({"filter": {"journalId": journal_id, "direction": "incoming"}}),
    )
    .await;
    assert_eq!(response["ids"], json!([]), "{response}");
    let (name, _) = call(
        &officer,
        "inbuxa:JournalEntry/query",
        json!({"filter": {"colour": "red"}}),
    )
    .await;
    assert_eq!(name, "error");

    // Exports need a reason, and hold every report the filter matches
    let (_, response) = call(
        &officer,
        "inbuxa:JournalExport/set",
        json!({"create": {"x": {"filter": {"sender": "search-sender"}}}}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["x"]["properties"],
        json!(["reason"]),
        "{response}"
    );
    let (_, response) = call(
        &officer,
        "inbuxa:JournalExport/set",
        json!({"create": {"x": {"filter": {"sender": "search-sender"}, "reason": "Case 12"}}}),
    )
    .await;
    let export = &response["created"]["x"];
    assert_eq!(export["count"], 3, "{response}");
    assert!(export["blobId"].as_str().is_some());
    assert_eq!(export["sha256"].as_str().map(str::len), Some(64));

    // The chain check, which the officer may run too
    let (_, response) = call(
        &officer,
        "inbuxa:JournalVerification/set",
        json!({"create": {"v": {}}}),
    )
    .await;
    assert_eq!(response["created"]["v"]["verified"], true, "{response}");

    // The officer changes no journals
    let (name, _) = call(
        &officer,
        "inbuxa:Journal/set",
        json!({"destroy": [journal_id.clone()]}),
    )
    .await;
    assert_eq!(name, "error");

    // Every search, listing, read, export and check is recorded
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:JournalEntry", "actorId": officer.id_string()}}),
    )
    .await;
    let ids = response["ids"].clone();
    let (_, response) = call(&admin, "inbuxa:AuditEvent/get", json!({"ids": ids})).await;
    let details: Vec<String> = response["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| format!("{} {}", e["action"], e["details"]))
        .collect();
    for expected in [
        "Searched the journal",
        "Listed 2 journal entries",
        "Read a journaled message from search-sender@example.com",
        "Exported 3 journal entries",
        "verify",
    ] {
        assert!(
            details.iter().any(|d| d.contains(expected)),
            "{expected}: {details:?}"
        );
    }

    call(
        &admin,
        "inbuxa:Journal/set",
        json!({"destroy": [journal_id]}),
    )
    .await;
    inbuxa_features::journal::invalidate();
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
    self::archive(&mut test).await;
    self::search(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
