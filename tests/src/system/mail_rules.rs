/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:MailRule` (dlp-and-mail-flow-rules spec, §2.2, §2.8): rules are
//! stored, listed in the order they run, checked when written, kept apart
//! by kind for permissions, and every change is audited.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{CustomRoles, Role, UserRoles},
};
use registry::types::map::Map;
use serde_json::{Value, json};

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

fn dlp_rule() -> Value {
    json!({
        "name": "Cards leaving",
        "kind": "dlp",
        "direction": "outgoing",
        "priority": 10,
        "conditions": [
            {"type": "recipientOutside"},
            {"type": "detected", "detectors": [{"id": "payment-card", "atLeast": 5}]}
        ],
        "actions": [{"type": "hold", "notice": "Held for review", "notifySender": true}]
    })
}

fn transport_rule() -> Value {
    json!({
        "name": "Disclaimer",
        "kind": "transport",
        "direction": "outgoing",
        "priority": 1,
        "conditions": [{"type": "recipientOutside"}],
        "actions": [{"type": "addDisclaimer", "text": "Sent by Example Co.", "position": "bottom"}]
    })
}

async fn names(account: &Account) -> Vec<String> {
    let (name, response) = call(account, "inbuxa:MailRule/get", json!({"ids": null})).await;
    assert_eq!(name, "inbuxa:MailRule/get", "{response}");
    response["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect()
}

pub async fn test(test: &mut TestServer) {
    println!("Running mail rule tests...");
    let admin = test.account("admin@example.com");

    // Created, then listed in the order they run
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"create": {"d": dlp_rule(), "t": transport_rule()}}),
    )
    .await;
    let dlp_id = response["created"]["d"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("DLP rule created: {response}"))
        .to_string();
    let transport_id = response["created"]["t"]["id"].as_str().unwrap().to_string();
    assert_eq!(names(&admin).await, vec!["Disclaimer", "Cards leaving"]);

    let (_, response) = call(&admin, "inbuxa:MailRule/get", json!({"ids": [dlp_id]})).await;
    let rule = &response["list"][0];
    assert_eq!(
        rule["conditions"][1]["detectors"][0]["atLeast"], 5,
        "{rule}"
    );
    assert_eq!(rule["actions"][0]["notifySender"], true);
    assert_eq!(rule["createdBy"], "admin@example.com");
    assert!(
        rule["createdAt"].as_str().is_some_and(|d| d.ends_with('Z')),
        "{rule}"
    );

    // Checked when written
    let mut inbound = dlp_rule();
    inbound["direction"] = "incoming".into();
    let mut unknown = dlp_rule();
    unknown["conditions"][1]["detectors"][0]["id"] = "no-such-detector".into();
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"create": {"a": inbound, "b": unknown, "c": {"name": "x", "kind": "dlp"}}}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["a"]["properties"][0], "direction",
        "{response}"
    );
    assert!(
        response["notCreated"]["b"]["description"]
            .as_str()
            .unwrap()
            .contains("no-such-detector"),
        "{response}"
    );
    assert!(response["notCreated"].get("c").is_some(), "{response}");

    // Changed in place; what the server sets can't be sent
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"update": {
            transport_id.as_str(): {"name": "Footer", "priority": 50},
            dlp_id.as_str(): {"createdBy": "someone else"}
        }}),
    )
    .await;
    assert!(
        response["updated"].get(transport_id.as_str()).is_some(),
        "{response}"
    );
    assert_eq!(
        response["notUpdated"][dlp_id.as_str()]["properties"][0],
        "createdBy",
        "{response}"
    );
    assert_eq!(names(&admin).await, vec!["Cards leaving", "Footer"]);

    // A compliance officer sees DLP rules, not mail flow rules, and changes
    // neither (settled answer 4)
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
            "rules-officer@example.com",
            "officer-secret-7731",
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
    assert_eq!(names(&officer).await, vec!["Cards leaving"]);
    let (name, response) = call(
        &officer,
        "inbuxa:MailRule/set",
        json!({"create": {"d": dlp_rule()}}),
    )
    .await;
    assert_eq!(name, "error", "the officer created a DLP rule: {response}");

    // Deleted
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"destroy": [transport_id]}),
    )
    .await;
    assert_eq!(
        response["destroyed"][0],
        transport_id.as_str(),
        "{response}"
    );
    assert_eq!(names(&admin).await, vec!["Cards leaving"]);

    // Every change is in the audit log
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:MailRule"}, "calculateTotal": true}),
    )
    .await;
    assert!(
        response["total"].as_u64().unwrap_or(0) >= 4,
        "creates, update and destroy audited: {response}"
    );
}

/// A draft from `sender`, submitted; the submission call's response.
async fn submit(
    sender: &Account,
    identity: &str,
    mailbox: &str,
    to: &[&str],
    subject: &str,
    body: &str,
    dlp_override: Option<&str>,
) -> Value {
    let (_, response) = call(
        sender,
        "Email/set",
        json!({"create": {"e": {
            "mailboxIds": {mailbox: true},
            "from": [{"email": sender.name()}],
            "to": to.iter().map(|a| json!({"email": a})).collect::<Vec<_>>(),
            "subject": subject,
            "bodyValues": {"b": {"value": body}},
            "textBody": [{"partId": "b", "type": "text/plain"}]
        }}}),
    )
    .await;
    let email = response["created"]["e"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("draft: {response}"))
        .to_string();
    let mut create = json!({"emailId": email, "identityId": identity});
    if let Some(reason) = dlp_override {
        create["inbuxa:dlpOverride"] = json!({"reason": reason});
    }
    call(
        sender,
        "EmailSubmission/set",
        json!({"create": {"s": create}}),
    )
    .await
    .1
}

/// DLP at DATA (§2.4–§2.7): a warning answered with a reason, a block no
/// reason answers, the subject tag, and records that name the rules and
/// counts but never what was found.
pub async fn dlp(test: &mut TestServer) {
    println!("Running DLP sending tests...");
    let admin = test.account("admin@example.com");
    let sender = admin
        .create_user_account(
            "dlp-sender@example.com",
            "dlp-sender-secret-5501",
            "DLP sender",
            &[],
            vec![],
        )
        .await;
    let (_, response) = call(
        &sender,
        "Identity/set",
        json!({"create": {"i": {"name": "Sender", "email": "dlp-sender@example.com"}}}),
    )
    .await;
    let identity = response["created"]["i"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let (_, response) = call(
        &sender,
        "Mailbox/set",
        json!({"create": {"m": {"name": "DLP drafts"}}}),
    )
    .await;
    let mailbox = response["created"]["m"]["id"].as_str().unwrap().to_string();
    let outside = ["someone@elsewhere.org"];
    let card = "Card 4242 4242 4242 4242, expires 12/31";

    // No rules: sent
    let response = submit(
        &sender, &identity, &mailbox, &outside, "Numbers", card, None,
    )
    .await;
    assert!(
        response["created"].get("s").is_some(),
        "no rules: {response}"
    );

    // A warning: refused with the rule and its notice, then sent with a reason
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"create": {"w": {
            "name": "Cards leaving", "kind": "dlp", "direction": "outgoing",
            "conditions": [{"type": "recipientOutside"},
                {"type": "detected", "detectors": [{"id": "payment-card"}]}],
            "actions": [{"type": "warn", "notice": "This looks like a card number."}]
        }}}),
    )
    .await;
    let warn_rule = response["created"]["w"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let response = submit(
        &sender, &identity, &mailbox, &outside, "Numbers", card, None,
    )
    .await;
    let refused = &response["notCreated"]["s"];
    assert_eq!(refused["type"], "inbuxa:dlpWarning", "{response}");
    assert_eq!(refused["rules"][0]["name"], "Cards leaving");
    assert_eq!(refused["description"], "This looks like a card number.");
    // Inside the server: no warning
    let response = submit(
        &sender,
        &identity,
        &mailbox,
        &["dlp-sender@example.com"],
        "Numbers",
        card,
        None,
    )
    .await;
    assert!(
        response["created"].get("s").is_some(),
        "local recipient: {response}"
    );
    let response = submit(
        &sender,
        &identity,
        &mailbox,
        &outside,
        "Numbers",
        card,
        Some("The client asked for it"),
    )
    .await;
    assert!(
        response["created"].get("s").is_some(),
        "overridden: {response}"
    );

    // A block: no reason gets past it
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"create": {"b": {
            "name": "Keys", "kind": "dlp", "direction": "outgoing",
            "conditions": [{"type": "detected", "detectors": [{"id": "private-key"}]}],
            "actions": [{"type": "block", "notice": "Private keys don't leave by mail."}]
        }}}),
    )
    .await;
    assert!(response["created"].get("b").is_some(), "{response}");
    let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----";
    let response = submit(
        &sender,
        &identity,
        &mailbox,
        &outside,
        "Key",
        key,
        Some("Please"),
    )
    .await;
    assert_eq!(
        response["notCreated"]["s"]["type"], "inbuxa:dlpBlocked",
        "{response}"
    );

    // The subject tag overrides, and doesn't go out: the sender's own copy
    // arrives without it
    let response = submit(
        &sender,
        &identity,
        &mailbox,
        &["someone@elsewhere.org", "dlp-sender@example.com"],
        "[override: Agreed with finance] Tagged numbers",
        card,
        None,
    )
    .await;
    assert!(
        response["created"].get("s").is_some(),
        "tag override: {response}"
    );
    let mut delivered = Vec::new();
    for _ in 0..50 {
        let (_, response) = call(
            &sender,
            "Email/query",
            json!({"filter": {"text": "Tagged"}}),
        )
        .await;
        let ids = response["ids"].clone();
        let (_, response) = call(
            &sender,
            "Email/get",
            json!({"ids": ids, "properties": ["subject", "mailboxIds"]}),
        )
        .await;
        delivered = response["list"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| !e["mailboxIds"].as_object().unwrap().contains_key(&mailbox))
            .map(|e| e["subject"].as_str().unwrap_or_default().to_string())
            // The bounce for the unreachable outside address quotes it
            .filter(|subject| !subject.starts_with("Failed to deliver"))
            .collect();
        if !delivered.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert_eq!(
        delivered,
        vec!["Tagged numbers".to_string()],
        "delivered subject"
    );

    // Recorded: sender, what happened, rules and counts, the reason; never
    // the number itself
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "message"}}),
    )
    .await;
    let ids = response["ids"].clone();
    let (_, response) = call(&admin, "inbuxa:AuditEvent/get", json!({"ids": ids})).await;
    let events = response["list"].as_array().unwrap();
    let details: Vec<&str> = events
        .iter()
        .filter_map(|e| e["details"].as_str())
        .collect();
    assert!(
        details
            .iter()
            .any(|d| d
                .starts_with("DLP warned, to elsewhere.org: \"Cards leaving\" (payment-card 1)")),
        "{details:?}"
    );
    assert!(
        details.iter().any(|d| d.starts_with("DLP blocked")),
        "{details:?}"
    );
    assert!(
        events.iter().any(
            |e| e["reason"] == "The client asked for it" && e["outcome"]["status"] == "success"
        ),
        "{response}"
    );
    assert!(
        events.iter().any(|e| e["reason"] == "Agreed with finance"),
        "{response}"
    );
    assert!(
        events
            .iter()
            .all(|e| e["actor"]["name"] == "dlp-sender@example.com"),
        "{response}"
    );
    let all = response.to_string();
    assert!(
        !all.contains("4242") && !all.contains("b3BlbnNz"),
        "matched text in the audit log"
    );

    // Rules off again for the tests that follow
    call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"destroy": [warn_rule]}),
    )
    .await;
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn mail_rules_tests() {
    let mut test = TestServerBuilder::new("mail_rules_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.com").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    self::dlp(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
