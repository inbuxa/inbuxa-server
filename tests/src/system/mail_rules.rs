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
    smtp::SmtpConnection,
};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{CustomRoles, Expression, MtaStageAuth, Role, UserRoles},
};
use registry::types::map::Map;
use serde_json::{Value, json};
use std::str::FromStr;

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

    // Group and tenant ids travel in their JMAP form
    let mut by_tenant = transport_rule();
    by_tenant["name"] = "By tenant".into();
    by_tenant["conditions"] = json!([{"type": "senderTenant", "tenants": ["b"]}]);
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"create": {"g": by_tenant}}),
    )
    .await;
    let tenant_rule = response["created"]["g"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let (_, response) = call(&admin, "inbuxa:MailRule/get", json!({"ids": [tenant_rule]})).await;
    assert_eq!(
        response["list"][0]["conditions"][0]["tenants"],
        json!(["b"]),
        "{response}"
    );
    call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"destroy": [tenant_rule]}),
    )
    .await;

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
    assert_eq!(response["created"]["s"]["inbuxa:held"], false, "{response}");

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

/// The subjects, bodies and a header of what `account` received whose
/// subject contains `text`, polling until something arrives.
async fn received(
    account: &Account,
    text: &str,
    header: &str,
    drafts: Option<&str>,
) -> Vec<(String, String, String)> {
    for _ in 0..50 {
        // Not the sender's own draft
        let filter = match drafts {
            Some(drafts) => json!({"subject": text, "inMailboxOtherThan": [drafts]}),
            None => json!({"subject": text}),
        };
        let (_, response) = call(account, "Email/query", json!({"filter": filter})).await;
        let ids = response["ids"].clone();
        let (_, response) = call(
            account,
            "Email/get",
            json!({"ids": ids, "properties": ["subject", "bodyValues", "textBody", format!("header:{header}:asText")],
                   "fetchTextBodyValues": true}),
        )
        .await;
        let list: Vec<(String, String, String)> = response["list"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| {
                !e["subject"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("Failed to deliver")
            })
            .map(|e| {
                let part = e["textBody"][0]["partId"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                (
                    e["subject"].as_str().unwrap_or_default().to_string(),
                    e["bodyValues"][part.as_str()]["value"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    e[format!("header:{header}:asText").as_str()]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                )
            })
            .collect();
        if !list.is_empty() {
            return list;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Vec::new()
}

/// Transport rules (§2.4): the actions that change a message, where it
/// goes, or refuse it, on outgoing and incoming mail.
pub async fn transport(test: &mut TestServer) {
    println!("Running mail flow action tests...");
    let admin = test.account("admin@example.com");
    let sender = admin
        .create_user_account(
            "flow-sender@example.com",
            "flow-sender-secret-6602",
            "Flow sender",
            &[],
            vec![],
        )
        .await;
    let other = admin
        .create_user_account(
            "flow-other@example.com",
            "flow-other-secret-6603",
            "Flow other",
            &[],
            vec![],
        )
        .await;
    let (_, response) = call(
        &sender,
        "Identity/set",
        json!({"create": {"i": {"name": "Sender", "email": "flow-sender@example.com"}}}),
    )
    .await;
    let identity = response["created"]["i"]["id"].as_str().unwrap().to_string();
    let (_, response) = call(
        &sender,
        "Mailbox/set",
        json!({"create": {"m": {"name": "Flow drafts"}}}),
    )
    .await;
    let mailbox = response["created"]["m"]["id"].as_str().unwrap().to_string();

    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"create": {
            "d": {"name": "Footer and tag", "kind": "transport", "direction": "outgoing",
                  "conditions": [{"type": "senderAddress", "addresses": ["flow-sender@example.com"]}],
                  "actions": [
                      {"type": "addDisclaimer", "text": "Sent by Example Co.", "position": "bottom"},
                      {"type": "addHeader", "name": "X-Flow", "value": "checked"},
                      {"type": "prefixSubject", "text": "[Example]"}
                  ]},
            "r": {"name": "Redirect projects", "kind": "transport", "direction": "outgoing",
                  "conditions": [{"type": "words", "words": ["project falcon"]}],
                  "actions": [{"type": "redirect", "addresses": ["flow-other@example.com"]}]},
            "x": {"name": "No invoices", "kind": "transport", "direction": "outgoing",
                  "conditions": [{"type": "words", "words": ["invoice-scam"]}],
                  "actions": [{"type": "refuse", "text": "This kind of message isn't sent from here."}]},
            "i": {"name": "Outside banner", "kind": "transport", "direction": "incoming",
                  "conditions": [], "actions": [{"type": "prefixSubject", "text": "[External]"}]}
        }}),
    )
    .await;
    assert_eq!(
        response["created"].as_object().map(|c| c.len()),
        Some(4),
        "{response}"
    );

    // Disclaimer, header and subject prefix on the sender's own copy
    let response = submit(
        &sender,
        &identity,
        &mailbox,
        &["flow-sender@example.com"],
        "Lunch",
        "See you at noon.",
        None,
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
    let got = received(&sender, "Lunch", "X-Flow", Some(&mailbox)).await;
    assert_eq!(got.len(), 1, "{got:?}");
    let (subject, body, header) = &got[0];
    assert_eq!(subject, "[Example] Lunch");
    assert!(
        body.starts_with("See you at noon.") && body.trim_end().ends_with("Sent by Example Co."),
        "{body:?}"
    );
    assert_eq!(header.trim(), "checked");

    // Redirected: the other user gets it, the named recipient doesn't
    let response = submit(
        &sender,
        &identity,
        &mailbox,
        &["flow-sender@example.com"],
        "Falcon",
        "About Project Falcon.",
        None,
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
    assert_eq!(
        received(&other, "Falcon", "X-Flow", None).await.len(),
        1,
        "redirected"
    );
    assert!(
        received(&sender, "Falcon", "X-Flow", Some(&mailbox))
            .await
            .is_empty(),
        "the named recipient didn't get it"
    );

    // Refused
    let response = submit(
        &sender,
        &identity,
        &mailbox,
        &["flow-sender@example.com"],
        "Pay",
        "invoice-scam inside",
        None,
    )
    .await;
    let refused = &response["notCreated"]["s"];
    assert_eq!(refused["type"], "forbiddenToSend", "{response}");
    assert!(
        refused["description"]
            .as_str()
            .unwrap_or_default()
            .contains("isn't sent from here"),
        "{response}"
    );

    // Incoming mail: the banner rule, and none of the outgoing ones
    // LMTP delivery without signing in, as mail from outside arrives
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
        &["flow-other@example.com"],
        "From: someone@elsewhere.org\r\nTo: flow-other@example.com\r\nSubject: Hello from outside\r\n\r\nHi.\r\n",
    )
    .await;
    let got = received(&other, "Hello from outside", "X-Flow", None).await;
    assert_eq!(
        got.first().map(|g| g.0.as_str()),
        Some("[External] Hello from outside"),
        "{got:?}"
    );
    assert!(
        got[0].2.is_empty(),
        "outgoing rules left incoming mail alone"
    );

    // The redirect and the refusal are recorded; the footer isn't
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "message", "text": "Mail flow"}}),
    )
    .await;
    let ids = response["ids"].clone();
    let (_, response) = call(&admin, "inbuxa:AuditEvent/get", json!({"ids": ids})).await;
    let details: Vec<String> = response["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["details"].as_str().map(str::to_string))
        .collect();
    assert!(
        details.iter().any(|d| d.starts_with(
            "Mail flow rule \"Redirect projects\" redirected to flow-other@example.com"
        )),
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .any(|d| d.starts_with("Mail flow rule \"No invoices\" refused")),
        "{details:?}"
    );
    assert!(
        !details.iter().any(|d| d.contains("Footer and tag")),
        "{details:?}"
    );

    // Off again
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/get",
        json!({"ids": null, "properties": ["id", "kind"]}),
    )
    .await;
    let transport: Vec<Value> = response["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["kind"] == "transport")
        .map(|r| r["id"].clone())
        .collect();
    call(&admin, "inbuxa:MailRule/set", json!({"destroy": transport})).await;
}

/// Hold for review (§2.6): held mail waits, shows in the review queue,
/// can't be sent around the review, and a reviewer releases or rejects it.
pub async fn hold(test: &mut TestServer) {
    println!("Running held mail tests...");
    let admin = test.account("admin@example.com");
    let sender = admin
        .create_user_account(
            "hold-sender@example.com",
            "hold-sender-secret-7703",
            "Hold sender",
            &[],
            vec![],
        )
        .await;
    let (_, response) = call(
        &sender,
        "Identity/set",
        json!({"create": {"i": {"name": "Sender", "email": "hold-sender@example.com"}}}),
    )
    .await;
    let identity = response["created"]["i"]["id"].as_str().unwrap().to_string();
    let (_, response) = call(
        &sender,
        "Mailbox/set",
        json!({"create": {"m": {"name": "Hold drafts"}}}),
    )
    .await;
    let mailbox = response["created"]["m"]["id"].as_str().unwrap().to_string();
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"create": {"h": {
            "name": "Hold cards", "kind": "dlp", "direction": "outgoing",
            "conditions": [{"type": "words", "words": ["hold-me"]},
                {"type": "detected", "detectors": [{"id": "payment-card"}]}],
            "actions": [{"type": "hold", "notice": "Card numbers are reviewed first.", "notifySender": true}]
        }}}),
    )
    .await;
    let rule = response["created"]["h"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    // How long held mail waits: 7 days unless set, from 1 to 90
    let (_, response) = call(&admin, "inbuxa:DlpSettings/get", json!({"ids": null})).await;
    assert_eq!(response["list"][0]["keepHeldDays"], 7, "{response}");
    let (_, response) = call(
        &admin,
        "inbuxa:DlpSettings/set",
        json!({"update": {"singleton": {"keepHeldDays": 0}}}),
    )
    .await;
    assert!(
        response["notUpdated"].get("singleton").is_some(),
        "{response}"
    );
    let (_, response) = call(
        &admin,
        "inbuxa:DlpSettings/set",
        json!({"update": {"singleton": {"keepHeldDays": 3}}}),
    )
    .await;
    assert!(response["updated"].get("singleton").is_some(), "{response}");
    let body = "hold-me: card 4242 4242 4242 4242";

    // Accepted, held, listed
    let response = submit(
        &sender,
        &identity,
        &mailbox,
        &["hold-sender@example.com"],
        "Held one",
        body,
        None,
    )
    .await;
    let submission = response["created"]["s"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("held, not refused: {response}"))
        .to_string();
    assert_eq!(response["created"]["s"]["inbuxa:held"], true, "{response}");
    let (_, response) = call(&admin, "inbuxa:HeldMessage/get", json!({"ids": null})).await;
    let list = response["list"]
        .as_array()
        .unwrap_or_else(|| panic!("{response}"));
    assert_eq!(list.len(), 1, "{response}");
    let first = list[0]["id"].as_str().unwrap().to_string();
    assert_eq!(list[0]["sender"], "hold-sender@example.com");
    assert_eq!(list[0]["subject"], "Held one");
    assert_eq!(list[0]["rules"][0]["name"], "Hold cards");
    let span = chrono_seconds(list[0]["expiresAt"].as_str().unwrap())
        - chrono_seconds(list[0]["heldAt"].as_str().unwrap());
    assert_eq!(span, 3 * 86_400, "held for the days set");
    assert_eq!(
        list[0]["counts"],
        json!([{"detector": "words", "count": 1}, {"detector": "payment-card", "count": 1}])
    );
    assert!(
        list[0].get("preview").is_none(),
        "no preview unless asked for"
    );

    // The sender is told, and it isn't delivered
    let notice = received(
        &sender,
        "Held for review: Held one",
        "X-Flow",
        Some(&mailbox),
    )
    .await;
    assert!(
        notice[0].1.contains("Card numbers are reviewed first."),
        "{notice:?}"
    );
    assert!(
        received_now(&sender, "Held one", &mailbox)
            .await
            .iter()
            .all(|s| s.starts_with("Held for review"))
    );

    // Not around the review: not from the queue, not by unsending
    let (_, response) = call(
        &admin,
        "x:QueuedMessage/set",
        json!({"update": {first.as_str(): {"nextRetry": "2026-01-01T00:00:00Z"}}}),
    )
    .await;
    assert!(
        response["notUpdated"][first.as_str()]["description"]
            .as_str()
            .unwrap_or_default()
            .contains("held for review"),
        "{response}"
    );
    let (_, response) = call(&admin, "x:QueuedMessage/set", json!({"destroy": [first]})).await;
    assert!(
        response["notDestroyed"].get(first.as_str()).is_some(),
        "{response}"
    );
    let (_, response) = call(
        &sender,
        "EmailSubmission/set",
        json!({"update": {submission.as_str(): {"undoStatus": "canceled"}}}),
    )
    .await;
    assert_eq!(
        response["notUpdated"][submission.as_str()]["type"],
        "cannotUnsend",
        "{response}"
    );

    // Reading it is recorded
    let (_, response) = call(
        &admin,
        "inbuxa:HeldMessage/get",
        json!({"ids": [first], "properties": ["id", "preview"]}),
    )
    .await;
    assert!(
        response["list"][0]["preview"]
            .as_str()
            .unwrap_or_default()
            .contains("4242 4242"),
        "{response}"
    );
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:HeldMessage", "action": "blobAccess"}}),
    )
    .await;
    assert_eq!(
        response["ids"].as_array().map(|i| i.len()),
        Some(1),
        "{response}"
    );

    // Rejected: a reason is required; the sender gets the note
    let (_, response) = call(
        &admin,
        "inbuxa:HeldMessage/set",
        json!({"update": {first.as_str(): {"decision": "reject"}}}),
    )
    .await;
    assert!(
        response["notUpdated"].get(first.as_str()).is_some(),
        "no reason: {response}"
    );
    let (_, response) = call(
        &admin,
        "inbuxa:HeldMessage/set",
        json!({"reason": "Card data may not leave by mail", "update": {first.as_str(): {"decision": "reject", "note": "Use the payments portal."}}}),
    )
    .await;
    assert!(
        response["updated"].get(first.as_str()).is_some(),
        "{response}"
    );
    let notice = received(&sender, "Not sent: Held one", "X-Flow", Some(&mailbox)).await;
    assert!(
        notice[0].1.contains("Use the payments portal."),
        "{notice:?}"
    );
    let (_, response) = call(&admin, "x:QueuedMessage/get", json!({"ids": [first]})).await;
    assert_eq!(
        response["notFound"][0],
        first.as_str(),
        "gone from the queue: {response}"
    );

    // Released: delivered
    let response = submit(
        &sender,
        &identity,
        &mailbox,
        &["hold-sender@example.com"],
        "Held two",
        body,
        None,
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
    let (_, response) = call(&admin, "inbuxa:HeldMessage/get", json!({"ids": null})).await;
    let second = response["list"][0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let (_, response) = call(
        &admin,
        "inbuxa:HeldMessage/set",
        json!({"reason": "Finance approved", "update": {second.as_str(): {"decision": "release"}}}),
    )
    .await;
    assert!(
        response["updated"].get(second.as_str()).is_some(),
        "{response}"
    );
    let mut delivered = Vec::new();
    for _ in 0..50 {
        delivered = received_now(&sender, "Held two", &mailbox).await;
        if delivered.iter().any(|s| s == "Held two") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(delivered.iter().any(|s| s == "Held two"), "{delivered:?}");
    let (_, response) = call(&admin, "inbuxa:HeldMessage/get", json!({"ids": null})).await;
    assert_eq!(
        response["list"].as_array().map(|l| l.len()),
        Some(0),
        "{response}"
    );

    // Both decisions are in the audit log, with their reasons
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:HeldMessage", "action": "update"}}),
    )
    .await;
    let ids = response["ids"].clone();
    let (_, response) = call(&admin, "inbuxa:AuditEvent/get", json!({"ids": ids})).await;
    let reasons: Vec<&str> = response["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["reason"].as_str())
        .collect();
    assert!(
        reasons.contains(&"Card data may not leave by mail")
            && reasons.contains(&"Finance approved"),
        "{response}"
    );

    // Unreviewed: returned by the daily clean-up once its time is up
    let response = submit(
        &sender,
        &identity,
        &mailbox,
        &["hold-sender@example.com"],
        "Held three",
        body,
        None,
    )
    .await;
    assert!(response["created"].get("s").is_some(), "{response}");
    let store = test.server.store();
    let mut record = inbuxa_features::mailflow::held::all(store)
        .await
        .unwrap()
        .pop()
        .expect("held");
    record.expires_at = 0;
    inbuxa_features::mailflow::held::create(store, &record)
        .await
        .unwrap();
    assert_eq!(smtp::queue::held::expire(&test.server).await.unwrap(), 1);
    assert!(
        inbuxa_features::mailflow::held::all(store)
            .await
            .unwrap()
            .is_empty()
    );
    let notice = received(&sender, "Not sent: Held three", "X-Flow", Some(&mailbox)).await;
    assert!(
        notice[0].1.contains("Nobody reviewed it within 3 days"),
        "{notice:?}"
    );
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:HeldMessage", "action": "destroy"}}),
    )
    .await;
    assert_eq!(
        response["ids"].as_array().map(|i| i.len()),
        Some(1),
        "expiry recorded: {response}"
    );

    call(&admin, "inbuxa:MailRule/set", json!({"destroy": [rule]})).await;
}

/// Seconds since the epoch of a UTC date the server wrote.
fn chrono_seconds(date: &str) -> i64 {
    jmap_proto::types::date::UTCDate::from_str(date)
        .map(|d| d.timestamp())
        .unwrap_or_default()
}

/// Subjects in `account` matching `text` right now, not in `drafts`.
async fn received_now(account: &Account, text: &str, drafts: &str) -> Vec<String> {
    let (_, response) = call(
        account,
        "Email/query",
        json!({"filter": {"subject": text, "inMailboxOtherThan": [drafts]}}),
    )
    .await;
    let ids = response["ids"].clone();
    let (_, response) = call(
        account,
        "Email/get",
        json!({"ids": ids, "properties": ["subject"]}),
    )
    .await;
    response["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["subject"].as_str().unwrap_or_default().to_string())
        .collect()
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
    self::transport(&mut test).await;
    self::hold(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
