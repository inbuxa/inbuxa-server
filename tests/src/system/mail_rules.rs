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
    "urn:inbuxa:jmap",
    "urn:inbuxa:jmap:registry",
];

async fn call(account: &Account, method: &str, mut arguments: Value) -> (String, Value) {
    if arguments.get("accountId").is_none() {
        arguments["accountId"] = account.id_string().into();
    }
    let response = account.jmap_request(USING, json!([[method, arguments, "0"]])).await;
    let call = response
        .0
        .pointer("/methodResponses/0")
        .cloned()
        .unwrap_or_else(|| panic!("{method}: {}", response.0));
    (call[0].as_str().unwrap_or_default().to_string(), call[1].clone())
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
    assert_eq!(rule["conditions"][1]["detectors"][0]["atLeast"], 5, "{rule}");
    assert_eq!(rule["actions"][0]["notifySender"], true);
    assert_eq!(rule["createdBy"], "admin@example.com");
    assert!(rule["createdAt"].as_str().is_some_and(|d| d.ends_with('Z')), "{rule}");

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
    assert_eq!(response["notCreated"]["a"]["properties"][0], "direction", "{response}");
    assert!(
        response["notCreated"]["b"]["description"].as_str().unwrap().contains("no-such-detector"),
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
    assert!(response["updated"].get(transport_id.as_str()).is_some(), "{response}");
    assert_eq!(response["notUpdated"][dlp_id.as_str()]["properties"][0], "createdBy", "{response}");
    assert_eq!(names(&admin).await, vec!["Cards leaving", "Footer"]);

    // A compliance officer sees DLP rules, not mail flow rules, and changes
    // neither (settled answer 4)
    let mut officer_role = None;
    for id in admin
        .registry_query_ids(ObjectType::Role, Vec::<(&str, &str)>::new(), Vec::<&str>::new())
        .await
    {
        let role = admin.registry_get::<Role>(id).await;
        if role.description == "Compliance Officer" && role.member_tenant_id.is_none() {
            officer_role = Some(id);
        }
    }
    let officer = admin
        .create_user_account("rules-officer@example.com", "officer-secret-7731", "Officer", &[], vec![])
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
    let (name, response) =
        call(&officer, "inbuxa:MailRule/set", json!({"create": {"d": dlp_rule()}})).await;
    assert_eq!(name, "error", "the officer created a DLP rule: {response}");

    // Deleted
    let (_, response) = call(
        &admin,
        "inbuxa:MailRule/set",
        json!({"destroy": [transport_id]}),
    )
    .await;
    assert_eq!(response["destroyed"][0], transport_id.as_str(), "{response}");
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
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
