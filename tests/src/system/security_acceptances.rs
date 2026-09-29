/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:SecurityAcceptance` (security to-do list spec, SS-23 to SS-26):
//! an accepted item is kept with who, when and why, a note is required,
//! nothing is edited, only administrators may accept, and every acceptance
//! made or removed is in the audit log.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
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

async fn list(account: &Account) -> Vec<Value> {
    let (name, response) = call(
        account,
        "inbuxa:SecurityAcceptance/get",
        json!({"ids": null}),
    )
    .await;
    assert_eq!(name, "inbuxa:SecurityAcceptance/get", "{response}");
    response["list"].as_array().unwrap().clone()
}

pub async fn test(test: &mut TestServer) {
    println!("Running security acceptance tests...");
    let admin = test.account("admin@example.com");

    // Accepted, with the server's who and when
    let (_, response) = call(
        &admin,
        "inbuxa:SecurityAcceptance/set",
        json!({"create": {
            "plain": {
                "check": "SS-1",
                "subject": "",
                "acceptedValue": true,
                "note": "  Old scanners on the LAN; replaced in March.  "
            },
            "relay": {
                "check": "SS-2",
                "acceptedValue": {"match": {}, "else": "is_local_ip(remote_ip)"},
                "note": "The office printer relays through us."
            }
        }}),
    )
    .await;
    let plain_id = response["created"]["plain"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("accepted: {response}"))
        .to_string();
    assert_eq!(
        response["created"]["plain"]["acceptedBy"], "admin@example.com",
        "{response}"
    );
    let relay_id = response["created"]["relay"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let all = list(&admin).await;
    assert_eq!(all.len(), 2, "{all:?}");
    let plain = all.iter().find(|a| a["id"] == plain_id.as_str()).unwrap();
    assert_eq!(plain["check"], "SS-1");
    assert_eq!(plain["subject"], "");
    assert_eq!(plain["acceptedValue"], true);
    assert_eq!(plain["note"], "Old scanners on the LAN; replaced in March.");
    assert!(
        plain["acceptedAt"]
            .as_str()
            .is_some_and(|d| d.ends_with('Z')),
        "{plain}"
    );
    let relay = all.iter().find(|a| a["id"] == relay_id.as_str()).unwrap();
    assert_eq!(relay["acceptedValue"]["else"], "is_local_ip(remote_ip)");

    // A note is required, the check must be one of ours, and what the
    // server sets can't be sent
    let (_, response) = call(
        &admin,
        "inbuxa:SecurityAcceptance/set",
        json!({"create": {
            "nonote": {"check": "SS-1", "acceptedValue": true, "note": "   "},
            "nocheck": {"check": "SS-99", "acceptedValue": true, "note": "x"},
            "by": {"check": "SS-1", "acceptedValue": true, "note": "x", "acceptedBy": "someone"}
        }}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["nonote"]["properties"][0], "note",
        "{response}"
    );
    assert_eq!(
        response["notCreated"]["nocheck"]["properties"][0], "check",
        "{response}"
    );
    assert_eq!(
        response["notCreated"]["by"]["properties"][0], "acceptedBy",
        "{response}"
    );
    assert_eq!(list(&admin).await.len(), 2);

    // Replaced, never edited
    let (name, response) = call(
        &admin,
        "inbuxa:SecurityAcceptance/set",
        json!({"update": {plain_id.as_str(): {"note": "changed"}}}),
    )
    .await;
    assert_eq!(name, "error", "an acceptance was edited: {response}");

    // Only administrators: someone without the permissions neither sees
    // nor accepts
    let user = admin
        .create_user_account(
            "security-user@example.com",
            "user-secret-8812",
            "User",
            &[],
            vec![],
        )
        .await;
    let (name, response) = call(
        &user,
        "inbuxa:SecurityAcceptance/set",
        json!({"create": {"x": {"check": "SS-1", "acceptedValue": true, "note": "mine"}}}),
    )
    .await;
    assert_eq!(name, "error", "a user accepted an item: {response}");
    let (name, response) = call(&user, "inbuxa:SecurityAcceptance/get", json!({"ids": null})).await;
    assert_eq!(name, "error", "a user read acceptances: {response}");

    // Removed
    let (_, response) = call(
        &admin,
        "inbuxa:SecurityAcceptance/set",
        json!({"destroy": [plain_id, "zzzzzz"]}),
    )
    .await;
    assert_eq!(response["destroyed"], json!([plain_id]), "{response}");
    assert!(
        response["notDestroyed"].get("zzzzzz").is_some(),
        "{response}"
    );
    let remaining = list(&admin).await;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0]["check"], "SS-2");

    // SS-26: accepted and removed are both in the audit log, with who and
    // what
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:SecurityAcceptance"}}),
    )
    .await;
    let ids = response["ids"].clone();
    let (_, response) = call(&admin, "inbuxa:AuditEvent/get", json!({"ids": ids})).await;
    let events = response["list"].as_array().unwrap();
    let created = events
        .iter()
        .filter(|e| e["action"] == "create" && e["outcome"]["status"] == "success")
        .count();
    assert_eq!(created, 2, "{response}");
    let removed = events
        .iter()
        .find(|e| e["action"] == "destroy" && e["outcome"]["status"] == "success")
        .unwrap_or_else(|| panic!("no removal recorded: {response}"));
    assert_eq!(removed["target"]["name"], "SS-1", "{removed}");
    assert!(
        events
            .iter()
            .all(|e| e["actor"]["name"] == "admin@example.com"),
        "{response}"
    );
    assert!(
        response.to_string().contains("Old scanners on the LAN"),
        "the note isn't in the record: {response}"
    );

    // Cleared for the tests that follow
    call(
        &admin,
        "inbuxa:SecurityAcceptance/set",
        json!({"destroy": [relay_id]}),
    )
    .await;
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn security_acceptance_tests() {
    let mut test = TestServerBuilder::new("security_acceptance_tests")
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
