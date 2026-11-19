/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Passkey` management (passkeys spec, PK-5, PK-14 to PK-17):
//! starting a registration, the limit per account, renaming, removing, who
//! reaches whose passkeys, and the audit log.

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

async fn list(account: &Account, of: &Account) -> Vec<Value> {
    let (name, response) = call(
        account,
        "inbuxa:Passkey/get",
        json!({"accountId": of.id_string(), "ids": null}),
    )
    .await;
    assert_eq!(name, "inbuxa:Passkey/get", "{response}");
    response["list"].as_array().unwrap().clone()
}

pub async fn test(test: &mut TestServer) {
    println!("Running passkey tests...");
    let admin = test.account("admin@example.com");
    let user = admin
        .create_user_account(
            "passkey-user@example.com",
            "passkey-secret-5521",
            "Passkey user",
            &[],
            vec![],
        )
        .await;
    let other = admin
        .create_user_account(
            "passkey-other@example.com",
            "passkey-other-6634",
            "Other user",
            &[],
            vec![],
        )
        .await;

    // PK-5: creating starts a registration: a pending passkey and the page
    // that finishes it
    let (_, response) = call(
        &user,
        "inbuxa:Passkey/set",
        json!({"create": {"phone": {"name": "  Phone  "}}}),
    )
    .await;
    let created = &response["created"]["phone"];
    let phone_id = created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("not created: {response}"))
        .to_string();
    assert_eq!(created["state"], "pending", "{response}");
    let url = created["registrationUrl"].as_str().unwrap_or_default();
    assert!(
        url.starts_with("https://") && url.contains("/passkey/register?ticket="),
        "{response}"
    );

    let mine = list(&user, &user).await;
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert_eq!(mine[0]["name"], "Phone");
    assert_eq!(mine[0]["state"], "pending");
    assert_eq!(mine[0]["usable"], false);
    assert_eq!(mine[0]["accountId"], user.id_string());
    // The ticket is shown once, when the registration starts
    assert_eq!(mine[0]["registrationUrl"], Value::Null, "{mine:?}");

    // A name is required, and what the server sets can't be sent
    let (_, response) = call(
        &user,
        "inbuxa:Passkey/set",
        json!({"create": {
            "blank": {"name": "   "},
            "none": {},
            "state": {"name": "Key", "state": "active"}
        }}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["blank"]["properties"][0], "name",
        "{response}"
    );
    assert_eq!(
        response["notCreated"]["none"]["properties"][0], "name",
        "{response}"
    );
    assert_eq!(
        response["notCreated"]["state"]["properties"][0], "state",
        "{response}"
    );

    // PK-14: only the name changes
    let (_, response) = call(
        &user,
        "inbuxa:Passkey/set",
        json!({"update": {
            phone_id.as_str(): {"name": "Work phone"}
        }}),
    )
    .await;
    assert!(
        response["updated"].get(phone_id.as_str()).is_some(),
        "{response}"
    );
    let (_, response) = call(
        &user,
        "inbuxa:Passkey/set",
        json!({"update": {phone_id.as_str(): {"rpId": "example.com"}}}),
    )
    .await;
    assert_eq!(
        response["notUpdated"][phone_id.as_str()]["properties"][0],
        "rpId",
        "{response}"
    );
    assert_eq!(list(&user, &user).await[0]["name"], "Work phone");

    // PK-5: ten per account, pending ones included
    let mut create = serde_json::Map::new();
    for n in 0..10 {
        create.insert(format!("k{n}"), json!({"name": format!("Key {n}")}));
    }
    let (_, response) = call(&user, "inbuxa:Passkey/set", json!({"create": create})).await;
    let made = response["created"].as_object().map_or(0, |m| m.len());
    assert_eq!(made, 9, "{response}");
    let over = response["notCreated"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(over["type"], "overQuota", "{response}");
    assert_eq!(list(&user, &user).await.len(), 10);

    // Someone else's passkeys are out of reach for an ordinary account
    let (name, response) = call(
        &other,
        "inbuxa:Passkey/get",
        json!({"accountId": user.id_string(), "ids": null}),
    )
    .await;
    assert_eq!(name, "error", "another user read passkeys: {response}");
    let (_, response) = call(
        &other,
        "inbuxa:Passkey/set",
        json!({"accountId": user.id_string(), "destroy": [phone_id]}),
    )
    .await;
    assert!(
        response["destroyed"]
            .as_array()
            .is_none_or(|d| d.is_empty()),
        "another user removed a passkey: {response}"
    );
    assert!(list(&other, &other).await.is_empty());

    // PK-16: an administrator sees and removes them
    let seen = list(&admin, &user).await;
    assert_eq!(seen.len(), 10, "{seen:?}");
    let all_ids = seen
        .iter()
        .map(|p| p["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let (_, response) = call(
        &admin,
        "inbuxa:Passkey/set",
        json!({"accountId": user.id_string(), "destroy": all_ids}),
    )
    .await;
    assert_eq!(
        response["destroyed"].as_array().map_or(0, |d| d.len()),
        10,
        "{response}"
    );
    assert!(list(&user, &user).await.is_empty());

    // PK-17: made and removed are in the audit log, by name
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:Passkey"}}),
    )
    .await;
    let ids = response["ids"].clone();
    let (_, response) = call(&admin, "inbuxa:AuditEvent/get", json!({"ids": ids})).await;
    let events = response["list"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "create" && e["outcome"]["status"] == "success"),
        "{response}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "destroy" && e["target"]["name"] == "Work phone"),
        "no removal recorded by name: {response}"
    );
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn passkey_tests() {
    let mut test = TestServerBuilder::new("passkey_tests")
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
