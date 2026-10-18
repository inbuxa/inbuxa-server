/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A stored secret reads back as "****", and "****" is never saved as one:
//! written straight at a secret it keeps the stored one, anywhere else the
//! write is refused.

use crate::utils::{account::Account, server::TestServerBuilder};
use common::Server;
use registry::{
    schema::{
        prelude::{ObjectInner, ObjectType},
        structs::{HttpAuth, SecretKey, SecretKeyOptional, WebHook},
    },
    types::id::ObjectId,
};
use serde_json::{Value, json};
use std::str::FromStr;
use types::id::Id;

const USING: &[&str] = &["urn:ietf:params:jmap:core", "urn:inbuxa:jmap:registry"];

async fn webhook_set(admin: &Account, arguments: Value) -> Value {
    let mut arguments = arguments;
    arguments["accountId"] = admin.id_string().into();
    let response = admin
        .jmap_request(USING, json!([["x:WebHook/set", arguments, "0"]]))
        .await;
    let call = response.0.pointer("/methodResponses/0").cloned().unwrap();
    assert_eq!(call[0], "x:WebHook/set", "{call}");
    call[1].clone()
}

/// The webhook's Basic password and signature key as stored.
async fn stored_secrets(server: &Server, id: &str) -> (String, String) {
    let object = server
        .registry()
        .get(ObjectId::new(
            ObjectType::WebHook,
            Id::from_str(id).unwrap(),
        ))
        .await
        .unwrap()
        .expect("webhook not found");
    let ObjectInner::WebHook(WebHook {
        http_auth: HttpAuth::Basic(basic),
        signature_key,
        ..
    }) = object.inner
    else {
        panic!("not a webhook with Basic auth");
    };
    let SecretKey::Value(password) = basic.secret else {
        panic!("password not stored as a value");
    };
    let SecretKeyOptional::Value(signature) = signature_key else {
        panic!("signature key not stored as a value");
    };
    (password.secret, signature.secret)
}

fn assert_refused(response: &Value, key: &str, id: &str, property: &str) {
    let error = &response[key][id];
    assert_eq!(error["type"], "invalidProperties", "{response}");
    assert_eq!(error["properties"], json!([property]), "{response}");
}

#[tokio::test(flavor = "multi_thread")]
pub async fn masked_secrets_tests() {
    let test = TestServerBuilder::new("masked_secrets_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    println!("Running masked secret tests...");

    let response = webhook_set(
        &admin,
        json!({"create": {"hook": {
            "url": "https://hooks.example.org/inbuxa",
            "enable": false,
            "httpAuth": {"@type": "Basic", "username": "inbuxa",
                         "secret": {"@type": "Value", "secret": "basic-password"}},
            "signatureKey": {"@type": "Value", "secret": "signing-key"}
        }}}),
    )
    .await;
    let id = response["created"]["hook"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let original = ("basic-password".to_string(), "signing-key".to_string());
    assert_eq!(stored_secrets(&test.server, &id).await, original);

    // Read back, the secrets are masked
    let response = admin
        .jmap_request(
            USING,
            json!([["x:WebHook/get", {"accountId": admin.id_string(), "ids": [&id]}, "0"]]),
        )
        .await;
    let hook = response
        .0
        .pointer("/methodResponses/0/1/list/0")
        .cloned()
        .unwrap();
    assert_eq!(hook["httpAuth"]["secret"]["secret"], "****", "{hook}");
    assert_eq!(hook["signatureKey"]["secret"], "****", "{hook}");

    // "****" straight at a secret keeps it, and the rest of the update applies
    let response = webhook_set(
        &admin,
        json!({"update": {&id: {
            "url": "https://hooks.example.org/changed",
            "httpAuth/secret/secret": "****",
            "signatureKey/secret": "****"
        }}}),
    )
    .await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    assert_eq!(stored_secrets(&test.server, &id).await, original);

    // Inside a whole object, there is no stored secret it could stand for
    for (patch, property) in [
        (
            json!({"httpAuth/secret": {"@type": "Value", "secret": "****"}}),
            "httpAuth",
        ),
        (
            json!({"signatureKey": {"@type": "Value", "secret": "****"}}),
            "signatureKey",
        ),
        (
            json!({"httpAuth": {"@type": "Basic", "username": "inbuxa",
                                "secret": {"@type": "Value", "secret": "****"}}}),
            "httpAuth",
        ),
    ] {
        let response = webhook_set(&admin, json!({"update": {&id: patch}})).await;
        assert_refused(&response, "notUpdated", &id, property);
        assert_eq!(stored_secrets(&test.server, &id).await, original);
    }

    // Nor in a new object
    let response = webhook_set(
        &admin,
        json!({"create": {"copy": {
            "url": "https://hooks.example.org/copy",
            "enable": false,
            "httpAuth": {"@type": "Basic", "username": "inbuxa",
                         "secret": {"@type": "Value", "secret": "****"}},
        }}}),
    )
    .await;
    assert_refused(&response, "notCreated", "copy", "httpAuth");

    // A real secret is still saved
    let response = webhook_set(
        &admin,
        json!({"update": {&id: {"httpAuth/secret/secret": "new-password"}}}),
    )
    .await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    assert_eq!(
        stored_secrets(&test.server, &id).await,
        ("new-password".to_string(), "signing-key".to_string())
    );

    if test.is_reset() {
        test.temp_dir.delete();
    }
}
