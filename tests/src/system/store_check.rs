/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:StoreCheck` (docs/spec/features/store-check.md).
//!
//! A clean store checks clean. Then blobs are taken from under messages:
//! one deleted with its commit marker left, one shared by two messages, one
//! overwritten with other content, and one message's link taken away while
//! its blob stays. A quick check finds the missing ones and the unlinked
//! one, each with the account and the message; a full check also finds the
//! damaged one. One check runs at a time, a running one stops when asked
//! and can't be destroyed, a finished one can, and nobody in a tenant or
//! without the permission reaches checks. Starting and stopping are
//! audited.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use email::{mailbox::INBOX_ID, message::metadata::MessageMetadata};
use registry::schema::{
    enums::CompressionAlgo,
    prelude::{ObjectType, Property},
    structs::{CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant, UserRoles},
};
use serde_json::{Value, json};
use std::{str::FromStr, time::Duration};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive, BatchBuilder, BlobLink, BlobOp},
};
use types::{blob_hash::BlobHash, collection::Collection, field::EmailField, id::Id};

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

async fn start(admin: &Account, check: Value) -> String {
    let (_, response) = call(
        admin,
        "inbuxa:StoreCheck/set",
        json!({"create": {"c": check}}),
    )
    .await;
    response["created"]["c"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("not started: {response}"))
        .to_string()
}

async fn get(admin: &Account, id: &str) -> Value {
    let (_, response) = call(admin, "inbuxa:StoreCheck/get", json!({"ids": [id]})).await;
    response["list"][0].clone()
}

/// The check once it's over.
async fn settled(admin: &Account, id: &str) -> Value {
    for _ in 0..600 {
        let check = get(admin, id).await;
        if check["status"] != "running" {
            return check;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the check didn't finish: {}", get(admin, id).await);
}

async fn import(client: &jmap_client::client::Client, body: &str) -> u32 {
    let id = client
        .email_import(
            format!("From: a@example.org\r\nSubject: {body}\r\n\r\n{body}\r\n").into_bytes(),
            [Id::from(INBOX_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap()
        .take_id();
    Id::from_str(&id).unwrap().document_id()
}

async fn blob_of(test: &TestServer, account_id: u32, document_id: u32) -> BlobHash {
    let archive = test
        .server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await
        .unwrap()
        .expect("the message's metadata");
    let metadata = archive.unarchive::<MessageMetadata>().unwrap();
    BlobHash::from(&metadata.blob_hash)
}

fn count(check: &Value, kind: &str) -> u64 {
    check[kind]
        .as_u64()
        .unwrap_or_else(|| panic!("no {kind}: {check}"))
}

/// The problems found for one message, as `kind` strings.
fn kinds_for(check: &Value, document_id: u32) -> Vec<String> {
    check["problems"]
        .as_array()
        .unwrap_or_else(|| panic!("no problems list: {check}"))
        .iter()
        .filter(|p| p["objectId"].as_u64() == Some(document_id as u64))
        .map(|p| p["kind"].as_str().unwrap_or_default().to_string())
        .collect()
}

pub async fn test(test: &mut TestServer) {
    println!("Running store check tests...");
    let admin = test.account("admin@example.com");
    let ann = test.account("ann@example.com");
    let ann_id = ann.id().document_id();
    let client = ann.jmap_client().await;

    let missing = import(&client, "Missing blob").await;
    let shared_a = import(&client, "Shared blob").await;
    let shared_b = import(&client, "Shared blob").await;
    let damaged = import(&client, "Damaged blob").await;
    let unlinked = import(&client, "Unlinked message").await;
    let fine = import(&client, "Nothing wrong").await;
    assert_eq!(
        blob_of(test, ann_id, shared_a).await,
        blob_of(test, ann_id, shared_b).await,
        "the same message twice shares its blob"
    );

    // A clean store checks clean
    let id = start(admin, json!({"mode": "quick"})).await;
    let check = settled(admin, &id).await;
    assert_eq!(check["status"], "done", "{check}");
    assert_eq!(check["progress"], 1.0, "{check}");
    for kind in ["missing", "damaged", "unlinked", "unreadable"] {
        assert_eq!(count(&check, kind), 0, "{kind} in a clean store: {check}");
    }
    assert!(count(&check, "blobsChecked") >= 5, "{check}");
    assert!(count(&check, "messagesChecked") >= 6, "{check}");
    assert_eq!(check["problems"], json!([]), "{check}");
    assert_eq!(check["mode"], "quick", "{check}");
    assert_eq!(check["createdBy"], "admin@example.com", "{check}");

    // Take blobs from under them
    let blobs = test.server.blob_store();
    blobs
        .delete_blob(blob_of(test, ann_id, missing).await.as_slice())
        .await
        .unwrap();
    blobs
        .delete_blob(blob_of(test, ann_id, shared_a).await.as_slice())
        .await
        .unwrap();
    blobs
        .put_blob(
            blob_of(test, ann_id, damaged).await.as_slice(),
            b"Something else entirely",
            CompressionAlgo::None,
        )
        .await
        .unwrap();
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(ann_id)
        .with_collection(Collection::Email)
        .with_document(unlinked)
        .clear(BlobOp::Link {
            hash: blob_of(test, ann_id, unlinked).await,
            to: BlobLink::Document,
        });
    test.server.store().write(batch.build_all()).await.unwrap();

    // Quick: what's gone, and the message without its link
    let id = start(admin, json!({"mode": "quick"})).await;
    let check = settled(admin, &id).await;
    assert_eq!(check["status"], "done", "{check}");
    assert_eq!(count(&check, "missing"), 3, "{check}");
    assert_eq!(
        count(&check, "damaged"),
        0,
        "quick doesn't read content: {check}"
    );
    assert_eq!(count(&check, "unlinked"), 1, "{check}");
    assert_eq!(kinds_for(&check, missing), ["missing"], "{check}");
    assert_eq!(kinds_for(&check, shared_a), ["missing"], "{check}");
    assert_eq!(kinds_for(&check, shared_b), ["missing"], "{check}");
    assert_eq!(kinds_for(&check, unlinked), ["unlinked"], "{check}");
    assert!(kinds_for(&check, fine).is_empty(), "{check}");
    let problem = check["problems"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["objectId"].as_u64() == Some(missing as u64))
        .unwrap()
        .clone();
    assert_eq!(problem["object"], "email", "{problem}");
    assert_eq!(problem["accountId"], ann.id_string(), "{problem}");
    assert_eq!(problem["accountName"], "ann@example.com", "{problem}");
    assert_eq!(
        problem["committed"], true,
        "lost after it was written: {problem}"
    );
    assert_eq!(
        problem["blobId"],
        blob_of(test, ann_id, missing).await.to_hex(),
        "{problem}"
    );
    let unlinked_problem = check["problems"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["objectId"].as_u64() == Some(unlinked as u64))
        .unwrap()
        .clone();
    assert_eq!(
        unlinked_problem["detail"], "the blob is still there",
        "{unlinked_problem}"
    );

    // Full: the overwritten one too
    let id = start(admin, json!({"mode": "full", "bytesPerSecond": 0})).await;
    let check = settled(admin, &id).await;
    assert_eq!(check["status"], "done", "{check}");
    assert_eq!(count(&check, "missing"), 3, "{check}");
    assert_eq!(count(&check, "damaged"), 1, "{check}");
    assert_eq!(count(&check, "unlinked"), 1, "{check}");
    assert_eq!(kinds_for(&check, damaged), ["damaged"], "{check}");
    assert!(count(&check, "bytesRead") > 0, "{check}");
    let full = id;

    // One at a time; a running one stops when asked, and stays until then
    let slow = start(admin, json!({"mode": "quick", "blobsPerSecond": 1})).await;
    let (_, response) = call(
        admin,
        "inbuxa:StoreCheck/set",
        json!({"create": {"again": {"mode": "quick"}}}),
    )
    .await;
    assert!(
        response["notCreated"]["again"]["description"]
            .as_str()
            .is_some_and(|d| d.contains("one check runs at a time")),
        "a second check while one runs: {response}"
    );
    let (_, response) = call(admin, "inbuxa:StoreCheck/set", json!({"destroy": [&slow]})).await;
    assert!(response["notDestroyed"].get(&slow).is_some(), "{response}");
    let (_, response) = call(
        admin,
        "inbuxa:StoreCheck/set",
        json!({"update": {&slow: {"mode": "full"}}}),
    )
    .await;
    assert!(response["notUpdated"].get(&slow).is_some(), "{response}");
    let (_, response) = call(
        admin,
        "inbuxa:StoreCheck/set",
        json!({"update": {&slow: {"action": "stop"}}}),
    )
    .await;
    assert!(response["updated"].get(&slow).is_some(), "{response}");
    let check = settled(admin, &slow).await;
    assert_eq!(check["status"], "stopped", "{check}");
    assert!(check["progress"].as_f64().unwrap() < 1.0, "{check}");
    let (_, response) = call(
        admin,
        "inbuxa:StoreCheck/set",
        json!({"update": {&slow: {"action": "stop"}}}),
    )
    .await;
    assert!(
        response["notUpdated"].get(&slow).is_some(),
        "stopping a stopped check: {response}"
    );

    // A finished one can be forgotten, with its problems
    let (_, response) = call(admin, "inbuxa:StoreCheck/set", json!({"destroy": [&full]})).await;
    assert_eq!(response["destroyed"], json!([full]), "{response}");
    let (_, response) = call(admin, "inbuxa:StoreCheck/get", json!({"ids": [&full]})).await;
    assert_eq!(response["notFound"], json!([full]), "{response}");
    let id = Id::from_str(&full).unwrap().id() as u32;
    assert!(
        inbuxa_features::store_check::problems(test.server.store(), id)
            .await
            .unwrap()
            .is_empty(),
        "a forgotten check's problems are gone too"
    );

    // Bad input
    for (create, why) in [
        (json!({"mode": "thorough"}), "mode"),
        (json!({"blobsPerSecond": -1}), "blobsPerSecond"),
        (json!({"status": "done"}), "status"),
    ] {
        let (_, response) = call(
            admin,
            "inbuxa:StoreCheck/set",
            json!({"create": {"x": create}}),
        )
        .await;
        assert!(
            response["notCreated"].get("x").is_some(),
            "{why}: {response}"
        );
    }

    // Starting and stopping are audited
    let (_, response) = call(
        admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:StoreCheck"}}),
    )
    .await;
    assert!(
        response["ids"].as_array().is_some_and(|ids| ids.len() >= 5),
        "creates, the stop and the destroy audited: {response}"
    );

    // Nobody without the permission, or in a tenant, reaches checks
    let (name, response) = call(ann, "inbuxa:StoreCheck/get", json!({"ids": null})).await;
    assert_eq!(name, "error", "a user: {response}");
    let tenant = admin
        .registry_create_object(Tenant {
            name: "Store check tenant".to_string(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Domain {
            name: "storecheck.example.org".to_string(),
            is_enabled: true,
            member_tenant_id: Some(tenant),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    let t_admin = admin
        .create_user_account(
            "tadmin@storecheck.example.org",
            "tenant-admin-secret-4417",
            "Tenant admin",
            &[],
            vec![],
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            t_admin.id(),
            json!({Property::Roles: UserRoles::Admin}),
        )
        .await;
    for (method, arguments) in [
        ("inbuxa:StoreCheck/get", json!({"ids": null})),
        (
            "inbuxa:StoreCheck/set",
            json!({"create": {"x": {"mode": "quick"}}}),
        ),
    ] {
        let (name, response) = call(&t_admin, method, arguments).await;
        assert_eq!(name, "error", "{method} by a tenant: {response}");
    }
}

/// Runs these tests alone: `cargo test -p tests store_check_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn store_check_tests() {
    let mut test = TestServerBuilder::new("store_check_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.com").await;
    test.insert_account(admin);
    let ann = test
        .create_user_account(
            "admin@example.com",
            "ann@example.com",
            "ann-secret-29871",
            &[],
            "Ann",
        )
        .await;
    test.insert_account(ann);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
