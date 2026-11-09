/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:BlobStoreChange` (docs/spec/features/blob-store-change.md).
//!
//! The forum topic 238 case: some mail went to a filesystem blob store,
//! then the setting went back to the data store. The test records that
//! change as a start-up would and gives the server the read-through store
//! it would build (a test server can't restart with another setting). One
//! message's blob is only in the old store, one is damaged there, one is
//! in neither. The first reads through and is kept; a copy copies the
//! rest it can, reports the damaged and the missing one, and leaves the
//! change unresolved. Put right, a second copy resolves it, and nothing
//! is read through any more. A slow copy stops when asked and can't be
//! dismissed while it runs. Nobody but an administrator reaches changes.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use email::{mailbox::INBOX_ID, message::metadata::MessageMetadata};
use inbuxa_features::blob_move::{self as model, Started};
use registry::schema::{enums::CompressionAlgo, structs};
use serde_json::{Value, json};
use std::{str::FromStr, sync::Arc, time::Duration};
use store::{
    BlobStore, ValueKey,
    backend::fs::FsStore,
    build::blob::blob_store_location,
    write::{
        AlignedBytes, Archive,
        blob_move::{MovingBlobStore, OldBlobStore},
        now,
    },
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

async fn get(admin: &Account, id: &str) -> Value {
    let (_, response) = call(admin, "inbuxa:BlobStoreChange/get", json!({"ids": [id]})).await;
    response["list"][0].clone()
}

async fn update(admin: &Account, id: &str, patch: Value) -> Value {
    let (_, response) = call(
        admin,
        "inbuxa:BlobStoreChange/set",
        json!({"update": {id: patch}}),
    )
    .await;
    response
}

/// The change once its copy is over.
async fn settled(admin: &Account, id: &str) -> Value {
    for _ in 0..900 {
        let change = get(admin, id).await;
        if change["status"] != "copying" {
            return change;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the copy didn't finish: {}", get(admin, id).await);
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

fn count(change: &Value, kind: &str) -> u64 {
    change[kind]
        .as_u64()
        .unwrap_or_else(|| panic!("no {kind}: {change}"))
}

/// Gives the server `blob` as its blob store, as a start-up would.
fn use_blob_store(test: &mut TestServer, blob: BlobStore) {
    let mut core = (*test.server.inner.shared_core.load_full()).clone();
    core.storage.blob = blob;
    test.server.inner.shared_core.store(Arc::new(core));
    test.reload_core();
}

/// Moves a message's blob from the current store to `old`, or puts
/// `content` there in its place.
async fn leave_behind(
    test: &TestServer,
    old: &BlobStore,
    hash: &BlobHash,
    content: Option<&[u8]>,
) -> Vec<u8> {
    let current = test.server.blob_store().current().clone();
    let original = current
        .get_blob(hash.as_slice(), 0..usize::MAX)
        .await
        .unwrap()
        .expect("the blob");
    old.put_blob(
        hash.as_slice(),
        content.unwrap_or(&original),
        CompressionAlgo::Lz4,
    )
    .await
    .unwrap();
    current.delete_blob(hash.as_slice()).await.unwrap();
    original
}

pub async fn test(test: &mut TestServer) {
    println!("Running blob store change tests...");
    let data = test.server.store().clone();

    // A start with blobs in a directory, then one with the setting back
    let dir = format!("{}/old-blobs", test.tmp_dir());
    let fs_settings = structs::FileSystemStore {
        path: dir.clone(),
        depth: 2,
    };
    let old_settings = structs::BlobStore::FileSystem(fs_settings.clone());
    let old = FsStore::open(fs_settings).await.unwrap();
    let here = structs::BlobStore::Default;
    model::at_start(
        &data,
        blob_store_location(&old_settings),
        &old_settings,
        1,
        now(),
    )
    .await
    .unwrap();
    let Started::Changed(change_id) =
        model::at_start(&data, blob_store_location(&here), &here, 1, now())
            .await
            .unwrap()
    else {
        panic!("no change recorded");
    };
    let id = Id::from(change_id).to_string();

    // The store a start-up would build: reading through to the old one
    let current = test.server.blob_store().clone();
    use_blob_store(
        test,
        BlobStore::Moving(Arc::new(MovingBlobStore::new(
            current.clone(),
            vec![OldBlobStore {
                change_id,
                store: old.clone(),
            }],
        ))),
    );

    let admin = test.account("admin@example.com");
    let ann = test.account("ann@example.com");
    let ann_id = ann.id().document_id();
    let client = ann.jmap_client().await;

    let behind = import(&client, "Delivered while the filesystem store was set").await;
    let damaged = import(&client, "Damaged in the old store").await;
    let gone = import(&client, "In neither store").await;
    let fine = import(&client, "Never moved").await;

    let behind_hash = blob_of(test, ann_id, behind).await;
    let damaged_hash = blob_of(test, ann_id, damaged).await;
    let gone_hash = blob_of(test, ann_id, gone).await;
    leave_behind(test, &old, &behind_hash, None).await;
    let damaged_content =
        leave_behind(test, &old, &damaged_hash, Some(b"Something else entirely")).await;
    let gone_content = current
        .get_blob(gone_hash.as_slice(), 0..usize::MAX)
        .await
        .unwrap()
        .unwrap();
    current.delete_blob(gone_hash.as_slice()).await.unwrap();

    // Listed, with where from and to and never the old store's settings
    let change = get(admin, &id).await;
    assert_eq!(change["status"], "pending", "{change}");
    assert_eq!(
        change["from"],
        blob_store_location(&old_settings),
        "{change}"
    );
    assert_eq!(change["to"], "the data store", "{change}");
    assert!(!change.to_string().contains("oldSettings"), "{change}");
    assert!(!change.to_string().contains("FileSystem"), "{change}");

    // BM-3: left behind, read through, and kept
    assert!(!current.blob_present(behind_hash.as_slice()).await.unwrap());
    let message = test.fetch_email(ann_id, behind).await;
    assert!(
        String::from_utf8_lossy(&message).contains("Delivered while the filesystem store was set"),
        "read through the old store"
    );
    assert!(
        current.blob_present(behind_hash.as_slice()).await.unwrap(),
        "kept in the current store"
    );
    assert!(
        old.blob_present(behind_hash.as_slice()).await.unwrap(),
        "nothing deleted from the old store"
    );

    // Refusals
    let (_, response) = call(
        admin,
        "inbuxa:BlobStoreChange/set",
        json!({"create": {"x": {}}}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["x"]["type"], "forbidden",
        "{response}"
    );
    let response = update(admin, &id, json!({"action": "rename"})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "invalidProperties",
        "{response}"
    );
    let response = update(admin, &id, json!({"from": "elsewhere", "action": "copy"})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "invalidProperties",
        "{response}"
    );
    let response = update(admin, &id, json!({"action": "stop"})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "{response}"
    );
    let (name, response) = call(ann, "inbuxa:BlobStoreChange/get", json!({"ids": null})).await;
    assert_eq!(name, "error", "a user reaches changes: {response}");

    // A slow copy stops when asked, and can't be dismissed meanwhile
    for n in 0..15 {
        import(&client, &format!("Filler {n}")).await;
    }
    let response = update(admin, &id, json!({"action": "copy", "blobsPerSecond": 1})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let response = update(admin, &id, json!({"action": "copy"})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "one copy at a time: {response}"
    );
    let (_, response) = call(
        admin,
        "inbuxa:BlobStoreChange/set",
        json!({"destroy": [id]}),
    )
    .await;
    assert_eq!(
        response["notDestroyed"][&id]["type"], "forbidden",
        "{response}"
    );
    let response = update(admin, &id, json!({"action": "stop"})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let change = settled(admin, &id).await;
    assert_eq!(change["status"], "stopped", "{change}");
    assert_eq!(change["copyStartedBy"], "admin@example.com", "{change}");

    // A copy: the damaged and the missing are reported, not copied
    let response = update(admin, &id, json!({"action": "copy", "blobsPerSecond": 0})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let change = settled(admin, &id).await;
    assert_eq!(change["status"], "incomplete", "{change}");
    assert_eq!(count(&change, "missing"), 1, "{change}");
    assert_eq!(count(&change, "damaged"), 1, "{change}");
    assert_eq!(count(&change, "unreadable"), 0, "{change}");
    assert!(count(&change, "alreadyThere") >= 2, "{change}");
    let problems = change["problems"].as_array().unwrap().clone();
    let of = |hash: &BlobHash| {
        problems
            .iter()
            .find(|p| p["blobId"] == hash.to_hex())
            .cloned()
            .unwrap_or_else(|| panic!("no problem for {}: {change}", hash.to_hex()))
    };
    let missing = of(&gone_hash);
    assert_eq!(missing["kind"], "missing", "{missing}");
    assert_eq!(missing["holder"], "email", "{missing}");
    assert_eq!(missing["accountId"], ann.id_string(), "{missing}");
    assert_eq!(missing["objectId"], gone as u64, "{missing}");
    assert_eq!(of(&damaged_hash)["kind"], "damaged");
    assert!(
        !current.blob_present(damaged_hash.as_slice()).await.unwrap(),
        "a damaged blob isn't copied"
    );
    assert!(
        test.server
            .blob_store()
            .moving()
            .is_some_and(|m| !m.old_stores().is_empty()),
        "still read through"
    );

    // Put right in the old store: a second copy resolves the change
    old.put_blob(
        damaged_hash.as_slice(),
        &damaged_content,
        CompressionAlgo::Lz4,
    )
    .await
    .unwrap();
    old.put_blob(gone_hash.as_slice(), &gone_content, CompressionAlgo::None)
        .await
        .unwrap();
    let response = update(admin, &id, json!({"action": "copy", "blobsPerSecond": 0})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let change = settled(admin, &id).await;
    assert_eq!(change["status"], "copied", "{change}");
    assert_eq!(count(&change, "copied"), 2, "{change}");
    assert_eq!(change["progress"], 1.0, "{change}");
    assert_eq!(change["problems"], json!([]), "{change}");
    for hash in [&damaged_hash, &gone_hash] {
        assert!(current.blob_present(hash.as_slice()).await.unwrap());
    }
    assert!(
        test.server
            .blob_store()
            .moving()
            .unwrap()
            .old_stores()
            .is_empty(),
        "nothing read through once resolved"
    );
    assert!(String::from_utf8_lossy(&test.fetch_email(ann_id, fine).await).contains("Never moved"));
    assert!(
        model::get(&data, change_id)
            .await
            .unwrap()
            .unwrap()
            .old_settings
            .is_none(),
        "the old store's settings go once resolved"
    );
    let response = update(admin, &id, json!({"action": "copy"})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "nothing left to copy: {response}"
    );

    // Dismissed
    let (_, response) = call(
        admin,
        "inbuxa:BlobStoreChange/set",
        json!({"destroy": [id]}),
    )
    .await;
    assert_eq!(response["destroyed"], json!([id]), "{response}");
    let (_, response) = call(admin, "inbuxa:BlobStoreChange/get", json!({"ids": [id]})).await;
    assert_eq!(response["notFound"], json!([id]), "{response}");

    use_blob_store(test, current);
}

/// Runs these tests alone: `cargo test -p tests blob_store_change_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn blob_store_change_tests() {
    let mut test = TestServerBuilder::new("blob_store_change_tests")
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
            "ann-secret-40917",
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
