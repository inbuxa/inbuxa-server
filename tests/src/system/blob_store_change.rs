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
//!
//! Then copying ahead (docs/spec/features/blob-store-copy-ahead.md): a
//! change to a filesystem store is planned, refused where it should be,
//! copied ahead and applied to the setting; deletes follow to the planned
//! store meanwhile. Mail delivered after the copy ahead is read through once
//! the server switches, and the last pass copies only what the copy ahead
//! didn't have.
//!
//! Then cleaning up (docs/spec/features/blob-store-cleanup.md): a resolved
//! change's old store is previewed, refused without a confirmation and
//! while a node is on the old store, and cleaned up. A blob missing from
//! the current store and one damaged there stay in the old store and are
//! reported; put right, a second run is done and the old store's settings
//! go.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use email::{mailbox::INBOX_ID, message::metadata::MessageMetadata};
use inbuxa_features::blob_move::{self as model, Started};
use registry::schema::{
    enums::CompressionAlgo,
    prelude::{Object, ObjectType},
    structs,
};
use serde_json::{Value, json};
use std::{str::FromStr, sync::Arc, time::Duration};
use store::{
    BlobStore, ValueKey,
    backend::fs::FsStore,
    build::blob::blob_store_location,
    registry::write::{RegistryWrite, RegistryWriteResult},
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
            .is_some(),
        "the old store's settings are kept for a cleanup (OC-1)"
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
    copy_ahead(test).await;
    clean_up(test).await;
}

async fn plan(admin: &Account, target: Value) -> Value {
    let (_, response) = call(
        admin,
        "inbuxa:BlobStoreChange/set",
        json!({"create": {"p": {"target": target}}}),
    )
    .await;
    response
}

async fn setting(test: &TestServer) -> structs::BlobStore {
    test.server
        .registry()
        .object::<structs::BlobStore>(Id::singleton())
        .await
        .unwrap()
        .unwrap_or_default()
}

async fn put_setting(test: &TestServer, settings: structs::BlobStore) {
    let registry = test.server.registry();
    let old = registry
        .get(ObjectType::BlobStore.singleton())
        .await
        .unwrap()
        .expect("the setting apply wrote");
    let mut new = old.clone();
    new.inner = Object::from(settings).inner;
    assert!(matches!(
        registry
            .write(RegistryWrite::update(Id::singleton(), &new, &old))
            .await
            .unwrap(),
        RegistryWriteResult::Success(_)
    ));
}

/// The blob-store-copy-ahead spec, CA-1 to CA-8.
async fn copy_ahead(test: &mut TestServer) {
    println!("Running blob store copy ahead tests...");
    let data = test.server.store().clone();
    let admin = test.account("admin@example.com");
    let ann = test.account("ann@example.com");
    let ann_id = ann.id().document_id();
    let client = ann.jmap_client().await;
    let current = test.server.blob_store().clone();
    // Where the server last said its blob store is: the data store, as the
    // test above left it, whatever the setting is
    let here = structs::BlobStore::Default;
    let original = setting(test).await;

    // From a server with no change left: with blobs in a directory, the
    // test above leaves the move from it to its old store behind
    for change in model::all(&data).await.unwrap() {
        model::remove(&data, change.id).await.unwrap();
    }

    let dir = format!("{}/planned-blobs", test.tmp_dir());
    let fs_settings = structs::FileSystemStore {
        path: dir.clone(),
        depth: 2,
    };
    let target = structs::BlobStore::FileSystem(fs_settings.clone());
    let target_json = serde_json::to_value(&target).unwrap();
    let planned_store = FsStore::open(fs_settings).await.unwrap();

    let before = import(&client, "Delivered before the copy ahead").await;
    let before_hash = blob_of(test, ann_id, before).await;

    // CA-1: refusals
    let response = plan(admin, json!({"@type": "Bogus"})).await;
    assert_eq!(
        response["notCreated"]["p"]["type"], "invalidProperties",
        "{response}"
    );
    let response = plan(admin, serde_json::to_value(&here).unwrap()).await;
    assert_eq!(
        response["notCreated"]["p"]["type"], "forbidden",
        "the same place: {response}"
    );
    let response = plan(
        admin,
        json!({"@type": "FileSystem", "path": "/dev/null/blobs", "depth": 2}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["p"]["type"], "invalidProperties",
        "a store that can't be written: {response}"
    );
    let (_, response) = call(
        admin,
        "inbuxa:BlobStoreChange/set",
        json!({"create": {"p": {"target": target_json, "from": "x"}}}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["p"]["type"], "invalidProperties",
        "{response}"
    );

    // Planned
    let response = plan(admin, target_json.clone()).await;
    let id = response["created"]["p"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("not planned: {response}"))
        .to_string();
    let change_id = Id::from_str(&id).unwrap().document_id();
    let change = get(admin, &id).await;
    assert_eq!(change["stage"], "planned", "{change}");
    assert_eq!(change["status"], "pending", "{change}");
    assert_eq!(change["from"], "the data store", "{change}");
    assert_eq!(change["to"], blob_store_location(&target), "{change}");
    assert_eq!(change["changedAt"], Value::Null, "{change}");
    assert!(!change.to_string().contains("FileSystem"), "{change}");
    let response = plan(
        admin,
        json!({"@type": "FileSystem", "path": format!("{dir}-2"), "depth": 2}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["p"]["type"], "forbidden",
        "one planned at a time: {response}"
    );
    let response = update(admin, &id, json!({"action": "apply"})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "applied before it's copied ahead: {response}"
    );
    // CA-3: not read through, and a snapshot isn't refused for it
    assert!(model::unresolved(&data).await.unwrap().is_empty());

    // CA-4: deletes follow
    let planned = test
        .server
        .blob_store()
        .moving()
        .and_then(|m| m.planned())
        .expect("deletes follow to the planned store");
    assert_eq!(planned.change_id, change_id);
    for store in [current.current(), &planned_store] {
        store
            .put_blob(b"deleted-meanwhile", b"x", CompressionAlgo::None)
            .await
            .unwrap();
    }
    test.server
        .blob_store()
        .delete_blob(b"deleted-meanwhile")
        .await
        .unwrap();
    assert!(
        !planned_store
            .blob_present(b"deleted-meanwhile")
            .await
            .unwrap(),
        "a delete followed to the planned store"
    );

    // CA-2: copied ahead; nothing resolved, the setting untouched
    let response = update(admin, &id, json!({"action": "copy", "blobsPerSecond": 0})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let change = settled(admin, &id).await;
    assert_eq!(change["status"], "copied", "{change}");
    assert_eq!(change["stage"], "planned", "{change}");
    let copied_ahead = count(&change, "copied");
    assert!(copied_ahead >= 1, "{change}");
    assert!(
        planned_store
            .blob_present(before_hash.as_slice())
            .await
            .unwrap(),
        "copied ahead"
    );
    assert_eq!(setting(test).await, original);

    // Written after the copy ahead: only the current store has them
    let late = import(&client, "Delivered after the copy ahead").await;
    let later = import(&client, "Also after the copy ahead").await;
    let late_hash = blob_of(test, ann_id, late).await;
    let later_hash = blob_of(test, ann_id, later).await;
    assert!(
        !planned_store
            .blob_present(late_hash.as_slice())
            .await
            .unwrap()
    );

    // CA-7: applied, once
    let response = update(admin, &id, json!({"action": "apply"})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    assert_eq!(setting(test).await, target);
    let change = get(admin, &id).await;
    assert_eq!(change["appliedBy"], "admin@example.com", "{change}");
    assert!(change["appliedAt"].is_string(), "{change}");
    let response = update(admin, &id, json!({"action": "apply"})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "{response}"
    );

    // CA-5: the switch, as a start with the new setting would make it
    let Started::Changed(switched) =
        model::at_start(&data, blob_store_location(&target), &target, 1, now())
            .await
            .unwrap()
    else {
        panic!("no change at the switch");
    };
    assert_eq!(switched, change_id, "the planned change became the change");
    use_blob_store(
        test,
        BlobStore::Moving(Arc::new(MovingBlobStore::new(
            planned_store.clone(),
            vec![OldBlobStore {
                change_id,
                store: current.current().clone(),
            }],
        ))),
    );
    let admin = test.account("admin@example.com");
    let change = get(admin, &id).await;
    assert_eq!(change["stage"], "changed", "{change}");
    assert_eq!(change["status"], "pending", "{change}");
    assert!(change["changedAt"].is_string(), "{change}");
    assert_eq!(change["copiedAhead"]["status"], "copied", "{change}");
    assert_eq!(change["copiedAhead"]["copied"], copied_ahead, "{change}");
    assert!(
        model::get(&data, change_id)
            .await
            .unwrap()
            .unwrap()
            .target_settings
            .is_none(),
        "the planned store's settings go at the switch"
    );

    // BM-3: what came after the copy ahead reads through
    let message = test.fetch_email(ann_id, late).await;
    assert!(String::from_utf8_lossy(&message).contains("Delivered after the copy ahead"));
    assert!(
        planned_store
            .blob_present(late_hash.as_slice())
            .await
            .unwrap()
    );

    // CA-6: the last pass copies only what the copy ahead didn't have
    let response = update(admin, &id, json!({"action": "copy", "blobsPerSecond": 0})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let change = settled(admin, &id).await;
    assert_eq!(change["status"], "copied", "{change}");
    let last_pass = count(&change, "copied");
    assert!(last_pass >= 1 && last_pass < copied_ahead, "{change}");
    assert!(count(&change, "alreadyThere") >= copied_ahead, "{change}");
    assert!(
        planned_store
            .blob_present(later_hash.as_slice())
            .await
            .unwrap()
    );

    // Put back as it was
    let (_, response) = call(
        admin,
        "inbuxa:BlobStoreChange/set",
        json!({"destroy": [id]}),
    )
    .await;
    assert_eq!(response["destroyed"], json!([id]), "{response}");
    use_blob_store(test, current.clone());
    put_setting(test, original.clone()).await;
    if let Started::Changed(back) =
        model::at_start(&data, blob_store_location(&here), &here, 1, now())
            .await
            .unwrap()
    {
        model::remove(&data, back).await.unwrap();
    }
    // The planned store is gone with the change
    services::inbuxa_blob_move::refresh(&test.server).await;
    assert!(
        test.server
            .blob_store()
            .moving()
            .is_none_or(|m| m.planned().is_none())
    );
}

/// The cleanup once its run is over.
async fn cleaned(admin: &Account, id: &str) -> Value {
    for _ in 0..900 {
        let change = get(admin, id).await;
        if change["cleanup"]["status"] != "running" {
            return change;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the cleanup didn't finish: {}", get(admin, id).await);
}

/// The blob-store-cleanup spec, OC-1 to OC-11.
async fn clean_up(test: &mut TestServer) {
    println!("Running blob store cleanup tests...");
    let data = test.server.store().clone();
    let admin = test.account("admin@example.com");
    let ann = test.account("ann@example.com");
    let ann_id = ann.id().document_id();
    let client = ann.jmap_client().await;
    let current = test.server.blob_store().current().clone();
    for change in model::all(&data).await.unwrap() {
        model::remove(&data, change.id).await.unwrap();
    }

    // Mail in both stores, as a copy leaves it
    let dir = format!("{}/cleanup-old-blobs", test.tmp_dir());
    let fs_settings = structs::FileSystemStore {
        path: dir.clone(),
        depth: 2,
    };
    let old_settings = structs::BlobStore::FileSystem(fs_settings.clone());
    let old = FsStore::open(fs_settings).await.unwrap();
    let here = structs::BlobStore::Default;
    let kept = import(&client, "In both stores").await;
    let altered = import(&client, "Damaged in the current store").await;
    let removed = import(&client, "Gone from the current store").await;
    let kept_hash = blob_of(test, ann_id, kept).await;
    let altered_hash = blob_of(test, ann_id, altered).await;
    let removed_hash = blob_of(test, ann_id, removed).await;
    for hash in [&kept_hash, &altered_hash, &removed_hash] {
        let stored = current.get_stored(hash.as_slice()).await.unwrap().unwrap();
        old.put_stored(hash.as_slice(), &stored).await.unwrap();
    }
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

    // OC-3: not before it's resolved
    let response = update(admin, &id, json!({"action": "cleanUp", "dryRun": true})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "{response}"
    );

    // Resolved by a copy; OC-1: the old store is kept
    let response = update(admin, &id, json!({"action": "copy", "blobsPerSecond": 0})).await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let change = settled(admin, &id).await;
    assert_eq!(change["status"], "copied", "{change}");
    assert_eq!(change["oldStoreKept"], true, "{change}");
    assert_eq!(change["cleanup"], Value::Null, "{change}");

    // OC-5: a preview deletes nothing
    let response = update(
        admin,
        &id,
        json!({"action": "cleanUp", "dryRun": true, "blobsPerSecond": 0}),
    )
    .await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let change = cleaned(admin, &id).await;
    let cleanup = &change["cleanup"];
    assert_eq!(cleanup["status"], "done", "{change}");
    assert_eq!(cleanup["dryRun"], true, "{change}");
    assert_eq!(cleanup["startedBy"], "admin@example.com", "{change}");
    assert_eq!(count(cleanup, "deleted"), 3, "{change}");
    assert!(count(cleanup, "bytesFreed") > 0, "{change}");
    assert!(count(cleanup, "notThere") >= 1, "{change}");
    assert!(old.blob_present(kept_hash.as_slice()).await.unwrap());
    assert_eq!(change["oldStoreKept"], true, "{change}");

    // OC-8: deleting needs the change's own id as the confirmation
    let response = update(admin, &id, json!({"action": "cleanUp"})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "{response}"
    );
    let other = Id::from(change_id + 100).to_string();
    let response = update(admin, &id, json!({"action": "cleanUp", "confirm": other})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "{response}"
    );

    // OC-2, OC-3: a node still on the old store refuses it
    let old_place = blob_store_location(&old_settings);
    model::note_node(&data, 99, &old_place, now())
        .await
        .unwrap();
    let response = update(admin, &id, json!({"action": "cleanUp", "confirm": id})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "{response}"
    );
    assert!(
        response["notUpdated"][&id]["description"]
            .as_str()
            .unwrap_or_default()
            .contains("Node 99"),
        "{response}"
    );
    model::note_node(&data, 99, &old_place, now() - 3_600)
        .await
        .unwrap();

    // A slow one stops when asked, and can't be dismissed meanwhile
    let response = update(
        admin,
        &id,
        json!({"action": "cleanUp", "dryRun": true, "blobsPerSecond": 1}),
    )
    .await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let response = update(admin, &id, json!({"action": "copy"})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "{response}"
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
    let change = cleaned(admin, &id).await;
    assert_eq!(change["cleanup"]["status"], "stopped", "{change}");

    // OC-4: what the current store lacks or holds damaged stays in the old one
    let altered_content = current
        .get_stored(altered_hash.as_slice())
        .await
        .unwrap()
        .unwrap();
    current
        .put_blob(
            altered_hash.as_slice(),
            b"Something else entirely",
            CompressionAlgo::None,
        )
        .await
        .unwrap();
    let removed_content = current
        .get_stored(removed_hash.as_slice())
        .await
        .unwrap()
        .unwrap();
    current.delete_blob(removed_hash.as_slice()).await.unwrap();
    let response = update(
        admin,
        &id,
        json!({"action": "cleanUp", "confirm": id, "blobsPerSecond": 0}),
    )
    .await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let change = cleaned(admin, &id).await;
    let cleanup = &change["cleanup"];
    assert_eq!(cleanup["status"], "incomplete", "{change}");
    assert_eq!(cleanup["dryRun"], false, "{change}");
    assert_eq!(count(cleanup, "deleted"), 1, "{change}");
    assert_eq!(count(cleanup, "missing"), 1, "{change}");
    assert_eq!(count(cleanup, "damaged"), 1, "{change}");
    assert_eq!(change["problems"], json!([]), "{change}");
    let problems = cleanup["problems"].as_array().unwrap();
    let kind_of = |hash: &BlobHash| {
        problems
            .iter()
            .find(|p| p["blobId"] == hash.to_hex())
            .map(|p| p["kind"].clone())
            .unwrap_or_else(|| panic!("no problem for {}: {change}", hash.to_hex()))
    };
    assert_eq!(kind_of(&removed_hash), "missing");
    assert_eq!(kind_of(&altered_hash), "damaged");
    assert!(!old.blob_present(kept_hash.as_slice()).await.unwrap());
    for hash in [&altered_hash, &removed_hash] {
        assert!(old.blob_present(hash.as_slice()).await.unwrap(), "kept");
    }
    assert!(
        String::from_utf8_lossy(&test.fetch_email(ann_id, kept).await).contains("In both stores"),
        "the message reads from the current store"
    );
    assert_eq!(get(admin, &id).await["oldStoreKept"], true);

    // Put right: a second run is done, and the old store's settings go
    current
        .put_stored(altered_hash.as_slice(), &altered_content)
        .await
        .unwrap();
    current
        .put_stored(removed_hash.as_slice(), &removed_content)
        .await
        .unwrap();
    let response = update(
        admin,
        &id,
        json!({"action": "cleanUp", "confirm": id, "blobsPerSecond": 0}),
    )
    .await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let change = cleaned(admin, &id).await;
    let cleanup = &change["cleanup"];
    assert_eq!(cleanup["status"], "done", "{change}");
    assert_eq!(count(cleanup, "deleted"), 2, "{change}");
    assert_eq!(change["oldStoreKept"], false, "{change}");
    for hash in [&kept_hash, &altered_hash, &removed_hash] {
        assert!(!old.blob_present(hash.as_slice()).await.unwrap());
    }
    for (message, text) in [
        (altered, "Damaged in the current store"),
        (removed, "Gone from the current store"),
    ] {
        assert!(String::from_utf8_lossy(&test.fetch_email(ann_id, message).await).contains(text));
    }
    assert!(
        model::get(&data, change_id)
            .await
            .unwrap()
            .unwrap()
            .old_settings
            .is_none()
    );
    let response = update(admin, &id, json!({"action": "cleanUp", "confirm": id})).await;
    assert_eq!(
        response["notUpdated"][&id]["type"], "forbidden",
        "nothing left to clean up: {response}"
    );

    // Dismissed
    let (_, response) = call(
        admin,
        "inbuxa:BlobStoreChange/set",
        json!({"destroy": [id]}),
    )
    .await;
    assert_eq!(response["destroyed"], json!([id]), "{response}");
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
