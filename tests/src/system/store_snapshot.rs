/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:StoreSnapshot` (docs/spec/features/store-snapshot.md).
//!
//! A snapshot taken while the server runs holds the mail that was in it and
//! not the mail that came after: a RocksDB store opened from its `data/`
//! has the messages, and their blobs are in it or, with a filesystem blob
//! store (`BLOB_STORE=FileSystem`), in its `blobs/`. The directory is
//! whole, named for its time, with `latest` and `snapshot.json`. Only the
//! latest two are kept; one can be destroyed, a snapshot can't be changed,
//! and one being taken can't be destroyed or joined by another. Nobody in
//! a tenant or without the permission reaches snapshots. While a blob store
//! change isn't settled, a new one is refused and those on disk are still
//! listed and destroyed. Taking and destroying are audited.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use email::{mailbox::INBOX_ID, message::metadata::MessageMetadata};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{
        self, CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant, UserRoles,
    },
};
use serde_json::{Value, json};
use std::{path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use store::{
    BlobStore, Store, ValueKey,
    backend::{fs::FsStore, rocksdb::RocksDbStore},
    write::{
        AlignedBytes, Archive,
        blob_move::{MovingBlobStore, OldBlobStore},
        snapshot::hold_blob_purge,
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

async fn take(admin: &Account) -> String {
    let (_, response) = call(
        admin,
        "inbuxa:StoreSnapshot/set",
        json!({"create": {"s": {}}}),
    )
    .await;
    response["created"]["s"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("not taken: {response}"))
        .to_string()
}

async fn get(admin: &Account, id: &str) -> Value {
    let (_, response) = call(admin, "inbuxa:StoreSnapshot/get", json!({"ids": [id]})).await;
    response["list"][0].clone()
}

async fn all(admin: &Account) -> Vec<Value> {
    let (_, response) = call(admin, "inbuxa:StoreSnapshot/get", json!({"ids": null})).await;
    response["list"]
        .as_array()
        .unwrap_or_else(|| panic!("no list: {response}"))
        .clone()
}

/// The snapshot once it's taken.
async fn settled(admin: &Account, id: &str) -> Value {
    for _ in 0..600 {
        let snapshot = get(admin, id).await;
        if snapshot["status"] != "running" {
            return snapshot;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the snapshot wasn't taken: {}", get(admin, id).await);
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

async fn blob_in(store: &Store, account_id: u32, document_id: u32) -> Option<BlobHash> {
    let archive = store
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await
        .unwrap()?;
    let metadata = archive.unarchive::<MessageMetadata>().unwrap();
    Some(BlobHash::from(&metadata.blob_hash))
}

fn path_of(snapshot: &Value) -> PathBuf {
    PathBuf::from(
        snapshot["path"]
            .as_str()
            .unwrap_or_else(|| panic!("no path: {snapshot}")),
    )
}

/// Gives the server `blob` as its blob store, as a start-up would. Requests
/// build their server from the shared core, so the test's own handle is
/// left as it is.
fn use_blob_store(test: &TestServer, blob: BlobStore) {
    let mut core = (*test.server.inner.shared_core.load_full()).clone();
    core.storage.blob = blob;
    test.server.inner.shared_core.store(Arc::new(core));
}

pub async fn test(test: &mut TestServer) {
    println!("Running store snapshot tests...");
    let admin = test.account("admin@example.com");
    let ann = test.account("ann@example.com");
    let ann_id = ann.id().document_id();
    let client = ann.jmap_client().await;
    let separate_blobs = matches!(test.server.blob_store().current(), BlobStore::Fs(_));
    println!(
        "Blobs {}",
        if separate_blobs {
            "in a filesystem blob store"
        } else {
            "in the data store"
        }
    );

    let before = [
        import(&client, "Before the snapshot, one").await,
        import(&client, "Before the snapshot, two").await,
    ];
    assert!(all(admin).await.is_empty(), "no snapshots yet");

    // A snapshot while the server runs
    let id = take(admin).await;
    let snapshot = settled(admin, &id).await;
    assert_eq!(snapshot["status"], "done", "{snapshot}");
    assert_eq!(snapshot["createdBy"], "admin@example.com", "{snapshot}");
    let holds = if separate_blobs {
        json!(["data", "blobs"])
    } else {
        json!(["data"])
    };
    assert_eq!(snapshot["holds"], holds, "{snapshot}");
    assert!(snapshot["size"].as_u64().unwrap() > 0, "{snapshot}");
    let after = import(&client, "After the snapshot").await;

    // The directory: whole, named for its time, `latest`, the manifest
    let path = path_of(&snapshot);
    let name = snapshot["name"].as_str().unwrap();
    assert_eq!(path.file_name().unwrap().to_str().unwrap(), name);
    assert!(name.len() == 16 && name.ends_with('Z'), "{name}");
    let root = path.parent().unwrap().to_path_buf();
    assert_eq!(root.file_name().unwrap(), "snapshots");
    assert_eq!(
        std::fs::read_link(root.join("latest")).unwrap(),
        PathBuf::from(name)
    );
    assert!(path.join("data/CURRENT").exists(), "a RocksDB checkpoint");
    assert_eq!(path.join("blobs").exists(), separate_blobs);
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(path.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(manifest["id"], json!(id), "{manifest}");
    assert_eq!(manifest["holds"], holds, "{manifest}");
    assert!(
        manifest["restore"].as_array().unwrap().len() >= 3,
        "{manifest}"
    );
    assert!(
        std::fs::read_dir(&root).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial")),
        "nothing partial left"
    );

    // Restored, it has the mail that was there, and not what came after
    let restored = RocksDbStore::open(structs::RocksDbStore {
        path: path.join("data").to_string_lossy().to_string(),
        ..Default::default()
    })
    .await
    .unwrap();
    let blobs = if separate_blobs {
        FsStore::open(structs::FileSystemStore {
            path: path.join("blobs").to_string_lossy().to_string(),
            ..Default::default()
        })
        .await
        .unwrap()
    } else {
        BlobStore::Store(restored.clone())
    };
    for (document_id, subject) in before.iter().zip(["one", "two"]) {
        let hash = blob_in(&restored, ann_id, *document_id)
            .await
            .unwrap_or_else(|| panic!("message {document_id} isn't in the snapshot"));
        let content = blobs
            .get_blob(hash.as_slice(), 0..usize::MAX)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("the blob of message {document_id} isn't in the snapshot"));
        let content = String::from_utf8_lossy(&content);
        assert!(content.contains(&format!("Before the snapshot, {subject}")));
    }
    assert!(
        blob_in(&restored, ann_id, after).await.is_none(),
        "mail that came after isn't in it"
    );
    drop(blobs);
    drop(restored);

    // A snapshot can't be changed, and takes no properties
    let (_, response) = call(
        admin,
        "inbuxa:StoreSnapshot/set",
        json!({"update": {&id: {"name": "x"}}}),
    )
    .await;
    assert!(response["notUpdated"].get(&id).is_some(), "{response}");
    let (_, response) = call(
        admin,
        "inbuxa:StoreSnapshot/set",
        json!({"create": {"x": {"path": "/tmp/elsewhere"}}}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["x"]["type"], "invalidProperties",
        "{response}"
    );

    // One at a time, and one being taken can't be destroyed. With separate
    // blobs a snapshot waits for the blob purge, so holding it here keeps
    // one being taken for as long as this needs
    if separate_blobs {
        let hold = hold_blob_purge().await;
        let waiting = take(admin).await;
        assert_eq!(get(admin, &waiting).await["status"], "running");
        let (_, response) = call(
            admin,
            "inbuxa:StoreSnapshot/set",
            json!({"create": {"x": {}}}),
        )
        .await;
        assert_eq!(
            response["notCreated"]["x"]["type"], "forbidden",
            "{response}"
        );
        let (_, response) = call(
            admin,
            "inbuxa:StoreSnapshot/set",
            json!({"destroy": [&waiting]}),
        )
        .await;
        assert_eq!(
            response["notDestroyed"][&waiting]["type"], "forbidden",
            "{response}"
        );
        drop(hold);
        assert_eq!(settled(admin, &waiting).await["status"], "done");
    } else {
        let next = take(admin).await;
        assert_eq!(settled(admin, &next).await["status"], "done");
    }

    // Only the latest two are kept
    let third = take(admin).await;
    let third_snapshot = settled(admin, &third).await;
    let listed = all(admin).await;
    assert_eq!(listed.len(), 2, "{listed:?}");
    assert_eq!(listed[0]["id"], json!(third), "newest first: {listed:?}");
    assert!(!path.exists(), "the oldest went");
    let (_, response) = call(admin, "inbuxa:StoreSnapshot/get", json!({"ids": [&id]})).await;
    assert_eq!(response["notFound"], json!([id]), "{response}");
    assert_eq!(
        std::fs::read_link(root.join("latest")).unwrap(),
        PathBuf::from(third_snapshot["name"].as_str().unwrap())
    );

    // Destroying one deletes it; `latest` moves to the one left
    let unknown = Id::from(1u64).to_string();
    let (_, response) = call(
        admin,
        "inbuxa:StoreSnapshot/set",
        json!({"destroy": [&third, &unknown]}),
    )
    .await;
    assert_eq!(response["destroyed"], json!([third]), "{response}");
    assert_eq!(
        response["notDestroyed"][&unknown]["type"], "notFound",
        "{response}"
    );
    assert!(!path_of(&third_snapshot).exists());
    let left = all(admin).await;
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(
        std::fs::read_link(root.join("latest")).unwrap(),
        PathBuf::from(left[0]["name"].as_str().unwrap())
    );

    // BM-8: while a blob store change isn't settled, a new snapshot is
    // refused, and the ones on disk are still listed and can be destroyed
    let blobs = test.server.blob_store().clone();
    let old = FsStore::open(structs::FileSystemStore {
        path: format!("{}/old-blobs", test.tmp_dir()),
        depth: 2,
    })
    .await
    .unwrap();
    use_blob_store(
        test,
        BlobStore::Moving(Arc::new(MovingBlobStore::new(
            blobs.clone(),
            vec![OldBlobStore {
                change_id: 1,
                store: old,
            }],
        ))),
    );
    let (_, response) = call(
        admin,
        "inbuxa:StoreSnapshot/set",
        json!({"create": {"x": {}}}),
    )
    .await;
    assert!(
        response["notCreated"]["x"]["description"]
            .as_str()
            .is_some_and(|d| d.contains("blob store changed")),
        "{response}"
    );
    let kept = all(admin).await;
    assert_eq!(kept.len(), 1, "still listed while refused: {kept:?}");
    let kept_id = kept[0]["id"].as_str().unwrap().to_string();
    let (_, response) = call(
        admin,
        "inbuxa:StoreSnapshot/set",
        json!({"destroy": [&kept_id]}),
    )
    .await;
    assert_eq!(response["destroyed"], json!([kept_id]), "{response}");
    assert!(!path_of(&kept[0]).exists());
    use_blob_store(test, blobs);

    // Taking and destroying are audited
    let (_, response) = call(
        admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:StoreSnapshot"}}),
    )
    .await;
    assert!(
        response["ids"].as_array().is_some_and(|ids| ids.len() >= 4),
        "three taken and one destroyed, audited: {response}"
    );

    // Nobody without the permission, or in a tenant, reaches snapshots
    let (name, response) = call(ann, "inbuxa:StoreSnapshot/get", json!({"ids": null})).await;
    assert_eq!(name, "error", "a user: {response}");
    let tenant = admin
        .registry_create_object(Tenant {
            name: "Store snapshot tenant".to_string(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Domain {
            name: "storesnapshot.example.org".to_string(),
            member_tenant_id: Some(tenant),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    let t_admin = admin
        .create_user_account(
            "tadmin@storesnapshot.example.org",
            "tenant-admin-secret-5521",
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
        ("inbuxa:StoreSnapshot/get", json!({"ids": null})),
        ("inbuxa:StoreSnapshot/set", json!({"create": {"x": {}}})),
    ] {
        let (name, response) = call(&t_admin, method, arguments).await;
        assert_eq!(name, "error", "{method} by a tenant: {response}");
    }
}

/// Runs these tests alone, with RocksDB:
/// `STORE=RocksDb cargo test -p tests store_snapshot_tests -- --ignored`,
/// and again with `BLOB_STORE=FileSystem` for a separate blob store.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn store_snapshot_tests() {
    let mut test = TestServerBuilder::new("store_snapshot_tests")
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
            "ann-secret-61734",
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
