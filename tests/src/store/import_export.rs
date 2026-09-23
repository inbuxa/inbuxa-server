/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::utils::{
    cleanup::{store_assert_is_empty, store_destroy},
    server::TestServer,
    temp_dir::TempDir,
};
use ::registry::schema::{
    enums::{CompressionAlgo, TaskStoreMaintenanceType},
    prelude::ObjectType,
    structs::Task,
};
use ahash::AHashSet;
use common::{
    DATABASE_SCHEMA_VERSION,
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY, backup::BackupParams},
};
use store::{
    rand,
    write::{
        AnyClass, AnyKey, BatchBuilder, BlobLink, BlobOp, Operation, QueueClass, QueueEvent,
        RegistryClass, TaskQueueClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
    *,
};
use types::{
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::{Field, MailboxField},
};

pub async fn test(test: &TestServer) {
    // Make sure the store is empty
    store_assert_is_empty(test.server.store(), test.server.blob_store().clone(), true).await;
    let db = test.server.store().clone();

    // Create blobs
    println!("Creating blobs...");
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        }),
        DATABASE_SCHEMA_VERSION.serialize(),
    );
    let mut blob_hashes = Vec::new();
    for blob_size in [16, 128, 1024, 2056, 102400] {
        let data = random_bytes(blob_size);
        let hash = BlobHash::generate(data.as_slice());
        blob_hashes.push(hash.clone());
        test.server
            .blob_store()
            .put_blob(hash.as_ref(), &data, CompressionAlgo::Lz4)
            .await
            .unwrap();
        batch.set(ValueClass::Blob(BlobOp::Commit { hash }), vec![]);
    }
    db.write(batch.build_all()).await.unwrap();

    // Create account data
    println!("Creating account data...");
    for account_id in 0u32..10u32 {
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);

        // Create properties of different sizes
        for collection in [
            Collection::Email,
            Collection::Mailbox,
            Collection::Thread,
            Collection::Identity,
        ] {
            batch.with_collection(collection);

            for document_id in [0, 10, 20, 30, 40] {
                batch.with_document(document_id);

                if collection == Collection::Mailbox {
                    batch
                        .set(
                            ValueClass::Property(Field::ARCHIVE.into()),
                            random_bytes(10),
                        )
                        .add(
                            ValueClass::Property(MailboxField::UidCounter.into()),
                            rand::random(),
                        );
                }

                for (idx, value_size) in [16, 128, 1024, 2056, 102400].into_iter().enumerate() {
                    batch.set(ValueClass::Property(idx as u8), random_bytes(value_size));
                }

                for grant_account_id in 0u32..10u32 {
                    if account_id != grant_account_id {
                        batch.set(
                            ValueClass::Acl(grant_account_id),
                            vec![account_id as u8, grant_account_id as u8, document_id as u8],
                        );
                    }
                }

                for hash in &blob_hashes {
                    batch.set(
                        ValueClass::Blob(BlobOp::Link {
                            hash: hash.clone(),
                            to: BlobLink::Document,
                        }),
                        vec![],
                    );
                }

                batch.log_item_insert(SyncCollection::from(collection), None);

                for field in 0..5 {
                    batch.any_op(Operation::Index {
                        field,
                        key: random_bytes(field as usize + 2),
                        set: true,
                    });
                }
            }
        }

        db.write(batch.build_all()).await.unwrap();
    }

    // Create queue, config and lookup data
    println!("Creating queue, config and lookup data...");
    let mut batch = BatchBuilder::new();
    for idx in [1, 2, 3, 4, 5] {
        batch.set(
            ValueClass::Queue(QueueClass::Message(rand::random())),
            random_bytes(idx),
        );
        batch.set(
            ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: rand::random(),
                queue_id: rand::random(),
                queue_name: rand::random(),
            })),
            random_bytes(idx),
        );
        batch.set(
            ValueClass::Registry(RegistryClass::Item {
                object_id: 0,
                item_id: 1,
            }),
            random_bytes(idx + 10),
        );
        batch.set(
            ValueClass::Registry(RegistryClass::IndexId {
                object_id: idx as u16,
                item_id: idx as u64 * 100,
            }),
            vec![],
        );
        for index_id in 0u16..3 {
            batch.set(
                ValueClass::Registry(RegistryClass::Index {
                    object_id: idx as u16,
                    index_id,
                    key: random_bytes(idx + index_id as usize),
                    item_id: idx as u64 * 100,
                }),
                vec![],
            );
        }
    }
    db.write(batch.build_all()).await.unwrap();

    // inbuxa: registry objects kept outside the registry subspace (archived
    // items for undelete, spam training samples, directory entries) and the
    // fork's own subspace. Exports used to leave the first two behind.
    println!("Creating archived items, spam samples and fork data...");
    let mut batch = BatchBuilder::new();
    for item_id in [1u64, 2, 3] {
        for object in [
            ObjectType::ArchivedItem,
            ObjectType::SpamTrainingSample,
            ObjectType::Account,
        ] {
            batch.set(
                ValueClass::Registry(RegistryClass::Item {
                    object_id: object as u16,
                    item_id,
                }),
                random_bytes(item_id as usize * 64),
            );
        }
        batch.set(
            ValueClass::Any(AnyClass {
                subspace: SUBSPACE_INBUXA,
                key: [b'U', b'x']
                    .into_iter()
                    .chain(item_id.to_be_bytes())
                    .collect(),
            }),
            random_bytes(32),
        );
    }
    db.write(batch.build_all()).await.unwrap();

    // inbuxa: the trained spam classifier lives in blobs with fixed names
    let mut named_blobs = Vec::new();
    for key in [SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY] {
        let data = random_bytes(4096);
        test.server
            .blob_store()
            .put_blob(key, &data, CompressionAlgo::Lz4)
            .await
            .unwrap();
        named_blobs.push((key, data));
    }

    // Create directory data
    println!("Creating directory data...");
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(u32::MAX)
        .with_collection(Collection::Principal);

    for account_id in [1, 2, 3, 4, 5] {
        batch
            .with_document(account_id)
            .add(ValueClass::Quota, account_id as i64 * 1000);
    }
    db.write(batch.build_all()).await.unwrap();

    // Obtain store hash
    println!("Calculating store hash...");
    let snapshot = Snapshot::new(&db).await;
    assert!(!snapshot.keys.is_empty(), "Store hash counts are empty",);
    for subspace in [
        SUBSPACE_DELETED_ITEMS,
        SUBSPACE_SPAM_SAMPLES,
        SUBSPACE_INBUXA,
    ] {
        assert!(
            snapshot.keys.iter().any(|k| k.subspace == subspace),
            "No test data in subspace {}",
            char::from(subspace)
        );
    }

    // Export store
    println!("Exporting store...");
    let temp_dir = TempDir::new("art_vandelay_tests", true);
    test.server
        .core
        .backup(BackupParams::new(temp_dir.path.clone()))
        .await;

    // Destroy store
    println!("Destroying store...");
    store_destroy(&db).await;
    store_assert_is_empty(&db, db.clone().into(), true).await;

    // Import store over a node id lease
    println!("Importing store...");
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::NodeId(0),
        KeySerializer::new(U64_LEN + 9)
            .write(0u64)
            .write("localhost")
            .finalize(),
    );
    db.write(batch.build_all()).await.unwrap();
    for (key, _) in &named_blobs {
        test.server.blob_store().delete_blob(key).await.unwrap();
    }
    let imported = test.server.core.restore(temp_dir.path.clone()).await;
    let mut batch = BatchBuilder::new();
    batch.clear(ValueClass::NodeId(0));
    db.write(batch.build_all()).await.unwrap();
    for subspace in [
        SUBSPACE_DELETED_ITEMS,
        SUBSPACE_SPAM_SAMPLES,
        SUBSPACE_INBUXA,
    ] {
        assert!(
            imported.contains(&subspace),
            "Subspace {} was not exported",
            char::from(subspace)
        );
    }

    // Verify hash
    print!("Verifying store hash...");
    snapshot.assert_is_eq(&Snapshot::new(&db).await);
    assert_named_blobs(test.server.blob_store(), &named_blobs).await;
    println!(" GREAT SUCCESS!");

    // inbuxa: import the same export into a fresh store of another backend,
    // the way a move from one database to another does it
    #[cfg(all(feature = "rocks", feature = "sqlite"))]
    cross_backend(test, &db, &temp_dir, &named_blobs).await;

    // Destroy store
    for (key, _) in &named_blobs {
        test.server.blob_store().delete_blob(key).await.unwrap();
    }
    store_destroy(&db).await;
    store_assert_is_empty(&db, db.clone().into(), true).await;
    temp_dir.delete();
}

#[cfg(all(feature = "rocks", feature = "sqlite"))]
async fn cross_backend(
    test: &TestServer,
    source: &Store,
    export: &TempDir,
    named_blobs: &[(&[u8], Vec<u8>)],
) {
    let source_type = std::env::var("STORE").unwrap();
    let target_type = if source_type.eq_ignore_ascii_case("sqlite") {
        "RocksDb"
    } else {
        "Sqlite"
    };
    println!("Importing the export into a fresh {target_type} store...");

    let target_dir = TempDir::new("art_vandelay_cross_backend", true);
    let target = Store::build(
        crate::utils::storage::build_data_store(target_type, &target_dir.path.to_string_lossy())
            .await,
    )
    .await
    .unwrap();
    target.create_tables().await.unwrap();
    store_destroy(&target).await;

    let mut core = test.server.core.as_ref().clone();
    core.storage.data = target.clone();
    core.storage.blob = target.clone().into();
    let imported = core.restore(export.path.clone()).await;

    // Counters are stored differently by the SQL and key-value backends, so
    // compare their keys here and their values through the counter API.
    print!("Verifying {target_type} store hash...");
    Snapshot::new_portable(source)
        .await
        .assert_is_eq(&Snapshot::new_portable(&target).await);
    for subspace in [SUBSPACE_COUNTER, SUBSPACE_QUOTA] {
        let mut keys = Vec::new();
        source
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace,
                        key: vec![0u8],
                    },
                    AnyKey {
                        subspace,
                        key: vec![u8::MAX; 10],
                    },
                )
                .no_values(),
                |key, _| {
                    keys.push(key.to_vec());
                    Ok(true)
                },
            )
            .await
            .unwrap();
        for key in keys {
            let class = || {
                ValueClass::Any(AnyClass {
                    subspace,
                    key: key.clone(),
                })
            };
            assert_eq!(
                source.get_counter(class()).await.unwrap(),
                target.get_counter(class()).await.unwrap(),
                "Counter mismatch in {} for {key:?}",
                char::from(subspace)
            );
        }
    }
    assert_named_blobs(&core.storage.blob, named_blobs).await;
    println!(" GREAT SUCCESS!");

    // The search index isn't exported; the import queues its rebuild
    let queued = core.queue_reindex(&imported).await;
    let expected = [
        TaskStoreMaintenanceType::ReindexAccounts,
        TaskStoreMaintenanceType::ReindexTelemetry,
    ];
    assert_eq!(queued, expected);
    let mut task_ids = Vec::new();
    target
        .iterate(
            IterateParams::new(
                AnyKey {
                    subspace: SUBSPACE_TASK_QUEUE,
                    key: vec![0u8],
                },
                AnyKey {
                    subspace: SUBSPACE_TASK_QUEUE,
                    key: vec![u8::MAX; 20],
                },
            )
            .no_values(),
            |key, _| {
                if key.deserialize_be_u64(0)? == 0 {
                    task_ids.push(key.deserialize_be_u64(U64_LEN)?);
                }
                Ok(true)
            },
        )
        .await
        .unwrap();
    let mut found = Vec::new();
    for id in task_ids {
        match target
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task { id },
            )))
            .await
            .unwrap()
        {
            Some(Task::StoreMaintenance(task)) => found.push(task.maintenance_type),
            other => panic!("Unexpected task {other:?}"),
        }
    }
    found.sort_by_key(|t| *t as u16);
    assert_eq!(found, expected, "Queued tasks don't match");

    store_destroy(&target).await;
    drop(core);
    drop(target);
    target_dir.delete();
}

async fn assert_named_blobs(blob_store: &BlobStore, named_blobs: &[(&[u8], Vec<u8>)]) {
    for (key, data) in named_blobs {
        assert_eq!(
            blob_store
                .get_blob(key, 0..usize::MAX)
                .await
                .unwrap()
                .as_ref(),
            Some(data),
            "Blob {} was not restored",
            String::from_utf8_lossy(key)
        );
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    keys: AHashSet<KeyValue>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct KeyValue {
    subspace: u8,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl Snapshot {
    async fn new(db: &Store) -> Self {
        Self::build(db, !db.is_sql(), true).await
    }

    /// Comparable across backends: no counter values, which the SQL and
    /// key-value stores encode differently, and no blobs, which only live in
    /// the data store when it doubles as the blob store.
    #[cfg(all(feature = "rocks", feature = "sqlite"))]
    async fn new_portable(db: &Store) -> Self {
        Self::build(db, false, false).await
    }

    async fn build(db: &Store, counter_values: bool, with_blobs: bool) -> Self {
        let is_sql = !counter_values;

        let mut keys = AHashSet::new();

        for (subspace, with_values) in [
            (SUBSPACE_ACL, true),
            (SUBSPACE_TASK_QUEUE, true),
            (SUBSPACE_INDEXES, false),
            (SUBSPACE_DELETED_ITEMS, true),
            (SUBSPACE_SPAM_SAMPLES, true),
            (SUBSPACE_BLOB_LINK, true),
            (SUBSPACE_BLOBS, true),
            (SUBSPACE_LOGS, true),
            (SUBSPACE_COUNTER, !is_sql),
            (SUBSPACE_IN_MEMORY_COUNTER, !is_sql),
            (SUBSPACE_IN_MEMORY_VALUE, true),
            (SUBSPACE_PROPERTY, true),
            (SUBSPACE_REGISTRY, true),
            (SUBSPACE_REGISTRY_IDX, !is_sql),
            (SUBSPACE_REGISTRY_PK, true),
            (SUBSPACE_QUEUE_MESSAGE, true),
            (SUBSPACE_QUEUE_EVENT, true),
            (SUBSPACE_QUOTA, !is_sql),
            (SUBSPACE_REPORT_OUT, true),
            (SUBSPACE_REPORT_IN, true),
            (SUBSPACE_DIRECTORY, true),
            (SUBSPACE_INBUXA, true),
        ] {
            if subspace == SUBSPACE_BLOBS && !with_blobs {
                continue;
            }
            let from_key = AnyKey {
                subspace,
                key: vec![0u8],
            };
            let to_key = AnyKey {
                subspace,
                key: vec![u8::MAX; 10],
            };

            db.iterate(
                IterateParams::new(from_key, to_key).set_values(with_values),
                |key, value| {
                    keys.insert(KeyValue {
                        subspace,
                        key: key.to_vec(),
                        value: value.to_vec(),
                    });

                    Ok(true)
                },
            )
            .await
            .unwrap();
        }

        Snapshot { keys }
    }

    fn assert_is_eq(&self, other: &Self) {
        let mut is_err = false;
        for key in &self.keys {
            if !other.keys.contains(key) {
                println!(
                    "Subspace {}, Key {:?} not found in restored snapshot",
                    char::from(key.subspace),
                    key.key,
                );
                is_err = true;
            }
        }
        for key in &other.keys {
            if !self.keys.contains(key) {
                println!(
                    "Subspace {}, Key {:?} not found in original snapshot",
                    char::from(key.subspace),
                    key.key,
                );
                is_err = true;
            }
        }

        if is_err {
            panic!("Snapshot mismatch");
        }
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}
