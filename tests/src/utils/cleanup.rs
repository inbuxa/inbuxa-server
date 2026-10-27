/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use ::registry::{
    schema::prelude::{OBJ_SINGLETON, ObjectType},
    types::EnumImpl,
};
use store::{
    ValueKey,
    write::{
        key::{CounterKind, DeserializeBigEndian},
        *,
    },
    *,
};
use trc::AddContext;
use types::blob_hash::{BLOB_HASH_LEN, BlobHash};

pub async fn store_destroy(store: &Store) {
    store_destroy_sql_indexes(store).await;

    for subspace in Subspace::ALL.iter().copied() {
        // The SQL stores keep their search index in tables of their own
        if subspace.is_internal_fts() && store.is_pg_or_mysql() {
            continue;
        }

        store
            .delete_range(
                AnyKey {
                    subspace,
                    key: vec![0u8],
                },
                AnyKey {
                    subspace,
                    key: vec![u8::MAX; 16],
                },
            )
            .await
            .unwrap();
    }
}

pub async fn search_store_destroy(store: &SearchStore) {
    match &store {
        SearchStore::Store(store) => {
            store_destroy_sql_indexes(store).await;
        }
        #[cfg(feature = "postgres")]
        SearchStore::PostgreSQL(store) => {
            store_destroy_sql_indexes(&Store::PostgreSQL(store.clone())).await;
        }
        #[cfg(feature = "mysql")]
        SearchStore::MySQL(store) => {
            store_destroy_sql_indexes(&Store::MySQL(store.clone())).await;
        }
        SearchStore::Replicated(store) => {
            store_destroy_sql_indexes(&store.primary).await;
        }
        SearchStore::ElasticSearch(store) => {
            if let Err(err) = store.drop_indexes().await {
                eprintln!("Failed to drop elasticsearch indexes: {}", err);
            }
            store.create_indexes().await.unwrap();
        }
        SearchStore::MeiliSearch(store) => {
            if let Err(err) = store.drop_indexes().await {
                eprintln!("Failed to drop meilisearch indexes: {}", err);
            }
            store.create_indexes().await.unwrap();
        }
    }
}

#[allow(unused_variables)]
async fn store_destroy_sql_indexes(store: &Store) {
    #[cfg(any(feature = "postgres", feature = "mysql"))]
    {
        if store.is_pg_or_mysql() {
            for index in [
                SearchIndex::Email,
                SearchIndex::Calendar,
                SearchIndex::Contacts,
                SearchIndex::File,
                SearchIndex::Tracing,
            ] {
                #[cfg(feature = "postgres")]
                let table = index.psql_table();
                #[cfg(feature = "mysql")]
                let table = index.mysql_table();

                let _ = store
                    .sql_query::<usize>(&format!("TRUNCATE TABLE {table}"), vec![])
                    .await;
            }
        }
    }
}

pub async fn store_blob_expire_all(store: &Store) {
    // Delete all temporary hashes
    let from_key = ValueKey {
        account_id: 0,
        collection: 0,
        document_id: 0,
        class: ValueClass::Blob(BlobOp::Commit {
            hash: BlobHash::default(),
        }),
    };
    let to_key = ValueKey {
        account_id: u32::MAX,
        collection: u8::MAX,
        document_id: u32::MAX,
        class: ValueClass::Blob(BlobOp::Link {
            hash: BlobHash::new_max(),
            to: BlobLink::Document,
        }),
    };
    let mut batch = BatchBuilder::new();
    let mut last_account_id = u32::MAX;
    store
        .iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                if key.len() == BLOB_HASH_LEN + U32_LEN + U64_LEN {
                    let account_id = key
                        .deserialize_be_u32(BLOB_HASH_LEN)
                        .caused_by(trc::location!())?;
                    if account_id != last_account_id {
                        last_account_id = account_id;
                        batch.with_account_id(account_id);
                    }
                    let hash =
                        BlobHash::try_from_hash_slice(key.get(..BLOB_HASH_LEN).unwrap()).unwrap();
                    let until = key
                        .deserialize_be_u64(BLOB_HASH_LEN + U32_LEN)
                        .caused_by(trc::location!())?;

                    // inbuxa: 1.0 writes a blob's Commit marker only when its
                    // hold is released, so a hold whose write failed has just
                    // the temporary link; expire the link rather than remove
                    // it, so purge_blobs drops the blob as well
                    batch.clear(ValueClass::Blob(BlobOp::Link {
                        hash: hash.clone(),
                        to: BlobLink::Temporary { until },
                    }));
                    batch.set(
                        ValueClass::Blob(BlobOp::Link {
                            hash,
                            to: BlobLink::Temporary { until: 0 },
                        }),
                        value.to_vec(),
                    );
                }

                Ok(true)
            },
        )
        .await
        .unwrap();
    store.write_batch(&mut batch).await.unwrap();
}

pub async fn store_lookup_expire_all(store: &Store) {
    // inbuxa: the in-memory store kept in the data store; everything with an
    // expiry goes, and counters are temporary
    store.purge_in_memory(u64::MAX - 1).await.unwrap();
    store
        .delete_range(
            AnyKey {
                subspace: Subspace::InMemoryCounter,
                key: vec![0u8],
            },
            AnyKey {
                subspace: Subspace::InMemoryCounter,
                key: vec![u8::MAX; 16],
            },
        )
        .await
        .unwrap();
}

#[allow(unused_variables)]
pub async fn store_assert_is_empty(store: &Store, blob_store: BlobStore, include_registry: bool) {
    store_blob_expire_all(store).await;
    store_lookup_expire_all(store).await;
    for shard_idx in 0..=u8::MAX {
        store
            .purge_blobs(blob_store.clone(), shard_idx)
            .await
            .unwrap();
    }
    store.purge_store().await.unwrap();

    let store = store.clone();
    let mut failed = false;
    let mut delete_batch = BatchBuilder::new();

    // inbuxa: 1.0's subspaces. Logs are cleared below; System keeps the
    // node's id and our own subspace was never checked
    for subspace in Subspace::ALL.iter().copied().filter(|subspace| {
        !matches!(
            subspace,
            Subspace::Logs | Subspace::System | Subspace::Inbuxa
        )
    }) {
        if subspace.is_internal_fts() && store.is_pg_or_mysql() {
            continue;
        }
        let with_values =
            subspace.shape() == Shape::Value || subspace == Subspace::Counter;

        let from_key = AnyKey {
            subspace,
            key: vec![0u8],
        };
        let to_key = AnyKey {
            subspace,
            key: vec![u8::MAX; 10],
        };

        store
            .iterate(
                IterateParams::new(from_key, to_key).set_values(with_values),
                |key, value| {
                    match subspace {
                        // inbuxa: 1.0 keys every counter by its kind first.
                        // Registry id counters stay; id, change and UID
                        // counters go; usage counters must be back at zero.
                        Subspace::Counter
                            if key.first().is_some_and(|kind| {
                                *kind == CounterKind::RegistryId.byte()
                                    || [
                                        CounterKind::DocumentId,
                                        CounterKind::ChangeId,
                                        CounterKind::MailboxUid,
                                        CounterKind::ReportRow,
                                        // a tenant's usage isn't reduced when
                                        // a member account is destroyed (0.16
                                        // neither); 0.16's check deleted it too
                                        CounterKind::TenantQuota,
                                    ]
                                    .into_iter()
                                    .any(|k| k.byte() == *kind)
                                    || value.iter().all(|b| *b == 0)
                            }) =>
                        {
                            if key[0] != CounterKind::RegistryId.byte() {
                                delete_batch.clear(ValueClass::Any(AnyClass {
                                    subspace,
                                    key: key.to_vec(),
                                }));
                            }
                            return Ok(true);
                        }
                        // inbuxa: the search queue's per-partition cursors
                        // stay; only queued documents count
                        Subspace::SearchQueue if key.len() != 1 + (2 * U32_LEN) + U64_LEN => {
                            return Ok(true);
                        }
                        Subspace::Indexes => {
                            println!(
                                concat!(
                                    "Found index key, account {}, collection {}, ",
                                    "document {}, property {}, value {:?}: {:?}"
                                ),
                                u32::from_be_bytes(key[0..4].try_into().unwrap()),
                                key[4],
                                u32::from_be_bytes(key[key.len() - 4..].try_into().unwrap()),
                                key[5],
                                String::from_utf8_lossy(&key[6..key.len() - 4]),
                                key
                            );
                        }
                        Subspace::Registry | Subspace::Directory | Subspace::SpamSamples => {
                            let object_id =
                                ObjectType::from_id(key.deserialize_be_u16(0).unwrap()).unwrap();

                            if include_registry && is_allowed_registry_type(object_id) {
                                return Ok(true);
                            }
                            let item_id = key.deserialize_be_u64(U16_LEN).unwrap();

                            println!(
                                "Found registry item for object type {:?} and id {}",
                                object_id, item_id
                            );
                        }
                        Subspace::RegistryIndex => {
                            let mut id = key.deserialize_be_u16(0).unwrap();
                            if id == u16::MAX {
                                id = key.deserialize_be_u16(U16_LEN).unwrap();
                            }

                            let object_id = ObjectType::from_id(id).unwrap();

                            if include_registry && is_allowed_registry_type(object_id) {
                                return Ok(true);
                            }

                            println!(
                                "Found registry index for object type {:?}: {:?}",
                                object_id, key
                            );
                        }
                        Subspace::RegistryPrimaryKey => {
                            let mut id = key.deserialize_be_u16(0).unwrap();
                            if id == RegistryClass::REFERENCE_MARKER {
                                // inbuxa: 1.0 references: marker, then the
                                // referenced object's type
                                id = key.deserialize_be_u16(U16_LEN).unwrap();
                            } else if id == u16::MAX {
                                id = value.deserialize_be_u16(0).unwrap();
                            }
                            let object_id = ObjectType::from_id(id).unwrap();
                            if include_registry && is_allowed_registry_type(object_id) {
                                return Ok(true);
                            }

                            println!(
                                "Found registry primary key for object type {:?}: {:?}",
                                object_id, key
                            );
                        }
                        _ => {
                            println!(
                                "Found key in {:?}: {:?} ({:?}) = {:?} ({:?})",
                                char::from(subspace.byte()),
                                key,
                                String::from_utf8_lossy(key),
                                value,
                                String::from_utf8_lossy(value)
                            );
                        }
                    }
                    failed = true;

                    Ok(true)
                },
            )
            .await
            .unwrap();
    }

    // Delete logs and counters
    store
        .delete_range(
            AnyKey {
                subspace: Subspace::Logs,
                key: &[0u8],
            },
            AnyKey {
                subspace: Subspace::Logs,
                key: &[
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                ],
            },
        )
        .await
        .unwrap();

    if !delete_batch.is_empty() {
        store.write_batch(&mut delete_batch).await.unwrap();
    }

    if failed {
        panic!("Store is not empty.");
    }
}

fn is_allowed_registry_type(object_type: ObjectType) -> bool {
    (object_type.flags() & OBJ_SINGLETON) != 0
        || matches!(
            object_type,
            ObjectType::Role
                | ObjectType::Account
                | ObjectType::NetworkListener
                | ObjectType::MtaDeliverySchedule
                | ObjectType::MtaRoute
                | ObjectType::MtaTlsStrategy
                | ObjectType::MtaVirtualQueue
                | ObjectType::MtaConnectionStrategy
                | ObjectType::MtaInboundThrottle
                | ObjectType::MtaQueueQuota
                | ObjectType::Tracer
                | ObjectType::Domain
        )
}
