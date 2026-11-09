/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{BlobStore, Store, backend::fs::FsStore, registry::bootstrap::Bootstrap};
use registry::schema::{prelude::ObjectType, structs};

impl BlobStore {
    pub async fn build(bp: &mut Bootstrap) -> Option<Self> {
        let config = bp.setting_infallible::<structs::BlobStore>().await;
        let mut warnings = Vec::new();
        let result = BlobStore::open(config, &bp.data_store, &mut warnings).await;
        for warning in warnings {
            bp.build_warning(ObjectType::BlobStore.singleton(), warning);
        }

        match result {
            Ok(store) => Some(store),
            Err(err) => {
                bp.build_error(ObjectType::BlobStore.singleton(), err);
                None
            }
        }
    }

    /// inbuxa: the blob store a setting names. Split out of `build` so a
    /// blob store the setting no longer names can be opened too, to read
    /// what was left in it (blob-store-change spec, BM-2).
    #[allow(unreachable_patterns)]
    pub async fn open(
        config: structs::BlobStore,
        data_store: &Store,
        warnings: &mut Vec<String>,
    ) -> Result<Self, String> {
        match config {
            structs::BlobStore::Default => Ok(BlobStore::Store(data_store.clone())),
            #[cfg(feature = "foundation")]
            structs::BlobStore::FoundationDb(foundation_db_store) => {
                crate::backend::foundationdb::FdbStore::open(foundation_db_store)
                    .await
                    .map(BlobStore::Store)
            }
            #[cfg(feature = "postgres")]
            structs::BlobStore::PostgreSql(postgre_sql_store) => {
                crate::backend::postgres::PostgresStore::open(postgre_sql_store)
                    .await
                    .map(BlobStore::Store)
            }
            #[cfg(feature = "mysql")]
            structs::BlobStore::MySql(my_sql_store) => {
                crate::backend::mysql::MysqlStore::open(my_sql_store)
                    .await
                    .map(BlobStore::Store)
            }
            #[cfg(feature = "s3")]
            structs::BlobStore::S3(s3_store) => crate::backend::s3::S3Store::open(s3_store).await,
            #[cfg(feature = "azure")]
            structs::BlobStore::Azure(azure_store) => {
                crate::backend::azure::AzureStore::open(azure_store).await
            }
            structs::BlobStore::FileSystem(file_system_store) => {
                FsStore::open(file_system_store).await
            }
            // inbuxa: ST-16 to ST-22
            structs::BlobStore::Sharded(sharded) => {
                crate::backend::scaleout::ShardedBlobStore::open(sharded, data_store, warnings)
                    .await
            }
            _ => Err("Binary was not compiled with the selected blob store backend".to_string()),
        }
    }
}

/// inbuxa: blob-store-change spec, BM-1: where a blob store setting puts
/// blobs, without its credentials or tuning. Two settings with the same
/// place read the same blobs; a different place doesn't have them.
pub fn blob_store_location(config: &structs::BlobStore) -> String {
    match config {
        structs::BlobStore::Default => "the data store".to_string(),
        // ST-16 to ST-22: the set moves blobs between its members itself
        structs::BlobStore::Sharded(_) => "a sharded set".to_string(),
        structs::BlobStore::S3(s3) => {
            let region = match &s3.region {
                structs::S3StoreRegion::Custom(custom) => {
                    format!("{} ({})", custom.custom_endpoint, custom.custom_region)
                }
                region => format!("{region:?}"),
            };
            with_prefix(
                format!("S3 {region}, bucket {}", s3.bucket),
                s3.key_prefix.as_deref(),
            )
        }
        structs::BlobStore::Azure(azure) => with_prefix(
            format!(
                "Azure {}, container {}",
                azure.storage_account, azure.container
            ),
            azure.key_prefix.as_deref(),
        ),
        structs::BlobStore::FileSystem(fs) => {
            format!("the directory {}, depth {}", fs.path, fs.depth.min(5))
        }
        structs::BlobStore::FoundationDb(fdb) => format!(
            "FoundationDB {}",
            fdb.cluster_file
                .as_deref()
                .unwrap_or("(default cluster file)")
        ),
        structs::BlobStore::PostgreSql(pg) => {
            format!("PostgreSQL {}:{}/{}", pg.host, pg.port, pg.database)
        }
        structs::BlobStore::MySql(my) => {
            format!("MySQL {}:{}/{}", my.host, my.port, my.database)
        }
    }
}

fn with_prefix(place: String, prefix: Option<&str>) -> String {
    match prefix.filter(|p| !p.is_empty()) {
        Some(prefix) => format!("{place}, prefix {prefix}"),
        None => place,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs(path: &str, depth: u64) -> structs::BlobStore {
        structs::BlobStore::FileSystem(structs::FileSystemStore {
            path: path.into(),
            depth,
        })
    }

    #[test]
    fn a_place_is_where_blobs_go_not_how() {
        assert_eq!(
            blob_store_location(&structs::BlobStore::Default),
            "the data store"
        );
        assert_eq!(
            blob_store_location(&fs("/srv/blobs", 2)),
            "the directory /srv/blobs, depth 2"
        );
        // The depth decides each blob's path, so it's part of the place
        assert_ne!(
            blob_store_location(&fs("/srv/blobs", 2)),
            blob_store_location(&fs("/srv/blobs", 3))
        );
        assert_ne!(
            blob_store_location(&fs("/srv/blobs", 2)),
            blob_store_location(&fs("/srv/other", 2))
        );
    }
}
