/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The sharded blob store (ST-16 to ST-22). A blob lives on its home
//! member; reads fall back to the others so blobs placed under an earlier
//! member list stay readable. Blobs are stored compressed and marked, as
//! on any blob store, before they reach a member.

use super::{home, layout};
use crate::{BlobStore, Store, backend::fs::FsStore};
use registry::schema::structs::{self, BlobStoreBase};

pub struct ShardedBlobStore {
    pub members: Vec<BlobStore>,
    pub locations: Vec<String>,
}

/// A member's kind and location, never its secrets (ST-20, ST-22).
pub fn location(member: &BlobStoreBase) -> String {
    match member {
        BlobStoreBase::S3(s3) => format!(
            "S3 {:?} bucket {} prefix {}",
            s3.region,
            s3.bucket,
            s3.key_prefix.as_deref().unwrap_or_default()
        ),
        BlobStoreBase::Azure(azure) => format!(
            "Azure account {} container {} prefix {}",
            azure.storage_account,
            azure.container,
            azure.key_prefix.as_deref().unwrap_or_default()
        ),
        BlobStoreBase::FileSystem(fs) => {
            format!("FileSystem {}", fs.path.trim_end_matches('/'))
        }
        BlobStoreBase::FoundationDb(fdb) => format!(
            "FoundationDb {}",
            fdb.cluster_file.as_deref().unwrap_or("default")
        ),
        BlobStoreBase::PostgreSql(pg) => {
            format!("PostgreSql {}:{} {}", pg.host, pg.port, pg.database)
        }
        BlobStoreBase::MySql(my) => format!("MySql {}:{} {}", my.host, my.port, my.database),
    }
}

#[allow(unreachable_patterns, unused_variables)]
async fn open_member(member: BlobStoreBase) -> Result<BlobStore, String> {
    match member {
        #[cfg(feature = "foundation")]
        BlobStoreBase::FoundationDb(config) => crate::backend::foundationdb::FdbStore::open(config)
            .await
            .map(BlobStore::Store),
        #[cfg(feature = "postgres")]
        BlobStoreBase::PostgreSql(config) => crate::backend::postgres::PostgresStore::open(config)
            .await
            .map(BlobStore::Store),
        #[cfg(feature = "mysql")]
        BlobStoreBase::MySql(config) => crate::backend::mysql::MysqlStore::open(config)
            .await
            .map(BlobStore::Store),
        #[cfg(feature = "s3")]
        BlobStoreBase::S3(config) => crate::backend::s3::S3Store::open(config).await,
        #[cfg(feature = "azure")]
        BlobStoreBase::Azure(config) => crate::backend::azure::AzureStore::open(config).await,
        BlobStoreBase::FileSystem(config) => FsStore::open(config).await,
        _ => Err("Binary was not compiled with this member's blob store backend".to_string()),
    }
}

impl ShardedBlobStore {
    /// Opens every member, checks the list (ST-22), and compares it with
    /// the recorded one (ST-20). Warnings are returned for the build log.
    pub async fn open(
        config: structs::ShardedBlobStore,
        data: &Store,
        warnings: &mut Vec<String>,
    ) -> Result<BlobStore, String> {
        let members = config.stores.into_iter().collect::<Vec<_>>();
        if members.len() < 2 {
            return Err("A sharded blob store needs at least two members".to_string());
        }
        let locations = members.iter().map(location).collect::<Vec<_>>();
        for (index, location) in locations.iter().enumerate() {
            if let Some(first) = locations[..index].iter().position(|l| l == location) {
                return Err(format!(
                    "Members {} and {} are the same place: {location}",
                    first + 1,
                    index + 1
                ));
            }
        }
        let mut opened = Vec::with_capacity(members.len());
        for (index, member) in members.into_iter().enumerate() {
            opened.push(
                open_member(member)
                    .await
                    .map_err(|err| format!("Member {}: {err}", index + 1))?,
            );
        }
        match layout::check(data, layout::key(b'b', ""), &locations, true)
            .await
            .map_err(|err| format!("Failed to read the recorded member list: {err}"))?
        {
            layout::Comparison::Unchanged => {}
            layout::Comparison::Changed(change) => warnings.push(format!(
                "The sharded blob store's member list changed ({change}); blobs whose home \
                 moved are found by searching the other members"
            )),
            layout::Comparison::Missing(missing) => {
                return Err(format!(
                    "Members recorded for the sharded blob store are missing, and blobs on \
                     them would be unreachable: {}",
                    missing.join("; ")
                ));
            }
        }
        Ok(BlobStore::Sharded(std::sync::Arc::new(ShardedBlobStore {
            members: opened,
            locations,
        })))
    }

    fn home(&self, key: &[u8]) -> usize {
        home(key, self.members.len())
    }

    /// The home member, then the others in order (ST-17). An error from
    /// the home member is returned without searching (ST-21).
    pub async fn get(&self, key: &[u8]) -> trc::Result<Option<Vec<u8>>> {
        let home = self.home(key);
        if let Some(data) = Box::pin(self.members[home].raw_get(key)).await? {
            return Ok(Some(data));
        }
        for (index, member) in self.members.iter().enumerate() {
            if index == home {
                continue;
            }
            if let Ok(Some(data)) = Box::pin(member.raw_get(key)).await {
                trc::event!(
                    Store(trc::StoreEvent::UnexpectedError),
                    Key = key,
                    Details = format!(
                        "Misplaced blob: found on member {}, its home is member {}",
                        index + 1,
                        home + 1
                    ),
                );
                return Ok(Some(data));
            }
        }
        Ok(None)
    }

    /// Writes go to the home member only (ST-18, ST-21).
    pub async fn put(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        Box::pin(self.members[self.home(key)].raw_put(key, data)).await
    }

    /// The home member first, then the others until one had it (ST-18).
    pub async fn delete(&self, key: &[u8]) -> trc::Result<bool> {
        let home = self.home(key);
        if Box::pin(self.members[home].raw_delete(key)).await? {
            return Ok(true);
        }
        for (index, member) in self.members.iter().enumerate() {
            if index != home && Box::pin(member.raw_delete(key)).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
