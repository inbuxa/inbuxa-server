/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The sharded in-memory and lookup store (ST-23 to ST-29). Every
//! single-key operation goes to the key's home member, with no fallback;
//! operations over many keys go to every member.

use super::{home, layout, without_credentials};
use crate::{InMemoryStore, Store};
use registry::schema::structs::{self, InMemoryStoreBase};

#[derive(Debug)]
pub struct ShardedInMemoryStore {
    pub members: Vec<InMemoryStore>,
    pub locations: Vec<String>,
}

/// A member's kind and location, without credentials (ST-26, ST-29).
pub fn location(member: &InMemoryStoreBase) -> String {
    let urls = |urls: &registry::types::map::Map<String>| {
        let mut urls = urls
            .iter()
            .map(|url| without_credentials(url))
            .collect::<Vec<_>>();
        urls.sort();
        urls.join(",")
    };
    match member {
        InMemoryStoreBase::Redis(redis) => format!("Redis {}", without_credentials(&redis.url)),
        InMemoryStoreBase::RedisCluster(cluster) => {
            format!("RedisCluster {}", urls(&cluster.urls))
        }
        InMemoryStoreBase::RedisSentinel(sentinel) => format!(
            "RedisSentinel {} {}",
            urls(&sentinel.urls),
            sentinel.service_name
        ),
    }
}

#[allow(unreachable_patterns, unused_variables)]
async fn open_member(member: InMemoryStoreBase) -> Result<InMemoryStore, String> {
    match member {
        #[cfg(feature = "redis")]
        InMemoryStoreBase::Redis(config) => {
            crate::backend::redis::RedisStore::open_single(config).await
        }
        #[cfg(feature = "redis")]
        InMemoryStoreBase::RedisCluster(config) => {
            crate::backend::redis::RedisStore::open_cluster(config).await
        }
        #[cfg(feature = "redis")]
        InMemoryStoreBase::RedisSentinel(config) => {
            crate::backend::redis::RedisStore::open_sentinel(config).await
        }
        _ => Err("Binary was not compiled with this member's in-memory backend".to_string()),
    }
}

impl ShardedInMemoryStore {
    /// Opens every member and checks the list (ST-29), then compares it with
    /// the recorded one (ST-26). `name` tells lookup stores apart.
    pub async fn open(
        config: structs::ShardedInMemoryStore,
        name: &str,
        data: &Store,
        warnings: &mut Vec<String>,
    ) -> Result<InMemoryStore, String> {
        let members = config.stores.into_iter().collect::<Vec<_>>();
        if members.len() < 2 {
            return Err("A sharded in-memory store needs at least two members".to_string());
        }
        let locations = members.iter().map(location).collect::<Vec<_>>();
        for (index, location) in locations.iter().enumerate() {
            if let Some(first) = locations[..index].iter().position(|l| l == location) {
                return Err(format!(
                    "Members {} and {} are the same server: {location}",
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
        // ST-26: a different list is an error to fix, not a reason to refuse
        let kind = if name.is_empty() { b'm' } else { b'l' };
        let difference = match layout::check(data, layout::key(kind, name), &locations, false).await
        {
            Ok(layout::Comparison::Unchanged) => None,
            Ok(layout::Comparison::Changed(change)) => Some(change),
            Ok(layout::Comparison::Missing(missing)) => {
                Some(format!("members gone: {}", missing.join("; ")))
            }
            Err(err) => Some(format!("the recorded list couldn't be read: {err}")),
        };
        if let Some(difference) = difference {
            let message = format!(
                "The sharded in-memory store's member list differs from the one recorded \
                 ({difference}); every node must use the same list"
            );
            trc::event!(
                Store(trc::StoreEvent::RedisError),
                Details = message.clone()
            );
            warnings.push(message);
        }
        Ok(InMemoryStore::Sharded(std::sync::Arc::new(
            ShardedInMemoryStore {
                members: opened,
                locations,
            },
        )))
    }

    /// The member a key lives on (ST-23).
    pub fn member(&self, key: &[u8]) -> &InMemoryStore {
        &self.members[home(key, self.members.len())]
    }
}
