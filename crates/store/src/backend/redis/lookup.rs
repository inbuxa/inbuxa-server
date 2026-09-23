/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{RedisPool, RedisStore, into_error};
use crate::{Deserialize, write::now};
use deadpool::managed::{Manager, Object, Pool};
use redis::{AsyncCommands, RedisError, RedisResult, RetryMethod, Script};
use std::sync::LazyLock;

static INCR_EXPIRE: LazyLock<Script> = LazyLock::new(|| {
    Script::new(
        "redis.call('INCRBY', KEYS[1], ARGV[1])
         redis.call('EXPIRE', KEYS[1], ARGV[2])
         return redis.call('GET', KEYS[1])",
    )
});

impl RedisStore {
    pub async fn key_set(&self, key: &[u8], value: &[u8], expires: Option<u64>) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_set_(conn, key, value, expires).await
                })
                .await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_set_(conn, key, value, expires).await
                })
                .await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_set_(conn, key, value, expires).await
                })
                .await
            }
        }
    }

    pub async fn key_incr(&self, key: &[u8], value: i64, expires: Option<u64>) -> trc::Result<i64> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_incr_(conn, key, value, expires).await
                })
                .await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_incr_(conn, key, value, expires).await
                })
                .await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_incr_(conn, key, value, expires).await
                })
                .await
            }
        }
    }

    pub async fn try_lock(&self, key: &[u8], expires: u64) -> trc::Result<bool> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| Self::try_lock_(conn, key, expires).await).await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| Self::try_lock_(conn, key, expires).await).await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| Self::try_lock_(conn, key, expires).await).await
            }
        }
    }

    pub async fn key_delete(&self, key: &[u8]) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| Self::key_delete_(conn, key).await).await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| Self::key_delete_(conn, key).await).await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| Self::key_delete_(conn, key).await).await
            }
        }
    }

    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_delete_prefix_(conn, prefix).await
                })
                .await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_delete_prefix_(conn, prefix).await
                })
                .await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_delete_prefix_(conn, prefix).await
                })
                .await
            }
        }
    }

    pub async fn key_get<T: Deserialize + std::fmt::Debug + 'static>(
        &self,
        key: &[u8],
    ) -> trc::Result<Option<T>> {
        let value = match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| Self::key_get_(conn, key).await).await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| Self::key_get_(conn, key).await).await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| Self::key_get_(conn, key).await).await
            }
        }?;

        value.map(T::deserialize_owned).transpose()
    }

    pub async fn counter_get(&self, key: &[u8]) -> trc::Result<i64> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| Self::counter_get_(conn, key).await).await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| Self::counter_get_(conn, key).await).await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| Self::counter_get_(conn, key).await).await
            }
        }
    }

    pub async fn key_exists(&self, key: &[u8]) -> trc::Result<bool> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| Self::key_exists_(conn, key).await).await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| Self::key_exists_(conn, key).await).await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| Self::key_exists_(conn, key).await).await
            }
        }
    }

    async fn key_get_(conn: &mut impl AsyncCommands, key: &[u8]) -> RedisResult<Option<Vec<u8>>> {
        redis::cmd("GET").arg(key).query_async(conn).await
    }

    async fn counter_get_(conn: &mut impl AsyncCommands, key: &[u8]) -> RedisResult<i64> {
        redis::cmd("GET")
            .arg(key)
            .query_async::<Option<i64>>(conn)
            .await
            .map(|value| value.unwrap_or(0))
    }

    async fn key_exists_(conn: &mut impl AsyncCommands, key: &[u8]) -> RedisResult<bool> {
        conn.exists(key).await
    }

    async fn key_set_(
        conn: &mut impl AsyncCommands,
        key: &[u8],
        value: &[u8],
        expires: Option<u64>,
    ) -> RedisResult<()> {
        if let Some(expires) = expires {
            conn.set_ex(key, value, expires).await
        } else {
            conn.set(key, value).await
        }
    }

    async fn key_incr_(
        conn: &mut impl AsyncCommands,
        key: &[u8],
        value: i64,
        expires: Option<u64>,
    ) -> RedisResult<i64> {
        if let Some(expires) = expires {
            INCR_EXPIRE
                .key(key)
                .arg(value)
                .arg(expires as i64)
                .invoke_async(conn)
                .await
        } else {
            conn.incr(key, value).await
        }
    }

    async fn try_lock_(
        conn: &mut impl AsyncCommands,
        key: &[u8],
        expires: u64,
    ) -> RedisResult<bool> {
        redis::cmd("SET")
            .arg(key)
            .arg(now() + expires)
            .arg("NX")
            .arg("EX")
            .arg(expires as i64)
            .query_async::<Option<String>>(conn)
            .await
            .map(|reply| reply.is_some())
    }

    async fn key_delete_(conn: &mut impl AsyncCommands, key: &[u8]) -> RedisResult<()> {
        conn.del(key).await
    }

    async fn key_delete_prefix_(conn: &mut impl AsyncCommands, prefix: &[u8]) -> RedisResult<()> {
        let mut pattern = Vec::with_capacity(prefix.len() + 1);
        pattern.extend_from_slice(prefix);
        pattern.push(b'*');

        let mut cursor = 0;
        loop {
            let (new_cursor, keys): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
                .cursor_arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(conn)
                .await?;

            if !keys.is_empty() {
                conn.del::<_, ()>(&keys).await?;
            }

            if new_cursor != 0 {
                cursor = new_cursor;
            } else {
                return Ok(());
            }
        }
    }
}

async fn with_conn<M, T>(
    pool: &Pool<M>,
    operation: impl AsyncFnOnce(&mut M::Type) -> RedisResult<T>,
) -> trc::Result<T>
where
    M: Manager<Error = trc::Error>,
{
    let mut conn = pool.get().await.map_err(into_error)?;

    match operation(conn.as_mut()).await {
        Ok(value) => Ok(value),
        Err(err) => {
            if is_stale_connection(&err) {
                drop(Object::take(conn));
            }
            Err(into_error(err))
        }
    }
}

fn is_stale_connection(err: &RedisError) -> bool {
    matches!(
        err.retry_method(),
        RetryMethod::Reconnect
            | RetryMethod::ReconnectFromInitialConnections
            | RetryMethod::RefreshSlotsAndRetry
            | RetryMethod::MovedRedirect
            | RetryMethod::AskRedirect
    )
}
