/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{RedisPool, RedisStore, into_error};
use crate::{Deserialize, write::now};
use deadpool::managed::{Manager, Object, Pool};
use futures::future::try_join_all;
use redis::{
    AsyncCommands, Cmd, ErrorKind, RedisError, RedisResult, RetryMethod, Script, Value,
    cluster_async::ClusterConnection,
    cluster_routing::{MultipleNodeRoutingInfo, RoutingInfo, SingleNodeRoutingInfo},
    from_redis_value,
};

const SCAN_COUNT: usize = 100;

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
                    self.key_incr_(conn, key, value, expires).await
                })
                .await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| {
                    self.key_incr_(conn, key, value, expires).await
                })
                .await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| {
                    self.key_incr_(conn, key, value, expires).await
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

    pub async fn try_lease(&self, key: &[u8], token: u64, expires: u64) -> trc::Result<bool> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| {
                    Self::try_lease_(conn, key, token, expires).await
                })
                .await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| {
                    Self::try_lease_(conn, key, token, expires).await
                })
                .await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| {
                    Self::try_lease_(conn, key, token, expires).await
                })
                .await
            }
        }
    }

    pub async fn renew_lease(&self, key: &[u8], token: u64, expires: u64) -> trc::Result<bool> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| {
                    self.lease_script_(conn, &self.lease_renew, key, token, Some(expires))
                        .await
                })
                .await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| {
                    self.lease_script_(conn, &self.lease_renew, key, token, Some(expires))
                        .await
                })
                .await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| {
                    self.lease_script_(conn, &self.lease_renew, key, token, Some(expires))
                        .await
                })
                .await
            }
        }
    }

    pub async fn release_lease(&self, key: &[u8], token: u64) -> trc::Result<bool> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| {
                    self.lease_script_(conn, &self.lease_release, key, token, None)
                        .await
                })
                .await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| {
                    self.lease_script_(conn, &self.lease_release, key, token, None)
                        .await
                })
                .await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| {
                    self.lease_script_(conn, &self.lease_release, key, token, None)
                        .await
                })
                .await
            }
        }
    }

    pub async fn renew_lock(&self, key: &[u8], expires: u64) -> trc::Result<()> {
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| {
                    Self::renew_lock_(conn, key, expires).await
                })
                .await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| {
                    Self::renew_lock_(conn, key, expires).await
                })
                .await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| {
                    Self::renew_lock_(conn, key, expires).await
                })
                .await
            }
        }
    }

    pub async fn key_delete(&self, key: &[u8]) -> trc::Result<bool> {
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

    pub async fn key_set_many(
        &self,
        items: &[(Vec<u8>, &[u8])],
        expires: Option<u64>,
    ) -> trc::Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_set_many_(conn, items, expires).await
                })
                .await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_set_many_(conn, items, expires).await
                })
                .await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_set_many_(conn, items, expires).await
                })
                .await
            }
        }
    }

    pub async fn key_get_many(&self, keys: &[Vec<u8>]) -> trc::Result<Vec<Option<Vec<u8>>>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| Self::key_get_many_(conn, keys).await).await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| Self::key_get_many_(conn, keys).await).await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| Self::key_get_many_(conn, keys).await).await
            }
        }
    }

    pub async fn key_unlink_many(&self, keys: &[Vec<u8>]) -> trc::Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| Self::key_unlink_many_(conn, keys).await).await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| Self::key_unlink_many_(conn, keys).await).await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| Self::key_unlink_many_(conn, keys).await).await
            }
        }
    }

    async fn key_set_many_(
        conn: &mut impl AsyncCommands,
        items: &[(Vec<u8>, &[u8])],
        expires: Option<u64>,
    ) -> RedisResult<()> {
        let mut pipe = redis::Pipeline::with_capacity(items.len());
        for (key, value) in items {
            pipe.cmd("SET").arg(key).arg(*value);
            if let Some(expires) = expires {
                pipe.arg("EX").arg(expires);
            }
            pipe.ignore();
        }

        pipe.query_async(conn).await
    }

    async fn key_get_many_(
        conn: &mut impl AsyncCommands,
        keys: &[Vec<u8>],
    ) -> RedisResult<Vec<Option<Vec<u8>>>> {
        let mut cmd = redis::cmd("MGET");
        for key in keys {
            cmd.arg(key);
        }

        cmd.query_async(conn).await
    }

    async fn key_unlink_many_(conn: &mut impl AsyncCommands, keys: &[Vec<u8>]) -> RedisResult<()> {
        let mut cmd = redis::cmd("UNLINK");
        for key in keys {
            cmd.arg(key);
        }

        cmd.query_async(conn).await
    }

    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        let pattern = scan_pattern(prefix);
        match &self.pool {
            RedisPool::Single(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_delete_prefix_(conn, &pattern).await
                })
                .await
            }
            RedisPool::Cluster(pool) => {
                with_conn(pool, async |conn| {
                    Self::cluster_key_delete_prefix_(conn, &pattern).await
                })
                .await
            }
            RedisPool::Sentinel(pool) => {
                with_conn(pool, async |conn| {
                    Self::key_delete_prefix_(conn, &pattern).await
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
        &self,
        conn: &mut impl AsyncCommands,
        key: &[u8],
        value: i64,
        expires: Option<u64>,
    ) -> RedisResult<i64> {
        if let Some(expires) = expires {
            self.incr_expire
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

    async fn try_lease_(
        conn: &mut impl AsyncCommands,
        key: &[u8],
        token: u64,
        expires: u64,
    ) -> RedisResult<bool> {
        redis::cmd("SET")
            .arg(key)
            .arg(token)
            .arg("NX")
            .arg("EX")
            .arg(expires as i64)
            .query_async::<Option<String>>(conn)
            .await
            .map(|reply| reply.is_some())
    }

    async fn lease_script_(
        &self,
        conn: &mut impl AsyncCommands,
        script: &Script,
        key: &[u8],
        token: u64,
        expires: Option<u64>,
    ) -> RedisResult<bool> {
        let mut invocation = script.key(key);
        invocation.arg(token);
        if let Some(expires) = expires {
            invocation.arg(expires as i64);
        }
        invocation
            .invoke_async::<i64>(conn)
            .await
            .map(|result| result > 0)
    }

    async fn renew_lock_(
        conn: &mut impl AsyncCommands,
        key: &[u8],
        expires: u64,
    ) -> RedisResult<()> {
        redis::cmd("SET")
            .arg(key)
            .arg(now() + expires)
            .arg("EX")
            .arg(expires as i64)
            .query_async::<()>(conn)
            .await
    }

    async fn key_delete_(conn: &mut impl AsyncCommands, key: &[u8]) -> RedisResult<bool> {
        conn.del::<_, usize>(key).await.map(|deleted| deleted > 0)
    }

    async fn key_delete_prefix_(conn: &mut impl AsyncCommands, pattern: &[u8]) -> RedisResult<()> {
        let mut cursor = 0;
        loop {
            let (new_cursor, keys): (u64, Vec<Vec<u8>>) =
                scan_cmd(cursor, pattern).query_async(conn).await?;

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

    async fn cluster_key_delete_prefix_(
        conn: &mut ClusterConnection,
        pattern: &[u8],
    ) -> RedisResult<()> {
        let Value::Map(primaries) = conn
            .route_command(
                scan_cmd(0, pattern),
                RoutingInfo::MultiNode((MultipleNodeRoutingInfo::AllMasters, None)),
            )
            .await?
        else {
            return Err(RedisError::from((
                ErrorKind::UnexpectedReturnType,
                "Unexpected reply to a SCAN sent to all cluster primaries",
            )));
        };

        try_join_all(primaries.into_iter().map(|(node, first_page)| {
            Self::cluster_node_key_delete_prefix_(conn.clone(), pattern, node, first_page)
        }))
        .await?;

        Ok(())
    }

    async fn cluster_node_key_delete_prefix_(
        mut conn: ClusterConnection,
        pattern: &[u8],
        node: Value,
        first_page: Value,
    ) -> RedisResult<()> {
        let node = node_routing(node)?;
        let (mut cursor, mut keys): (u64, Vec<Vec<u8>>) =
            from_redis_value(first_page.extract_error()?)?;
        loop {
            if !keys.is_empty() {
                Self::key_unlink_many_(&mut conn, &keys).await?;
            }

            if cursor == 0 {
                return Ok(());
            }

            (cursor, keys) = from_redis_value(
                conn.route_command(scan_cmd(cursor, pattern), node.clone())
                    .await?
                    .extract_error()?,
            )?;
        }
    }
}

fn scan_pattern(prefix: &[u8]) -> Vec<u8> {
    let mut pattern = Vec::with_capacity(prefix.len() + 1);
    for &byte in prefix {
        if matches!(byte, b'*' | b'?' | b'[' | b'\\') {
            pattern.push(b'\\');
        }
        pattern.push(byte);
    }
    pattern.push(b'*');
    pattern
}

fn scan_cmd(cursor: u64, pattern: &[u8]) -> Cmd {
    let mut cmd = redis::cmd("SCAN");
    cmd.cursor_arg(cursor)
        .arg("MATCH")
        .arg(pattern)
        .arg("COUNT")
        .arg(SCAN_COUNT);
    cmd
}

fn node_routing(node: Value) -> RedisResult<RoutingInfo> {
    let node: String = from_redis_value(node)?;
    let Some((host, port)) = node
        .rsplit_once(':')
        .and_then(|(host, port)| Some((host, port.parse().ok()?)))
    else {
        return Err(RedisError::from((
            ErrorKind::UnexpectedReturnType,
            "Invalid cluster node address",
            node,
        )));
    };

    Ok(RoutingInfo::SingleNode(SingleNodeRoutingInfo::ByAddress {
        host: host.to_string(),
        port,
    }))
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
            if is_stale_connection(&err) || err.is_timeout() {
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
