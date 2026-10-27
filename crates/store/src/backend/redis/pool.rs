/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    RedisClusterConnectionManager, RedisConnectionManager, RedisSentinelConnectionManager,
    into_error,
};
use deadpool::managed;
use redis::{
    aio::{ConnectionLike, MultiplexedConnection},
    cluster_async::ClusterConnection,
};
use std::time::Duration;

const PING_IF_IDLE_FOR: Duration = Duration::from_secs(5);

impl managed::Manager for RedisConnectionManager {
    type Type = MultiplexedConnection;
    type Error = trc::Error;

    async fn create(&self) -> Result<MultiplexedConnection, trc::Error> {
        match tokio::time::timeout(
            self.timeout,
            Box::pin(self.client.get_multiplexed_async_connection()),
        )
        .await
        {
            Ok(conn) => conn.map_err(into_error),
            Err(_) => Err(trc::StoreEvent::RedisError.ctx(trc::Key::Details, "Connection Timeout")),
        }
    }

    async fn recycle(
        &self,
        conn: &mut MultiplexedConnection,
        metrics: &managed::Metrics,
    ) -> managed::RecycleResult<trc::Error> {
        ping_if_idle(conn, metrics).await
    }
}

impl managed::Manager for RedisClusterConnectionManager {
    type Type = ClusterConnection;
    type Error = trc::Error;

    async fn create(&self) -> Result<ClusterConnection, trc::Error> {
        match tokio::time::timeout(self.timeout, self.client.get_async_connection()).await {
            Ok(conn) => conn.map_err(into_error),
            Err(_) => Err(trc::StoreEvent::RedisError.ctx(trc::Key::Details, "Connection Timeout")),
        }
    }

    async fn recycle(
        &self,
        conn: &mut ClusterConnection,
        metrics: &managed::Metrics,
    ) -> managed::RecycleResult<trc::Error> {
        ping_if_idle(conn, metrics).await
    }
}

impl managed::Manager for RedisSentinelConnectionManager {
    type Type = MultiplexedConnection;
    type Error = trc::Error;

    async fn create(&self) -> Result<MultiplexedConnection, trc::Error> {
        let mut client = self.client.lock().await;
        match tokio::time::timeout(self.timeout, Box::pin(client.get_async_connection())).await {
            Ok(conn) => conn.map_err(into_error),
            Err(_) => Err(trc::StoreEvent::RedisError.ctx(trc::Key::Details, "Connection Timeout")),
        }
    }

    async fn recycle(
        &self,
        conn: &mut MultiplexedConnection,
        metrics: &managed::Metrics,
    ) -> managed::RecycleResult<trc::Error> {
        ping_if_idle(conn, metrics).await
    }
}

async fn ping_if_idle(
    conn: &mut impl ConnectionLike,
    metrics: &managed::Metrics,
) -> managed::RecycleResult<trc::Error> {
    if metrics.last_used() < PING_IF_IDLE_FOR {
        return Ok(());
    }
    conn.req_packed_command(&redis::cmd("PING"))
        .await
        .map(|_| ())
        .map_err(|err| managed::RecycleError::Backend(into_error(err)))
}

