/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Msg, Subscription};
use deadpool::managed::Manager;
use futures::StreamExt;
use redis::{
    AsyncCommands, PushInfo, aio::MultiplexedConnection, cluster::ClusterConfig,
    cluster_async::ClusterConnection,
};
use std::{fmt::Display, sync::Arc};
use store::backend::redis::{RedisPool, RedisStore};
use tokio::sync::mpsc::UnboundedReceiver;

pub enum RedisSubscription {
    Single(redis::aio::PubSubStream),
    Cluster {
        _conn: ClusterConnection,
        rx: UnboundedReceiver<PushInfo>,
    },
}

pub struct RedisPublisher {
    store: Arc<RedisStore>,
    topic: &'static str,
    connection: Option<PublishConnection>,
}

enum PublishConnection {
    Multiplexed(MultiplexedConnection),
    Cluster(ClusterConnection),
}

impl RedisPublisher {
    pub(crate) fn new(store: Arc<RedisStore>, topic: &'static str) -> Self {
        RedisPublisher {
            store,
            topic,
            connection: None,
        }
    }

    pub async fn publish(&mut self, payload: &[u8]) -> trc::Result<()> {
        let connection = match &mut self.connection {
            Some(connection) => connection,
            None => self
                .connection
                .insert(PublishConnection::open(&self.store).await?),
        };
        let result = match connection {
            PublishConnection::Multiplexed(connection) => {
                connection.publish(self.topic, payload).await
            }
            PublishConnection::Cluster(connection) => connection.publish(self.topic, payload).await,
        };
        if result.is_err() {
            self.connection = None;
        }
        result.map_err(into_error)
    }
}

impl PublishConnection {
    async fn open(store: &RedisStore) -> trc::Result<Self> {
        match &store.pool {
            RedisPool::Single(pool) => pool.manager().create().await.map(Self::Multiplexed),
            RedisPool::Cluster(pool) => pool.manager().create().await.map(Self::Cluster),
            RedisPool::Sentinel(pool) => pool.manager().create().await.map(Self::Multiplexed),
        }
    }
}

pub(crate) async fn redis_subscribe(
    redis: &RedisStore,
    topic: &'static str,
) -> trc::Result<Subscription> {
    match &redis.pool {
        RedisPool::Single(pool) => {
            let mut pubsub = pool
                .manager()
                .client
                .get_async_pubsub()
                .await
                .map_err(into_error)?;
            pubsub.subscribe(topic).await.map_err(into_error)?;

            Ok(Subscription::Redis(RedisSubscription::Single(
                pubsub.into_on_message(),
            )))
        }
        RedisPool::Cluster(pool) => {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

            let mut _conn = pool
                .manager()
                .client
                .get_async_connection_with_config(ClusterConfig::default().set_push_sender(tx))
                .await
                .map_err(into_error)?;

            _conn.subscribe(topic).await.map_err(into_error)?;

            Ok(Subscription::Redis(RedisSubscription::Cluster {
                _conn,
                rx,
            }))
        }
        RedisPool::Sentinel(pool) => {
            let client = pool
                .manager()
                .client
                .lock()
                .await
                .async_get_client()
                .await
                .map_err(into_error)?;

            let mut pubsub = client.get_async_pubsub().await.map_err(into_error)?;
            pubsub.subscribe(topic).await.map_err(into_error)?;

            Ok(Subscription::Redis(RedisSubscription::Single(
                pubsub.into_on_message(),
            )))
        }
    }
}

impl RedisSubscription {
    pub async fn next<'x>(&mut self) -> Option<Msg<'x>> {
        match self {
            RedisSubscription::Single(stream) => stream.next().await.map(Msg::Redis),
            RedisSubscription::Cluster { rx, .. } => loop {
                if let Some(msg) = redis::Msg::from_push_info(rx.recv().await?) {
                    return Some(Msg::Redis(msg));
                }
            },
        }
    }
}

#[inline(always)]
fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::RedisError.reason(err)
}
