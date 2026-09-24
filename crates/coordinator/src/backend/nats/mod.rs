/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::Coordinator;
use async_nats::Client;
use registry::schema::structs::NatsCoordinator;
use trc::ClusterEvent;

pub mod pubsub;

#[derive(Debug)]
pub struct NatsPubSub {
    client: Client,
}

impl NatsPubSub {
    pub async fn open(config: NatsCoordinator) -> Result<Coordinator, String> {
        if config.addresses.is_empty() {
            return Err("No Nats addresses specified".to_string());
        }

        let mut opts = async_nats::ConnectOptions::new()
            .max_reconnects(config.max_reconnects.map(|v| v as usize))
            .connection_timeout(config.timeout_connection.into_inner())
            .request_timeout(config.timeout_request.into_inner().into())
            .ping_interval(config.ping_interval.into_inner())
            .client_capacity(config.capacity_client as usize)
            .subscription_capacity(config.capacity_subscription as usize)
            .read_buffer_capacity(config.capacity_read_buffer as u16)
            .require_tls(config.use_tls);

        if config.no_echo {
            opts = opts.no_echo();
        }

        if let (Some(user), Some(pass)) = (
            config.auth_username,
            config.auth_secret.secret().await?.map(|v| v.into_owned()),
        ) {
            opts = opts.user_and_password(user.to_string(), pass.to_string());
        } else if let Some(credentials) = config.credentials.secret().await?.map(|v| v.into_owned())
        {
            opts = opts.token(credentials);
        }

        // inbuxa: connect in the background and keep trying, so a node that
        // starts while NATS is down still joins the cluster once NATS is
        // back, instead of running without a coordinator until restarted;
        // and report the connection going and coming back
        let reporter = Arc::new(Reporter::default());
        opts = opts.retry_on_initial_connect().event_callback({
            let reporter = reporter.clone();
            move |event| {
                let reporter = reporter.clone();
                async move { reporter.report(event) }
            }
        });
        let connection_timeout = config.timeout_connection.into_inner();

        async_nats::connect_with_options(config.addresses.into_inner(), opts)
            .await
            .map(|client| {
                reporter.watch_first_connection(client.clone(), connection_timeout);
                Coordinator::Nats(Arc::new(NatsPubSub { client }))
            })
            .map_err(|err| format!("Failed to connect to Nats: {}", err))
    }

    /// inbuxa: whether the client is connected to a NATS server right now.
    pub fn is_connected(&self) -> bool {
        matches!(
            self.client.connection_state(),
            async_nats::connection::State::Connected
        )
    }
}

/// inbuxa: reports the client's connection events as the server's own.
#[derive(Default)]
struct Reporter {
    connected_once: AtomicBool,
    // A failed attempt raises an error each time the client retries, every
    // few seconds while NATS is down: report the first after each change
    error_reported: AtomicBool,
}

impl Reporter {
    fn report(&self, event: async_nats::Event) {
        match event {
            async_nats::Event::Connected => {
                self.connected_once.store(true, Ordering::Relaxed);
                self.error_reported.store(false, Ordering::Relaxed);
                trc::event!(Cluster(ClusterEvent::CoordinatorConnected), Type = "nats");
            }
            async_nats::Event::Disconnected => {
                self.error_reported.store(false, Ordering::Relaxed);
                trc::event!(
                    Cluster(ClusterEvent::CoordinatorDisconnected),
                    Type = "nats",
                    Details = "Connection lost; reconnecting in the background",
                );
            }
            async_nats::Event::Closed => {
                trc::event!(
                    Cluster(ClusterEvent::CoordinatorDisconnected),
                    Type = "nats",
                    Details = "Connection closed; no further attempts will be made",
                );
            }
            async_nats::Event::ClientError(async_nats::ClientError::MaxReconnects) => {
                trc::event!(
                    Cluster(ClusterEvent::CoordinatorDisconnected),
                    Type = "nats",
                    Details = "Gave up reconnecting (maxReconnects reached)",
                );
            }
            async_nats::Event::ClientError(err) => {
                if !self.error_reported.swap(true, Ordering::Relaxed) {
                    trc::event!(
                        Cluster(ClusterEvent::CoordinatorError),
                        Type = "nats",
                        Details = "Connection attempt failed; retrying",
                        Reason = err.to_string(),
                    );
                }
            }
            event => {
                trc::event!(
                    Cluster(ClusterEvent::CoordinatorError),
                    Type = "nats",
                    Details = event.to_string(),
                );
            }
        }
    }

    /// The first connection is made in the background, so say so when it
    /// hasn't been made within the connection timeout. The client keeps
    /// trying, and reports the connection when it comes.
    fn watch_first_connection(self: &Arc<Self>, client: Client, timeout: Duration) {
        let reporter = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            if !reporter.connected_once.load(Ordering::Relaxed)
                && !matches!(
                    client.connection_state(),
                    async_nats::connection::State::Connected
                )
            {
                trc::event!(
                    Cluster(ClusterEvent::CoordinatorDisconnected),
                    Type = "nats",
                    Details = "Not connected at startup; retrying in the background",
                );
            }
        });
    }
}
