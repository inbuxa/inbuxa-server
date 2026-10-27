/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::Coordinator;
use async_nats::Client;
use registry::schema::structs::NatsCoordinator;
use utils::tls::rustls_client_config;

pub mod pubsub;

#[derive(Debug)]
pub struct NatsPubSub {
    client: Client,
}

impl NatsPubSub {
    pub async fn open(config: NatsCoordinator) -> Result<Coordinator, String> {
        if config.hosts.is_empty() {
            return Err("No Nats hosts specified".to_string());
        }

        let mut opts = async_nats::ConnectOptions::new()
            .max_reconnects(config.max_reconnects.map(|v| v as usize))
            .connection_timeout(config.connect_timeout.into_inner())
            .request_timeout(config.request_timeout.into_inner().into())
            .ping_interval(config.ping_interval.into_inner())
            .client_capacity(config.client_capacity as usize)
            .subscription_capacity(config.subscription_capacity as usize)
            .read_buffer_capacity(config.read_buffer_capacity as u16)
            .require_tls(config.use_tls);

        if config.allow_invalid_certs {
            opts = opts.tls_client_config(rustls_client_config(true)?);
        }

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

        async_nats::connect_with_options(config.hosts.into_inner(), opts)
            .await
            .map(|client| Coordinator::Nats(Arc::new(NatsPubSub { client })))
            .map_err(|err| format!("Failed to connect to Nats: {}", err))
    }
}
