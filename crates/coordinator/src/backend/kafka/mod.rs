/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::Coordinator;
use rdkafka::{
    ClientConfig, ClientContext, TopicPartitionList,
    consumer::{BaseConsumer, ConsumerContext, Rebalance, StreamConsumer},
    error::KafkaResult,
    producer::FutureProducer,
};
use registry::schema::structs::KafkaCoordinator;

pub mod pubsub;

pub(super) type LoggingConsumer = StreamConsumer<CustomContext>;

pub struct KafkaPubSub {
    consumer_builder: ClientConfig,
    producer: FutureProducer,
}

impl KafkaPubSub {
    pub async fn open(config: KafkaCoordinator, node_id: u16) -> Result<Coordinator, String> {
        if config.hosts.is_empty() {
            return Err("No Kafka hosts specified".to_string());
        }

        let mut client_config = ClientConfig::new();
        client_config.set("bootstrap.servers", config.hosts.into_inner().join(","));
        if config.use_tls {
            client_config.set("security.protocol", "ssl");
            if config.allow_invalid_certs {
                client_config.set("enable.ssl.certificate.verification", "false");
            }
        }

        let mut consumer_builder = client_config.clone();
        consumer_builder
            .set("group.id", format!("{}-{node_id}", config.group_id))
            .set("auto.offset.reset", "latest")
            .set("enable.partition.eof", "false")
            .set(
                "session.timeout.ms",
                config.session_timeout.as_millis().to_string(),
            )
            .set("enable.auto.commit", "true")
            .set("auto.commit.interval.ms", "100");

        let producer = client_config
            .set(
                "message.timeout.ms",
                config.message_timeout.as_millis().to_string(),
            )
            .set("linger.ms", "0")
            .create()
            .map_err(|err| format!("Failed to create Kafka producer: {}", err))?;

        Ok(Coordinator::Kafka(Arc::new(KafkaPubSub {
            consumer_builder,
            producer,
        })))
    }
}

impl std::fmt::Debug for KafkaPubSub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaPubSub").finish()
    }
}

pub struct CustomContext;

impl ClientContext for CustomContext {}

impl ConsumerContext for CustomContext {
    fn pre_rebalance(&self, _: &BaseConsumer<Self>, _: &Rebalance) {}

    fn post_rebalance(&self, _: &BaseConsumer<Self>, _: &Rebalance) {}

    fn commit_callback(&self, _: KafkaResult<()>, _: &TopicPartitionList) {}
}

