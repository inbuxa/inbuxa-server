/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CustomContext, KafkaPubSub, LoggingConsumer};
use crate::{Msg, Subscription};
use futures::StreamExt;
use rdkafka::{
    consumer::{Consumer, MessageStream},
    producer::{FutureProducer, FutureRecord},
};
use std::time::Duration;
use trc::{ClusterEvent, Error, EventType};

pub struct KafkaSubscription {
    consumer: LoggingConsumer,
}

pub type KafkaStream<'x> = MessageStream<'x, CustomContext>;

pub struct KafkaPublisher {
    producer: FutureProducer,
    topic: &'static str,
}

impl KafkaPubSub {
    pub(crate) fn publisher(&self, topic: &'static str) -> KafkaPublisher {
        KafkaPublisher {
            producer: self.producer.clone(),
            topic,
        }
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<Subscription> {
        let consumer: LoggingConsumer = self
            .consumer_builder
            .create_with_context(CustomContext)
            .map_err(|err| {
                Error::new(EventType::Cluster(ClusterEvent::SubscriberError)).reason(err)
            })?;
        consumer.subscribe(&[topic]).map_err(|err| {
            Error::new(EventType::Cluster(ClusterEvent::SubscriberError)).reason(err)
        })?;

        Ok(Subscription::Kafka(KafkaSubscription { consumer }))
    }
}

impl KafkaPublisher {
    pub async fn publish(&mut self, payload: &[u8]) -> trc::Result<()> {
        self.producer
            .send(
                FutureRecord::<(), [u8]>::to(self.topic).payload(payload),
                Duration::ZERO,
            )
            .await
            .map(|_| ())
            .map_err(|(err, _)| {
                Error::new(EventType::Cluster(ClusterEvent::PublisherError)).reason(err)
            })
    }
}

impl KafkaSubscription {
    pub(crate) fn stream(&self) -> KafkaStream<'_> {
        self.consumer.stream()
    }
}

pub(crate) async fn kafka_next<'x>(stream: &mut KafkaStream<'x>) -> Option<Msg<'x>> {
    stream.next().await?.ok().map(Msg::Kafka)
}
