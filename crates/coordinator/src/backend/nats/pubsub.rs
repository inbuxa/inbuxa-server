/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::NatsPubSub;
use crate::{Msg, Subscription};
use async_nats::{Client, Subscriber, connection::State};
use futures::StreamExt;
use trc::{ClusterEvent, Error, EventType};

pub struct NatsPublisher {
    client: Client,
    topic: &'static str,
}

impl NatsPubSub {
    pub(crate) fn publisher(&self, topic: &'static str) -> NatsPublisher {
        NatsPublisher {
            client: self.client.clone(),
            topic,
        }
    }

    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<Subscription> {
        self.client
            .subscribe(topic)
            .await
            .map(Subscription::Nats)
            .map_err(|err| {
                Error::new(EventType::Cluster(ClusterEvent::SubscriberError)).reason(err)
            })
    }
}

impl NatsPublisher {
    pub async fn publish(&mut self, payload: &mut Vec<u8>) -> trc::Result<()> {
        if self.client.connection_state() != State::Connected {
            return Err(Error::new(EventType::Cluster(ClusterEvent::PublisherError))
                .details("Not connected to NATS"));
        }
        self.client
            .publish(self.topic, std::mem::take(payload).into())
            .await
            .map_err(|err| Error::new(EventType::Cluster(ClusterEvent::PublisherError)).reason(err))
    }
}

pub(crate) async fn nats_next<'x>(subscriber: &mut Subscriber) -> Option<Msg<'x>> {
    subscriber.next().await.map(Msg::Nats)
}
