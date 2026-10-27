/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ZenohPubSub;
use crate::{Msg, Subscription};
use std::sync::Arc;
use trc::{ClusterEvent, Error, EventType};
use zenoh::{handlers::FifoChannelHandler, pubsub::Publisher, sample::Sample};

pub type ZenohSubscription = zenoh::pubsub::Subscriber<FifoChannelHandler<Sample>>;

pub enum ZenohMsg {
    Contiguous(Sample),
    Fragmented(Vec<u8>),
}

pub struct ZenohPublisher {
    pubsub: Arc<ZenohPubSub>,
    topic: &'static str,
    publisher: Option<Publisher<'static>>,
}

impl ZenohPubSub {
    pub async fn subscribe(&self, topic: &'static str) -> trc::Result<Subscription> {
        self.session
            .declare_subscriber(topic)
            .await
            .map(Subscription::Zenoh)
            .map_err(|err| {
                Error::new(EventType::Cluster(ClusterEvent::SubscriberError)).reason(err)
            })
    }
}

impl ZenohPublisher {
    pub(crate) fn new(pubsub: Arc<ZenohPubSub>, topic: &'static str) -> Self {
        ZenohPublisher {
            pubsub,
            topic,
            publisher: None,
        }
    }

    pub async fn publish(&mut self, payload: &mut Vec<u8>) -> trc::Result<()> {
        let publisher = match &mut self.publisher {
            Some(publisher) => publisher,
            None => self.publisher.insert(
                self.pubsub
                    .session
                    .declare_publisher(self.topic)
                    .await
                    .map_err(into_error)?,
            ),
        };
        let result = publisher.put(std::mem::take(payload)).await;
        if result.is_err() {
            self.publisher = None;
        }
        result.map_err(into_error)
    }
}

pub(crate) async fn zenoh_next<'x>(subscription: &ZenohSubscription) -> Option<Msg<'x>> {
    let sample = subscription.recv_async().await.ok()?;
    let mut slices = sample.payload().slices();
    let msg = if slices.nth(1).is_none() {
        ZenohMsg::Contiguous(sample)
    } else {
        ZenohMsg::Fragmented(sample.payload().to_bytes().into_owned())
    };
    Some(Msg::Zenoh(msg))
}

impl ZenohMsg {
    pub fn payload(&self) -> &[u8] {
        match self {
            ZenohMsg::Contiguous(sample) => sample.payload().slices().next().unwrap_or_default(),
            ZenohMsg::Fragmented(payload) => payload,
        }
    }
}

fn into_error(err: impl std::fmt::Display) -> trc::Error {
    Error::new(EventType::Cluster(ClusterEvent::PublisherError)).reason(err)
}
