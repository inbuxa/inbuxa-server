/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    BROADCAST_TOPIC, BroadcastBatch, MAX_BATCH_SIZE, RETRY_INITIAL, RETRY_MAX, backlog::Backlog,
};
use common::{IPC_CHANNEL_BUFFER, Inner, ipc::BroadcastEvent};
use coordinator::Publisher;
use std::{collections::VecDeque, future::Future, sync::Arc};
use tokio::sync::mpsc;
use trc::ClusterEvent;

const MAX_PAYLOAD_BYTES: usize = 512 * 1024;

struct BatchPublisher {
    inner: Arc<Inner>,
    publisher: Publisher,
    payload: Vec<u8>,
    node_id: u16,
}

struct Intake<'x> {
    event_rx: &'x mut mpsc::Receiver<BroadcastEvent>,
    received: Vec<BroadcastEvent>,
    queued: VecDeque<BroadcastEvent>,
    backlog: Backlog,
    is_open: bool,
}

pub fn spawn_broadcast_publisher(inner: Arc<Inner>, mut event_rx: mpsc::Receiver<BroadcastEvent>) {
    let (publisher, node_id) = {
        let core = inner.shared_core.load();
        let Some(publisher) = core.storage.coordinator.publisher(BROADCAST_TOPIC) else {
            return;
        };
        (publisher, core.network.node_id as u16)
    };

    tokio::spawn(async move {
        let mut batch = BroadcastBatch::init();
        let mut publisher = BatchPublisher {
            inner,
            publisher,
            payload: Vec::new(),
            node_id,
        };
        let mut intake = Intake::new(&mut event_rx);
        let mut backoff = RETRY_INITIAL;

        trc::event!(Cluster(ClusterEvent::PublisherStart));

        while intake.next_batch(&mut batch).await {
            match intake.absorb(publisher.publish(&mut batch)).await {
                Ok(()) => {
                    intake.backlog.release(&mut batch);
                    backoff = RETRY_INITIAL;
                }
                Err(err) => {
                    trc::event!(Cluster(ClusterEvent::PublisherError), CausedBy = err);
                    intake.absorb(tokio::time::sleep(backoff)).await;
                    backoff = (backoff * 2).min(RETRY_MAX);
                }
            }
            intake.report_dropped();
        }

        trc::event!(Cluster(ClusterEvent::PublisherStop));
    });
}

impl BatchPublisher {
    async fn publish(
        &mut self,
        batch: &mut BroadcastBatch<Vec<BroadcastEvent>>,
    ) -> trc::Result<()> {
        let read_version = self
            .inner
            .shared_core
            .load()
            .storage
            .data
            .read_snapshot_version();
        batch.serialize(self.node_id, read_version, &mut self.payload);
        if self.payload.len() <= MAX_PAYLOAD_BYTES {
            self.publisher.publish(&mut self.payload).await
        } else {
            self.publish_split(&mut batch.messages, read_version).await
        }
    }

    #[cold]
    async fn publish_split(
        &mut self,
        events: &mut Vec<BroadcastEvent>,
        read_version: Option<u64>,
    ) -> trc::Result<()> {
        while let Some(count) = next_chunk(
            events,
            self.node_id,
            read_version,
            &mut self.payload,
            MAX_PAYLOAD_BYTES,
        ) {
            self.publisher.publish(&mut self.payload).await?;
            events.drain(..count);
        }
        Ok(())
    }
}

fn next_chunk(
    events: &mut Vec<BroadcastEvent>,
    node_id: u16,
    read_version: Option<u64>,
    payload: &mut Vec<u8>,
    max_bytes: usize,
) -> Option<usize> {
    while !events.is_empty() {
        let mut count = events.len();
        loop {
            BroadcastBatch {
                messages: &events[..count],
            }
            .serialize(node_id, read_version, payload);
            if payload.len() <= max_bytes || count == 1 {
                break;
            }
            count /= 2;
        }
        if payload.len() <= max_bytes {
            return Some(count);
        }
        match events.remove(0) {
            BroadcastEvent::CacheInvalidate(mut items) if items.len() > 1 => {
                let tail = items.split_off(items.len() / 2);
                events.insert(0, BroadcastEvent::CacheInvalidate(tail));
                events.insert(0, BroadcastEvent::CacheInvalidate(items));
            }
            _ => {
                trc::event!(
                    Cluster(ClusterEvent::PublisherError),
                    Details = "Dropped a broadcast event larger than the maximum payload",
                    Size = payload.len(),
                );
            }
        }
    }
    None
}

impl<'x> Intake<'x> {
    fn new(event_rx: &'x mut mpsc::Receiver<BroadcastEvent>) -> Self {
        Intake {
            event_rx,
            received: Vec::with_capacity(MAX_BATCH_SIZE),
            queued: VecDeque::new(),
            backlog: Backlog::default(),
            is_open: true,
        }
    }

    async fn next_batch(&mut self, batch: &mut BroadcastBatch<Vec<BroadcastEvent>>) -> bool {
        if !batch.messages.is_empty() {
            return true;
        }
        if !self.queued.is_empty() {
            batch.take_from(&mut self.queued);
            return true;
        }
        if self.backlog.fill(batch) || (self.is_open && batch.recv(self.event_rx).await) {
            return true;
        }
        self.is_open = false;
        false
    }

    async fn absorb<T>(&mut self, until: impl Future<Output = T>) -> T {
        tokio::pin!(until);
        loop {
            tokio::select! {
                biased;
                result = &mut until => return result,
                count = self.event_rx.recv_many(&mut self.received, MAX_BATCH_SIZE), if self.is_open => {
                    if count == 0 {
                        self.is_open = false;
                    }
                    for event in self.received.drain(..) {
                        if self.queued.len() < IPC_CHANNEL_BUFFER && self.backlog.is_empty() {
                            self.queued.push_back(event);
                        } else {
                            self.backlog.push(event);
                        }
                    }
                }
            }
        }
    }

    fn report_dropped(&mut self) {
        let dropped = self.backlog.take_dropped();
        if dropped > 0 {
            trc::event!(
                Cluster(ClusterEvent::PublisherError),
                Details = "Dropped the oldest pending broadcast events",
                Total = dropped,
                Size = self.backlog.bytes(),
            );
        }
    }
}

