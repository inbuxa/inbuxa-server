/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{
    EmailIngest, IngestEmail, IngestedEmail, PendingIngest, sorted_intersect, thread_hash,
};
use crate::message::thread::ThreadFields;
use common::Server;
use mail_parser::Message;
use store::write::{BatchBuilder, PendingId};
use trc::{AddContext, EventType, LimitEvent, MessageIngestEvent};
use utils::hash128::Hash128;

const MAX_GROUP_EMAILS: usize = 32;
const MAX_GROUP_BYTES: usize = 8 * 1024 * 1024;

pub struct IngestGroup {
    batch: BatchBuilder,
    pending: Vec<PendingIngest>,
    threads: Vec<(ThreadKey, PendingId)>,
    size: usize,
    max_emails: usize,
}

#[derive(Default)]
pub struct ThreadKey {
    hash: Hash128,
    message_ids: Vec<u128>,
}

impl ThreadKey {
    pub fn new(message: &Message<'_>) -> Self {
        let fields = ThreadFields::scan(message);
        ThreadKey {
            hash: thread_hash(fields.subject),
            message_ids: fields.message_ids,
        }
    }
}

impl Default for IngestGroup {
    fn default() -> Self {
        IngestGroup::with_max_emails(MAX_GROUP_EMAILS)
    }
}

impl IngestGroup {
    pub fn with_max_emails(max_emails: usize) -> Self {
        IngestGroup {
            batch: BatchBuilder::new(),
            pending: Vec::new(),
            threads: Vec::new(),
            size: 0,
            max_emails,
        }
    }

    pub fn must_flush_before(&self, size: usize) -> bool {
        !self.pending.is_empty()
            && (self.pending.len() >= self.max_emails
                || self.size.saturating_add(size) > MAX_GROUP_BYTES
                || self.batch.is_large_batch())
    }

    fn pending_thread(&self, key: &ThreadKey) -> Option<PendingId> {
        if key.message_ids.is_empty() {
            return None;
        }
        let mut threads = self
            .threads
            .iter()
            .filter(|(pending, _)| {
                pending.hash == key.hash
                    && sorted_intersect(
                        pending.message_ids.iter().copied(),
                        key.message_ids.iter().copied(),
                    )
            })
            .map(|(_, thread_id)| *thread_id);
        let first = threads.next()?;
        threads.all(|thread_id| thread_id == first).then_some(first)
    }

    pub async fn ingest(
        &mut self,
        server: &Server,
        mut params: IngestEmail<'_>,
        key: ThreadKey,
    ) -> trc::Result<()> {
        let size = params.raw_message.len();
        let group_thread = self.pending_thread(&key);
        match server
            .email_ingest_into(&mut params, &mut self.batch, group_thread)
            .await
        {
            Ok(pending) => {
                if let PendingIngest::Queued(email) = &pending
                    && !key.message_ids.is_empty()
                {
                    self.threads.push((key, email.thread_id));
                }
                self.pending.push(pending);
                self.size = self.size.saturating_add(size);
                Ok(())
            }
            Err(err) => {
                if !is_rejection(&err) {
                    self.discard();
                }
                Err(err)
            }
        }
    }

    fn discard(&mut self) {
        self.batch = BatchBuilder::new();
        self.pending.clear();
        self.threads.clear();
        self.size = 0;
    }

    pub async fn flush(&mut self, server: &Server) -> trc::Result<Vec<IngestedEmail>> {
        let mut batch = std::mem::take(&mut self.batch);
        let pending = std::mem::take(&mut self.pending);
        self.threads.clear();
        self.size = 0;
        if pending.is_empty() {
            return Ok(Vec::new());
        }

        let queues = batch.queue_notify();
        let assigned_ids = server
            .store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
        server.inner.mark_caches_stale_from(&assigned_ids);

        let mut ingested = Vec::with_capacity(pending.len());
        for pending in pending {
            ingested.push(match pending {
                PendingIngest::Queued(pending) => {
                    server.email_ingest_finish(pending, &assigned_ids).await
                }
                PendingIngest::Duplicate(email) => email,
            });
        }
        server.notify_queues(queues).await;

        Ok(ingested)
    }
}

fn is_rejection(err: &trc::Error) -> bool {
    match err.as_ref() {
        EventType::MessageIngest(MessageIngestEvent::Error)
        | EventType::Limit(LimitEvent::Quota)
        // inbuxa: MT-19
        | EventType::Limit(LimitEvent::TenantQuota) => true,
        _ => false,
    }
}
