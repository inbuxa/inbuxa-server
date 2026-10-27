/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{IngestedEmail, THREAD_SCAN_WINDOW, has_message_id};
use common::Server;
use registry::{
    schema::structs::{Task, TaskMergeThreads, TaskStatus},
    types::map::Map,
};
use std::ops::Range;
use store::{
    IterateParams, Key, U32_LEN, ValueKey,
    write::{BatchBuilder, IndexPropertyClass, ValueClass, key::DeserializeBigEndian},
};
use tinyvec::TinyVec;
use trc::AddContext;
use types::{collection::Collection, field::EmailField};
use utils::hash128::Hash128;

#[derive(Debug)]
pub struct PendingThread {
    hash: Hash128,
    message_ids: Vec<u128>,
    bucket_full: bool,
}

#[derive(Debug, Default)]
pub struct ThreadRecheck {
    account_id: u32,
    pending: Vec<PendingThread>,
}

struct Bucket {
    thread: PendingThread,
    thread_ids: TinyVec<[u32; 2]>,
}

type BucketRange = IterateParams<ValueKey<ValueClass>>;

struct Group {
    prefix: Vec<u8>,
    hash: Hash128,
    buckets: Range<usize>,
    message_ids: Vec<u128>,
    rows: usize,
    full: bool,
}

impl PendingThread {
    pub(super) fn new(hash: Hash128, message_ids: Vec<u128>, bucket_full: bool) -> Self {
        PendingThread {
            hash,
            message_ids,
            bucket_full,
        }
    }
}

impl ThreadRecheck {
    pub fn push(&mut self, account_id: u32, email: &mut IngestedEmail) {
        if let Some(thread) = email.thread_recheck.take() {
            self.account_id = account_id;
            self.pending.push(thread);
        }
    }

    pub async fn finish(self, server: &Server, session_id: u64) {
        if let Err(err) = self.run(server).await {
            trc::error!(err.span_id(session_id).details("Failed to recheck threads"));
        }
    }

    async fn run(self, server: &Server) -> trc::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let account_id = self.account_id;
        let mut detector = ForkDetector::new(account_id, self.pending);
        let (mut small, full) = detector.ranges();
        let mut observe = |key: &[u8], value: &[u8]| detector.observe(key, value).map(|_| true);

        let store = server.store();
        if small.len() > 1 {
            store.iterate_many(small, &mut observe).await
        } else if let Some(range) = small.pop() {
            store
                .iterate(range.limit(THREAD_SCAN_WINDOW), &mut observe)
                .await
        } else {
            Ok(())
        }
        .caused_by(trc::location!())?;
        for range in full {
            store
                .iterate(range, &mut observe)
                .await
                .caused_by(trc::location!())?;
        }

        let mut forks = detector.forks().peekable();
        if forks.peek().is_none() {
            return Ok(());
        }

        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        for thread in forks {
            batch.schedule_task(Task::MergeThreads(TaskMergeThreads {
                account_id: account_id.into(),
                status: TaskStatus::now(),
                thread_name: thread.hash.to_string(),
                message_ids: Map::new(
                    thread
                        .message_ids
                        .into_iter()
                        .map(|id| id.to_string())
                        .collect(),
                ),
            }));
        }

        let queues = batch.queue_notify();
        server
            .store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
        server.notify_queues(queues).await;
        Ok(())
    }
}

struct ForkDetector {
    account_id: u32,
    buckets: Vec<Bucket>,
    groups: Vec<Group>,
}

impl ForkDetector {
    fn new(account_id: u32, mut pending: Vec<PendingThread>) -> Self {
        pending.sort_unstable_by_key(|thread| thread.hash);
        let mut groups: Vec<Group> = Vec::new();
        for (idx, thread) in pending.iter().enumerate() {
            match groups.last_mut() {
                Some(group) if group.hash == thread.hash => {
                    group.buckets.end = idx + 1;
                    group.full |= thread.bucket_full;
                    group.message_ids.extend_from_slice(&thread.message_ids);
                }
                _ => {
                    let mut prefix = thread_key(account_id, thread.hash, 0).serialize(0);
                    prefix.truncate(prefix.len() - U32_LEN);
                    groups.push(Group {
                        prefix,
                        hash: thread.hash,
                        buckets: idx..idx + 1,
                        message_ids: thread.message_ids.clone(),
                        rows: 0,
                        full: thread.bucket_full,
                    });
                }
            }
        }
        for group in &mut groups {
            if group.buckets.len() > 1 {
                group.message_ids.sort_unstable();
                group.message_ids.dedup();
            }
        }
        groups.sort_unstable_by(|a, b| a.prefix.cmp(&b.prefix));

        ForkDetector {
            account_id,
            buckets: pending
                .into_iter()
                .map(|thread| Bucket {
                    thread,
                    thread_ids: TinyVec::new(),
                })
                .collect(),
            groups,
        }
    }

    fn ranges(&self) -> (Vec<BucketRange>, Vec<BucketRange>) {
        let range = |group: &Group| {
            IterateParams::new(
                thread_key(self.account_id, group.hash, u32::MAX),
                thread_key(self.account_id, group.hash, 0),
            )
        };
        let mut small = Vec::with_capacity(self.groups.len());
        let mut full = Vec::new();
        for group in &self.groups {
            if group.full {
                full.push(range(group).limit(THREAD_SCAN_WINDOW));
            } else {
                small.push(range(group));
            }
        }
        (small, full)
    }

    fn observe(&mut self, key: &[u8], value: &[u8]) -> trc::Result<()> {
        let Some(group) = key
            .len()
            .checked_sub(U32_LEN)
            .and_then(|len| key.get(..len))
            .and_then(|prefix| {
                self.groups
                    .binary_search_by(|group| group.prefix.as_slice().cmp(prefix))
                    .ok()
            })
            .and_then(|idx| self.groups.get_mut(idx))
        else {
            return Ok(());
        };
        group.rows += 1;
        let references = value.get(U32_LEN..).unwrap_or_default();
        if group.rows > THREAD_SCAN_WINDOW || !has_message_id(&group.message_ids, references) {
            return Ok(());
        }

        let thread_id = value.deserialize_be_u32(0)?;
        for bucket in self
            .buckets
            .get_mut(group.buckets.clone())
            .unwrap_or_default()
        {
            if bucket.thread_ids.len() < 2
                && !bucket.thread_ids.contains(&thread_id)
                && has_message_id(&bucket.thread.message_ids, references)
            {
                bucket.thread_ids.push(thread_id);
            }
        }
        Ok(())
    }

    fn forks(self) -> impl Iterator<Item = PendingThread> {
        self.buckets
            .into_iter()
            .filter(|bucket| bucket.thread_ids.len() > 1)
            .map(|bucket| bucket.thread)
    }
}

fn thread_key(account_id: u32, hash: Hash128, document_id: u32) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: Collection::Email.into(),
        document_id,
        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
            property: EmailField::Threading.into(),
            hash,
        }),
    }
}

