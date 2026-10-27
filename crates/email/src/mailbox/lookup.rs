/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ARCHIVE_ID, DRAFTS_ID, INBOX_ID, JUNK_ID, Mailbox, SENT_ID, TRASH_ID, index::name_index_class,
};
use crate::cache::{MessageCacheFetch, mailbox::MailboxCacheAccess};
use common::{MessageStoreCache, Server};
use std::{future::Future, pin::Pin, sync::Arc};
use store::{
    IterateParams, Key, U32_LEN, ValueKey,
    write::{Archive, ArchiveBytes, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{collection::Collection, special_use::SpecialUse};

const ROOT_ID: u32 = u32::MAX;
const INBOX_NAME: &[u8] = b"inbox";
const MAX_PATH_SEGMENTS: usize = 64;
const MAX_JOINED_SEGMENTS: usize = 16;

pub trait MailboxLookup: Sync + Send {
    fn mailbox_id_by_path(
        &self,
        account_id: u32,
        path: &str,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;

    fn mailbox_id_by_role(
        &self,
        account_id: u32,
        role: SpecialUse,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;

    fn mailbox_id_exists(
        &self,
        account_id: u32,
        document_id: u32,
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

impl MailboxLookup for Server {
    async fn mailbox_id_by_path(&self, account_id: u32, path: &str) -> trc::Result<Option<u32>> {
        let mut lookup = PathLookup::new(path);
        loop {
            if let Some(document_id) = lookup.resolve() {
                return Ok(Some(document_id));
            }
            if !lookup.next_pass() {
                return Ok(None);
            }
            fetch_names(self, account_id, &mut lookup).await?;
        }
    }

    async fn mailbox_id_by_role(
        &self,
        account_id: u32,
        role: SpecialUse,
    ) -> trc::Result<Option<u32>> {
        let default_id = match role {
            SpecialUse::Inbox => return Ok(Some(INBOX_ID)),
            SpecialUse::Trash => return Ok(Some(TRASH_ID)),
            SpecialUse::None => return Ok(None),
            SpecialUse::Junk => Some(JUNK_ID),
            SpecialUse::Drafts => Some(DRAFTS_ID),
            SpecialUse::Sent => Some(SENT_ID),
            SpecialUse::Archive => Some(ARCHIVE_ID),
            SpecialUse::Important
            | SpecialUse::Memos
            | SpecialUse::Scheduled
            | SpecialUse::Snoozed
            | SpecialUse::Shared => None,
        };

        if let Some(cache) = self.fresh_messages(account_id) {
            return Ok(cache
                .mailbox_by_role(&role)
                .map(|mailbox| mailbox.document_id));
        }

        if let Some(document_id) = default_id
            && let Some(archive) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Mailbox,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            && archive
                .unarchive::<Mailbox>()
                .caused_by(trc::location!())?
                .role()
                == role
        {
            return Ok(Some(document_id));
        }

        let cache: Pin<Box<dyn Future<Output = trc::Result<Arc<MessageStoreCache>>> + Send + '_>> =
            Box::pin(self.get_cached_messages(account_id));
        cache.await.caused_by(trc::location!()).map(|cache| {
            cache
                .mailbox_by_role(&role)
                .map(|mailbox| mailbox.document_id)
        })
    }

    async fn mailbox_id_exists(&self, account_id: u32, document_id: u32) -> trc::Result<bool> {
        self.store()
            .key_exists(ValueKey::archive(
                account_id,
                Collection::Mailbox,
                document_id,
            ))
            .await
            .caused_by(trc::location!())
    }
}

struct PathLookup {
    segments: Vec<Box<[u8]>>,
    queries: Vec<NameQuery>,
    candidates: Vec<Candidate>,
    pass: LookupPass,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LookupPass {
    Start,
    Segments,
    Joined,
}

struct NameQuery {
    name: Box<[u8]>,
    spans: Vec<(usize, usize)>,
    fetched: bool,
}

struct Candidate {
    start: usize,
    end: usize,
    document_id: u32,
    parent_id: u32,
}

impl PathLookup {
    fn new(path: &str) -> Self {
        PathLookup {
            segments: path
                .split('/')
                .map(|segment| segment.as_bytes().to_ascii_lowercase().into_boxed_slice())
                .collect(),
            queries: Vec::new(),
            candidates: Vec::new(),
            pass: LookupPass::Start,
        }
    }

    fn next_pass(&mut self) -> bool {
        match self.pass {
            LookupPass::Start if self.segments.len() <= MAX_PATH_SEGMENTS => {
                self.pass = LookupPass::Segments;
                self.query_spans(|start, end| end == start + 1);
                true
            }
            LookupPass::Segments if (2..=MAX_JOINED_SEGMENTS).contains(&self.segments.len()) => {
                self.pass = LookupPass::Joined;
                self.query_spans(|start, end| end > start + 1);
                true
            }
            LookupPass::Start | LookupPass::Segments | LookupPass::Joined => false,
        }
    }

    fn span_name(&self, start: usize, end: usize) -> Box<[u8]> {
        let segments = self.segments.get(start..end).unwrap_or_default();
        let mut name = Vec::with_capacity(
            segments
                .iter()
                .map(|segment| segment.len() + 1)
                .sum::<usize>(),
        );
        if let Some((first, rest)) = segments.split_first() {
            name.extend_from_slice(first);
            for segment in rest {
                name.push(b'/');
                name.extend_from_slice(segment);
            }
        }
        name.into_boxed_slice()
    }

    fn is_inbox_span(&self, start: usize, end: usize) -> bool {
        start == 0
            && end == 1
            && self
                .segments
                .first()
                .is_some_and(|name| **name == *INBOX_NAME)
    }

    fn query_spans(&mut self, include: impl Fn(usize, usize) -> bool) {
        let num_segments = self.segments.len();
        for end in 1..=num_segments {
            for start in 0..end {
                if !include(start, end) || self.is_inbox_span(start, end) {
                    continue;
                }
                let name = self.span_name(start, end);
                match self.queries.iter_mut().find(|query| query.name == name) {
                    Some(query) => query.spans.push((start, end)),
                    None => self.queries.push(NameQuery {
                        name,
                        spans: vec![(start, end)],
                        fetched: false,
                    }),
                }
            }
        }
    }

    fn add_candidate(&mut self, name: &[u8], document_id: u32, parent_id: u32) {
        if let Some(query) = self.queries.iter().find(|query| *query.name == *name) {
            self.candidates
                .extend(query.spans.iter().map(|&(start, end)| Candidate {
                    start,
                    end,
                    document_id,
                    parent_id,
                }));
        }
    }

    fn resolve(&self) -> Option<u32> {
        let num_segments = self.segments.len();
        let mut reach: Vec<Vec<u32>> = Vec::with_capacity(num_segments + 1);
        reach.push(vec![ROOT_ID]);
        for end in 1..=num_segments {
            let mut matched = Vec::new();
            for (start, parents) in reach.iter().enumerate() {
                if parents.is_empty() {
                    continue;
                }
                if self.is_inbox_span(start, end) {
                    matched.push(INBOX_ID);
                    continue;
                }
                matched.extend(
                    self.candidates
                        .iter()
                        .filter(|candidate| {
                            candidate.start == start
                                && candidate.end == end
                                && candidate.document_id != INBOX_ID
                                && parents.contains(&candidate.parent_id)
                        })
                        .map(|candidate| candidate.document_id),
                );
            }
            matched.sort_unstable();
            matched.dedup();
            reach.push(matched);
        }
        reach.last().and_then(|ids| ids.first().copied())
    }
}

async fn fetch_names(server: &Server, account_id: u32, lookup: &mut PathLookup) -> trc::Result<()> {
    let mut ranges = lookup
        .queries
        .iter_mut()
        .filter(|query| !query.fetched)
        .map(|query| {
            query.fetched = true;
            let class = name_index_class(&query.name);
            let begin = ValueKey {
                account_id,
                collection: Collection::Mailbox.into(),
                document_id: u32::MAX,
                class: class.clone(),
            };
            let end = ValueKey {
                account_id,
                collection: Collection::Mailbox.into(),
                document_id: 0,
                class,
            };
            (begin.serialize(0), IterateParams::new(begin, end))
        })
        .collect::<Vec<_>>();
    ranges.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
    ranges.dedup_by(|(a, _), (b, _)| a == b);

    let mut collect = |key: &[u8], value: &[u8]| {
        let document_id = !key.deserialize_be_u32(key.len() - U32_LEN)?;
        let parent_id = value.deserialize_be_u32(0)?;
        lookup.add_candidate(
            value.get(U32_LEN..).unwrap_or_default(),
            document_id,
            parent_id,
        );
        Ok(true)
    };

    let store = server.store();
    if ranges.len() > 1 {
        store
            .iterate_many(
                ranges.into_iter().map(|(_, params)| params).collect(),
                &mut collect,
            )
            .await
    } else if let Some((_, params)) = ranges.pop() {
        store.iterate(params, &mut collect).await
    } else {
        Ok(())
    }
    .caused_by(trc::location!())
}

