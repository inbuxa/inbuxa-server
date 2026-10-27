/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    CommitError, Write,
    flight::{StatementId, StatementKind, Transaction},
};
use crate::{
    Shape, Subspace, WITH_SUBSPACE,
    write::{
        Advance, AssignedIds, Batch, BatchCursor, NewKeyAsserts, Operation, ValueOp, insert_follows,
    },
};
use ahash::RandomState;
use hashbrown::HashTable;
use std::{mem, ops::Range};
use tokio_postgres::Row;

pub(super) const PG_PRE_READ_PER_KEY_MAX: usize = 8;
pub(super) const PG_READ_BATCH_KEYS: usize = 256;
const LINEAR_LOOKUP_MAX: usize = 16;
const SUBSPACES: usize = Subspace::ALL.len();

const _: () = assert!(SUBSPACES <= u32::BITS as usize);

#[derive(Default)]
pub(super) struct ReadSet {
    pub(super) keys: ReadKeys,
    pub(super) values: ReadValues,
    pub(super) checked_by_insert: Vec<usize>,
}

#[derive(Default)]
pub(super) struct ReadKeys {
    bytes: Vec<u8>,
    spans: Vec<KeySpan>,
    index: Option<KeyIndex>,
    subspaces: u32,
}

#[derive(Default)]
pub(super) struct ReadValues(Vec<ReadValue>);

#[derive(Default)]
pub(super) struct ReadPlan<'k> {
    pub(super) single: Vec<(usize, &'k [u8], StatementId)>,
    pub(super) many_keys: Vec<&'k [u8]>,
    pub(super) many_slots: Vec<usize>,
    pub(super) chunks: Vec<(StatementId, Range<usize>)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Pass {
    BeforeAllocation(NewKeyAsserts),
    AfterAllocation,
}

struct KeySpan {
    start: usize,
    end: usize,
    subspace: Subspace,
}

struct KeyIndex {
    slots: HashTable<usize>,
    hasher: RandomState,
}

#[derive(Default)]
struct ReadValue {
    current: Current,
    asserted: bool,
}

#[derive(Default)]
enum Current {
    #[default]
    Unread,
    Absent,
    Stored(Row),
    Written(usize),
}

impl ReadSet {
    pub(super) fn collect(
        &mut self,
        batch: &mut Batch<'_>,
        ids: &mut AssignedIds,
        key_buf: &mut Vec<u8>,
        pass: Pass,
    ) -> usize {
        let mut cursor = BatchCursor::new(batch);
        let mut pending_document = false;
        let mut deferred = 0;
        let mut checked_by_insert = mem::take(&mut self.checked_by_insert);
        let mut next_checked = 0;
        let mut remaining = &mut *batch.ops;
        let mut index = 0;

        while let Some((op, rest)) = mem::take(&mut remaining).split_first_mut() {
            remaining = rest;
            let op_index = index;
            index += 1;

            if let Operation::DocumentId { document_id } = op {
                pending_document = document_id.is_pending();
                if pending_document && pass != Pass::AfterAllocation {
                    continue;
                }
            }

            let (class, asserts_absent) = match cursor.advance(op, ids) {
                Advance::Value {
                    class,
                    op: ValueOp::MergeFnc(_),
                } => (class, false),
                Advance::Assert {
                    class,
                    assert_value,
                } => (class, assert_value.is_none()),
                _ => continue,
            };
            let subspace = cursor.subspace(class);

            match pass {
                Pass::BeforeAllocation(_) if !pending_document => {
                    cursor.value_key(class, key_buf, WITH_SUBSPACE);
                    self.insert(subspace, key_buf);
                }
                Pass::BeforeAllocation(asserts) => {
                    if cursor.is_document_independent(class, key_buf) {
                        self.insert(subspace, key_buf);
                    } else if asserts == NewKeyAsserts::CheckedByInsert
                        && asserts_absent
                        && !matches!(subspace.shape(), Shape::Presence)
                        && insert_follows(class, remaining)
                    {
                        checked_by_insert.push(op_index);
                    } else {
                        deferred += 1;
                    }
                }
                Pass::AfterAllocation if pending_document => {
                    if checked_by_insert.get(next_checked) == Some(&op_index) {
                        next_checked += 1;
                    } else {
                        cursor.value_key(class, key_buf, WITH_SUBSPACE);
                        self.insert(subspace, key_buf);
                    }
                }
                Pass::AfterAllocation => {}
            }
        }

        self.checked_by_insert = checked_by_insert;
        deferred
    }

    pub(super) fn assume_absent(&mut self, subspace: Subspace, key: &[u8]) -> usize {
        self.keys.push(subspace, key);
        self.values.0.push(ReadValue {
            current: Current::Absent,
            asserted: false,
        });
        self.values.0.len() - 1
    }

    pub(super) fn clear_range(&mut self, subspace: Subspace, from: &[u8], to: &[u8]) {
        if self.keys.subspaces & (1 << subspace.index()) == 0 {
            return;
        }
        let range = from..to;
        for (span, value) in self.keys.spans.iter().zip(self.values.0.iter_mut()) {
            if span.subspace == subspace && range.contains(&span.key(&self.keys.bytes)) {
                value.current = Current::Absent;
            }
        }
    }

    fn insert(&mut self, subspace: Subspace, key: &[u8]) {
        if self.keys.find(subspace, key).is_none() {
            self.keys.push(subspace, key);
            self.values.0.push(ReadValue::default());
        }
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.keys.spans.len()
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.keys.spans.is_empty()
    }
}

impl ReadKeys {
    pub(super) fn find(&self, subspace: Subspace, key: &[u8]) -> Option<usize> {
        if self.subspaces & (1 << subspace.index()) == 0 {
            return None;
        }

        match &self.index {
            Some(index) => index
                .slots
                .find(index.hasher.hash_one(key), |slot| {
                    self.spans
                        .get(*slot)
                        .is_some_and(|span| span.prefixed(&self.bytes) == key)
                })
                .copied(),
            None => self
                .spans
                .iter()
                .position(|span| span.prefixed(&self.bytes) == key),
        }
    }

    fn push(&mut self, subspace: Subspace, key: &[u8]) {
        let slot = self.spans.len();
        let start = self.bytes.len();
        self.bytes.extend_from_slice(key);
        self.spans.push(KeySpan {
            start,
            end: self.bytes.len(),
            subspace,
        });
        self.subspaces |= 1 << subspace.index();

        let ReadKeys {
            bytes,
            spans,
            index,
            ..
        } = self;
        match index {
            Some(index) => index.insert(slot, bytes, spans),
            None if spans.len() > LINEAR_LOOKUP_MAX => {
                let mut new_index = KeyIndex {
                    slots: HashTable::with_capacity(spans.len() * 2),
                    hasher: RandomState::new(),
                };
                for slot in 0..spans.len() {
                    new_index.insert(slot, bytes, spans);
                }
                *index = Some(new_index);
            }
            None => {}
        }
    }

    pub(super) fn plan(&self, from: usize, trx: &mut Transaction<'_>) -> ReadPlan<'_> {
        let spans = self.spans.get(from..).unwrap_or_default();
        let mut counts = [0usize; SUBSPACES];
        for span in spans {
            counts[span.subspace.index()] += 1;
        }

        let mut plan = ReadPlan::default();
        for (slot, span) in (from..).zip(spans) {
            if counts[span.subspace.index()] <= PG_PRE_READ_PER_KEY_MAX {
                plan.single.push((
                    slot,
                    span.key(&self.bytes),
                    trx.statement_id(span.subspace, StatementKind::ReadForUpdate),
                ));
            } else {
                plan.many_slots.push(slot);
            }
        }

        if !plan.many_slots.is_empty() {
            plan.many_slots.sort_unstable_by(|a, b| {
                self.spans[*a]
                    .prefixed(&self.bytes)
                    .cmp(self.spans[*b].prefixed(&self.bytes))
            });
            plan.many_keys = plan
                .many_slots
                .iter()
                .map(|slot| self.spans[*slot].key(&self.bytes))
                .collect();

            let mut start = 0;
            for run in plan
                .many_slots
                .chunk_by(|a, b| self.spans[*a].subspace == self.spans[*b].subspace)
            {
                let end = start + run.len();
                if let Some(slot) = run.first() {
                    let statement = trx
                        .statement_id(self.spans[*slot].subspace, StatementKind::ReadManyForUpdate);
                    for chunk_start in (start..end).step_by(PG_READ_BATCH_KEYS) {
                        plan.chunks.push((
                            statement,
                            chunk_start..(chunk_start + PG_READ_BATCH_KEYS).min(end),
                        ));
                    }
                }
                start = end;
            }
        }

        plan
    }
}

impl ReadValues {
    #[inline]
    pub(super) fn read(&mut self, slot: usize, row: Option<Row>) {
        self.0[slot].current = row.map_or(Current::Absent, Current::Stored);
    }

    #[inline]
    pub(super) fn written(&mut self, slot: usize, write: usize) {
        self.0[slot].current = Current::Written(write);
    }

    #[inline]
    pub(super) fn cleared(&mut self, slot: usize) {
        self.0[slot].current = Current::Absent;
    }

    #[inline]
    pub(super) fn asserted(&mut self, slot: usize) {
        self.0[slot].asserted = true;
    }

    #[inline]
    pub(super) fn is_asserted(&self, slot: usize) -> bool {
        self.0[slot].asserted
    }

    #[inline]
    pub(super) fn exists(&self, slot: usize) -> bool {
        matches!(
            self.0[slot].current,
            Current::Stored(_) | Current::Written(_)
        )
    }

    pub(super) fn value<'a>(
        &'a self,
        slot: usize,
        writes: &'a [Write<'_>],
    ) -> Result<Option<&'a [u8]>, CommitError> {
        match &self.0[slot].current {
            Current::Absent => Ok(None),
            Current::Stored(row) => row
                .try_get(row.len().saturating_sub(1))
                .map(Some)
                .map_err(CommitError::from),
            Current::Written(write) => Ok(writes.get(*write).and_then(Write::value)),
            Current::Unread => Err(missing_read()),
        }
    }
}

impl KeyIndex {
    fn insert(&mut self, slot: usize, bytes: &[u8], spans: &[KeySpan]) {
        let hash_of = |slot: &usize| {
            self.hasher.hash_one(
                spans
                    .get(*slot)
                    .map_or(&[][..], |span| span.prefixed(bytes)),
            )
        };
        let hash = hash_of(&slot);
        self.slots.insert_unique(hash, slot, hash_of);
    }
}

impl KeySpan {
    #[inline]
    fn prefixed<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        bytes.get(self.start..self.end).unwrap_or_default()
    }

    #[inline]
    fn key<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        unprefixed(self.prefixed(bytes))
    }
}

#[inline]
pub(super) fn unprefixed(key: &[u8]) -> &[u8] {
    key.split_first().map_or(key, |(_, key)| key)
}

#[cold]
pub(super) fn missing_read() -> CommitError {
    CommitError::Internal(
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Merge or assert key was not read")
            .caused_by(trc::location!()),
    )
}
