/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::CommitError;
use crate::{
    Shape, Subspace, WITH_SUBSPACE,
    backend::mysql::{
        into_error,
        read::{MAX_POINT_KEYS, PointRows, point_statement},
        sql::SqlStatements,
    },
    write::{
        Advance, AssignedIds, Batch, BatchCursor, NewKeyAsserts, Operation, ValueOp, insert_follows,
    },
};
use futures::TryStreamExt;
use mysql_async::{Row, Transaction, prelude::Queryable};
use std::{borrow::Cow, mem, ops::Range};

#[derive(Default)]
pub(super) struct ReadSet {
    keys: Vec<u8>,
    entries: Vec<Entry>,
}

struct Entry {
    key: Range<usize>,
    subspace: Subspace,
    fetch: bool,
    asserted: bool,
    last_read: usize,
    current: Current,
}

enum Current {
    Absent,
    Present,
    Stored(Vec<u8>),
}

impl ReadSet {
    pub(super) fn collect(
        batch: &mut Batch<'_>,
        ids: &mut AssignedIds,
        key_buf: &mut Vec<u8>,
        new_key_asserts: NewKeyAsserts,
    ) -> Self {
        let mut reads = ReadSet::default();
        let mut cursor = BatchCursor::new(batch);
        let mut pending_document = false;
        let mut remaining = &mut *batch.ops;
        let mut index = 0;

        while let Some((op, rest)) = mem::take(&mut remaining).split_first_mut() {
            remaining = rest;
            let op_index = index;
            index += 1;
            if let Operation::DocumentId { document_id } = op {
                pending_document = document_id.is_pending();
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
            let checked_by_insert = new_key_asserts == NewKeyAsserts::CheckedByInsert
                && asserts_absent
                && pending_document
                && !matches!(subspace.shape(), Shape::Presence)
                && insert_follows(class, remaining)
                && !cursor.is_document_independent(class, key_buf);
            cursor.value_key(class, key_buf, WITH_SUBSPACE);
            reads.push(subspace, key_buf, !checked_by_insert, op_index);
        }

        reads.seal();
        reads
    }

    fn push(&mut self, subspace: Subspace, key: &[u8], fetch: bool, op_index: usize) {
        let start = self.keys.len();
        self.keys.extend_from_slice(key);
        self.entries.push(Entry {
            key: start..self.keys.len(),
            subspace,
            fetch,
            asserted: false,
            last_read: op_index,
            current: Current::Absent,
        });
    }

    fn seal(&mut self) {
        let ReadSet { keys, entries } = self;
        entries.sort_unstable_by(|a, b| a.key(keys).cmp(b.key(keys)));
        entries.dedup_by(|next, kept| {
            let duplicate = next.key(keys) == kept.key(keys);
            if duplicate {
                kept.fetch |= next.fetch;
                kept.last_read = kept.last_read.max(next.last_read);
            }
            duplicate
        });
    }

    pub(super) async fn fetch(
        &mut self,
        trx: &mut Transaction<'_>,
        sql: &SqlStatements,
    ) -> Result<(), CommitError> {
        let ReadSet { keys, entries } = self;
        let mut fetch_keys: Vec<&[u8]> = Vec::new();
        let mut fetch_slots = Vec::new();

        for run in entries.chunk_by_mut(|a, b| a.subspace == b.subspace) {
            let Some(subspace) = run.first().map(|entry| entry.subspace) else {
                continue;
            };
            fetch_keys.clear();
            fetch_slots.clear();
            for (slot, entry) in run.iter().enumerate().filter(|(_, entry)| entry.fetch) {
                fetch_keys.push(unprefixed(entry.key(keys)));
                fetch_slots.push(slot);
            }

            match (fetch_keys.as_slice(), fetch_slots.as_slice()) {
                ([], _) => {}
                ([key], [slot]) => {
                    let s = trx.prep(&*sql.get(subspace).get_value_for_update).await?;
                    let value = trx.exec_first::<Vec<u8>, _, _>(&s, (key,)).await?;
                    if let Some(entry) = run.get_mut(*slot) {
                        entry.current = value.map_or(Current::Absent, Current::Stored);
                    }
                }
                _ => {
                    for (chunk_keys, chunk_slots) in fetch_keys
                        .chunks(MAX_POINT_KEYS)
                        .zip(fetch_slots.chunks(MAX_POINT_KEYS))
                    {
                        let (query, params) =
                            point_statement(subspace.name(), PointRows::ForUpdate, chunk_keys);
                        let s = trx.prep(&query).await?;
                        let mut rows = trx.exec_stream::<Row, _, _>(&s, params).await?;
                        while let Some(mut row) = rows.try_next().await? {
                            let value = row
                                .take_opt::<Vec<u8>, _>(1)
                                .transpose()
                                .map_err(into_error)?;
                            let key = row
                                .take_opt::<Vec<u8>, _>(0)
                                .transpose()
                                .map_err(into_error)?;
                            let entry = key
                                .and_then(|key| chunk_keys.binary_search(&key.as_slice()).ok())
                                .and_then(|index| chunk_slots.get(index))
                                .and_then(|slot| run.get_mut(*slot))
                                .ok_or_else(missing_read)?;
                            entry.current = Current::Stored(value.unwrap_or_default());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[inline]
    pub(super) fn find(&self, key: &[u8]) -> Option<usize> {
        self.entries
            .binary_search_by(|entry| entry.key(&self.keys).cmp(key))
            .ok()
    }

    #[inline]
    pub(super) fn value(&self, slot: usize) -> Result<Option<&[u8]>, CommitError> {
        match self.entries.get(slot).map(|entry| &entry.current) {
            Some(Current::Stored(value)) => Ok(Some(value)),
            Some(Current::Absent) => Ok(None),
            Some(Current::Present) | None => Err(missing_read()),
        }
    }

    #[inline]
    pub(super) fn exists(&self, slot: usize) -> bool {
        self.entries
            .get(slot)
            .is_some_and(|entry| !matches!(entry.current, Current::Absent))
    }

    #[inline]
    pub(super) fn is_asserted(&self, slot: usize) -> bool {
        self.entries.get(slot).is_some_and(|entry| entry.asserted)
    }

    #[inline]
    pub(super) fn asserted(&mut self, slot: usize) {
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.asserted = true;
        }
    }

    #[inline]
    pub(super) fn written(&mut self, slot: usize, op_index: usize, value: Cow<'_, [u8]>) {
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.current = if op_index < entry.last_read {
                Current::Stored(value.into_owned())
            } else {
                Current::Present
            };
        }
    }

    pub(super) fn clear_range(&mut self, subspace: Subspace, from: &[u8], to: &[u8]) {
        let ReadSet { keys, entries } = self;
        let range = from..to;
        for entry in entries.iter_mut() {
            if entry.subspace == subspace && range.contains(&unprefixed(entry.key(keys))) {
                entry.current = Current::Absent;
            }
        }
    }

    #[inline]
    pub(super) fn cleared(&mut self, slot: usize) {
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.current = Current::Absent;
        }
    }

    #[inline]
    pub(super) fn needs_fetch(&self) -> bool {
        self.entries.iter().any(|entry| entry.fetch)
    }
}

impl Entry {
    #[inline]
    fn key<'a>(&self, keys: &'a [u8]) -> &'a [u8] {
        keys.get(self.key.clone()).unwrap_or_default()
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

