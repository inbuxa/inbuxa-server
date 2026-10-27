/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    CACHE_CHUNK, ColBlock, CustomKeywords, MAX_RECEIVED_AT, MessageCache, MessageUid, MessagesCache,
};
use compact_str::CompactString;
use std::{
    iter::{Chain, FusedIterator, Peekable},
    slice::Iter,
    sync::Arc,
};
use store::roaring::RoaringBitmap;
use tinyvec::TinyVec;

const INDEX_CHUNK: usize = 8000;

const INDEX_BUCKET: u64 = 16;

const INDEX_TABLE_FACTOR: usize = 2;

const INDEX_TAIL: usize = 8;

const MAX_SHIFT: u32 = 31;

const _: () = assert!(INDEX_CHUNK <= u16::MAX as usize);

const APPEND_BLOCK: usize = 1024;

const THREAD_WINDOW: u32 = 1 << 26;

impl MessageCache {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        document_id: u32,
        mailboxes: TinyVec<[MessageUid; 2]>,
        keywords: u32,
        thread_id: u32,
        change_id: u64,
        size: u32,
        received_at: u64,
        sent_at: i32,
    ) -> Self {
        Self {
            document_id,
            mailboxes,
            keywords,
            thread_id,
            change_id,
            size,
            received_at,
            sent_at,
        }
    }

    #[inline(always)]
    pub fn document_id(&self) -> u32 {
        self.document_id
    }

    #[inline(always)]
    pub fn mailboxes(&self) -> &[MessageUid] {
        &self.mailboxes
    }

    #[inline(always)]
    pub fn keywords(&self) -> u32 {
        self.keywords
    }

    #[inline(always)]
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }

    #[inline(always)]
    pub fn change_id(&self) -> u64 {
        self.change_id
    }

    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.size
    }

    #[inline(always)]
    pub fn received_at(&self) -> u64 {
        self.received_at
    }

    #[inline(always)]
    pub fn received_at_secs(&self) -> u32 {
        debug_assert!(
            self.received_at <= MAX_RECEIVED_AT,
            "received_at {} exceeds the representable range and should have been clamped by the caller",
            self.received_at
        );
        self.received_at.min(MAX_RECEIVED_AT) as u32
    }

    #[inline(always)]
    pub fn sent_at(&self) -> i32 {
        self.sent_at
    }

    #[inline(always)]
    pub fn sort_rank(&self) -> (u64, u32) {
        (self.received_at, self.document_id)
    }

    #[inline(always)]
    pub fn has_mailbox_id(&self, mailbox_id: u32) -> bool {
        self.mailboxes
            .iter()
            .any(|uid| uid.mailbox_id == mailbox_id)
    }

    #[inline(always)]
    pub fn uid_in(&self, mailbox_id: u32) -> Option<u32> {
        self.mailboxes
            .iter()
            .find(|uid| uid.mailbox_id == mailbox_id)
            .map(|uid| uid.uid)
    }
}

impl ColBlock {
    fn from_records(items: &[MessageCache]) -> Self {
        let mut mb_offsets = Vec::with_capacity(items.len() + 1);
        let mut mb_arena = Vec::with_capacity(items.len());
        let mut offset = 0u32;
        for item in items {
            mb_offsets.push(offset);
            mb_arena.extend_from_slice(&item.mailboxes);
            offset += item.mailboxes.len() as u32;
        }
        mb_offsets.push(offset);
        let thread_ids: Arc<[u32]> = items.iter().map(|item| item.thread_id).collect();

        ColBlock {
            document_ids: items.iter().map(|item| item.document_id).collect(),
            change_ids: items.iter().map(|item| item.change_id).collect(),
            received_at: items.iter().map(|item| item.received_at_secs()).collect(),
            sent_at: items.iter().map(|item| item.sent_at).collect(),
            sizes: items.iter().map(|item| item.size).collect(),
            keywords: items.iter().map(|item| item.keywords).collect(),
            thread_range: ThreadRange::of(&thread_ids),
            thread_ids,
            mb_offsets: mb_offsets.into(),
            mb_arena: mb_arena.into(),
        }
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.document_ids.len()
    }

    #[inline(always)]
    fn mailboxes(&self, slot: u32) -> &[MessageUid] {
        let from = self.mb_offsets[slot as usize] as usize;
        let to = self.mb_offsets[slot as usize + 1] as usize;
        &self.mb_arena[from..to]
    }

    #[inline(always)]
    fn rank(&self, slot: usize) -> (u64, u32) {
        (self.received_at[slot] as u64, self.document_ids[slot])
    }

    fn patch_slots(&mut self, slots: &[(u32, u32, &MessageCache)]) {
        Self::patch_column(&mut self.change_ids, slots, |record| record.change_id);
        Self::patch_column(&mut self.keywords, slots, |record| record.keywords);
        Self::patch_column(&mut self.thread_ids, slots, |record| record.thread_id);
        Self::patch_column(&mut self.sizes, slots, |record| record.size);
        self.patch_mailboxes(slots);
        for (_, _, record) in slots {
            self.thread_range.widen(record.thread_id);
        }
    }

    fn patch_column<T: Copy + PartialEq>(
        column: &mut Arc<[T]>,
        slots: &[(u32, u32, &MessageCache)],
        pick: impl Fn(&MessageCache) -> T,
    ) {
        if slots
            .iter()
            .all(|(_, slot, record)| column[*slot as usize] == pick(record))
        {
            return;
        }
        let patched = Arc::make_mut(column);
        for (_, slot, record) in slots {
            if let Some(value) = patched.get_mut(*slot as usize) {
                *value = pick(record);
            }
        }
    }

    fn patch_mailboxes(&mut self, slots: &[(u32, u32, &MessageCache)]) {
        if slots
            .iter()
            .all(|(_, slot, record)| self.mailboxes(*slot) == record.mailboxes.as_slice())
        {
            return;
        }
        let mut mb_offsets = Vec::with_capacity(self.len() + 1);
        let mut mb_arena = Vec::with_capacity(self.mb_arena.len());
        let mut offset = 0u32;
        let mut updated = slots.iter().peekable();
        for slot in 0..self.len() as u32 {
            mb_offsets.push(offset);
            let mailboxes = match updated.next_if(|(_, at, _)| *at == slot) {
                Some((_, _, record)) => record.mailboxes.as_slice(),
                None => self.mailboxes(slot),
            };
            mb_arena.extend_from_slice(mailboxes);
            offset += mailboxes.len() as u32;
        }
        mb_offsets.push(offset);
        self.mb_offsets = mb_offsets.into();
        self.mb_arena = mb_arena.into();
    }

    fn weight(&self) -> u64 {
        ((self.document_ids.len()
            * (std::mem::size_of::<u32>() * 5
                + std::mem::size_of::<i32>()
                + std::mem::size_of::<u64>()))
            + (self.mb_offsets.len() * std::mem::size_of::<u32>())
            + (self.mb_arena.len() * std::mem::size_of::<MessageUid>())
            + std::mem::size_of::<ColBlock>()) as u64
    }
}

struct ColBuilder {
    document_ids: Vec<u32>,
    change_ids: Vec<u64>,
    received_at: Vec<u32>,
    sent_at: Vec<i32>,
    sizes: Vec<u32>,
    keywords: Vec<u32>,
    thread_ids: Vec<u32>,
    mb_offsets: Vec<u32>,
    mb_arena: Vec<MessageUid>,
}

impl ColBuilder {
    fn with_capacity(rows: usize, arena: usize) -> Self {
        ColBuilder {
            document_ids: Vec::with_capacity(rows),
            change_ids: Vec::with_capacity(rows),
            received_at: Vec::with_capacity(rows),
            sent_at: Vec::with_capacity(rows),
            sizes: Vec::with_capacity(rows),
            keywords: Vec::with_capacity(rows),
            thread_ids: Vec::with_capacity(rows),
            mb_offsets: Vec::with_capacity(rows + 1),
            mb_arena: Vec::with_capacity(arena),
        }
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.document_ids.len()
    }

    #[inline(always)]
    fn push_record(&mut self, record: &MessageCache) {
        self.document_ids.push(record.document_id);
        self.change_ids.push(record.change_id);
        self.received_at.push(record.received_at_secs());
        self.sent_at.push(record.sent_at);
        self.sizes.push(record.size);
        self.keywords.push(record.keywords);
        self.thread_ids.push(record.thread_id);
        self.mb_offsets.push(self.mb_arena.len() as u32);
        self.mb_arena.extend_from_slice(&record.mailboxes);
    }

    fn copy_run(&mut self, old: &ColBlock, from: usize, to: usize) {
        if from >= to {
            return;
        }
        self.document_ids
            .extend_from_slice(&old.document_ids[from..to]);
        self.change_ids.extend_from_slice(&old.change_ids[from..to]);
        self.received_at
            .extend_from_slice(&old.received_at[from..to]);
        self.sent_at.extend_from_slice(&old.sent_at[from..to]);
        self.sizes.extend_from_slice(&old.sizes[from..to]);
        self.keywords.extend_from_slice(&old.keywords[from..to]);
        self.thread_ids.extend_from_slice(&old.thread_ids[from..to]);

        let base = old.mb_offsets[from];
        let shift = self.mb_arena.len() as u32;
        self.mb_offsets
            .extend(old.mb_offsets[from..to].iter().map(|o| o - base + shift));
        self.mb_arena.extend_from_slice(
            &old.mb_arena[old.mb_offsets[from] as usize..old.mb_offsets[to] as usize],
        );
    }

    fn finish_into(mut self, out: &mut BlockList) {
        let rows = self.len();
        if rows == 0 {
            return;
        }
        self.mb_offsets.push(self.mb_arena.len() as u32);

        if rows <= CACHE_CHUNK * 2 {
            out.push(ColBlock {
                document_ids: self.document_ids.into(),
                change_ids: self.change_ids.into(),
                received_at: self.received_at.into(),
                sent_at: self.sent_at.into(),
                sizes: self.sizes.into(),
                keywords: self.keywords.into(),
                thread_range: ThreadRange::of(&self.thread_ids),
                thread_ids: self.thread_ids.into(),
                mb_offsets: self.mb_offsets.into(),
                mb_arena: self.mb_arena.into(),
            });
            return;
        }

        let mut from = 0usize;
        while from < rows {
            let to = (from + CACHE_CHUNK).min(rows);
            let base = self.mb_offsets[from];
            let arena_from = base as usize;
            let arena_to = self.mb_offsets[to] as usize;
            let mut mb_offsets = self.mb_offsets[from..to]
                .iter()
                .map(|offset| offset - base)
                .collect::<Vec<_>>();
            mb_offsets.push((arena_to - arena_from) as u32);

            out.push(ColBlock {
                document_ids: self.document_ids[from..to].into(),
                change_ids: self.change_ids[from..to].into(),
                received_at: self.received_at[from..to].into(),
                sent_at: self.sent_at[from..to].into(),
                sizes: self.sizes[from..to].into(),
                keywords: self.keywords[from..to].into(),
                thread_range: ThreadRange::of(&self.thread_ids[from..to]),
                thread_ids: self.thread_ids[from..to].into(),
                mb_offsets: mb_offsets.into(),
                mb_arena: self.mb_arena[arena_from..arena_to].into(),
            });
            from = to;
        }
    }
}

const SHIFT_BUCKET: usize = 1024;

struct PositionShift {
    steps: Vec<(u32, i32)>,
    bucket_first: Vec<u32>,
    bucket_delta: Vec<i32>,
    first_key: u32,
}

impl PositionShift {
    fn build(
        insert_positions: impl Iterator<Item = u32>,
        delete_positions: impl Iterator<Item = u32>,
        old_len: usize,
    ) -> Self {
        let mut steps: Vec<(u32, i32)> = Vec::new();
        let mut inserted = insert_positions.peekable();
        let mut deleted = delete_positions.map(|position| position + 1).peekable();
        let mut total = 0i32;
        loop {
            let (key, delta) = match (inserted.peek(), deleted.peek()) {
                (Some(insert), Some(delete)) if insert > delete => (deleted.next().unwrap(), -1i32),
                (Some(_), _) => (inserted.next().unwrap(), 1i32),
                (None, Some(_)) => (deleted.next().unwrap(), -1i32),
                (None, None) => break,
            };

            total += delta;
            if let Some(last) = steps.last_mut()
                && last.0 == key
            {
                last.1 = total;
            } else {
                steps.push((key, total));
            }
        }

        let buckets = old_len / SHIFT_BUCKET + 2;
        let mut bucket_first = Vec::with_capacity(buckets);
        let mut bucket_delta = Vec::with_capacity(buckets);
        let mut cursor = steps.iter().enumerate().peekable();
        let mut carried = 0i32;
        for bucket in 0..buckets {
            let start = (bucket * SHIFT_BUCKET) as u32;
            while let Some((_, (_, delta))) = cursor.next_if(|(_, (key, _))| *key < start) {
                carried = *delta;
            }
            bucket_first.push(cursor.peek().map_or(steps.len(), |(at, _)| *at) as u32);
            bucket_delta.push(carried);
        }

        PositionShift {
            first_key: steps.first().map_or(u32::MAX, |(key, _)| *key),
            steps,
            bucket_first,
            bucket_delta,
        }
    }

    fn span(&self, position: u32) -> (i32, u32, u32) {
        if position < self.first_key {
            return (0, 0, self.first_key);
        }
        let bucket = (position as usize / SHIFT_BUCKET).min(self.bucket_first.len() - 1);
        let from = self.bucket_first[bucket] as usize;
        let next = from
            + self.steps[from..]
                .iter()
                .take_while(|(key, _)| *key <= position)
                .count();
        let (low, delta) = next
            .checked_sub(1)
            .and_then(|last| self.steps.get(last))
            .copied()
            .unwrap_or((0, 0));
        let high = self.steps.get(next).map_or(u32::MAX, |(key, _)| *key);
        (delta, low, high)
    }

    fn constant_over(&self, from: u32, to: u32) -> Option<i32> {
        let next = self.steps.partition_point(|(key, _)| *key <= from);
        self.steps
            .get(next)
            .is_none_or(|(key, _)| *key > to)
            .then(|| self.at(from))
    }

    #[inline(always)]
    fn at(&self, position: u32) -> i32 {
        if position < self.first_key {
            return 0;
        }
        let bucket = (position as usize / SHIFT_BUCKET).min(self.bucket_first.len() - 1);
        let from = self.bucket_first[bucket] as usize;

        self.steps[from..]
            .iter()
            .take_while(|(key, _)| *key <= position)
            .last()
            .map_or(self.bucket_delta[bucket], |(_, delta)| *delta)
    }
}

struct ShiftCursor<'x> {
    shift: &'x PositionShift,
    delta: i32,
    low: u32,
    high: u32,
}

impl<'x> ShiftCursor<'x> {
    fn new(shift: &'x PositionShift) -> Self {
        ShiftCursor {
            shift,
            delta: 0,
            low: 1,
            high: 0,
        }
    }

    #[inline(always)]
    fn apply(&mut self, position: u32) -> u32 {
        if position < self.low || position >= self.high {
            (self.delta, self.low, self.high) = self.shift.span(position);
        }
        position.wrapping_add_signed(self.delta)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct IdIndex {
    sealed: Arc<[IndexChunk]>,
    tail: Arc<[IndexChunk]>,
    firsts: Arc<[u32]>,
    table: Arc<[u32]>,
    base: u32,
    shift: u32,
    chunks_weight: u64,
}

#[derive(Debug, Clone)]
struct IndexChunk {
    data: Arc<[u32]>,
    first: u32,
    len: u32,
    min_position: u32,
    max_position: u32,
    shift: u32,
}

impl IndexChunk {
    fn build(pairs: &[[u32; 2]], directory: &mut Vec<u16>) -> Option<Self> {
        let ([first, _], [last, _]) = (pairs.first()?, pairs.last()?);
        let (first, last) = (*first, *last);
        let len = pairs.len();
        let shift = Self::shift_of(len, last - first);

        let rows = len as u16;
        directory.clear();
        directory.resize(((last - first) >> shift) as usize + 2, rows);
        for (at, [document_id, _]) in (0..rows).zip(pairs).rev() {
            if let Some(start) = directory.get_mut(((document_id - first) >> shift) as usize) {
                *start = at;
            }
        }
        let mut next = rows;
        for start in directory.iter_mut().rev() {
            next = next.min(*start);
            *start = next;
        }

        let (min_position, max_position) = Self::position_range(pairs);

        let mut data: Arc<[u32]> =
            std::iter::repeat_n(0, len * 2 + directory.len().div_ceil(2)).collect();
        let (flat, words) = Arc::make_mut(&mut data).split_at_mut(len * 2);
        flat.copy_from_slice(pairs.as_flattened());
        for (word, halves) in words.iter_mut().zip(directory.chunks(2)) {
            *word = halves
                .iter()
                .rev()
                .fold(0, |word, half| (word << 16) | u32::from(*half));
        }

        Some(IndexChunk {
            data,
            first,
            len: len as u32,
            min_position,
            max_position,
            shift,
        })
    }

    fn decode<T>(
        data: &[T],
        rows: usize,
        native: impl Fn(&T) -> u32 + Copy,
        len: usize,
        after: Option<u32>,
    ) -> Option<Self> {
        if rows == 0 || rows > INDEX_CHUNK {
            return None;
        }
        let (flat, words) = data.split_at_checked(rows * 2)?;
        let first = native(flat.first()?);
        let range = native(flat.get(rows * 2 - 2)?).checked_sub(first)?;
        let shift = Self::shift_of(rows, range);
        let buckets = (range >> shift) as usize + 2;
        if words.len() != buckets.div_ceil(2) || after.is_some_and(|after| after >= first) {
            return None;
        }

        let data = data.iter().map(native).collect::<Arc<[u32]>>();
        let (flat, words) = data.split_at(rows * 2);
        let pairs = flat.as_chunks::<2>().0;
        let [_, first_position] = *pairs.first()?;
        let (unordered, min_position, max_position) = pairs.iter().zip(pairs.iter().skip(1)).fold(
            (0u32, first_position, first_position),
            |(unordered, min, max), ([previous, _], [next, position])| {
                (
                    unordered | u32::from(previous >= next),
                    min.min(*position),
                    max.max(*position),
                )
            },
        );
        let bucket_of = |at: usize| {
            pairs
                .get(at)
                .map(|[document_id, _]| (document_id.wrapping_sub(first) >> shift) as usize)
        };
        let indexed = (0..buckets).all(|bucket| {
            directory_entry(words, bucket).is_some_and(|start| {
                (start == 0 || bucket_of(start - 1).is_some_and(|before| before < bucket))
                    && (start == rows || bucket_of(start).is_some_and(|at| at >= bucket))
            })
        });
        if unordered != 0 || !indexed || max_position as usize >= len {
            return None;
        }

        Some(IndexChunk {
            first,
            len: rows as u32,
            min_position,
            max_position,
            shift,
            data,
        })
    }

    #[inline(always)]
    fn shift_of(len: usize, range: u32) -> u32 {
        let span = (u64::from(range) + 1) * INDEX_BUCKET;
        let mut shift = 0u32;
        while shift < MAX_SHIFT && ((len as u64) << shift) < span {
            shift += 1;
        }
        shift
    }

    #[inline(always)]
    fn position_range(pairs: &[[u32; 2]]) -> (u32, u32) {
        pairs
            .iter()
            .fold((u32::MAX, 0), |(min, max), [_, position]| {
                (min.min(*position), max.max(*position))
            })
    }

    fn shifted(&self, shift: &PositionShift) -> Self {
        let mut data = Arc::<[u32]>::from(&self.data[..]);
        let (flat, _) = Arc::make_mut(&mut data).split_at_mut(self.len as usize * 2);
        let pairs = flat.as_chunks_mut::<2>().0;
        match shift.constant_over(self.min_position, self.max_position) {
            Some(delta) => {
                for [_, position] in pairs {
                    *position = position.wrapping_add_signed(delta);
                }
            }
            None => {
                let mut cursor = ShiftCursor::new(shift);
                for [_, position] in pairs {
                    *position = cursor.apply(*position);
                }
            }
        }
        IndexChunk {
            data,
            min_position: self
                .min_position
                .wrapping_add_signed(shift.at(self.min_position)),
            max_position: self
                .max_position
                .wrapping_add_signed(shift.at(self.max_position)),
            ..*self
        }
    }

    #[inline(always)]
    fn pairs(&self) -> &[[u32; 2]] {
        self.data
            .get(..self.len as usize * 2)
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
    }

    #[inline(always)]
    fn position(&self, document_id: u32) -> Option<u32> {
        let offset = document_id.checked_sub(self.first)?;
        let (pairs, directory) = self.data.split_at_checked(self.len as usize * 2)?;
        let bucket = (offset >> self.shift) as usize;
        let from = directory_entry(directory, bucket)?;
        let to = directory_entry(directory, bucket + 1)?;
        let within = (offset & ((1u32 << self.shift) - 1)) as usize;
        let width = 1usize << self.shift;
        let window = pairs
            .as_chunks::<2>()
            .0
            .get(from.max(to.saturating_sub(width - within))..to.min(from + within + 1))?;
        window
            .binary_search_by_key(&document_id, |[id, _]| *id)
            .ok()
            .and_then(|at| window.get(at))
            .map(|[_, position]| *position)
    }

    fn weight(&self) -> u64 {
        (self.data.len() * std::mem::size_of::<u32>() + std::mem::size_of::<IndexChunk>()) as u64
    }
}

#[inline(always)]
fn directory_entry(directory: &[u32], at: usize) -> Option<usize> {
    directory
        .get(at / 2)
        .map(|word| ((word >> ((at % 2) * 16)) & 0xffff) as usize)
}

impl IdIndex {
    pub(crate) fn from_sorted(entries: &[(u32, u32)]) -> Self {
        let mut writer = IndexWriter::with_capacity(
            entries.len().div_ceil(INDEX_CHUNK),
            entries.len().min(INDEX_CHUNK),
        );
        for (document_id, position) in entries {
            writer.push(*document_id, *position);
        }
        writer.finish()
    }

    pub(crate) fn decode<'x, T: 'x>(
        chunks: impl Iterator<Item = (&'x [T], usize)>,
        native: impl Fn(&T) -> u32 + Copy,
        len: usize,
    ) -> Option<Self> {
        let mut decoded = Vec::with_capacity(chunks.size_hint().0);
        let mut indexed = 0usize;
        let mut after = None;
        for (data, rows) in chunks {
            let chunk = IndexChunk::decode(data, rows, native, len, after)?;
            after = chunk.pairs().last().map(|[document_id, _]| *document_id);
            indexed += rows;
            decoded.push(chunk);
        }
        (indexed == len).then(|| Self::from_chunks(decoded))
    }

    fn from_chunks(mut chunks: Vec<IndexChunk>) -> Self {
        let tail = chunks.split_off(chunks.len().saturating_sub(1));
        Self::assemble(chunks.into(), tail)
    }

    fn assemble(sealed: Arc<[IndexChunk]>, tail: Vec<IndexChunk>) -> Self {
        let chunks_weight = sealed
            .iter()
            .chain(&tail)
            .map(IndexChunk::weight)
            .sum::<u64>();
        let firsts = sealed
            .iter()
            .chain(&tail)
            .map(|chunk| chunk.first)
            .collect::<Arc<[u32]>>();
        let (Some(base), Some(last)) = (firsts.first().copied(), firsts.last().copied()) else {
            return IdIndex {
                sealed,
                tail: tail.into(),
                firsts,
                table: Arc::from([]),
                base: 0,
                shift: 0,
                chunks_weight,
            };
        };
        let span = last - base;
        let wanted = firsts.len() * INDEX_TABLE_FACTOR;
        let mut shift = 0u32;
        while shift < MAX_SHIFT && (span >> shift) as usize >= wanted {
            shift += 1;
        }

        let buckets = (span >> shift) as usize + 1;
        let mut table = Vec::with_capacity(buckets + 1);
        let mut following = firsts.iter().skip(1).peekable();
        let mut chunk = 0u32;
        for bucket in 0..buckets as u64 {
            let start = u64::from(base) + (bucket << shift);
            while following
                .next_if(|first| u64::from(**first) <= start)
                .is_some()
            {
                chunk += 1;
            }
            table.push(chunk);
        }
        table.push(firsts.len() as u32 - 1);

        IdIndex {
            sealed,
            tail: tail.into(),
            firsts,
            table: table.into(),
            base,
            shift,
            chunks_weight,
        }
    }

    #[inline(always)]
    fn position(&self, document_id: u32) -> Option<u32> {
        let offset = document_id.checked_sub(self.base)?;
        let bucket = ((offset >> self.shift) as usize).min(self.table.len().checked_sub(2)?);
        let &[from, to] = self.table.get(bucket..bucket + 2)? else {
            return None;
        };
        let from = from as usize;
        let chunk = from
            + self
                .firsts
                .get(from + 1..=to as usize)?
                .partition_point(|first| *first <= document_id);
        self.chunk(chunk)?.position(document_id)
    }

    #[inline(always)]
    fn chunk(&self, at: usize) -> Option<&IndexChunk> {
        match at.checked_sub(self.sealed.len()) {
            None => self.sealed.get(at),
            Some(at) => self.tail.get(at),
        }
    }

    fn chunks(&self) -> impl DoubleEndedIterator<Item = &IndexChunk> + Clone + '_ {
        self.sealed.iter().chain(self.tail.iter())
    }

    pub(crate) fn chunk_parts(&self) -> impl Iterator<Item = (&[u32], u32)> + '_ {
        self.chunks().map(|chunk| (&chunk.data[..], chunk.len))
    }

    #[cfg(all(test, stalwart_tests))]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.chunks()
            .flat_map(IndexChunk::pairs)
            .map(|[document_id, position]| (*document_id, *position))
    }

    fn document_ids(&self) -> DocumentIds<'_> {
        DocumentIds {
            current: [].iter(),
            rest: self.sealed.iter().chain(self.tail.iter()),
        }
    }

    fn len(&self) -> usize {
        self.chunks().map(|chunk| chunk.len as usize).sum()
    }

    fn weight(&self) -> u64 {
        self.chunks_weight
            + ((self.table.len() + self.firsts.len()) * std::mem::size_of::<u32>()) as u64
    }

    fn last_id(&self) -> Option<u32> {
        self.tail
            .last()
            .and_then(|chunk| chunk.pairs().last())
            .map(|[document_id, _]| *document_id)
    }

    fn append(&self, entries: &[(u32, u32)]) -> Self {
        if entries.is_empty() {
            return self.clone();
        }
        let Some((last, settled)) = self.tail.split_last() else {
            return Self::from_sorted(entries);
        };

        if last.len as usize + entries.len() <= INDEX_CHUNK {
            let mut pairs = Vec::with_capacity(last.len as usize + entries.len());
            pairs.extend_from_slice(last.pairs());
            pairs.extend(
                entries
                    .iter()
                    .map(|(document_id, position)| [*document_id, *position]),
            );
            if let Some(chunk) = IndexChunk::build(&pairs, &mut Vec::new()) {
                return IdIndex {
                    sealed: self.sealed.clone(),
                    chunks_weight: self.chunks_weight - last.weight() + chunk.weight(),
                    tail: settled.iter().cloned().chain([chunk]).collect(),
                    firsts: self.firsts.clone(),
                    table: self.table.clone(),
                    base: self.base,
                    shift: self.shift,
                };
            }
        }

        let mut writer = IndexWriter::with_capacity(
            entries.len() / INDEX_CHUNK + 2,
            (last.len as usize % INDEX_CHUNK + entries.len()).min(INDEX_CHUNK),
        );
        if (last.len as usize) < INDEX_CHUNK {
            writer.extend(last.pairs(), None);
        } else {
            writer.share(last, None);
        }
        for (document_id, position) in entries {
            writer.push(*document_id, *position);
        }
        let fresh = writer.into_chunks();
        if settled.len() + fresh.len() <= INDEX_TAIL {
            Self::assemble(
                self.sealed.clone(),
                settled.iter().cloned().chain(fresh).collect(),
            )
        } else {
            Self::from_chunks(
                self.sealed
                    .iter()
                    .chain(settled)
                    .cloned()
                    .chain(fresh)
                    .collect(),
            )
        }
    }

    fn rebuild(
        &self,
        shift: &PositionShift,
        inserted: &[(u32, u32)],
        deleted: &[u32],
        len: usize,
    ) -> Self {
        let mut writer = IndexWriter::with_capacity(
            self.firsts.len() + inserted.len() / INDEX_CHUNK + 1,
            len.min(INDEX_CHUNK),
        );
        let mut added = inserted.iter().peekable();
        let mut removed = deleted.iter().peekable();
        let uppers = self
            .firsts
            .iter()
            .skip(1)
            .map(|first| Some(*first))
            .chain([None]);

        for (chunk, upper) in self.chunks().zip(uppers) {
            let below = |document_id: u32| upper.is_none_or(|upper| document_id < upper);
            let shifted = (chunk.max_position >= shift.first_key).then_some(shift);
            if !added.peek().is_some_and(|(id, _)| below(*id))
                && !removed.peek().is_some_and(|id| below(**id))
            {
                writer.share(chunk, shifted);
                continue;
            }

            let mut pairs = chunk.pairs();
            loop {
                let next_added = added.peek().map(|(id, _)| *id).filter(|id| below(*id));
                let next_removed = removed.peek().map(|id| **id).filter(|id| below(*id));
                let Some(event) = next_added.into_iter().chain(next_removed).min() else {
                    break;
                };
                let (run, rest) = pairs.split_at(pairs.partition_point(|[id, _]| *id < event));
                writer.extend(run, shifted);
                pairs = rest;

                if let Some((id, at)) = added.next_if(|(id, _)| *id == event) {
                    writer.push(*id, *at);
                } else if removed.next().is_some()
                    && let Some(([id, _], rest)) = pairs.split_first()
                    && *id == event
                {
                    pairs = rest;
                }
            }
            writer.extend(pairs, shifted);
        }

        for (id, at) in added {
            writer.push(*id, *at);
        }
        writer.finish()
    }
}

struct DocumentIds<'x> {
    current: Iter<'x, [u32; 2]>,
    rest: Chain<Iter<'x, IndexChunk>, Iter<'x, IndexChunk>>,
}

impl Iterator for DocumentIds<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        loop {
            if let Some([document_id, _]) = self.current.next() {
                return Some(*document_id);
            }
            self.current = self.rest.next()?.pairs().iter();
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.current.len()
            + self
                .rest
                .clone()
                .map(|chunk| chunk.len as usize)
                .sum::<usize>();
        (len, Some(len))
    }

    fn fold<B, F>(self, init: B, mut fold: F) -> B
    where
        F: FnMut(B, u32) -> B,
    {
        let init = self
            .current
            .fold(init, |acc, [document_id, _]| fold(acc, *document_id));
        self.rest.fold(init, |acc, chunk| {
            chunk
                .pairs()
                .iter()
                .fold(acc, |acc, [document_id, _]| fold(acc, *document_id))
        })
    }
}

impl ExactSizeIterator for DocumentIds<'_> {}

impl FusedIterator for DocumentIds<'_> {}

struct IndexWriter {
    chunks: Vec<IndexChunk>,
    pending: Vec<[u32; 2]>,
    directory: Vec<u16>,
}

impl IndexWriter {
    fn with_capacity(chunks: usize, pending: usize) -> Self {
        IndexWriter {
            chunks: Vec::with_capacity(chunks),
            pending: Vec::with_capacity(pending),
            directory: Vec::new(),
        }
    }

    #[inline(always)]
    fn push(&mut self, document_id: u32, position: u32) {
        self.pending.push([document_id, position]);
        if self.pending.len() == INDEX_CHUNK {
            self.flush();
        }
    }

    fn extend(&mut self, mut pairs: &[[u32; 2]], shift: Option<&PositionShift>) {
        let mut cursor = shift.map(ShiftCursor::new);
        while !pairs.is_empty() {
            let (head, rest) = pairs.split_at(pairs.len().min(INDEX_CHUNK - self.pending.len()));
            match &mut cursor {
                Some(cursor) => self.pending.extend(
                    head.iter()
                        .map(|[id, position]| [*id, cursor.apply(*position)]),
                ),
                None => self.pending.extend_from_slice(head),
            }
            if self.pending.len() == INDEX_CHUNK {
                self.flush();
            }
            pairs = rest;
        }
    }

    fn share(&mut self, chunk: &IndexChunk, shift: Option<&PositionShift>) {
        if !self.pending.is_empty() && self.pending.len() + chunk.len as usize <= INDEX_CHUNK {
            self.extend(chunk.pairs(), shift);
        } else {
            self.flush();
            self.chunks.push(match shift {
                Some(shift) => chunk.shifted(shift),
                None => chunk.clone(),
            });
        }
    }

    fn flush(&mut self) {
        if let Some(chunk) = IndexChunk::build(&self.pending, &mut self.directory) {
            self.chunks.push(chunk);
            self.pending.clear();
        }
    }

    fn into_chunks(mut self) -> Vec<IndexChunk> {
        self.flush();
        self.chunks
    }

    fn finish(self) -> IdIndex {
        IdIndex::from_chunks(self.into_chunks())
    }
}

struct BlockList {
    blocks: Vec<Arc<ColBlock>>,
    starts: Vec<u32>,
    len: u32,
    removed: u64,
    added: u64,
}

impl BlockList {
    fn with_capacity(blocks: usize) -> Self {
        BlockList {
            blocks: Vec::with_capacity(blocks),
            starts: Vec::with_capacity(blocks),
            len: 0,
            removed: 0,
            added: 0,
        }
    }

    fn of(cache: &MessagesCache) -> Self {
        BlockList {
            blocks: cache.blocks.clone(),
            starts: cache.starts.clone(),
            len: cache.len as u32,
            removed: 0,
            added: 0,
        }
    }

    #[inline(always)]
    fn share(&mut self, block: &Arc<ColBlock>, rows: u32) {
        self.starts.push(self.len);
        self.len += rows;
        self.blocks.push(block.clone());
    }

    fn push(&mut self, block: ColBlock) {
        self.added += block.weight();
        self.starts.push(self.len);
        self.len += block.len() as u32;
        self.blocks.push(Arc::new(block));
    }

    fn retire(&mut self, block: &ColBlock) {
        self.removed += block.weight();
    }

    fn patch(&mut self, slots: &[(u32, u32, &MessageCache)]) {
        let Some(block) = slots
            .first()
            .and_then(|(block, _, _)| self.blocks.get_mut(*block as usize))
        else {
            return;
        };
        self.removed += block.weight();
        Arc::make_mut(block).patch_slots(slots);
        self.added += block.weight();
    }
}

struct SpliceCursor<'x, 'r> {
    deletes: Peekable<Iter<'x, (u32, u32)>>,
    edits: Peekable<Iter<'x, (u32, u32, &'r MessageCache)>>,
    inserts: Peekable<Iter<'x, (u32, u32, &'r MessageCache)>>,
    inserted: Vec<(u32, u32)>,
}

impl SpliceCursor<'_, '_> {
    #[inline(always)]
    fn next_slot(&mut self, block: u32) -> Option<u32> {
        [
            self.deletes
                .peek()
                .and_then(|(at, slot)| (*at == block).then_some(*slot)),
            self.edits
                .peek()
                .and_then(|(at, slot, _)| (*at == block).then_some(*slot)),
            self.inserts
                .peek()
                .and_then(|(at, slot, _)| (*at == block).then_some(*slot)),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn splice_into(&mut self, builder: &mut ColBuilder, old: &ColBlock, block: u32, start: u32) {
        let mut run = 0usize;
        while let Some(slot) = self.next_slot(block) {
            let at = slot as usize;
            builder.copy_run(old, run, at);
            run = run.max(at);

            while let Some((_, _, record)) = self
                .inserts
                .next_if(|(target, inserted_at, _)| *target == block && *inserted_at == slot)
            {
                self.inserted
                    .push((record.document_id, start + builder.len() as u32));
                builder.push_record(record);
            }

            let deleted = self
                .deletes
                .next_if(|(target, deleted_at)| *target == block && *deleted_at == slot)
                .is_some();
            let edit = self
                .edits
                .next_if(|(target, edited_at, _)| *target == block && *edited_at == slot);
            if run == at {
                if deleted {
                    run = at + 1;
                } else if let Some((_, _, record)) = edit {
                    builder.push_record(record);
                    run = at + 1;
                }
            }
        }
        builder.copy_run(old, run, old.len());
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ThreadRange {
    min: u32,
    max: u32,
}

impl ThreadRange {
    pub(crate) fn of(thread_ids: &[u32]) -> Self {
        thread_ids.iter().fold(
            ThreadRange {
                min: u32::MAX,
                max: 0,
            },
            |range, thread_id| ThreadRange {
                min: range.min.min(*thread_id),
                max: range.max.max(*thread_id),
            },
        )
    }

    #[inline(always)]
    fn widen(&mut self, thread_id: u32) {
        self.min = self.min.min(thread_id);
        self.max = self.max.max(thread_id);
    }
}

struct ThreadSet {
    base: u32,
    span: u32,
    words: Box<[u64]>,
    remaining: u64,
}

impl ThreadSet {
    fn new(base: u32, threads: impl DoubleEndedIterator<Item = u32> + Clone) -> Self {
        let words = threads
            .clone()
            .next_back()
            .map_or(0, |last| (last - base) as usize / 64)
            + 1;
        let mut set = ThreadSet {
            base,
            span: (words * 64).try_into().unwrap_or(u32::MAX),
            words: vec![0u64; words].into_boxed_slice(),
            remaining: 0,
        };
        for thread_id in threads {
            set.insert(thread_id);
        }
        set
    }

    #[inline(always)]
    fn insert(&mut self, thread_id: u32) {
        let offset = thread_id.wrapping_sub(self.base);
        if offset < self.span {
            let word = &mut self.words[(offset / 64) as usize];
            let bit = 1u64 << (offset % 64);
            if *word & bit == 0 {
                *word |= bit;
                self.remaining += 1;
            }
        }
    }

    #[inline(always)]
    fn overlaps(&self, range: ThreadRange) -> bool {
        range.max >= self.base && u64::from(range.min) < u64::from(self.base) + u64::from(self.span)
    }

    #[inline(always)]
    fn contains(&self, thread_id: u32) -> bool {
        let offset = thread_id.wrapping_sub(self.base);
        offset < self.span && self.words[(offset / 64) as usize] & (1u64 << (offset % 64)) != 0
    }

    #[inline(always)]
    fn remove(&mut self, thread_id: u32) {
        let offset = thread_id.wrapping_sub(self.base);
        if offset < self.span {
            let word = &mut self.words[(offset / 64) as usize];
            let bit = 1u64 << (offset % 64);
            if *word & bit != 0 {
                *word &= !bit;
                self.remaining -= 1;
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        let base = self.base;
        self.words
            .iter()
            .enumerate()
            .flat_map(move |(index, word)| {
                let mut word = *word;
                let offset = base + (index * 64) as u32;
                std::iter::from_fn(move || {
                    (word != 0).then(|| {
                        let bit = word.trailing_zeros();
                        word &= word - 1;
                        offset + bit
                    })
                })
            })
    }
}

impl MessagesCache {
    pub fn new(change_id: u64, items: Vec<MessageCache>, keywords: Vec<CustomKeywords>) -> Self {
        debug_assert!(
            items.is_sorted_by_key(|item| item.sort_rank()),
            "items must be ordered by (received_at, document_id)"
        );
        debug_assert!(
            keywords.is_sorted_by_key(|entry| entry.document_id),
            "custom keywords must be ordered by document_id"
        );

        Self::from_records(change_id, &items, keywords.into())
    }

    fn from_records(
        change_id: u64,
        items: &[MessageCache],
        keywords: Arc<[CustomKeywords]>,
    ) -> Self {
        let blocks = items
            .chunks(CACHE_CHUNK)
            .map(|chunk| Arc::new(ColBlock::from_records(chunk)))
            .collect::<Vec<_>>();
        let (starts, len) = Self::starts_of(&blocks);

        Self::assemble(change_id, blocks, starts, len, keywords)
    }

    fn starts_of(blocks: &[Arc<ColBlock>]) -> (Vec<u32>, usize) {
        let mut starts = Vec::with_capacity(blocks.len());
        let mut start = 0u32;
        for block in blocks {
            starts.push(start);
            start += block.len() as u32;
        }
        (starts, start as usize)
    }

    fn assemble(
        change_id: u64,
        blocks: Vec<Arc<ColBlock>>,
        starts: Vec<u32>,
        len: usize,
        keywords: Arc<[CustomKeywords]>,
    ) -> Self {
        let mut index = Vec::with_capacity(len);
        for (block, start) in blocks.iter().zip(starts.iter()) {
            index.extend(
                block
                    .document_ids
                    .iter()
                    .zip(*start..)
                    .map(|(document_id, position)| (*document_id, position)),
            );
        }
        index.sort_unstable_by_key(|(document_id, _)| *document_id);

        Self::from_parts(
            change_id,
            blocks,
            starts,
            IdIndex::from_sorted(&index),
            keywords,
            len,
        )
    }

    pub(crate) fn from_parts(
        change_id: u64,
        blocks: Vec<Arc<ColBlock>>,
        starts: Vec<u32>,
        index: IdIndex,
        keywords: Arc<[CustomKeywords]>,
        len: usize,
    ) -> Self {
        let size = keywords_weight(&keywords)
            + blocks.iter().map(|block| block.weight()).sum::<u64>()
            + index.weight();

        MessagesCache {
            change_id,
            blocks,
            starts,
            index,
            keywords,
            len,
            size,
        }
    }

    fn successor(
        &self,
        change_id: u64,
        list: BlockList,
        index: IdIndex,
        keywords: Arc<[CustomKeywords]>,
    ) -> Self {
        let (retired_keywords, kept_keywords) = if Arc::ptr_eq(&keywords, &self.keywords) {
            (0, 0)
        } else {
            (keywords_weight(&self.keywords), keywords_weight(&keywords))
        };
        let size = self.size - list.removed - self.index.weight() - retired_keywords
            + list.added
            + index.weight()
            + kept_keywords;

        MessagesCache {
            change_id,
            blocks: list.blocks,
            starts: list.starts,
            index,
            keywords,
            len: list.len as usize,
            size,
        }
    }

    fn block_rows(&self) -> impl Iterator<Item = u32> + '_ {
        self.starts
            .iter()
            .copied()
            .zip(self.starts.iter().copied().skip(1).chain([self.len as u32]))
            .map(|(start, end)| end - start)
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn keywords(&self) -> &[CustomKeywords] {
        &self.keywords
    }

    #[inline(always)]
    pub fn shared_keywords(&self) -> Arc<[CustomKeywords]> {
        self.keywords.clone()
    }

    #[inline(always)]
    fn locate(&self, position: u32) -> Option<(u32, u32)> {
        if (position as usize) >= self.len {
            return None;
        }
        let block = match self.starts.binary_search(&position) {
            Ok(block) => block,
            Err(next) => next - 1,
        };
        Some((block as u32, position - self.starts[block]))
    }

    #[inline(always)]
    pub fn position(&self, document_id: u32) -> Option<u32> {
        self.index.position(document_id)
    }

    #[inline(always)]
    pub fn contains(&self, document_id: u32) -> bool {
        self.index.position(document_id).is_some()
    }

    #[inline(always)]
    pub fn document_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.index.document_ids()
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = MessageRef<'_>> + '_ {
        self.blocks
            .iter()
            .zip(self.starts.iter().copied())
            .flat_map(|(block, start)| {
                let block: &ColBlock = block;
                (0..block.len() as u32).map(move |slot| MessageRef {
                    block,
                    position: start + slot,
                    slot,
                })
            })
    }

    #[inline(always)]
    pub fn at(&self, position: u32) -> Option<MessageRef<'_>> {
        let (block, slot) = self.locate(position)?;
        Some(MessageRef {
            block: self.blocks.get(block as usize)?,
            position,
            slot,
        })
    }

    #[inline(always)]
    pub fn by_id(&self, document_id: u32) -> Option<MessageRef<'_>> {
        self.position(document_id).and_then(|p| self.at(p))
    }

    pub fn emptied_threads(
        &self,
        thread_ids: &RoaringBitmap,
        deleted_ids: &RoaringBitmap,
    ) -> Vec<u32> {
        let mut emptied = Vec::new();
        let mut next = thread_ids.min();
        while let Some(base) = next {
            let window = base..=base.saturating_add(THREAD_WINDOW - 1);
            let mut pending = ThreadSet::new(base, thread_ids.range(window.clone()));
            self.remove_surviving_threads(&mut pending, deleted_ids);
            emptied.extend(pending.iter());
            next = window
                .end()
                .checked_add(1)
                .and_then(|from| thread_ids.range(from..).next());
        }
        emptied
    }

    fn remove_surviving_threads(&self, pending: &mut ThreadSet, deleted_ids: &RoaringBitmap) {
        for block in &self.blocks {
            if !pending.overlaps(block.thread_range) {
                continue;
            }
            for (thread_id, document_id) in block.thread_ids.iter().zip(block.document_ids.iter()) {
                if pending.contains(*thread_id) && !deleted_ids.contains(*document_id) {
                    pending.remove(*thread_id);
                    if pending.remaining == 0 {
                        return;
                    }
                }
            }
        }
    }

    pub fn patch(
        &self,
        change_id: u64,
        updates: &[(u32, MessageCache)],
        keywords: Arc<[CustomKeywords]>,
    ) -> Self {
        let mut touched = updates
            .iter()
            .filter_map(|(position, record)| {
                let (block, slot) = self.locate(*position)?;
                debug_assert_eq!(
                    self.blocks[block as usize].document_ids[slot as usize], record.document_id,
                    "a patch must not move a message to a different position"
                );
                Some((block, slot, record))
            })
            .collect::<Vec<_>>();
        touched.sort_unstable_by_key(|(block, slot, _)| (*block, *slot));

        let mut list = BlockList::of(self);
        for slots in touched.chunk_by(|(left, _, _), (right, _, _)| left == right) {
            list.patch(slots);
        }

        self.successor(change_id, list, self.index.clone(), keywords)
    }

    fn locate_insert(&self, rank: (u64, u32)) -> (u32, u32) {
        let block = self
            .blocks
            .partition_point(|block| block.rank(block.len() - 1) < rank);
        match self.blocks.get(block) {
            Some(col) => {
                let (mut low, mut high) = (0usize, col.len());
                while low < high {
                    let mid = low + (high - low) / 2;
                    if col.rank(mid) < rank {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }
                (block as u32, low as u32)
            }
            None => {
                let last = self.blocks.len() - 1;
                (last as u32, self.blocks[last].len() as u32)
            }
        }
    }

    pub fn splice(
        &self,
        change_id: u64,
        deletes: &[u32],
        updates: &[(u32, MessageCache)],
        inserts: &[MessageCache],
        keywords: Arc<[CustomKeywords]>,
    ) -> Self {
        debug_assert!(
            inserts.is_sorted_by_key(|item| item.sort_rank()),
            "inserts must be ordered by (received_at, document_id)"
        );
        debug_assert!(
            deletes.is_sorted(),
            "deletes must be ordered by document id"
        );

        if self.blocks.is_empty() {
            return Self::from_records(change_id, inserts, keywords);
        }

        let mut deletions = deletes
            .iter()
            .filter_map(|document_id| {
                self.position(*document_id)
                    .and_then(|position| self.locate(position))
            })
            .collect::<Vec<_>>();
        deletions.sort_unstable();

        let mut edits = updates
            .iter()
            .filter_map(|(position, record)| {
                let (block, slot) = self.locate(*position)?;
                debug_assert_eq!(
                    self.blocks[block as usize].rank(slot as usize),
                    (record.received_at_secs() as u64, record.document_id),
                    "an update must not move a message to a different position"
                );
                Some((block, slot, record))
            })
            .collect::<Vec<_>>();
        edits.sort_unstable_by_key(|(block, slot, _)| (*block, *slot));

        if deletions.is_empty() && self.appends_at_end(inserts) {
            return self.append(change_id, &edits, inserts, keywords);
        }

        let insertions = inserts
            .iter()
            .map(|record| {
                let (block, slot) =
                    self.locate_insert((record.received_at_secs() as u64, record.document_id));
                (block, slot, record)
            })
            .collect::<Vec<_>>();

        let extra_arena = inserts
            .iter()
            .map(|record| record.mailboxes.len())
            .sum::<usize>();
        let mut list = BlockList::with_capacity(self.blocks.len() + 1);
        let mut cursor = SpliceCursor {
            deletes: deletions.iter().peekable(),
            edits: edits.iter().peekable(),
            inserts: insertions.iter().peekable(),
            inserted: Vec::with_capacity(inserts.len()),
        };

        for ((block_idx, old), rows) in (0u32..).zip(self.blocks.iter()).zip(self.block_rows()) {
            if cursor.next_slot(block_idx).is_none() {
                list.share(old, rows);
                continue;
            }

            list.retire(old);
            let mut builder = ColBuilder::with_capacity(
                old.len() + inserts.len(),
                old.mb_arena.len() + extra_arena,
            );
            cursor.splice_into(&mut builder, old, block_idx, list.len);
            builder.finish_into(&mut list);
        }

        let len = list.len as usize;

        let shift = PositionShift::build(
            insertions
                .iter()
                .map(|(block, slot, _)| self.starts[*block as usize] + slot),
            deletions
                .iter()
                .map(|(block, slot)| self.starts[*block as usize] + slot),
            self.len,
        );
        let mut inserted = cursor.inserted;
        inserted.sort_unstable_by_key(|(document_id, _)| *document_id);

        let index = self.index.rebuild(&shift, &inserted, deletes, len);
        debug_assert_eq!(index.len(), len, "the index must cover every message");

        self.successor(change_id, list, index, keywords)
    }

    fn appends_at_end(&self, inserts: &[MessageCache]) -> bool {
        let Some(first) = inserts.first() else {
            return true;
        };
        let (Some(last_id), Some(last)) = (self.index.last_id(), self.blocks.last()) else {
            return false;
        };
        last.rank(last.len() - 1) < (first.received_at_secs() as u64, first.document_id)
            && inserts.iter().all(|record| record.document_id > last_id)
    }

    fn append_from(&self, inserts: usize) -> usize {
        if inserts == 0 {
            return self.blocks.len();
        }
        let (tail_blocks, tail_rows) = self
            .blocks
            .iter()
            .rev()
            .take_while(|block| block.len() < CACHE_CHUNK)
            .fold((0usize, 0usize), |(count, rows), block| {
                (count + 1, rows + block.len())
            });
        if tail_blocks > 1 && tail_rows + inserts >= CACHE_CHUNK {
            self.blocks.len() - tail_blocks
        } else if self
            .blocks
            .last()
            .is_some_and(|block| block.len() < APPEND_BLOCK)
        {
            self.blocks.len() - 1
        } else {
            self.blocks.len()
        }
    }

    fn append(
        &self,
        change_id: u64,
        edits: &[(u32, u32, &MessageCache)],
        inserts: &[MessageCache],
        keywords: Arc<[CustomKeywords]>,
    ) -> Self {
        let merge_from = self.append_from(inserts.len());
        let mut cursor = SpliceCursor {
            deletes: [].iter().peekable(),
            edits: edits.iter().peekable(),
            inserts: [].iter().peekable(),
            inserted: Vec::new(),
        };
        let mut list =
            BlockList::with_capacity(self.blocks.len() + 1 + inserts.len() / CACHE_CHUNK);

        for ((block_idx, old), rows) in (0u32..)
            .zip(self.blocks.iter().take(merge_from))
            .zip(self.block_rows())
        {
            if cursor.next_slot(block_idx).is_none() {
                list.share(old, rows);
                continue;
            }
            list.retire(old);
            let mut builder = ColBuilder::with_capacity(old.len(), old.mb_arena.len());
            cursor.splice_into(&mut builder, old, block_idx, 0);
            builder.finish_into(&mut list);
        }

        if !inserts.is_empty() {
            let tail = self.blocks.iter().skip(merge_from);
            let mut builder = ColBuilder::with_capacity(
                tail.clone().map(|block| block.len()).sum::<usize>() + inserts.len(),
                tail.clone()
                    .map(|block| block.mb_arena.len())
                    .chain(inserts.iter().map(|record| record.mailboxes.len()))
                    .sum::<usize>(),
            );
            for (block_idx, old) in (merge_from as u32..).zip(tail) {
                list.retire(old);
                cursor.splice_into(&mut builder, old, block_idx, 0);
            }
            for record in inserts {
                builder.push_record(record);
            }
            builder.finish_into(&mut list);
        }

        let mut entries = inserts
            .iter()
            .zip(self.len as u32..)
            .map(|(record, position)| (record.document_id, position))
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|(document_id, _)| *document_id);

        let index = self.index.append(&entries);
        self.successor(change_id, list, index, keywords)
    }

    #[inline(always)]
    pub fn custom_keywords_of(&self, document_id: u32) -> &[CompactString] {
        self.keywords
            .binary_search_by_key(&document_id, |entry| entry.document_id)
            .map_or(&[][..], |idx| &self.keywords[idx].names)
    }
}

fn keywords_weight(keywords: &[CustomKeywords]) -> u64 {
    keywords
        .iter()
        .map(|entry| {
            std::mem::size_of::<CustomKeywords>()
                + (entry.names.len() * std::mem::size_of::<String>())
        })
        .sum::<usize>() as u64
}

#[derive(Clone, Copy)]
pub struct MessageRef<'x> {
    block: &'x ColBlock,
    position: u32,
    slot: u32,
}

impl<'x> MessageRef<'x> {
    #[inline(always)]
    fn col(&self) -> &'x ColBlock {
        self.block
    }

    #[inline(always)]
    pub fn position(&self) -> u32 {
        self.position
    }

    #[inline(always)]
    pub fn document_id(&self) -> u32 {
        self.col().document_ids[self.slot as usize]
    }

    #[inline(always)]
    pub fn mailboxes(&self) -> &'x [MessageUid] {
        self.col().mailboxes(self.slot)
    }

    #[inline(always)]
    pub fn keywords(&self) -> u32 {
        self.col().keywords[self.slot as usize]
    }

    #[inline(always)]
    pub fn thread_id(&self) -> u32 {
        self.col().thread_ids[self.slot as usize]
    }

    #[inline(always)]
    pub fn change_id(&self) -> u64 {
        self.col().change_ids[self.slot as usize]
    }

    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.col().sizes[self.slot as usize]
    }

    #[inline(always)]
    pub fn received_at(&self) -> u64 {
        self.col().received_at[self.slot as usize] as u64
    }

    #[inline(always)]
    pub fn sent_at(&self) -> i32 {
        self.col().sent_at[self.slot as usize]
    }

    #[inline(always)]
    pub fn sent_at_absolute(&self) -> i64 {
        self.received_at() as i64 + self.sent_at() as i64
    }

    #[inline(always)]
    pub fn sort_rank(&self) -> (u64, u32) {
        (self.received_at(), self.document_id())
    }

    #[inline(always)]
    pub fn has_mailbox_id(&self, mailbox_id: u32) -> bool {
        self.mailboxes()
            .iter()
            .any(|uid| uid.mailbox_id == mailbox_id)
    }

    #[inline(always)]
    pub fn uid_in(&self, mailbox_id: u32) -> Option<u32> {
        self.mailboxes()
            .iter()
            .find(|uid| uid.mailbox_id == mailbox_id)
            .map(|uid| uid.uid)
    }

    pub fn to_record(&self) -> MessageCache {
        MessageCache::new(
            self.document_id(),
            self.mailboxes().iter().copied().collect(),
            self.keywords(),
            self.thread_id(),
            self.change_id(),
            self.size(),
            self.received_at(),
            self.sent_at(),
        )
    }
}

