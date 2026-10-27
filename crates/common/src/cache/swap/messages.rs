/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SwapPart, frame::SwapFrame};
use crate::{
    CACHE_CHUNK, ColBlock, CustomKeywords, MessageUid, MessagesCache,
    cache::email::{IdIndex, ThreadRange},
};
use compact_str::CompactString;
use rkyv::{
    boxed::ArchivedBox,
    rend::unaligned::{i32_ule, u32_ule, u64_ule},
    with::InlineAsBox,
};
use std::{mem::size_of, sync::Arc};

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedBlock<'x> {
    #[rkyv(with = InlineAsBox)]
    pub document_ids: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub change_ids: &'x [u64],
    #[rkyv(with = InlineAsBox)]
    pub received_at: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub sent_at: &'x [i32],
    #[rkyv(with = InlineAsBox)]
    pub sizes: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub keywords: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub thread_ids: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub mb_offsets: &'x [u32],
    #[rkyv(with = InlineAsBox)]
    pub mb_arena: &'x [u64],
}

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedIndexChunk<'x> {
    #[rkyv(with = InlineAsBox)]
    pub data: &'x [u32],
    pub len: u32,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedMessages<'x> {
    pub change_id: u64,
    pub len: u32,
    #[rkyv(with = InlineAsBox)]
    pub starts: &'x [u32],
    pub blocks: Vec<ArchivedBlock<'x>>,
    pub index: Vec<ArchivedIndexChunk<'x>>,
    pub custom_ids: Vec<u32>,
    pub custom_offsets: Vec<u32>,
    #[rkyv(with = rkyv::with::Map<InlineAsBox>)]
    pub custom_names: Vec<&'x str>,
}

impl MessagesCache {
    pub fn to_snapshot(&self) -> Option<Vec<u8>> {
        let arena = self.mailbox_arena();
        Self::seal_snapshot(
            &self.pack(&arena),
            self.change_id,
            self.len as u32,
            self.snapshot_len(),
        )
    }

    fn snapshot_len(&self) -> usize {
        let blocks = self
            .blocks
            .iter()
            .map(|block| {
                size_of::<ArchivedArchivedBlock>()
                    + block.document_ids.len() * (size_of::<u32_ule>() * 6 + size_of::<u64_ule>())
                    + block.mb_offsets.len() * size_of::<u32_ule>()
                    + block.mb_arena.len() * size_of::<u64_ule>()
            })
            .sum::<usize>();
        let custom = self
            .keywords
            .iter()
            .map(|entry| {
                size_of::<u32_ule>() * 2
                    + entry
                        .names
                        .iter()
                        .map(|name| size_of::<ArchivedBox<str>>() + name.len())
                        .sum::<usize>()
            })
            .sum::<usize>();

        size_of::<ArchivedArchivedMessages>()
            + blocks
            + self.starts.len() * size_of::<u32_ule>()
            + self
                .index
                .chunk_parts()
                .map(|(data, _)| {
                    size_of::<ArchivedArchivedIndexChunk>() + data.len() * size_of::<u32_ule>()
                })
                .sum::<usize>()
            + size_of::<u32_ule>()
            + custom
    }

    fn mailbox_arena(&self) -> Vec<u64> {
        let mut arena =
            Vec::with_capacity(self.blocks.iter().map(|block| block.mb_arena.len()).sum());
        for block in &self.blocks {
            arena.extend(block.mb_arena.iter().map(MessageUid::pack));
        }
        arena
    }

    fn pack<'x>(&'x self, arena: &'x [u64]) -> ArchivedMessages<'x> {
        let mut blocks = Vec::with_capacity(self.blocks.len());
        let mut rest = arena;
        for block in &self.blocks {
            let (mb_arena, tail) = rest
                .split_at_checked(block.mb_arena.len())
                .unwrap_or((rest, &[]));
            rest = tail;
            blocks.push(ArchivedBlock {
                document_ids: &block.document_ids,
                change_ids: &block.change_ids,
                received_at: &block.received_at,
                sent_at: &block.sent_at,
                sizes: &block.sizes,
                keywords: &block.keywords,
                thread_ids: &block.thread_ids,
                mb_offsets: &block.mb_offsets,
                mb_arena,
            });
        }

        let index = self
            .index
            .chunk_parts()
            .map(|(data, len)| ArchivedIndexChunk { data, len })
            .collect();

        let mut custom_ids = Vec::with_capacity(self.keywords.len());
        let mut custom_offsets = Vec::with_capacity(self.keywords.len() + 1);
        let mut custom_names = Vec::new();
        custom_offsets.push(0u32);
        for entry in self.keywords.iter() {
            custom_ids.push(entry.document_id);
            for name in entry.names.iter() {
                custom_names.push(name.as_str());
            }
            custom_offsets.push(custom_names.len() as u32);
        }

        ArchivedMessages {
            change_id: self.change_id,
            len: self.len as u32,
            starts: &self.starts,
            blocks,
            index,
            custom_ids,
            custom_offsets,
            custom_names,
        }
    }

    fn seal_snapshot(
        archived: &ArchivedMessages<'_>,
        change_id: u64,
        count: u32,
        payload_len: usize,
    ) -> Option<Vec<u8>> {
        let mut out = SwapFrame::reserve_header();
        out.reserve_exact(payload_len);
        let mut out = rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(archived, out).ok()?;

        SwapFrame::seal(&mut out, SwapPart::Messages, change_id, count).then_some(out)
    }

    pub fn from_snapshot(buf: &[u8]) -> Option<Self> {
        let frame = SwapFrame::parse(buf)?;
        if frame.part() != SwapPart::Messages {
            return None;
        }

        let archived =
            rkyv::access::<ArchivedArchivedMessages, rkyv::rancor::Error>(frame.payload()).ok()?;
        let len = archived.len.to_native() as usize;
        let starts = archived
            .starts
            .iter()
            .map(|start| start.to_native())
            .collect::<Vec<_>>();
        if starts.len() != archived.blocks.len() {
            return None;
        }

        let mut blocks = Vec::with_capacity(archived.blocks.len());
        let mut total = 0usize;
        for (block, start) in archived.blocks.iter().zip(&starts) {
            let count = block.document_ids.len();
            if count == 0 || count > CACHE_CHUNK * 2 {
                return None;
            }
            if block.change_ids.len() != count
                || block.received_at.len() != count
                || block.sent_at.len() != count
                || block.sizes.len() != count
                || block.keywords.len() != count
                || block.thread_ids.len() != count
                || block.mb_offsets.len() != count + 1
            {
                return None;
            }
            if block.mb_offsets[0].to_native() != 0
                || block.mb_offsets[count].to_native() as usize != block.mb_arena.len()
                || !block
                    .mb_offsets
                    .iter()
                    .map(|offset| offset.to_native())
                    .is_sorted()
            {
                return None;
            }
            if *start as usize != total {
                return None;
            }

            total += count;
            let thread_ids = copy_u32(&block.thread_ids);
            blocks.push(Arc::new(ColBlock {
                document_ids: copy_u32(&block.document_ids),
                change_ids: copy_u64(&block.change_ids),
                received_at: copy_u32(&block.received_at),
                sent_at: copy_i32(&block.sent_at),
                sizes: copy_u32(&block.sizes),
                keywords: copy_u32(&block.keywords),
                thread_range: ThreadRange::of(&thread_ids),
                thread_ids,
                mb_offsets: copy_u32(&block.mb_offsets),
                mb_arena: copy_uid(&block.mb_arena),
            }));
        }
        if total != len {
            return None;
        }

        let index = IdIndex::decode(
            archived
                .index
                .iter()
                .map(|chunk| (&*chunk.data, chunk.len.to_native() as usize)),
            |value| value.to_native(),
            len,
        )?;

        let custom_count = archived.custom_ids.len();
        if archived.custom_offsets.len() != custom_count + 1 {
            return None;
        }
        let mut keywords = Vec::with_capacity(custom_count);
        for (document_id, range) in archived
            .custom_ids
            .iter()
            .zip(archived.custom_offsets.windows(2))
        {
            let document_id = document_id.to_native();
            let from = range[0].to_native() as usize;
            let to = range[1].to_native() as usize;
            let names = archived.custom_names.get(from..to)?;
            keywords.push(CustomKeywords {
                names: names
                    .iter()
                    .map(|name| CompactString::from(&**name))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                document_id,
            });
        }

        Some(MessagesCache::from_parts(
            archived.change_id.to_native(),
            blocks,
            starts,
            index,
            keywords.into(),
            len,
        ))
    }
}

impl MessageUid {
    fn pack(&self) -> u64 {
        ((self.uid as u64) << 32) | self.mailbox_id as u64
    }

    fn unpack(packed: u64) -> Self {
        MessageUid {
            mailbox_id: packed as u32,
            uid: (packed >> 32) as u32,
        }
    }
}

fn copy_u32(src: &[u32_ule]) -> Arc<[u32]> {
    src.iter().map(|value| value.to_native()).collect()
}

fn copy_i32(src: &[i32_ule]) -> Arc<[i32]> {
    src.iter().map(|value| value.to_native()).collect()
}

fn copy_u64(src: &[u64_ule]) -> Arc<[u64]> {
    src.iter().map(|value| value.to_native()).collect()
}

fn copy_uid(src: &[u64_ule]) -> Arc<[MessageUid]> {
    src.iter()
        .map(|value| MessageUid::unpack(value.to_native()))
        .collect()
}


