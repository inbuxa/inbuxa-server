/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;
use xxhash_rust::xxh3::xxh3_64;

const MAGIC: u32 = 0x5357_5031;
const VERSION: u16 = 1;

pub const POINTER_LEN: usize = 48;
pub const MAX_CALL_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLayout {
    size: u32,
    count: u32,
}

pub struct ChunkAssembler {
    data: Vec<u8>,
    length: usize,
    chunk_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapPointer {
    write_id: u64,
    generation: u64,
    length: u64,
    chunks: Option<ChunkLayout>,
}

impl ChunkLayout {
    pub fn new(length: u64, size: u32) -> Option<Self> {
        if size == 0 {
            return None;
        }
        Some(ChunkLayout {
            size,
            count: u32::try_from(length.div_ceil(u64::from(size))).ok()?,
        })
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn chunks_per_batch(&self, max_bytes: usize) -> u32 {
        u32::try_from(max_bytes / self.size as usize)
            .unwrap_or(u32::MAX)
            .max(1)
    }

    pub fn batches(&self, max_bytes: usize) -> impl Iterator<Item = Range<u32>> + use<> {
        index_batches(self.count, self.chunks_per_batch(max_bytes))
    }

    pub fn split<'x>(
        &self,
        data: &'x [u8],
        max_bytes: usize,
    ) -> impl Iterator<Item = (Range<u32>, &'x [u8])> + use<'x> {
        let batch_len = self.size as usize * self.chunks_per_batch(max_bytes) as usize;
        self.batches(max_bytes).zip(data.chunks(batch_len))
    }
}

impl ChunkAssembler {
    pub fn new(layout: ChunkLayout, length: usize) -> Self {
        ChunkAssembler {
            data: Vec::with_capacity(length),
            length,
            chunk_size: layout.size as usize,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> bool {
        let expected = self.chunk_size.min(self.length - self.data.len());
        if expected > 0 && chunk.len() == expected {
            self.data.extend_from_slice(chunk);
            true
        } else {
            false
        }
    }

    pub fn finish(self) -> Option<Vec<u8>> {
        (self.data.len() == self.length).then_some(self.data)
    }
}

pub fn index_batches(count: u32, per_batch: u32) -> impl Iterator<Item = Range<u32>> {
    let per_batch = per_batch.max(1);
    (0..count)
        .step_by(per_batch as usize)
        .map(move |start| start..start.saturating_add(per_batch).min(count))
}

impl SwapPointer {
    pub fn new(write_id: u64, generation: u64, length: u64, chunks: Option<ChunkLayout>) -> Self {
        SwapPointer {
            write_id,
            generation,
            length,
            chunks,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn chunks(&self) -> Option<ChunkLayout> {
        self.chunks
    }

    pub fn encode(&self) -> Vec<u8> {
        let (chunk_size, chunk_count) = self
            .chunks
            .map_or((0, 0), |chunks| (chunks.size, chunks.count));
        let mut out = Vec::with_capacity(POINTER_LEN);
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.write_id.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.length.to_le_bytes());
        out.extend_from_slice(&chunk_size.to_le_bytes());
        out.extend_from_slice(&chunk_count.to_le_bytes());
        let seal = xxh3_64(&out);
        out.extend_from_slice(&seal.to_le_bytes());
        out
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() != POINTER_LEN {
            return None;
        }
        let (sealed, seal) = buf.split_last_chunk::<8>()?;
        if xxh3_64(sealed) != u64::from_le_bytes(*seal) {
            return None;
        }

        let (magic, rest) = sealed.split_first_chunk::<4>()?;
        let (version, rest) = rest.split_first_chunk::<2>()?;
        let (reserved, rest) = rest.split_first_chunk::<2>()?;
        let (write_id, rest) = rest.split_first_chunk::<8>()?;
        let (generation, rest) = rest.split_first_chunk::<8>()?;
        let (length, rest) = rest.split_first_chunk::<8>()?;
        let (chunk_size, rest) = rest.split_first_chunk::<4>()?;
        let (chunk_count, rest) = rest.split_first_chunk::<4>()?;

        if !rest.is_empty()
            || u32::from_le_bytes(*magic) != MAGIC
            || u16::from_le_bytes(*version) != VERSION
            || u16::from_le_bytes(*reserved) != 0
        {
            return None;
        }

        let length = u64::from_le_bytes(*length);
        let chunk_count = u32::from_le_bytes(*chunk_count);
        let chunks = match u32::from_le_bytes(*chunk_size) {
            0 if chunk_count == 0 => None,
            0 => return None,
            size => Some(ChunkLayout::new(length, size).filter(|c| c.count == chunk_count)?),
        };

        Some(SwapPointer {
            write_id: u64::from_le_bytes(*write_id),
            generation: u64::from_le_bytes(*generation),
            length,
            chunks,
        })
    }
}

