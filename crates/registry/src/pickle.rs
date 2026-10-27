/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::types::EnumImpl;
use std::{borrow::Cow, collections::HashMap};
use utils::map::vec_map::VecMap;

const COMPRESS_MARKER: u8 = 1 << 7;
const COMPRESS_WATERMARK: usize = 8192;
const COMPRESS_LEN_SIZE: usize = std::mem::size_of::<u32>();
const BLOCK_PLACEHOLDER_LEN: usize = 2;
const BLOCK_SHORT_LIMIT: usize = 1 << 14;
const SMALL_HEADER_LIMIT: u64 = 1 << 7;
pub const MAX_BITMAP_FLAGS: u64 = 64;

pub trait Pickle: Sized {
    fn pickle(&self, out: &mut Vec<u8>);
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self>;
}

pub struct PickledStream<'x> {
    data: Cow<'x, [u8]>,
    pos: usize,
    end: usize,
    version: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct Block {
    parent_end: usize,
    fields: u64,
    flags: u64,
    bitmap: u64,
}

impl Block {
    #[inline(always)]
    pub fn has(&self, field: u64) -> bool {
        field < self.fields
    }

    #[inline(always)]
    pub fn flag(&self, flag: u64) -> bool {
        flag < self.flags
            && u32::try_from(flag)
                .ok()
                .and_then(|shift| self.bitmap.checked_shr(shift))
                .is_some_and(|word| word & 1 != 0)
    }
}

pub(crate) fn maybe_compress_pickle(input: Vec<u8>) -> Vec<u8> {
    let Some((&version, body)) = input.split_first() else {
        return input;
    };
    let Ok(body_len) = u32::try_from(body.len()) else {
        return input;
    };
    if body.len() <= COMPRESS_WATERMARK {
        return input;
    }
    let mut bytes =
        vec![0u8; 1 + COMPRESS_LEN_SIZE + lz4_flex::block::get_maximum_output_size(body.len())];
    let Some((header, rest)) = bytes.split_first_mut() else {
        return input;
    };
    *header = version | COMPRESS_MARKER;
    let Some((len_slot, compressed)) = rest.split_first_chunk_mut::<COMPRESS_LEN_SIZE>() else {
        return input;
    };
    *len_slot = body_len.to_le_bytes();
    match lz4_flex::compress_into(body, compressed) {
        Ok(compressed_len) if compressed_len < body.len() => {
            bytes.truncate(1 + COMPRESS_LEN_SIZE + compressed_len);
            bytes
        }
        _ => input,
    }
}

impl<'x> PickledStream<'x> {
    pub fn new(data: &'x [u8]) -> Option<Self> {
        let (marker, data) = data.split_first()?;
        let version = marker & !COMPRESS_MARKER;
        let data = if marker & COMPRESS_MARKER != 0 {
            Cow::Owned(lz4_flex::block::decompress_size_prepended(data).ok()?)
        } else {
            Cow::Borrowed(data)
        };
        Some(PickledStream {
            end: data.len(),
            data,
            pos: 0,
            version,
        })
    }

    #[inline(always)]
    pub fn remaining_len(&self) -> usize {
        self.end.saturating_sub(self.pos)
    }

    #[inline(always)]
    fn remaining(&self) -> &[u8] {
        self.data.get(self.pos..self.end).unwrap_or_default()
    }

    #[inline(always)]
    pub fn read(&mut self) -> Option<u8> {
        let byte = *self.remaining().first()?;
        self.pos += 1;
        Some(byte)
    }

    #[inline(always)]
    pub fn read_bytes(&mut self, len: usize) -> Option<&[u8]> {
        let start = self.pos;
        let stop = start.checked_add(len).filter(|stop| *stop <= self.end)?;
        self.pos = stop;
        self.data.get(start..stop)
    }

    #[inline(always)]
    pub fn read_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let bytes = *self.remaining().first_chunk::<N>()?;
        self.pos += N;
        Some(bytes)
    }

    #[inline(always)]
    pub fn read_varint(&mut self) -> Option<u64> {
        let mut buf = self.remaining();
        let available = buf.len();
        let value = varint::read(&mut buf)?;
        self.pos += available - buf.len();
        Some(value)
    }

    #[inline(always)]
    pub fn read_bitmap(&mut self, flags: u64) -> Option<u64> {
        match usize::try_from(flags.div_ceil(8)).ok()? {
            0 => Some(0),
            1 => self.read().map(u64::from),
            len => {
                let bytes = self.read_bytes(len)?;
                let mut word = [0u8; 8];
                word.iter_mut()
                    .zip(bytes)
                    .for_each(|(dst, src)| *dst = *src);
                Some(u64::from_le_bytes(word))
            }
        }
    }

    #[inline(always)]
    pub fn open_block(&mut self) -> Option<Block> {
        let len = usize::try_from(self.read_varint()?).ok()?;
        let block_end = self.pos.checked_add(len).filter(|end| *end <= self.end)?;
        let parent_end = std::mem::replace(&mut self.end, block_end);
        let fields = self.read_varint()?;
        let flags = self.read_varint()?;
        let bitmap = self.read_bitmap(flags)?;
        Some(Block {
            parent_end,
            fields,
            flags,
            bitmap,
        })
    }

    #[inline(always)]
    pub fn close_block(&mut self, block: Block) {
        self.pos = self.end;
        self.end = block.parent_end;
    }

    #[inline(always)]
    pub fn eof(&self) -> bool {
        self.pos >= self.end
    }

    #[inline(always)]
    pub fn bytes(&self) -> &[u8] {
        self.data.as_ref()
    }

    #[inline(always)]
    pub fn version(&self) -> u8 {
        self.version
    }
}

#[inline(always)]
pub fn write_bitmap(out: &mut Vec<u8>, bitmap: u64, flags: u64) {
    match flags.div_ceil(8) {
        0 => {}
        1 => out.push(bitmap as u8),
        len => out.extend_from_slice(bitmap.to_le_bytes().get(..len as usize).unwrap_or_default()),
    }
}

#[inline(always)]
pub fn begin_block(out: &mut Vec<u8>, fields: u64, flags: u64, bitmap: u64) -> usize {
    let start = out.len();
    if fields < SMALL_HEADER_LIMIT && flags < SMALL_HEADER_LIMIT {
        out.extend_from_slice(&[0, 0, ((fields as u8) << 1) | 1, ((flags as u8) << 1) | 1]);
    } else {
        out.extend_from_slice(&[0; BLOCK_PLACEHOLDER_LEN]);
        varint::write(out, fields);
        varint::write(out, flags);
    }
    write_bitmap(out, bitmap, flags);
    start
}

#[inline(always)]
pub fn end_block(out: &mut Vec<u8>, start: usize) {
    let len = out.len() - start - BLOCK_PLACEHOLDER_LEN;
    if len < BLOCK_SHORT_LIMIT {
        if let Some(slot) = out.get_mut(start..start + BLOCK_PLACEHOLDER_LEN) {
            slot.copy_from_slice(&(((len << 2) | 0b10) as u16).to_le_bytes());
        }
    } else {
        end_long_block(out, start, len);
    }
}

#[cold]
fn end_long_block(out: &mut Vec<u8>, start: usize, len: usize) {
    let mut header = Vec::with_capacity(9);
    varint::write(&mut header, len as u64);
    out.splice(start..start + BLOCK_PLACEHOLDER_LEN, header);
}

pub mod varint {
    #[inline(always)]
    pub fn write(out: &mut Vec<u8>, value: u64) {
        if value < 1 << 7 {
            out.push(((value as u8) << 1) | 1);
        } else if value < 1 << 14 {
            out.extend_from_slice(&(((value << 2) | 0b10) as u16).to_le_bytes());
        } else if value < 1 << 21 {
            let [a, b, c, _] = (((value << 3) | 0b100) as u32).to_le_bytes();
            out.extend_from_slice(&[a, b, c]);
        } else if value < 1 << 28 {
            out.extend_from_slice(&(((value << 4) | 0b1000) as u32).to_le_bytes());
        } else {
            write_wide(out, value);
        }
    }

    #[inline(always)]
    fn write_wide(out: &mut Vec<u8>, value: u64) {
        if value < 1 << 56 {
            let bits = u64::BITS - value.leading_zeros();
            let len = bits.div_ceil(7);
            let word = (value << len) | (1 << (len - 1));
            let start = out.len();
            out.extend_from_slice(&word.to_le_bytes());
            out.truncate(start + len as usize);
        } else {
            out.push(0);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }

    #[inline(always)]
    pub fn read(buf: &mut &[u8]) -> Option<u64> {
        let (&byte, rest) = buf.split_first()?;
        if byte & 1 != 0 {
            *buf = rest;
            return Some((byte >> 1) as u64);
        }
        if let Some(chunk) = buf.first_chunk::<8>() {
            let word = u64::from_le_bytes(*chunk);
            match byte.trailing_zeros() {
                1 => {
                    *buf = buf.get(2..)?;
                    return Some((word >> 2) & 0x3FFF);
                }
                2 => {
                    *buf = buf.get(3..)?;
                    return Some((word >> 3) & 0x1F_FFFF);
                }
                3 => {
                    *buf = buf.get(4..)?;
                    return Some((word >> 4) & 0x0FFF_FFFF);
                }
                4 => {
                    *buf = buf.get(5..)?;
                    return Some((word >> 5) & 0x7_FFFF_FFFF);
                }
                zeros @ 5..=7 => {
                    let len = zeros + 1;
                    *buf = buf.get(len as usize..)?;
                    return Some((word >> len) & (u64::MAX >> (64 - 7 * len)));
                }
                _ => {}
            }
        }
        read_tail(buf)
    }

    #[inline]
    fn read_tail(buf: &mut &[u8]) -> Option<u64> {
        let (&first, rest) = buf.split_first()?;
        if first == 0 {
            let (word, rest) = rest.split_first_chunk::<8>()?;
            *buf = rest;
            return Some(u64::from_le_bytes(*word));
        }
        let len = first.trailing_zeros() + 1;
        let (bytes, rest) = buf.split_at_checked(len as usize)?;
        let mut word = [0u8; 8];
        word.iter_mut()
            .zip(bytes)
            .for_each(|(dst, src)| *dst = *src);
        *buf = rest;
        Some(u64::from_le_bytes(word) >> len)
    }

    #[inline(always)]
    pub fn zigzag(value: i64) -> u64 {
        ((value << 1) ^ (value >> 63)) as u64
    }

    #[inline(always)]
    pub fn unzigzag(value: u64) -> i64 {
        ((value >> 1) as i64) ^ -((value & 1) as i64)
    }
}

impl Pickle for u64 {
    #[inline(always)]
    fn pickle(&self, out: &mut Vec<u8>) {
        varint::write(out, *self);
    }

    #[inline(always)]
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        stream.read_varint()
    }
}

impl Pickle for u32 {
    #[inline(always)]
    fn pickle(&self, out: &mut Vec<u8>) {
        varint::write(out, u64::from(*self));
    }

    #[inline(always)]
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        u32::try_from(stream.read_varint()?).ok()
    }
}

impl Pickle for u16 {
    #[inline(always)]
    fn pickle(&self, out: &mut Vec<u8>) {
        varint::write(out, u64::from(*self));
    }

    #[inline(always)]
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        u16::try_from(stream.read_varint()?).ok()
    }
}

impl Pickle for i64 {
    #[inline(always)]
    fn pickle(&self, out: &mut Vec<u8>) {
        varint::write(out, varint::zigzag(*self));
    }

    #[inline(always)]
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        stream.read_varint().map(varint::unzigzag)
    }
}

impl Pickle for bool {
    #[inline(always)]
    fn pickle(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }

    #[inline(always)]
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        match stream.read()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

impl Pickle for String {
    #[inline(always)]
    fn pickle(&self, out: &mut Vec<u8>) {
        varint::write(out, self.len() as u64);
        out.extend_from_slice(self.as_bytes());
    }

    #[inline(always)]
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let len = usize::try_from(stream.read_varint()?).ok()?;
        std::str::from_utf8(stream.read_bytes(len)?)
            .ok()
            .map(str::to_owned)
    }
}

impl<T: EnumImpl> Pickle for T {
    #[inline(always)]
    fn pickle(&self, out: &mut Vec<u8>) {
        self.to_id().pickle(out);
    }

    #[inline(always)]
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        u16::unpickle(stream).and_then(Self::from_id)
    }
}

impl<T: Pickle> Pickle for Option<T> {
    #[inline(always)]
    fn pickle(&self, out: &mut Vec<u8>) {
        match self {
            Some(value) => {
                out.push(1);
                value.pickle(out);
            }
            None => out.push(0),
        }
    }

    #[inline(always)]
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        match stream.read()? {
            0 => Some(None),
            1 => T::unpickle(stream).map(Some),
            _ => None,
        }
    }
}

impl<K, V, S> Pickle for HashMap<K, V, S>
where
    K: Pickle + std::hash::Hash + Eq,
    V: Pickle,
    S: std::hash::BuildHasher + Default,
{
    fn pickle(&self, out: &mut Vec<u8>) {
        varint::write(out, self.len() as u64);
        for (key, value) in self {
            key.pickle(out);
            value.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let len = usize::try_from(stream.read_varint()?).ok()?;
        let mut map =
            HashMap::with_capacity_and_hasher(len.min(stream.remaining().len()), S::default());
        for _ in 0..len {
            let key = K::unpickle(stream)?;
            let value = V::unpickle(stream)?;
            map.insert(key, value);
        }
        Some(map)
    }
}

impl<K, V> Pickle for VecMap<K, V>
where
    K: Pickle + std::hash::Hash + Eq,
    V: Pickle,
{
    fn pickle(&self, out: &mut Vec<u8>) {
        varint::write(out, self.len() as u64);
        for (key, value) in self {
            key.pickle(out);
            value.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let len = usize::try_from(stream.read_varint()?).ok()?;
        let mut map = VecMap::with_capacity(len.min(stream.remaining().len()));
        for _ in 0..len {
            let key = K::unpickle(stream)?;
            let value = V::unpickle(stream)?;
            map.append(key, value);
        }
        Some(map)
    }
}

impl Pickle for trc::Key {
    #[inline(always)]
    fn pickle(&self, out: &mut Vec<u8>) {
        self.to_id().pickle(out);
    }

    #[inline(always)]
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        u16::unpickle(stream).and_then(Self::from_id)
    }
}

