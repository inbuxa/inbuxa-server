/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Subspace, U16_LEN, U32_LEN,
    search::{MAX_STORED_DOCUMENT_SIZE, SearchField},
    write::{
        AnyKey, Dictionary, SearchIndex,
        compress::{COMPRESS_WATERMARK_DICTIONARY, compress, decompress_into},
    },
};
use utils::{
    cheeky_hash::CheekyHash,
    codec::leb128::{Leb128, Leb128Reader, Leb128Writer},
};

const RANGE_PADDING: [u8; 22] = [u8::MAX; 22];
const DOCUMENT_PLAIN: u8 = 0;
const DOCUMENT_ZSTD: u8 = 1;

pub(crate) const ACCOUNT_TERM_BASE_LEN: usize = U32_LEN + 2;
pub(crate) const GLOBAL_TERM_BASE_LEN: usize = 2;

pub(crate) struct Writer {
    buf: Vec<u8>,
}

pub(crate) struct AccountTermKey<'x> {
    pub term: &'x [u8],
    pub len: u8,
    pub field: u8,
    pub block_id: u16,
}

pub(crate) struct PrefixKey<'x> {
    pub term: &'x [u8],
    pub len: u8,
    pub block_id: u16,
}

pub(crate) struct Reader<'x> {
    bytes: &'x [u8],
}

impl<'x> Reader<'x> {
    pub fn new(bytes: &'x [u8]) -> Self {
        Reader { bytes }
    }

    #[inline(always)]
    pub fn leb128<T: Leb128>(&mut self) -> Option<T> {
        self.bytes.read_leb128()
    }

    #[inline(always)]
    pub fn skip_leb128(&mut self, count: usize) -> Option<()> {
        self.bytes.skip_leb128(count)
    }

    pub fn u8(&mut self) -> Option<u8> {
        let (&byte, rest) = self.bytes.split_first()?;
        self.bytes = rest;
        Some(byte)
    }

    pub fn slice(&mut self, len: usize) -> Option<&'x [u8]> {
        let (slice, rest) = self.bytes.split_at_checked(len)?;
        self.bytes = rest;
        Some(slice)
    }

    pub fn term(&mut self) -> Option<CheekyHash> {
        let len = self.u8()?;
        let key = self.slice((len as usize).min(CheekyHash::HASH_SIZE))?;
        CheekyHash::from_key_bytes(key, len)
    }
}

impl Writer {
    pub fn with_capacity(capacity: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(capacity + 1),
        }
    }

    pub fn into_document(self) -> Vec<u8> {
        let mut plain = self.buf;

        if plain.len() >= COMPRESS_WATERMARK_DICTIONARY
            && let Ok(mut compressed) = compress(Some(Dictionary::Term), &plain, 1)
            && compressed.len() < plain.len()
        {
            compressed.push(DOCUMENT_ZSTD);
            return compressed;
        }

        plain.reserve_exact(1);
        plain.push(DOCUMENT_PLAIN);
        plain
    }

    pub fn push_leb128<T: Leb128>(&mut self, value: T) {
        self.buf.push_leb128(value);
    }

    pub fn push_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn push_term(&mut self, term: &CheekyHash) {
        self.buf.push(term.len() as u8);
        self.buf.extend_from_slice(term.as_key());
    }
}

pub(crate) fn read_document<'x>(stored: &'x [u8], scratch: &'x mut Vec<u8>) -> Option<&'x [u8]> {
    let (marker, payload) = stored.split_last()?;

    match *marker {
        DOCUMENT_PLAIN => Some(payload),
        DOCUMENT_ZSTD => decompress_into(payload, scratch, MAX_STORED_DOCUMENT_SIZE)
            .ok()
            .map(|_| scratch.as_slice()),
        _ => None,
    }
}

pub(crate) fn term_key(key: Vec<u8>) -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: Subspace::SearchTerm,
        key,
    }
}

pub(crate) fn document_key(key: Vec<u8>) -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: Subspace::SearchDocument,
        key,
    }
}

pub(crate) fn account_region_range(index: SearchIndex, account_id: u32) -> (Vec<u8>, Vec<u8>) {
    let mut begin = Vec::with_capacity(1 + U32_LEN + RANGE_PADDING.len());
    begin.push(index.to_u8());
    begin.extend_from_slice(&account_id.to_be_bytes());
    let mut end = begin.clone();
    end.extend_from_slice(&RANGE_PADDING);
    (begin, end)
}

fn account_term_base(index: SearchIndex, account_id: u32, group: u8, capacity: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(ACCOUNT_TERM_BASE_LEN + capacity);
    key.push(index.to_u8());
    key.extend_from_slice(&account_id.to_be_bytes());
    key.push(group);
    key
}

pub(crate) fn account_term_prefix_range(
    index: SearchIndex,
    account_id: u32,
    group: u8,
    prefix: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = account_term_base(index, account_id, group, prefix.len() + RANGE_PADDING.len());
    begin.extend_from_slice(prefix);
    let mut end = begin.clone();
    end.extend_from_slice(&RANGE_PADDING);
    (begin, end)
}

pub(crate) fn account_term_range(
    index: SearchIndex,
    account_id: u32,
    field: u8,
    term: &CheekyHash,
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = account_term_base(
        index,
        account_id,
        index.term_group(field),
        term.key_len() + U16_LEN + 3,
    );
    begin.extend_from_slice(term.as_key());
    begin.push(term.len() as u8);
    begin.push(field);
    let mut end = begin.clone();
    end.extend_from_slice(&[u8::MAX; U16_LEN + 1]);
    (begin, end)
}

pub(crate) fn account_term_block_key(
    index: SearchIndex,
    account_id: u32,
    field: u8,
    term: &CheekyHash,
    block: u16,
) -> Vec<u8> {
    let mut key = account_term_base(
        index,
        account_id,
        index.term_group(field),
        term.key_len() + U16_LEN + 3,
    );
    key.extend_from_slice(term.as_key());
    key.push(term.len() as u8);
    key.push(field);
    key.extend_from_slice(&block.to_be_bytes());
    key
}

pub(crate) fn account_term_block_range(
    index: SearchIndex,
    account_id: u32,
    field: u8,
    term: &CheekyHash,
    from_block: u16,
    until_block: u16,
) -> (Vec<u8>, Vec<u8>) {
    let begin = account_term_block_key(index, account_id, field, term, from_block);
    let mut end = account_term_block_key(index, account_id, field, term, until_block);
    end.push(u8::MAX);
    (begin, end)
}

pub(crate) fn account_terms_range(
    index: SearchIndex,
    account_id: u32,
    group: u8,
    first: &CheekyHash,
    last: &CheekyHash,
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = account_term_base(index, account_id, group, first.key_len() + 1);
    let mut end = begin.clone();
    begin.extend_from_slice(first.as_key());
    begin.push(first.len() as u8);
    end.extend_from_slice(last.as_key());
    end.push(last.len() as u8);
    end.extend_from_slice(&[u8::MAX; U16_LEN + 2]);
    (begin, end)
}

pub(crate) fn parse_account_term_key(key: &[u8]) -> Option<AccountTermKey<'_>> {
    let (rest, block) = key
        .get(ACCOUNT_TERM_BASE_LEN..)?
        .split_last_chunk::<U16_LEN>()?;
    let (field, rest) = rest.split_last()?;
    let (len, term) = rest.split_last()?;
    Some(AccountTermKey {
        term,
        len: *len,
        field: *field,
        block_id: u16::from_be_bytes(*block),
    })
}

pub(crate) fn global_term_prefix_range(
    index: SearchIndex,
    field: u8,
    prefix: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = Vec::with_capacity(prefix.len() + RANGE_PADDING.len() + 2);
    begin.push(index.to_u8());
    begin.push(field);
    begin.extend_from_slice(prefix);
    let mut end = begin.clone();
    end.extend_from_slice(&RANGE_PADDING);
    (begin, end)
}

pub(crate) fn account_document_key(
    index: SearchIndex,
    account_id: u32,
    document_id: u32,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + U32_LEN * 2);
    key.push(index.to_u8());
    key.extend_from_slice(&account_id.to_be_bytes());
    key.extend_from_slice(&document_id.to_be_bytes());
    key
}

pub(crate) fn global_term_block_range(
    index: SearchIndex,
    field: u8,
    term: &CheekyHash,
    from_block: u16,
    until_block: u16,
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = Vec::with_capacity(GLOBAL_TERM_BASE_LEN + term.key_len() + U16_LEN + 2);
    begin.push(index.to_u8());
    begin.push(field);
    begin.extend_from_slice(term.as_key());
    begin.push(term.len() as u8);
    let mut end = begin.clone();
    begin.extend_from_slice(&from_block.to_be_bytes());
    end.extend_from_slice(&until_block.to_be_bytes());
    end.push(u8::MAX);
    (begin, end)
}

pub(crate) fn global_document_id_range(
    index: SearchIndex,
    from_block: u16,
    until_block: u16,
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = Vec::with_capacity(U16_LEN + 3);
    begin.push(index.to_u8());
    begin.push(SearchField::Id.u8_id());
    let mut end = begin.clone();
    begin.extend_from_slice(&from_block.to_be_bytes());
    end.extend_from_slice(&until_block.to_be_bytes());
    end.push(u8::MAX);
    (begin, end)
}

pub(crate) fn parse_prefix_key(
    key: &[u8],
    base_len: usize,
    block_len: usize,
) -> Option<PrefixKey<'_>> {
    let mut suffix = key.get(base_len..)?;
    let mut block_id = 0;
    if block_len > 0 {
        let (rest, block) = suffix.split_at_checked(suffix.len().checked_sub(block_len)?)?;
        block_id = match block {
            [block] => *block as u16,
            [hi, lo] => u16::from_be_bytes([*hi, *lo]),
            _ => return None,
        };
        suffix = rest;
    }
    let (len, term) = suffix.split_last()?;
    Some(PrefixKey {
        term,
        len: *len,
        block_id,
    })
}

pub(crate) fn parse_block_id(key: &[u8]) -> Option<u16> {
    key.get(key.len().checked_sub(U16_LEN)?..)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
}


