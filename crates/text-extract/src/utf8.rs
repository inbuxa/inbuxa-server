/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::xml::scan::incomplete_utf8_tail;

const BLOCK: usize = 4096;
const SPARSE_RATIO: usize = 4;

pub(crate) struct LazyUtf8<'a> {
    source: &'a [u8],
    block: &'a str,
    block_start: usize,
    validated: usize,
    requested: usize,
    sparse: bool,
}

impl<'a> LazyUtf8<'a> {
    pub(crate) fn new(source: &'a [u8]) -> Self {
        LazyUtf8 {
            source,
            block: "",
            block_start: 0,
            validated: 0,
            requested: 0,
            sparse: false,
        }
    }

    #[inline]
    pub(crate) fn get(&mut self, start: usize, len: usize) -> Option<&'a str> {
        self.requested += len;
        let offset = match start
            .checked_sub(self.block_start)
            .filter(|offset| offset + len <= self.block.len())
        {
            Some(offset) => offset,
            None if self.sparse => return None,
            None => {
                self.validate_from(start, len)?;
                0
            }
        };
        self.block.get(offset..offset + len)
    }

    #[inline(never)]
    fn validate_from(&mut self, start: usize, len: usize) -> Option<()> {
        if self.validated > self.requested.saturating_mul(SPARSE_RATIO) {
            self.sparse = true;
            return None;
        }
        let end = (start + len).max(start + BLOCK).min(self.source.len());
        self.block = valid_prefix(self.source.get(start..end)?);
        self.block_start = start;
        self.validated += end - start;
        Some(())
    }
}

fn valid_prefix(bytes: &[u8]) -> &str {
    let complete = bytes
        .get(..bytes.len() - incomplete_utf8_tail(bytes))
        .unwrap_or(bytes);
    match std::str::from_utf8(complete) {
        Ok(text) => text,
        Err(error) => complete
            .get(..error.valid_up_to())
            .and_then(|prefix| std::str::from_utf8(prefix).ok())
            .unwrap_or_default(),
    }
}

