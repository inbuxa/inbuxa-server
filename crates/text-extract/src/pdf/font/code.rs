/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::pdf::tables::CodeRange;

pub(crate) const MAX_CODE_LEN: usize = 4;
const BYTE_VALUES: usize = 256;
const AMBIGUOUS: u8 = u8::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Code {
    pub(crate) value: u32,
    pub(crate) len: u8,
    pub(crate) valid: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct CodeSplitter {
    ranges: Vec<CodeRange>,
    lengths: Box<[u8; BYTE_VALUES]>,
    shortest: Box<[u8; BYTE_VALUES]>,
}

pub(crate) fn code_value(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > MAX_CODE_LEN {
        return None;
    }
    Some(
        bytes
            .iter()
            .fold(0u32, |value, &byte| value << 8 | u32::from(byte)),
    )
}

impl Code {
    pub(crate) fn bytes(&self) -> impl Iterator<Item = u8> {
        let len = u32::from(self.len.min(MAX_CODE_LEN as u8));
        let value = self.value;
        (0..len)
            .rev()
            .map(move |index| (value >> (index * 8)) as u8)
    }
}

impl CodeSplitter {
    pub(crate) fn fixed(len: u8) -> Self {
        let len = len.clamp(1, MAX_CODE_LEN as u8);
        CodeSplitter {
            ranges: Vec::new(),
            lengths: Box::new([len; BYTE_VALUES]),
            shortest: Box::new([len; BYTE_VALUES]),
        }
    }

    pub(crate) fn from_ranges(ranges: &[CodeRange], fallback: u8) -> Self {
        if ranges.is_empty() {
            return CodeSplitter::fixed(fallback);
        }
        let mut lengths = Box::new([0u8; BYTE_VALUES]);
        let mut shortest = Box::new([0u8; BYTE_VALUES]);
        for ((byte, length), short) in (0..=u8::MAX)
            .zip(lengths.iter_mut())
            .zip(shortest.iter_mut())
        {
            for range in ranges.iter().filter(|range| range.accepts_prefix(&[byte])) {
                let len = u8::try_from(range.len()).unwrap_or(AMBIGUOUS);
                *length = match *length {
                    0 => len,
                    current if current == len => len,
                    _ => AMBIGUOUS,
                };
                *short = match *short {
                    0 => len,
                    current => current.min(len),
                };
            }
        }
        CodeSplitter {
            ranges: ranges.to_vec(),
            lengths,
            shortest,
        }
    }

    pub(crate) fn split(&self, bytes: &[u8]) -> Option<Code> {
        let &first = bytes.first()?;
        let index = usize::from(first);
        match self.lengths.get(index).copied().unwrap_or_default() {
            0 => Some(Code {
                value: u32::from(first),
                len: 1,
                valid: false,
            }),
            AMBIGUOUS => Some(self.split_slow(bytes, index)),
            len => Some(take(bytes, usize::from(len), true)),
        }
    }

    fn split_slow(&self, bytes: &[u8], index: usize) -> Code {
        for len in 1..=MAX_CODE_LEN {
            let Some(prefix) = bytes.get(..len) else {
                break;
            };
            if self.ranges.iter().any(|range| range.contains(prefix)) {
                return take(bytes, len, true);
            }
            if !self.ranges.iter().any(|range| range.accepts_prefix(prefix)) {
                break;
            }
        }
        let len = self.shortest.get(index).copied().unwrap_or(1).max(1);
        take(bytes, usize::from(len), false)
    }
}

fn take(bytes: &[u8], len: usize, valid: bool) -> Code {
    let taken = bytes.get(..len).unwrap_or(bytes);
    Code {
        value: code_value(taken).unwrap_or_default(),
        len: taken.len() as u8,
        valid: valid && taken.len() == len,
    }
}

