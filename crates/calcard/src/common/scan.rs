/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::{memchr2, memchr3};

pub(crate) const EOL: u16 = 1;
pub(crate) const WHITESPACE: u16 = 1 << 1;
pub(crate) const BACKSLASH: u16 = 1 << 2;
pub(crate) const QUOTE: u16 = 1 << 3;
pub(crate) const COLON: u16 = 1 << 4;
pub(crate) const SEMICOLON: u16 = 1 << 5;
pub(crate) const COMMA: u16 = 1 << 6;
pub(crate) const EQUAL: u16 = 1 << 7;
pub(crate) const DOT: u16 = 1 << 8;
pub(crate) const CONTROL: u16 = 1 << 9;
pub(crate) const CARET: u16 = 1 << 10;

const LINE_ESCAPES: u16 = EOL | BACKSLASH;

static CLASS: [u16; 256] = class_table();

const fn class_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut byte = 0;
    while byte < table.len() {
        table[byte] = match byte as u8 {
            b'\r' | b'\n' => EOL,
            b' ' | b'\t' => WHITESPACE,
            b'\\' => BACKSLASH,
            b'"' => QUOTE,
            b':' => COLON,
            b';' => SEMICOLON,
            b',' => COMMA,
            b'=' => EQUAL,
            b'.' => DOT,
            b'^' => CARET,
            0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F => CONTROL,
            _ => 0,
        };
        byte += 1;
    }
    table
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mask(u16);

impl Mask {
    #[inline(always)]
    pub(crate) const fn new(classes: u16) -> Self {
        Mask(classes | EOL)
    }

    #[inline(always)]
    pub(crate) fn class_of(self, byte: u8) -> u16 {
        CLASS[byte as usize] & self.0
    }

    #[inline(always)]
    pub(crate) fn plain_len(self, bytes: &[u8]) -> usize {
        match bytes.first() {
            Some(&byte) if self.class_of(byte) == 0 => {
                if self.0 & !LINE_ESCAPES != 0 {
                    self.class_scan(bytes)
                } else if self.0 & BACKSLASH != 0 {
                    memchr3(b'\r', b'\n', b'\\', bytes).unwrap_or(bytes.len())
                } else {
                    memchr2(b'\r', b'\n', bytes).unwrap_or(bytes.len())
                }
            }
            _ => 0,
        }
    }

    #[inline(always)]
    fn class_scan(self, bytes: &[u8]) -> usize {
        let (chunks, tail) = bytes.as_chunks::<4>();
        for (chunk_idx, &[a, b, c, d]) in chunks.iter().enumerate() {
            let (a, b, c, d) = (
                self.class_of(a),
                self.class_of(b),
                self.class_of(c),
                self.class_of(d),
            );
            if a | b | c | d != 0 {
                return chunk_idx * 4
                    + if a != 0 {
                        0
                    } else if b != 0 {
                        1
                    } else if c != 0 {
                        2
                    } else {
                        3
                    };
            }
        }
        chunks.len() * 4
            + tail
                .iter()
                .position(|&byte| self.class_of(byte) != 0)
                .unwrap_or(tail.len())
    }
}

