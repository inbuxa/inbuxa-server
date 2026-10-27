/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::{memchr, memchr2};

pub(crate) struct HeaderIterator<'x> {
    message: &'x [u8],
    pos: usize,
    start_pos: usize,
}

enum FieldScan {
    Named { colon: usize, end: usize },
    Unnamed { end: usize },
    End { pos: usize },
}

#[inline(always)]
fn scan_field(message: &[u8], start_pos: usize, from: usize) -> FieldScan {
    let mut cur = from;

    while let Some(rest) = message.get(cur..) {
        let Some(offset) = memchr2(b':', b'\n', rest) else {
            break;
        };
        let Some((head, tail)) = rest.split_at_checked(offset) else {
            break;
        };
        let pos = cur + offset;

        if tail.first() == Some(&b':') {
            return scan_value(message, pos);
        } else if head.last() == Some(&b'\r') || pos == start_pos {
            return FieldScan::End { pos: pos + 1 };
        }

        match message.get(pos + 1) {
            Some(b' ' | b'\t') => cur = pos + 1,
            _ => return FieldScan::Unnamed { end: pos + 1 },
        }
    }

    FieldScan::End { pos: message.len() }
}

#[inline(always)]
fn scan_value(message: &[u8], colon: usize) -> FieldScan {
    let mut cur = colon + 1;

    while let Some(rest) = message.get(cur..) {
        let Some(offset) = memchr(b'\n', rest) else {
            break;
        };
        let pos = cur + offset;

        match message.get(pos + 1) {
            Some(b' ' | b'\t') => cur = pos + 1,
            _ => {
                return FieldScan::Named {
                    colon,
                    end: pos + 1,
                };
            }
        }
    }

    FieldScan::End { pos: message.len() }
}

impl<'x> HeaderIterator<'x> {
    pub fn new(message: &'x [u8]) -> Self {
        HeaderIterator {
            message,
            pos: 0,
            start_pos: 0,
        }
    }

    pub fn seek_start(&mut self) {
        let rest = self.message.get(self.pos..).unwrap_or_default();
        self.pos += rest
            .iter()
            .position(|ch| !ch.is_ascii_whitespace())
            .unwrap_or(rest.len());
    }
}

impl<'x> Iterator for HeaderIterator<'x> {
    type Item = (&'x [u8], &'x [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        match scan_field(self.message, self.start_pos, self.pos) {
            FieldScan::Named { colon, end } => {
                let header_name = self.message.get(self.start_pos..colon).unwrap_or_default();
                let header_value = self.message.get(colon + 1..end).unwrap_or_default();

                self.start_pos = end;
                self.pos = end;

                Some((header_name, header_value))
            }
            FieldScan::Unnamed { end } => {
                let header_name = self.message.get(self.start_pos..end).unwrap_or_default();

                self.start_pos = end;
                self.pos = end;

                Some((header_name, b""))
            }
            FieldScan::End { pos } => {
                self.pos = pos;

                None
            }
        }
    }
}
