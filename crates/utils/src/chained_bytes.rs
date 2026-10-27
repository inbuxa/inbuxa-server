/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::memchr_iter;
use std::{borrow::Cow, ops::Range};

#[derive(Debug, Clone, Copy, Default)]
pub struct ChainedBytes<'x> {
    head: &'x [u8],
    tail: &'x [u8],
}

impl<'x> ChainedBytes<'x> {
    pub const fn new(bytes: &'x [u8]) -> Self {
        Self {
            head: bytes,
            tail: &[],
        }
    }

    pub const fn chain(head: &'x [u8], tail: &'x [u8]) -> Self {
        Self { head, tail }
    }

    pub fn from_blob(head: &'x [u8], blob: &'x [u8], body_offset: usize) -> Self {
        Self {
            head,
            tail: blob.get(body_offset..).unwrap_or_default(),
        }
    }

    pub const fn len(&self) -> usize {
        self.head.len() + self.tail.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.head.is_empty() && self.tail.is_empty()
    }

    pub const fn segments(&self) -> [&'x [u8]; 2] {
        [self.head, self.tail]
    }

    #[inline]
    pub fn view(&self, range: Range<usize>) -> Option<Self> {
        let split = self.head.len();
        if range.end <= split {
            self.head.get(range).map(Self::new)
        } else if range.start >= split {
            self.tail
                .get(range.start - split..range.end - split)
                .map(Self::new)
        } else {
            Some(Self::chain(
                self.head.get(range.start..)?,
                self.tail.get(..range.end - split)?,
            ))
        }
    }

    #[inline]
    pub fn get(&self, range: Range<usize>) -> Option<Cow<'x, [u8]>> {
        let split = self.head.len();
        if range.end <= split {
            self.head.get(range).map(Cow::Borrowed)
        } else if range.start >= split {
            self.tail
                .get(range.start - split..range.end - split)
                .map(Cow::Borrowed)
        } else {
            self.concat(range)
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.segments().concat()
    }

    #[inline]
    pub fn extend_into(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.len());
        buf.extend_from_slice(self.head);
        buf.extend_from_slice(self.tail);
    }

    pub fn line_prefix_len(&self, lines: usize) -> usize {
        let Some(nth) = lines.checked_sub(1) else {
            return 0;
        };
        let [head, tail] = self.segments();
        memchr_iter(b'\n', head)
            .chain(memchr_iter(b'\n', tail).map(|pos| pos + head.len()))
            .nth(nth)
            .map_or(self.len(), |pos| pos + 1)
    }

    #[cold]
    fn concat(&self, range: Range<usize>) -> Option<Cow<'x, [u8]>> {
        self.view(range).map(|bytes| Cow::Owned(bytes.to_vec()))
    }
}

impl PartialEq for ChainedBytes<'_> {
    fn eq(&self, other: &Self) -> bool {
        let (short, long) = if self.head.len() <= other.head.len() {
            (self, other)
        } else {
            (other, self)
        };
        if short.len() != long.len() {
            return false;
        }
        let Some((long_head, long_middle)) = long.head.split_at_checked(short.head.len()) else {
            return false;
        };
        let Some((short_middle, short_tail)) = short.tail.split_at_checked(long_middle.len())
        else {
            return false;
        };
        short.head == long_head && short_middle == long_middle && short_tail == long.tail
    }
}

impl Eq for ChainedBytes<'_> {}

