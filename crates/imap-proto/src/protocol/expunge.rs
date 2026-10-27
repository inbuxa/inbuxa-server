/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ImapResponse, Sequence, push_int, serialize_sequence};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub use_vanished: bool,
    pub ids: Vec<u32>,
}

impl ImapResponse for Response {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        self.serialize_to(buf);
    }

    fn size_hint(&self) -> usize {
        const EXPUNGE_LINE_LEN: usize = 21;
        const VANISHED_FRAMING_LEN: usize = 24;
        const RANGE_LEN: usize = 8;

        if !self.use_vanished {
            self.ids.len() * EXPUNGE_LINE_LEN
        } else {
            VANISHED_FRAMING_LEN + self.ids.len() * RANGE_LEN
        }
    }
}

impl Response {
    pub fn serialize_to(&self, buf: &mut Vec<u8>) {
        if !self.use_vanished {
            for (num_deletions, id) in self.ids.iter().enumerate() {
                buf.extend_from_slice(b"* ");
                push_int(buf, id.saturating_sub(num_deletions as u32));
                buf.extend_from_slice(b" EXPUNGE\r\n");
            }
        } else {
            serialize_vanished(buf, false, &self.ids);
        }
    }
}

fn serialize_vanished(buf: &mut Vec<u8>, earlier: bool, ids: &[u32]) {
    if earlier {
        buf.extend_from_slice(b"* VANISHED (EARLIER) ");
    } else {
        buf.extend_from_slice(b"* VANISHED ");
    }
    serialize_sequence(buf, ids);
    buf.extend_from_slice(b"\r\n");
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vanished {
    pub earlier: bool,
    pub ids: Vec<u32>,
}

impl Vanished {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        serialize_vanished(buf, self.earlier, &self.ids);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VanishedFilter {
    ranges: Vec<(u32, u32)>,
}

impl VanishedFilter {
    pub fn new(sequence: &Sequence, last_uid: u32) -> Option<Self> {
        let mut ranges = Vec::new();
        if !Self::collect(sequence, last_uid, &mut ranges) {
            return None;
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        Some(Self { ranges: merged })
    }

    fn collect(sequence: &Sequence, last_uid: u32, ranges: &mut Vec<(u32, u32)>) -> bool {
        match sequence {
            Sequence::Number { value } => ranges.push((*value, *value)),
            Sequence::Range {
                start: Some(start),
                end: Some(end),
            } => ranges.push((*start.min(end), *start.max(end))),
            Sequence::Range {
                start: Some(bound),
                end: None,
            }
            | Sequence::Range {
                start: None,
                end: Some(bound),
            } => ranges.push((*bound, u32::MAX)),
            Sequence::Range {
                start: None,
                end: None,
            } => ranges.push((last_uid, u32::MAX)),
            Sequence::List { items } => {
                return items
                    .iter()
                    .all(|item| Self::collect(item, last_uid, ranges));
            }
            Sequence::SavedSearch => return false,
        }
        true
    }

    pub fn contains(&self, uid: u32) -> bool {
        let pos = self.ranges.partition_point(|&(_, end)| end < uid);
        self.ranges.get(pos).is_some_and(|&(start, _)| start <= uid)
    }
}

