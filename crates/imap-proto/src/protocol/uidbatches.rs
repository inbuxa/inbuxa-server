/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use compact_str::CompactString;

use super::push_int;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub batch_size: u32,
    pub batch_range: Option<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub ranges: Vec<(u32, u32)>,
}

impl Response {
    pub fn serialize(self, tag: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + tag.len() + (self.ranges.len() * 22));
        buf.extend_from_slice(b"* UIDBATCHES (TAG \"");
        buf.extend_from_slice(tag.as_bytes());
        buf.extend_from_slice(b"\")");
        for (pos, (high, low)) in self.ranges.iter().enumerate() {
            buf.push(if pos == 0 { b' ' } else { b',' });
            push_int(&mut buf, *high);
            buf.push(b':');
            push_int(&mut buf, *low);
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

