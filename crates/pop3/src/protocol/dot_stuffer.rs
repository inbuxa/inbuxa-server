/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::response::MessageEnd;
use memchr::memchr_iter;
use utils::chained_bytes::ChainedBytes;

const CRLF: &[u8] = b"\r\n";

const DENSE_LINE_LEN: usize = 8;
const DENSE_STREAK: u32 = 8;
const SPARSE_LINE_LEN: usize = 64;

pub struct DotStuffer {
    last: u8,
}

impl Default for DotStuffer {
    fn default() -> Self {
        Self { last: b'\n' }
    }
}

impl DotStuffer {
    pub fn push(&mut self, buf: &mut Vec<u8>, bytes: &[u8]) {
        let mut offset = 0;
        while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
            offset += self.copy_sparse(buf, rest);
            offset += self.copy_dense(buf, bytes.get(offset..).unwrap_or_default());
        }
    }

    pub fn finish(self, buf: &mut Vec<u8>, end: MessageEnd) {
        if self.last != b'\n' {
            buf.extend_from_slice(b"\r\n");
        }
        if end == MessageEnd::BlankLine {
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(b".\r\n");
    }

    pub fn wire_len(bytes: &ChainedBytes<'_>) -> usize {
        let mut last = b'\n';
        let mut bare_lf = 0;
        for segment in bytes.segments() {
            for pos in memchr_iter(b'\n', segment) {
                let prev = pos
                    .checked_sub(1)
                    .and_then(|prev| segment.get(prev))
                    .copied()
                    .unwrap_or(last);
                if prev != b'\r' {
                    bare_lf += 1;
                }
            }
            if let Some(&byte) = segment.last() {
                last = byte;
            }
        }
        let final_crlf = if last != b'\n' { CRLF.len() } else { 0 };
        bytes.len() + bare_lf + final_crlf
    }

    fn copy_sparse(&mut self, buf: &mut Vec<u8>, bytes: &[u8]) -> usize {
        if self.last == b'\n' && bytes.first() == Some(&b'.') {
            buf.push(b'.');
        }
        let mut run_start = 0;
        let mut short_lines = 0;
        for pos in memchr_iter(b'\n', bytes) {
            let prev = pos
                .checked_sub(1)
                .and_then(|prev| bytes.get(prev))
                .copied()
                .unwrap_or(self.last);
            let is_bare = prev != b'\r';
            let is_dot = bytes.get(pos + 1) == Some(&b'.');
            if is_bare || is_dot {
                buf.extend_from_slice(bytes.get(run_start..pos).unwrap_or_default());
                if pos - run_start < DENSE_LINE_LEN {
                    short_lines += 1;
                    if short_lines == DENSE_STREAK {
                        self.last = prev;
                        return pos;
                    }
                } else {
                    short_lines = 0;
                }
                if is_bare {
                    buf.push(b'\r');
                }
                buf.push(b'\n');
                if is_dot {
                    buf.push(b'.');
                }
                run_start = pos + 1;
            }
        }
        buf.extend_from_slice(bytes.get(run_start..).unwrap_or_default());
        if let Some(&last) = bytes.last() {
            self.last = last;
        }
        bytes.len()
    }

    fn copy_dense(&mut self, buf: &mut Vec<u8>, bytes: &[u8]) -> usize {
        let mut line_start = 0;
        for (pos, &byte) in bytes.iter().enumerate() {
            if byte == b'\n' {
                if self.last != b'\r' {
                    buf.push(b'\r');
                }
                buf.push(b'\n');
                self.last = b'\n';
                if pos - line_start >= SPARSE_LINE_LEN {
                    return pos + 1;
                }
                line_start = pos + 1;
            } else {
                if byte == b'.' && self.last == b'\n' {
                    buf.push(b'.');
                }
                buf.push(byte);
                self.last = byte;
            }
        }
        bytes.len()
    }
}

