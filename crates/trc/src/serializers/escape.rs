/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const WORD: usize = 8;
const LSB: u64 = 0x0101_0101_0101_0101;
const MSB: u64 = 0x8080_8080_8080_8080;
const HEX: &[u8; 16] = b"0123456789abcdef";
const HEX_ESCAPE: u8 = b'x';

static ESCAPES: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut byte = 0;
    while byte < 0x20 {
        table[byte] = HEX_ESCAPE;
        byte += 1;
    }
    table[0x7f] = HEX_ESCAPE;
    table[b'\r' as usize] = b'r';
    table[b'\n' as usize] = b'n';
    table[b'\t' as usize] = b't';
    table[b'\\' as usize] = b'\\';
    table[b'"' as usize] = b'"';
    table
};

#[inline(always)]
const fn has_zero_byte(word: u64) -> u64 {
    word.wrapping_sub(LSB) & !word & MSB
}

#[inline(always)]
const fn may_need_escape(word: u64) -> bool {
    let below_space = word.wrapping_sub(LSB * 0x20) & !word & MSB;
    (below_space
        | has_zero_byte(word ^ (LSB * b'"' as u64))
        | has_zero_byte(word ^ (LSB * b'\\' as u64))
        | has_zero_byte(word ^ (LSB * 0x7f)))
        != 0
}

pub fn escape_into(out: &mut Vec<u8>, input: &[u8]) {
    let mut clean_start = 0;
    let mut offset = 0;
    let (chunks, remainder) = input.as_chunks::<WORD>();

    for chunk in chunks {
        if may_need_escape(u64::from_le_bytes(*chunk)) {
            clean_start = escape_bytes(out, input, chunk, offset, clean_start);
        }
        offset += WORD;
    }

    clean_start = escape_bytes(out, input, remainder, offset, clean_start);
    out.extend_from_slice(&input[clean_start..]);
}

#[inline(always)]
fn escape_bytes(
    out: &mut Vec<u8>,
    input: &[u8],
    bytes: &[u8],
    offset: usize,
    mut clean_start: usize,
) -> usize {
    for (pos, &byte) in bytes.iter().enumerate() {
        let escape = ESCAPES[byte as usize];
        if escape != 0 {
            let pos = offset + pos;
            out.extend_from_slice(&input[clean_start..pos]);
            if escape == HEX_ESCAPE {
                out.extend_from_slice(&[
                    b'\\',
                    b'x',
                    HEX[(byte >> 4) as usize],
                    HEX[(byte & 0x0f) as usize],
                ]);
            } else {
                out.extend_from_slice(&[b'\\', escape]);
            }
            clean_start = pos + 1;
        }
    }
    clean_start
}

