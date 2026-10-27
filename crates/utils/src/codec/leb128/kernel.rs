/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const MSB: u64 = 0x8080_8080_8080_8080;
const LOW7: u64 = 0x7F7F_7F7F_7F7F_7F7F;
const SHORT_LIMIT: u64 = 1 << 56;

#[inline(always)]
const fn spread(value: u64) -> u64 {
    let value = (value & 0x0000_0000_0FFF_FFFF) | ((value & 0x00FF_FFFF_F000_0000) << 4);
    let value = (value & 0x0000_3FFF_0000_3FFF) | ((value & 0x0FFF_C000_0FFF_C000) << 2);
    (value & 0x007F_007F_007F_007F) | ((value & 0x3F80_3F80_3F80_3F80) << 1)
}

#[inline(always)]
const fn compact(value: u64) -> u64 {
    let value = (value & 0x007F_007F_007F_007F) | ((value & 0x7F00_7F00_7F00_7F00) >> 1);
    let value = (value & 0x0000_3FFF_0000_3FFF) | ((value & 0x3FFF_0000_3FFF_0000) >> 2);
    (value & 0x0000_0000_0FFF_FFFF) | ((value & 0x0FFF_FFFF_0000_0000) >> 4)
}

#[inline(always)]
pub(super) const fn encoded_len(value: u64) -> usize {
    let bits = u64::BITS - (value | 1).leading_zeros();
    (bits as usize * 9 + 64) / 64
}

#[inline(always)]
pub(super) const fn encode(value: u64) -> (u64, u64, usize) {
    if value < SHORT_LIMIT {
        let spread = spread(value);
        let top = (u64::BITS - 1 - (spread | 1).leading_zeros()) & !7;
        (
            spread | (MSB & ((1 << top) - 1)),
            0,
            (top as usize >> 3) + 1,
        )
    } else {
        let high = value >> 56;
        let extra = high >> 7;
        (spread(value) | MSB, high | (extra << 8), 9 + extra as usize)
    }
}

#[inline(always)]
pub(super) fn push(out: &mut Vec<u8>, mut value: u64) {
    loop {
        if value < 0x80 {
            out.push(value as u8);
            break;
        }
        out.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
}

#[inline(always)]
pub(super) fn decode(bytes: &[u8], max_len: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, &byte) in bytes.iter().take(max_len).enumerate() {
        let bits = u64::from(byte & 0x7F);
        let shift = 7 * index as u32;
        if (bits << shift) >> shift != bits {
            return None;
        }
        value |= bits << shift;
        if byte < 0x80 {
            return Some((value, index + 1));
        }
    }
    None
}

#[inline(always)]
pub(super) fn decode_wide(bytes: &[u8], max_len: usize) -> Option<(u64, usize)> {
    match bytes.first_chunk::<8>() {
        Some(chunk) if u64::from_le_bytes(*chunk) & MSB == MSB => {
            decode_long(u64::from_le_bytes(*chunk), bytes)
        }
        _ => decode(bytes, max_len),
    }
}

#[inline]
fn decode_long(word: u64, bytes: &[u8]) -> Option<(u64, usize)> {
    let &ninth = bytes.get(8)?;
    let value = compact(word & LOW7) | (u64::from(ninth & 0x7F) << 56);
    if ninth < 0x80 {
        Some((value, 9))
    } else {
        let &tenth = bytes.get(9)?;
        (tenth <= 1).then_some((value | (u64::from(tenth) << 63), 10))
    }
}

#[inline]
pub(super) fn skip(bytes: &[u8], mut count: usize) -> Option<usize> {
    let mut offset = 0;
    while count > 0 {
        let rest = bytes.get(offset..)?;
        if let Some(chunk) = rest.first_chunk::<8>() {
            let mut stops = !u64::from_le_bytes(*chunk) & MSB;
            let found = stops.count_ones() as usize;
            if found < count {
                offset += 8;
                count -= found;
            } else {
                for _ in 1..count {
                    stops &= stops - 1;
                }
                return Some(offset + (stops.trailing_zeros() as usize >> 3) + 1);
            }
        } else {
            for (index, &byte) in rest.iter().enumerate() {
                if byte < 0x80 {
                    count -= 1;
                    if count == 0 {
                        return Some(offset + index + 1);
                    }
                }
            }
            return None;
        }
    }
    Some(offset)
}
