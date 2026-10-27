/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ASCII_ALNUM, ASCII_SPACE, StopChar, TokenType};

cfg_select! {
    swar_alnum => {
        pub(super) use dispatch::scan_word;
    }
    _ => {
        pub(super) use sequential::scan_word;
    }
}

#[inline(always)]
fn scalar_alnum_run(bytes: &[u8], mut pos: usize) -> (usize, u8) {
    let mut classes = 0;
    while let Some(&byte) = bytes.get(pos) {
        let class = ASCII_ALNUM[byte as usize];
        if class == 0 {
            break;
        }
        classes |= class;
        pos += 1;
    }
    (pos, classes)
}

#[inline(always)]
fn ascii_stop<'x>(byte: u8) -> StopChar<'x> {
    let is_space = ASCII_SPACE[byte as usize];
    (
        if is_space {
            TokenType::Space
        } else {
            TokenType::Punctuation(byte as char)
        },
        1,
        is_space,
    )
}

#[inline(always)]
fn non_ascii_stop<'x>(ch: char) -> StopChar<'x> {
    let is_space = ch.is_whitespace();
    (
        if is_space {
            TokenType::Space
        } else {
            TokenType::Other(ch)
        },
        ch.len_utf8(),
        is_space,
    )
}

#[cfg(any(all(test, stalwart_tests), not(swar_alnum)))]
mod sequential {
    use super::{
        super::{CLASS_ALPHA, StopChar, char_at, is_alphabetic},
        ascii_stop, non_ascii_stop, scalar_alnum_run,
    };

    #[inline(always)]
    pub(in super::super) fn scan_word(
        text: &str,
        mut pos: usize,
    ) -> (usize, u8, Option<StopChar<'_>>) {
        let bytes = text.as_bytes();
        let mut classes = 0;
        let stop = loop {
            let (end, run_classes) = scalar_alnum_run(bytes, pos);
            pos = end;
            classes |= run_classes;
            match bytes.get(pos) {
                None => break None,
                Some(&byte) if byte < 0x80 => break Some(ascii_stop(byte)),
                Some(_) => match char_at(text, pos) {
                    Some(ch) if is_alphabetic(ch as u32) => {
                        classes |= CLASS_ALPHA;
                        pos += ch.len_utf8();
                    }
                    Some(ch) => break Some(non_ascii_stop(ch)),
                    None => break None,
                },
            }
        };
        (pos, classes, stop)
    }
}

#[cfg(any(all(test, stalwart_tests), swar_alnum))]
mod dispatch {
    use super::{
        super::{ASCII_ALNUM, CLASS_ALPHA, StopChar, is_alphabetic},
        ascii_stop, non_ascii_stop, swar,
    };

    #[inline(always)]
    pub(in super::super) fn scan_word(
        text: &str,
        mut pos: usize,
    ) -> (usize, u8, Option<StopChar<'_>>) {
        let bytes = text.as_bytes();
        let mut classes = 0;
        let stop = loop {
            match bytes.get(pos) {
                None => break None,
                Some(&byte) if ASCII_ALNUM[byte as usize] != 0 => {
                    let (end, run_classes) = swar::ascii_alnum_run(bytes, pos);
                    pos = end;
                    classes |= run_classes;
                }
                Some(&byte) if byte < 0x80 => break Some(ascii_stop(byte)),
                Some(_) => {
                    let Some((code, len)) = decode_non_ascii(bytes, pos) else {
                        break None;
                    };
                    if !is_alphabetic(code) {
                        break char::from_u32(code).map(non_ascii_stop);
                    }
                    classes |= CLASS_ALPHA;
                    pos += len;
                    if bytes.get(pos).is_some_and(|&byte| byte >= 0x80) {
                        pos = non_ascii_alphabetic_run(bytes, pos);
                    }
                }
            }
        };
        (pos, classes, stop)
    }

    #[inline(always)]
    pub(super) fn decode_non_ascii(bytes: &[u8], pos: usize) -> Option<(u32, usize)> {
        match *bytes.get(pos..)? {
            [lead @ 0xC0..=0xDF, b1, ..] => {
                Some(((u32::from(lead & 0x1F) << 6) | u32::from(b1 & 0x3F), 2))
            }
            [lead @ 0xE0..=0xEF, b1, b2, ..] => Some((
                (u32::from(lead & 0x0F) << 12) | (u32::from(b1 & 0x3F) << 6) | u32::from(b2 & 0x3F),
                3,
            )),
            [lead @ 0xF0..=0xF7, b1, b2, b3, ..] => Some((
                (u32::from(lead & 0x07) << 18)
                    | (u32::from(b1 & 0x3F) << 12)
                    | (u32::from(b2 & 0x3F) << 6)
                    | u32::from(b3 & 0x3F),
                4,
            )),
            _ => None,
        }
    }

    #[inline(never)]
    fn non_ascii_alphabetic_run(bytes: &[u8], mut pos: usize) -> usize {
        while let Some((code, len)) = decode_non_ascii(bytes, pos) {
            if !is_alphabetic(code) {
                break;
            }
            pos += len;
        }
        pos
    }
}

#[cfg(any(all(test, stalwart_tests), swar_alnum))]
mod swar {
    use super::{
        super::{CLASS_ALPHA, CLASS_DIGIT},
        scalar_alnum_run,
    };

    const LANES: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = LANES * 0x80;
    const LOW: u64 = LANES * 0x7f;
    const CASE: u64 = LANES * 0x20;
    const WORD: usize = size_of::<u64>();

    #[inline(always)]
    fn in_range(low: u64, first: u8, last: u8) -> u64 {
        (low + LANES * (0x80 - first as u64)) & !(low + LANES * (0x7f - last as u64))
    }

    #[inline(always)]
    fn run_classes(digits: u64, alphas: u64) -> u8 {
        (u8::from(digits != 0) * CLASS_DIGIT) | (u8::from(alphas != 0) * CLASS_ALPHA)
    }

    #[inline(always)]
    pub(super) fn ascii_alnum_run(bytes: &[u8], mut pos: usize) -> (usize, u8) {
        let mut digits = 0;
        let mut alphas = 0;
        while let Some(chunk) = bytes.get(pos..).and_then(<[u8]>::first_chunk::<WORD>) {
            let word = u64::from_le_bytes(*chunk);
            let low = word & LOW;
            let ascii = !word & HIGH;
            let digit = in_range(low, b'0', b'9') & ascii;
            let alpha = in_range(low | CASE, b'a', b'z') & ascii;
            let stop = !(digit | alpha) & HIGH;
            let run = stop.wrapping_sub(1) & !stop;
            digits |= digit & run;
            alphas |= alpha & run;
            if stop != 0 {
                return (
                    pos + (stop.trailing_zeros() / u8::BITS) as usize,
                    run_classes(digits, alphas),
                );
            }
            pos += WORD;
        }
        let (end, classes) = scalar_alnum_run(bytes, pos);
        (end, classes | run_classes(digits, alphas))
    }
}

