/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

include!(concat!(env!("OUT_DIR"), "/unicode_bmp.rs"));

#[inline(always)]
fn bmp_bit(table: &[u64], code: u32) -> Option<bool> {
    table
        .get(code as usize / 64)
        .map(|word| (word >> (code % 64)) & 1 != 0)
}

#[inline(always)]
pub(super) fn is_alphabetic(code: u32) -> bool {
    bmp_bit(&ALPHABETIC_BMP, code)
        .unwrap_or_else(|| char::from_u32(code).is_some_and(char::is_alphabetic))
}

#[inline(always)]
pub(super) fn is_alphanumeric(ch: char) -> bool {
    bmp_bit(&ALPHANUMERIC_BMP, ch as u32).unwrap_or_else(|| ch.is_alphanumeric())
}

#[inline(always)]
pub(super) fn is_uppercase(ch: char) -> bool {
    bmp_bit(&UPPERCASE_BMP, ch as u32).unwrap_or_else(|| ch.is_uppercase())
}

