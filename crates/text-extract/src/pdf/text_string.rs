/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::tables::pdfdoc_char;

const UTF16_BE_BOM: &[u8] = b"\xFE\xFF";
const UTF16_LE_BOM: &[u8] = b"\xFF\xFE";
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
const ESCAPE: u8 = 0x1B;
const ESCAPE_UNIT: u16 = 0x1B;

pub(crate) fn decode_text_string(bytes: &[u8], out: &mut String) {
    if let Some(rest) = bytes.strip_prefix(UTF16_BE_BOM) {
        push_utf16(
            rest.as_chunks::<2>()
                .0
                .iter()
                .map(|&pair| u16::from_be_bytes(pair)),
            out,
        );
    } else if let Some(rest) = bytes.strip_prefix(UTF16_LE_BOM) {
        push_utf16(
            rest.as_chunks::<2>()
                .0
                .iter()
                .map(|&pair| u16::from_le_bytes(pair)),
            out,
        );
    } else if let Some(rest) = bytes.strip_prefix(UTF8_BOM) {
        let mut skipping = false;
        for chunk in rest.utf8_chunks() {
            for ch in chunk.valid().chars() {
                if ch == char::from(ESCAPE) {
                    skipping = !skipping;
                } else if !skipping {
                    out.push(ch);
                }
            }
            if !chunk.invalid().is_empty() && !skipping {
                out.push(char::REPLACEMENT_CHARACTER);
            }
        }
    } else {
        let mut skipping = false;
        for &byte in bytes {
            if byte == ESCAPE {
                skipping = !skipping;
            } else if !skipping && let Some(ch) = pdfdoc_char(byte) {
                out.push(ch);
            }
        }
    }
}

fn push_utf16(units: impl Iterator<Item = u16>, out: &mut String) {
    let mut skipping = false;
    let filtered = units.filter(|&unit| {
        if unit == ESCAPE_UNIT {
            skipping = !skipping;
            return false;
        }
        !skipping
    });
    out.extend(char::decode_utf16(filtered).map(|ch| ch.unwrap_or(char::REPLACEMENT_CHARACTER)));
}

