/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::pdf::tables::{
    CodeRadix, GlyphCode, glyph_name_code, glyph_unicode, zapf_dingbats_unicode,
};

const NOTDEF: &[u8] = b".notdef";
const MAX_INDEX_DIGITS: usize = 3;
const INDEXED_CODES: std::ops::RangeInclusive<u32> = 0x20..=0xFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accept,
    Space,
    Reject,
    PrivateUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Numeric {
    Glyph(CodeRadix),
    Indexed,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NameResolver {
    pub(crate) zapf: bool,
    pub(crate) numeric: Option<Numeric>,
}

pub(crate) fn verdict(text: &str) -> Verdict {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return Verdict::Reject;
    };
    if chars.next().is_some() {
        return if text.chars().all(|ch| ch == '\0') {
            Verdict::Reject
        } else {
            Verdict::Accept
        };
    }
    match u32::from(first) {
        0x08..=0x0D => Verdict::Space,
        0x00..=0x1F | 0x7F..=0x9F | 0xFFFD..=0xFFFF | 0xFDD0..=0xFDEF => Verdict::Reject,
        code if is_private_use(code) => Verdict::PrivateUse,
        _ => Verdict::Accept,
    }
}

pub(crate) fn is_private_use(code: u32) -> bool {
    matches!(code, 0xE000..=0xF8FF | 0xF_0000..=0x10_FFFF)
}

impl NameResolver {
    pub(crate) fn for_names<'n>(zapf: bool, names: impl Iterator<Item = &'n [u8]> + Clone) -> Self {
        let numeric = numeric_radix(names.clone())
            .map(Numeric::Glyph)
            .or_else(|| (!zapf && indexed(names)).then_some(Numeric::Indexed));
        NameResolver { zapf, numeric }
    }

    pub(crate) fn resolve(&self, name: &[u8], out: &mut String) -> bool {
        if name.is_empty() || name == NOTDEF {
            return false;
        }
        let mark = out.len();
        let found = if self.zapf {
            zapf_dingbats_unicode(name, out)
        } else {
            glyph_unicode(name, out)
        };
        if found {
            if verdict(out.get(mark..).unwrap_or_default()) == Verdict::Accept {
                return true;
            }
            out.truncate(mark);
        }
        let code = match self.numeric {
            Some(Numeric::Glyph(radix)) => match glyph_name_code(name, radix) {
                Some(GlyphCode::Code(code)) => Some(code),
                _ => None,
            },
            Some(Numeric::Indexed) => index(name).filter(|code| INDEXED_CODES.contains(code)),
            None => None,
        };
        match code.and_then(char::from_u32) {
            Some(ch) if verdict(ch.encode_utf8(&mut [0u8; 4])) == Verdict::Accept => {
                out.push(ch);
                true
            }
            _ => false,
        }
    }
}

fn index(name: &[u8]) -> Option<u32> {
    let digits = name.strip_prefix(b"a")?;
    if digits.is_empty() || digits.len() > MAX_INDEX_DIGITS {
        return None;
    }
    digits.iter().try_fold(0u32, |value, &byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(byte - b'0'))
    })
}

fn indexed<'n>(names: impl Iterator<Item = &'n [u8]>) -> bool {
    let mut any = false;
    for name in names {
        if index(name).is_none() {
            return false;
        }
        any = true;
    }
    any
}

fn numeric_radix<'n>(names: impl Iterator<Item = &'n [u8]> + Clone) -> Option<CodeRadix> {
    let mut any = false;
    let mut radix = CodeRadix::Decimal;
    for name in names.clone() {
        any = true;
        match glyph_name_code(name, CodeRadix::Decimal)? {
            GlyphCode::Code(_) => {}
            GlyphCode::NeedsHex => radix = CodeRadix::Hex,
        }
    }
    if !any {
        return None;
    }
    if radix == CodeRadix::Hex
        && !names.into_iter().all(|name| {
            matches!(
                glyph_name_code(name, CodeRadix::Hex),
                Some(GlyphCode::Code(_))
            )
        })
    {
        return None;
    }
    Some(radix)
}

