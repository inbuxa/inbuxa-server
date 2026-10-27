/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    format::{AsciiPush, BufferedWrite},
    parser::Timestamp,
};
use crate::vcard::Jscomp;
use encodify::{Fold, base64};
use mail_parser::DateTime;
use std::fmt::{self, Display, Write};

pub(crate) const MAX_LINE_LEN: usize = 75;
const FOLD: &str = "\r\n ";

pub(crate) const DOCUMENT_BUFFER: usize = 4096;
pub(crate) const ENTRY_BUFFER: usize = 512;

const TEXT: u8 = 1;
const TEXT_SEMICOLON: u8 = 1 << 1;
const TEXT_COMMA: u8 = 1 << 2;
const URI: u8 = 1 << 3;
const PARAM: u8 = 1 << 4;
const PARAM_CARET: u8 = 1 << 5;
const JSCOMP: u8 = 1 << 6;
const QUOTE: u8 = 1 << 7;

const fn byte_class(ch: u8) -> u8 {
    let mut class = 0;
    if matches!(ch, b'\r' | b'\n' | b'\\') {
        class |= TEXT;
    }
    if ch == b';' {
        class |= TEXT_SEMICOLON;
    }
    if ch == b',' {
        class |= TEXT_COMMA;
    }
    if matches!(ch, b'\r' | b'\n') {
        class |= URI;
    }
    if ch == b'\\' || !matches!(ch, 0x09 | 0x20 | 0x21 | 0x23..=0x7E | 0x80..=0xFF) {
        class |= PARAM;
    }
    if ch == b'^' {
        class |= PARAM_CARET;
    }
    if matches!(ch, b'\\' | b',' | b':' | b'=' | b';' | b'"' | b'\r' | b'\n') {
        class |= JSCOMP;
    }
    if matches!(ch, b',' | b':' | b'=' | b' ' | b';' | b'"') {
        class |= QUOTE;
    }
    class
}

static BYTE_CLASS: [u8; 256] = {
    let mut table = [0; 256];
    let mut ch = 0;
    while ch < table.len() {
        table[ch] = byte_class(ch as u8);
        ch += 1;
    }
    table
};

const LANE_ONES: u64 = 0x0101_0101_0101_0101;
const LANE_HIGHS: u64 = 0x8080_8080_8080_8080;

#[inline(always)]
const fn lanes_equal(word: u64, byte: u8) -> u64 {
    let lanes = word ^ (LANE_ONES * byte as u64);
    lanes.wrapping_sub(LANE_ONES) & !lanes & LANE_HIGHS
}

#[inline(always)]
const fn lanes_below(word: u64, byte: u8) -> u64 {
    word.wrapping_sub(LANE_ONES * byte as u64) & !word & LANE_HIGHS
}

#[inline(always)]
const fn candidate_lanes<const MASK: u8>(word: u64) -> u64 {
    let mut lanes = 0;
    if MASK & (TEXT | URI | JSCOMP) != 0 {
        lanes |= lanes_equal(word, b'\r') | lanes_equal(word, b'\n');
    }
    if MASK & (TEXT | PARAM | JSCOMP) != 0 {
        lanes |= lanes_equal(word, b'\\');
    }
    if MASK & (TEXT_SEMICOLON | JSCOMP | QUOTE) != 0 {
        lanes |= lanes_equal(word, b';');
    }
    if MASK & (TEXT_COMMA | JSCOMP | QUOTE) != 0 {
        lanes |= lanes_equal(word, b',');
    }
    if MASK & (PARAM | JSCOMP | QUOTE) != 0 {
        lanes |= lanes_equal(word, b'"');
    }
    if MASK & (JSCOMP | QUOTE) != 0 {
        lanes |= lanes_equal(word, b':') | lanes_equal(word, b'=');
    }
    if MASK & QUOTE != 0 {
        lanes |= lanes_equal(word, b' ');
    }
    if MASK & PARAM != 0 {
        lanes |= lanes_below(word, 0x20) | lanes_equal(word, 0x7F);
    }
    if MASK & PARAM_CARET != 0 {
        lanes |= lanes_equal(word, b'^');
    }
    lanes
}

#[inline(always)]
fn find_class<const MASK: u8>(bytes: &[u8]) -> Option<usize> {
    let (words, tail) = bytes.as_chunks::<8>();
    let mut offset = 0;
    for word in words {
        let mut lanes = candidate_lanes::<MASK>(u64::from_le_bytes(*word));
        while lanes != 0 {
            let pos = offset + (lanes.trailing_zeros() / 8) as usize;
            if MASK & PARAM == 0
                || bytes
                    .get(pos)
                    .is_some_and(|&ch| BYTE_CLASS[usize::from(ch)] & MASK != 0)
            {
                return Some(pos);
            }
            lanes &= lanes - 1;
        }
        offset += 8;
    }
    tail.iter()
        .position(|&ch| BYTE_CLASS[usize::from(ch)] & MASK != 0)
        .map(|pos| offset + pos)
}

#[inline(always)]
fn split_at_class<const MASK: u8>(text: &str) -> Option<(&str, u8, &str)> {
    let pos = find_class::<MASK>(text.as_bytes())?;
    let (run, rest) = text.split_at_checked(pos)?;
    let special = *rest.as_bytes().first()?;
    Some((run, special, rest.get(1..)?))
}

pub(crate) trait LineWriter: Write + AsciiPush {
    fn write_atomic(&mut self, text: &str) -> fmt::Result;

    fn write_base64(&mut self, data: &[u8]) -> fmt::Result;
}

pub(crate) struct FoldingWriter<'x, W: Write + AsciiPush + ?Sized> {
    out: &'x mut W,
    line_len: usize,
}

impl<'x, W: Write + AsciiPush + ?Sized> FoldingWriter<'x, W> {
    pub(crate) fn new(out: &'x mut W) -> Self {
        Self { out, line_len: 0 }
    }

    pub(crate) fn end_line(&mut self) -> fmt::Result {
        self.line_len = 0;
        self.out.push_ascii(b"\r\n")
    }

    pub(crate) fn write_boundary(&mut self, keyword: &str, name: &str) -> fmt::Result {
        self.write_atomic(keyword)?;
        self.write_atomic(name)?;
        self.end_line()
    }

    pub(crate) fn write_raw(&mut self, text: &str) -> fmt::Result {
        self.out.write_str(text)
    }

    #[inline(never)]
    fn write_folded(&mut self, text: &str) -> fmt::Result {
        let mut rest = text;

        loop {
            let available = MAX_LINE_LEN.saturating_sub(self.line_len);

            if rest.len() <= available {
                self.line_len += rest.len();
                return self.out.write_str(rest);
            }

            match rest.split_at_checked(rest.floor_char_boundary(available)) {
                Some((line, tail)) if !line.is_empty() => {
                    self.out.write_str(line)?;
                    self.line_len += line.len();
                    rest = tail;
                }
                _ => {
                    self.out.push_ascii(FOLD.as_bytes())?;
                    self.line_len = 1;
                }
            }
        }
    }

    #[inline(never)]
    fn push_ascii_folded(&mut self, bytes: &[u8]) -> fmt::Result {
        let mut rest = bytes;

        while !rest.is_empty() {
            let available = MAX_LINE_LEN.saturating_sub(self.line_len);
            if available == 0 {
                self.out.push_ascii(FOLD.as_bytes())?;
                self.line_len = 1;
                continue;
            }
            let (line, tail) = rest
                .split_at_checked(available.min(rest.len()))
                .unwrap_or((rest, &[]));
            self.out.push_ascii(line)?;
            self.line_len += line.len();
            rest = tail;
        }

        Ok(())
    }
}

impl<W: Write + AsciiPush + ?Sized> AsciiPush for FoldingWriter<'_, W> {
    #[inline(always)]
    fn push_ascii(&mut self, bytes: &[u8]) -> fmt::Result {
        if bytes.len() <= MAX_LINE_LEN.saturating_sub(self.line_len) {
            self.line_len += bytes.len();
            self.out.push_ascii(bytes)
        } else {
            self.push_ascii_folded(bytes)
        }
    }
}

impl<W: Write + AsciiPush + ?Sized> LineWriter for FoldingWriter<'_, W> {
    #[inline(always)]
    fn write_atomic(&mut self, text: &str) -> fmt::Result {
        let len = text.len();
        if len > MAX_LINE_LEN - 1 {
            return self.write_str(text);
        }
        if self.line_len + len > MAX_LINE_LEN {
            self.out.push_ascii(FOLD.as_bytes())?;
            self.line_len = 1;
        }
        self.line_len += len;
        self.out.write_str(text)
    }

    fn write_base64(&mut self, data: &[u8]) -> fmt::Result {
        let mut result = Ok(());
        let out = &mut *self.out;
        base64::STANDARD.encode_folded(data, &mut self.line_len, Fold::CONTENT_LINE, |piece| {
            if result.is_ok() {
                result = out.push_ascii(piece);
            }
        });
        result
    }
}

impl LineWriter for String {
    fn write_atomic(&mut self, text: &str) -> fmt::Result {
        self.push_str(text);
        Ok(())
    }

    fn write_base64(&mut self, data: &[u8]) -> fmt::Result {
        base64::STANDARD.encode_append(data, self);
        Ok(())
    }
}

impl<W: Write + AsciiPush + ?Sized> Write for FoldingWriter<'_, W> {
    #[inline]
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if text.len() <= MAX_LINE_LEN.saturating_sub(self.line_len) {
            self.line_len += text.len();
            self.out.write_str(text)
        } else {
            self.write_folded(text)
        }
    }

    fn write_char(&mut self, ch: char) -> fmt::Result {
        let ch_len = ch.len_utf8();
        if self.line_len + ch_len > MAX_LINE_LEN {
            self.out.push_ascii(FOLD.as_bytes())?;
            self.line_len = 1;
        }
        self.line_len += ch_len;
        self.out.write_char(ch)
    }
}

const INLINE_COMPONENTS: usize = 256;

pub(crate) struct VisitedComponents {
    inline: [u64; INLINE_COMPONENTS / 64],
    spilled: Vec<u64>,
}

impl VisitedComponents {
    pub(crate) fn new(len: usize) -> Self {
        Self {
            inline: [0; INLINE_COMPONENTS / 64],
            spilled: if len > INLINE_COMPONENTS {
                vec![0; len.div_ceil(64)]
            } else {
                Vec::new()
            },
        }
    }

    #[inline]
    pub(crate) fn insert(&mut self, id: usize) -> bool {
        let words = if self.spilled.is_empty() {
            self.inline.as_mut_slice()
        } else {
            self.spilled.as_mut_slice()
        };
        match words.get_mut(id / 64) {
            Some(word) => {
                let bit = 1 << (id % 64);
                let fresh = *word & bit == 0;
                *word |= bit;
                fresh
            }
            None => false,
        }
    }
}

pub(crate) fn write_text(
    out: &mut impl LineWriter,
    value: &str,
    escape_semicolon: bool,
    escape_comma: bool,
) -> fmt::Result {
    match (escape_semicolon, escape_comma) {
        (true, true) => write_text_class::<{ TEXT | TEXT_SEMICOLON | TEXT_COMMA }>(out, value),
        (true, false) => write_text_class::<{ TEXT | TEXT_SEMICOLON }>(out, value),
        (false, true) => write_text_class::<{ TEXT | TEXT_COMMA }>(out, value),
        (false, false) => write_text_class::<TEXT>(out, value),
    }
}

fn write_text_class<const MASK: u8>(out: &mut impl LineWriter, value: &str) -> fmt::Result {
    let mut rest = value;
    while let Some((run, special, tail)) = split_at_class::<MASK>(rest) {
        if !run.is_empty() {
            out.write_str(run)?;
        }
        out.write_atomic(match special {
            b'\r' => "\\r",
            b'\n' => "\\n",
            b'\\' => "\\\\",
            b';' => "\\;",
            _ => "\\,",
        })?;
        rest = tail;
    }

    if rest.is_empty() {
        Ok(())
    } else {
        out.write_str(rest)
    }
}

pub(crate) fn write_uri(out: &mut impl LineWriter, value: &str) -> fmt::Result {
    let mut rest = value;
    while let Some((run, special, tail)) = split_at_class::<URI>(rest) {
        if !run.is_empty() {
            out.write_str(run)?;
        }
        out.write_atomic(if special == b'\r' { "\\r" } else { "\\n" })?;
        rest = tail;
    }

    if rest.is_empty() {
        Ok(())
    } else {
        out.write_str(rest)
    }
}

pub(crate) trait NeedsQuotes {
    fn needs_quotes(&self) -> bool;
}

impl<T: AsRef<[u8]>> NeedsQuotes for T {
    fn needs_quotes(&self) -> bool {
        find_class::<QUOTE>(self.as_ref()).is_some()
    }
}

pub(crate) fn write_param_value(
    out: &mut impl LineWriter,
    value: &str,
    caret_escape: bool,
) -> fmt::Result {
    if value.needs_quotes() {
        write_quoted_param_value(out, value, caret_escape)
    } else {
        write_param_text(out, value, caret_escape)
    }
}

pub(crate) fn write_quoted_param_value(
    out: &mut impl LineWriter,
    value: &str,
    caret_escape: bool,
) -> fmt::Result {
    out.write_atomic("\"")?;
    write_param_text(out, value, caret_escape)?;
    out.write_atomic("\"")
}

pub(crate) fn write_param_text(
    out: &mut impl LineWriter,
    value: &str,
    caret_escape: bool,
) -> fmt::Result {
    if caret_escape {
        write_param_text_class::<{ PARAM | PARAM_CARET }>(out, value)
    } else {
        write_param_text_class::<PARAM>(out, value)
    }
}

fn write_param_text_class<const MASK: u8>(out: &mut impl LineWriter, value: &str) -> fmt::Result {
    let caret_escape = MASK & PARAM_CARET != 0;
    let mut rest = value;
    while let Some((run, special, tail)) = split_at_class::<MASK>(rest) {
        if !run.is_empty() {
            out.write_str(run)?;
        }
        let escaped = match special {
            b'\r' if tail.starts_with('\n') => None,
            b'\n' | b'\r' if caret_escape => Some("^n"),
            b'\n' | b'\r' => Some("\\n"),
            b'^' => Some("^^"),
            b'"' if caret_escape => Some("^'"),
            b'"' => Some("\\\""),
            b'\\' => Some("\\\\"),
            _ => None,
        };
        if let Some(escaped) = escaped {
            out.write_atomic(escaped)?;
        }
        rest = tail;
    }

    if rest.is_empty() {
        Ok(())
    } else {
        out.write_str(rest)
    }
}

pub(crate) enum JscompRef<'x> {
    Entry { position: u32, value: u32 },
    Separator(&'x str),
}

impl<'x> From<&'x Jscomp> for JscompRef<'x> {
    fn from(jscomp: &'x Jscomp) -> Self {
        match jscomp {
            Jscomp::Entry { position, value } => JscompRef::Entry {
                position: *position,
                value: *value,
            },
            Jscomp::Separator(separator) => JscompRef::Separator(separator),
        }
    }
}

impl JscompRef<'_> {
    fn write_to(self, out: &mut impl LineWriter) -> fmt::Result {
        match self {
            JscompRef::Entry { position, value } => {
                out.push_u64(position.into())?;
                if value > 0 {
                    out.push_byte(b',')?;
                    out.push_u64(value.into())?;
                }
                Ok(())
            }
            JscompRef::Separator("") => Ok(()),
            JscompRef::Separator(separator) => {
                out.write_atomic("s,")?;
                let mut rest = separator;
                while let Some((run, special, tail)) = split_at_class::<JSCOMP>(rest) {
                    if !run.is_empty() {
                        out.write_str(run)?;
                    }
                    let escaped = match special {
                        b'\\' => "\\\\",
                        b',' => "\\,",
                        b':' => "\\:",
                        b'=' => "\\=",
                        b';' => "\\;",
                        b'"' => "\\\"",
                        _ => "",
                    };
                    if !escaped.is_empty() {
                        out.write_atomic(escaped)?;
                    }
                    rest = tail;
                }

                if rest.is_empty() {
                    Ok(())
                } else {
                    out.write_str(rest)
                }
            }
        }
    }
}

pub(crate) fn write_jscomps<'x, J: 'x>(out: &mut impl LineWriter, values: &'x [J]) -> fmt::Result
where
    &'x J: Into<JscompRef<'x>>,
{
    for (pos, item) in values.iter().enumerate() {
        if pos > 0 {
            out.write_atomic(";")?;
        }
        item.into().write_to(out)?;
    }

    Ok(())
}

impl Timestamp {
    pub(crate) fn push_to(&self, buf: &mut impl AsciiPush) -> fmt::Result {
        let dt = DateTime::from_timestamp(self.0);
        buf.push_4_digits(dt.year)?;
        buf.push_2_digits(dt.month)?;
        buf.push_2_digits(dt.day)?;
        buf.push_byte(b'T')?;
        buf.push_2_digits(dt.hour)?;
        buf.push_2_digits(dt.minute)?;
        buf.push_2_digits(dt.second)?;
        buf.push_byte(b'Z')
    }
}

#[cfg(all(test, stalwart_tests))]
pub(crate) fn assert_fold_width(text: &str, context: &str) {
    let mut lines = text.split("\r\n").peekable();
    let is_v21 = text.contains("\r\nVERSION:2.1\r\n");
    let mut ends_v21_base64 = false;

    while let Some(line) = lines.next() {
        if !line.is_empty() && !line.starts_with(' ') {
            ends_v21_base64 = is_v21 && line.contains(";ENCODING=BASE64");
        }
        assert!(
            line.len() <= MAX_LINE_LEN,
            "physical line of {} octets exceeds the {MAX_LINE_LEN} octet fold width in {context}: {line:?}",
            line.len()
        );
        assert!(
            !line.is_empty() || lines.peek().is_none() || std::mem::take(&mut ends_v21_base64),
            "empty physical line in {context}: {text:?}"
        );
        assert!(
            line != " ",
            "continuation line holding nothing but the fold character in {context}: {text:?}"
        );
    }
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_buffered::<32>(|buf| self.push_to(buf))
    }
}
