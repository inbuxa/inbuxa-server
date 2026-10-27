/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Parser,
    common::{
        Encoding, IanaParse,
        scan::{self, Mask},
    },
};
use encodify::base64;
use std::ops::{Deref, Range};

const SPARE_BYTES: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Token<'x> {
    pub(crate) text: TokenText<'x>,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) stop_char: StopChar,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TokenText<'x> {
    Borrowed(&'x str),
    Owned(String),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum StopChar {
    Colon,
    Semicolon,
    Comma,
    Equal,
    Dot,
    Lf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mode(u16);

impl Mode {
    pub(crate) const STOP_COLON: Mode = Mode(scan::COLON);
    pub(crate) const STOP_SEMICOLON: Mode = Mode(scan::SEMICOLON);
    pub(crate) const STOP_COMMA: Mode = Mode(scan::COMMA);
    pub(crate) const STOP_EQUAL: Mode = Mode(scan::EQUAL);
    pub(crate) const STOP_DOT: Mode = Mode(scan::DOT);
    pub(crate) const UNFOLD_QP: Mode = Mode(1 << 11);
    pub(crate) const UNFOLD_B64: Mode = Mode(1 << 12);
    pub(crate) const UNQUOTE: Mode = Mode(scan::QUOTE);
    pub(crate) const SKIP_WS: Mode = Mode(scan::WHITESPACE);
    pub(crate) const STRIP_CTL: Mode = Mode(scan::CONTROL);
    pub(crate) const UNESCAPE_CARET: Mode = Mode(scan::CARET);
    pub(crate) const UNESCAPE_BACKSLASH: Mode = Mode(scan::BACKSLASH);

    pub(crate) const INITIAL: Mode = Mode(
        Mode::STOP_COLON.0
            | Mode::STOP_SEMICOLON.0
            | Mode::STOP_COMMA.0
            | Mode::STOP_EQUAL.0
            | Mode::UNQUOTE.0
            | Mode::UNESCAPE_BACKSLASH.0,
    );
    const IANA_TOKEN: Mode = Mode(
        Mode::STOP_COLON.0
            | Mode::STOP_SEMICOLON.0
            | Mode::STOP_COMMA.0
            | Mode::STOP_EQUAL.0
            | Mode::UNQUOTE.0
            | Mode::SKIP_WS.0
            | Mode::UNESCAPE_BACKSLASH.0,
    );
    const SINGLE_VALUE: Mode = Mode::UNESCAPE_BACKSLASH;
    const MULTI_VALUE_COMMA: Mode =
        Mode(Mode::STOP_COMMA.0 | Mode::SKIP_WS.0 | Mode::UNESCAPE_BACKSLASH.0);
    const MULTI_VALUE_SEMICOLON: Mode = Mode(Mode::STOP_SEMICOLON.0 | Mode::UNESCAPE_BACKSLASH.0);
    const MULTI_VALUE_SEMICOLON_AND_COMMA: Mode =
        Mode(Mode::STOP_SEMICOLON.0 | Mode::STOP_COMMA.0 | Mode::UNESCAPE_BACKSLASH.0);
    const PARAM_VALUE: Mode = Mode(
        Mode::STOP_COLON.0
            | Mode::STOP_SEMICOLON.0
            | Mode::STOP_COMMA.0
            | Mode::UNQUOTE.0
            | Mode::SKIP_WS.0
            | Mode::STRIP_CTL.0
            | Mode::UNESCAPE_CARET.0
            | Mode::UNESCAPE_BACKSLASH.0,
    );
    const RRULE_VALUE: Mode = Mode(
        Mode::STOP_COLON.0
            | Mode::STOP_COMMA.0
            | Mode::STOP_EQUAL.0
            | Mode::STOP_SEMICOLON.0
            | Mode::SKIP_WS.0
            | Mode::UNESCAPE_BACKSLASH.0,
    );

    const PLAIN_VALUE: Mode = Mode(Mode::UNESCAPE_BACKSLASH.0 | Mode::UNFOLD_B64.0);

    const UNFOLD: u16 = Self::UNFOLD_QP.0 | Self::UNFOLD_B64.0;
    const UNQUOTED_ONLY: u16 =
        scan::WHITESPACE | scan::COLON | scan::SEMICOLON | scan::COMMA | scan::EQUAL | scan::DOT;

    #[inline(always)]
    pub(crate) const fn contains(self, flag: Mode) -> bool {
        self.0 & flag.0 == flag.0
    }

    #[inline(always)]
    pub(crate) fn set(&mut self, flag: Mode, enabled: bool) {
        if enabled {
            self.0 |= flag.0;
        } else {
            self.0 &= !flag.0;
        }
    }

    #[inline(always)]
    const fn unquoted_mask(self) -> Mask {
        Mask::new(self.0 & !Self::UNFOLD)
    }

    #[inline(always)]
    const fn quoted_mask(self) -> Mask {
        Mask::new(self.0 & !Self::UNFOLD & !Self::UNQUOTED_ONLY)
    }
}

impl<'x> Parser<'x> {
    pub(crate) fn expect_iana_token(&mut self) {
        self.mode = Mode::IANA_TOKEN;
    }

    pub(crate) fn expect_single_value(&mut self) {
        self.mode = Mode::SINGLE_VALUE;
    }

    pub(crate) fn expect_multi_value_comma(&mut self) {
        self.mode = Mode::MULTI_VALUE_COMMA;
    }

    pub(crate) fn expect_multi_value_semicolon(&mut self) {
        self.mode = Mode::MULTI_VALUE_SEMICOLON;
    }

    pub(crate) fn expect_multi_value_semicolon_and_comma(&mut self) {
        self.mode = Mode::MULTI_VALUE_SEMICOLON_AND_COMMA;
    }

    pub(crate) fn expect_param_value(&mut self) {
        self.mode = Mode::PARAM_VALUE;
    }

    pub(crate) fn expect_rrule_value(&mut self) {
        self.mode = Mode::RRULE_VALUE;
    }

    fn caret_escape(&self, idx: usize) -> Option<(usize, char)> {
        let mut bytes = self.input.get(idx + 1..)?.iter().zip(idx + 1..);
        while let Some((ch, pos)) = bytes.next() {
            match ch {
                b'\r' if matches!(self.input.get(pos + 1), Some(b'\n')) => {}
                b'\n' => {
                    bytes.next().filter(|(ch, _)| matches!(ch, b' ' | b'\t'))?;
                }
                b'^' => return Some((pos, '^')),
                b'n' => return Some((pos, '\n')),
                b'\'' => return Some((pos, '"')),
                _ => return None,
            }
        }
        None
    }

    fn is_base64_continuation(&self, idx: usize) -> bool {
        let mut has_data = false;

        for ch in self.input.get(idx + 1..).unwrap_or_default() {
            match ch {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' => has_data = true,
                b'\r' => {}
                b'\n' => break,
                _ => return false,
            }
        }

        has_data
    }

    #[inline(always)]
    fn borrowed(&self, start: usize, end: usize) -> TokenText<'x> {
        TokenText::Borrowed(self.source.get(start..end).unwrap_or_default())
    }

    pub(crate) fn token(&mut self) -> Option<Token<'x>> {
        let input = self.input;
        let start = self.pos;
        let mask = self.mode.unquoted_mask();
        let rest = input.get(start..).unwrap_or_default();
        let run = mask.plain_len(rest);
        let end = start + run;
        let Some(&ch) = rest.get(run) else {
            if run == 0 {
                return None;
            }
            self.pos = end;
            self.last_token_end = end - 1;
            return Some(Token {
                text: self.borrowed(start, end),
                start,
                end: end - 1,
                stop_char: StopChar::Lf,
            });
        };
        let (stop_char, next) = match mask.class_of(ch) {
            scan::COLON => (StopChar::Colon, end + 1),
            scan::SEMICOLON => (StopChar::Semicolon, end + 1),
            scan::COMMA => (StopChar::Comma, end + 1),
            scan::EQUAL => (StopChar::Equal, end + 1),
            scan::DOT => (StopChar::Dot, end + 1),
            scan::EOL => {
                let lf = if ch == b'\n' {
                    end
                } else if input.get(end + 1) == Some(&b'\n') {
                    end + 1
                } else {
                    return self.token_slow(start, run);
                };
                if matches!(input.get(lf + 1), Some(b' ' | b'\t'))
                    || (run != 0
                        && self.mode.contains(Mode::UNFOLD_QP)
                        && input.get(end - 1) == Some(&b'='))
                    || self.mode.contains(Mode::UNFOLD_B64)
                {
                    return self.token_slow(start, run);
                }
                (StopChar::Lf, lf + 1)
            }
            scan::QUOTE if run == 0 => return self.quoted_token(start),
            _ => return self.token_slow(start, run),
        };
        self.pos = next;
        Some(if run != 0 {
            self.last_token_end = end - 1;
            Token {
                text: self.borrowed(start, end),
                start,
                end: end - 1,
                stop_char,
            }
        } else {
            Token {
                text: TokenText::Borrowed(""),
                start: next - 1,
                end: next - 1,
                stop_char,
            }
        })
    }

    #[inline(always)]
    fn quoted_token(&mut self, quote: usize) -> Option<Token<'x>> {
        let input = self.input;
        let inner_start = quote + 1;
        let inner = input.get(inner_start..).unwrap_or_default();
        let inner_len = self.mode.quoted_mask().plain_len(inner);
        let close = inner_start + inner_len;
        let stop_char = match input.get(close..close + 2) {
            Some(&[b'"', stop]) => match self.mode.unquoted_mask().class_of(stop) {
                scan::COLON => StopChar::Colon,
                scan::SEMICOLON => StopChar::Semicolon,
                scan::COMMA => StopChar::Comma,
                scan::EQUAL => StopChar::Equal,
                scan::DOT => StopChar::Dot,
                _ => return self.token_slow(quote, 0),
            },
            _ => return self.token_slow(quote, 0),
        };
        self.pos = close + 2;
        Some(if inner_len != 0 {
            self.last_token_end = close - 1;
            Token {
                text: self.borrowed(inner_start, close),
                start: inner_start,
                end: close - 1,
                stop_char,
            }
        } else {
            Token {
                text: TokenText::Borrowed(""),
                start: close + 1,
                end: close + 1,
                stop_char,
            }
        })
    }

    #[inline(never)]
    fn token_slow(&mut self, start: usize, run: usize) -> Option<Token<'x>> {
        let input = self.input;
        let source = self.source;
        let unquoted_mask = self.mode.unquoted_mask();
        let quoted_mask = self.mode.quoted_mask();
        let mut mask = unquoted_mask;
        let mut pos = start + run;
        let mut offset_start = if run != 0 { start } else { usize::MAX };
        let mut offset_end = if run != 0 {
            start + run - 1
        } else {
            usize::MAX
        };
        let mut last_idx = 0;
        let mut in_quote = false;
        let mut buf = OwnedText::default();
        let mut skipped_ws = usize::MAX;

        let stop_char = 'outer: loop {
            let Some(&ch) = input.get(pos) else {
                if offset_start != usize::MAX {
                    break StopChar::Lf;
                }
                self.pos = pos;
                return None;
            };
            let idx = pos;
            pos += 1;
            last_idx = idx;

            'special: {
                let content = match mask.class_of(ch) {
                    scan::EOL => {
                        let idx = if ch == b'\n' {
                            idx
                        } else if input.get(pos) == Some(&b'\n') {
                            last_idx = pos;
                            pos += 1;
                            last_idx
                        } else {
                            break 'special;
                        };
                        if self.mode.contains(Mode::UNFOLD_QP)
                            && buf.last().or_else(|| input.get(offset_end).copied()) == Some(b'=')
                        {
                            offset_end = idx;

                            if !buf.is_empty() {
                                buf.push('\n');
                            }
                        } else if let Some(b' ' | b'\t') = input.get(pos) {
                            pos += 1;
                            if buf.is_empty() && offset_start != usize::MAX {
                                buf.start(source.get(offset_start..=offset_end));
                            }

                            if skipped_ws != usize::MAX && !buf.is_empty() {
                                buf.restore_whitespace(input.get(skipped_ws..idx));
                            }
                            skipped_ws = usize::MAX;
                        } else if self.mode.contains(Mode::UNFOLD_B64)
                            && self.is_base64_continuation(idx)
                        {
                            if buf.is_empty() && offset_start != usize::MAX {
                                buf.start(source.get(offset_start..=offset_end));
                            }
                            skipped_ws = usize::MAX;
                        } else {
                            break 'outer StopChar::Lf;
                        }
                        break 'special;
                    }
                    scan::WHITESPACE => {
                        if !buf.last().is_some_and(|last| last != ch) {
                            if skipped_ws == usize::MAX {
                                skipped_ws = idx;
                            }
                            break 'special;
                        }
                        if ch == b'\t' { '\t' } else { ' ' }
                    }
                    scan::BACKSLASH => {
                        let mut next_ch = b'\\';
                        let mut next_offset_end = idx;
                        while let Some(&escaped) = input.get(pos) {
                            let escaped_idx = pos;
                            pos += 1;
                            match escaped {
                                b'\t' | b'\r' => {}
                                b'\n' => {
                                    if let Some(b' ' | b'\t') = input.get(pos) {
                                        pos += 1;
                                        if let Some(&folded) = input.get(pos) {
                                            next_ch = folded;
                                            next_offset_end = pos;
                                            pos += 1;
                                            break;
                                        }
                                    } else {
                                        offset_end = escaped_idx - 1;
                                        break 'outer StopChar::Lf;
                                    }
                                }
                                _ => {
                                    next_ch = escaped;
                                    next_offset_end = escaped_idx;
                                    break;
                                }
                            }
                        }
                        if offset_start != usize::MAX {
                            if buf.is_empty() {
                                buf.start(source.get(offset_start..=offset_end));
                            }

                            if skipped_ws != usize::MAX {
                                buf.restore_whitespace(input.get(skipped_ws..idx));
                            }
                        } else {
                            offset_start = next_offset_end;
                        }
                        skipped_ws = usize::MAX;
                        match next_ch {
                            b'n' | b'N' => buf.push('\n'),
                            b'r' | b'R' => buf.push('\r'),
                            ascii if ascii.is_ascii() => buf.push(char::from(ascii)),
                            _ => {
                                if let Some(escaped) = source
                                    .get(next_offset_end..)
                                    .and_then(|rest| rest.chars().next())
                                {
                                    buf.push(escaped);
                                    pos = next_offset_end + escaped.len_utf8();
                                    next_offset_end = pos - 1;
                                }
                            }
                        }
                        offset_end = next_offset_end;
                        break 'special;
                    }
                    scan::QUOTE => {
                        in_quote = !in_quote;
                        mask = if in_quote { quoted_mask } else { unquoted_mask };
                        break 'special;
                    }
                    scan::COLON => break 'outer StopChar::Colon,
                    scan::SEMICOLON => break 'outer StopChar::Semicolon,
                    scan::COMMA => break 'outer StopChar::Comma,
                    scan::EQUAL => break 'outer StopChar::Equal,
                    scan::DOT => break 'outer StopChar::Dot,
                    scan::CONTROL => {
                        if buf.is_empty() && offset_start != usize::MAX {
                            buf.start(source.get(offset_start..=offset_end));
                        }
                        break 'special;
                    }
                    scan::CARET => {
                        if let Some((escape_idx, decoded)) = self.caret_escape(idx) {
                            if offset_start != usize::MAX {
                                if buf.is_empty() {
                                    buf.start(source.get(offset_start..=offset_end));
                                }
                                if skipped_ws != usize::MAX {
                                    buf.restore_whitespace(input.get(skipped_ws..idx));
                                }
                            } else {
                                offset_start = escape_idx;
                            }
                            skipped_ws = usize::MAX;
                            buf.push(decoded);
                            offset_end = escape_idx;
                            pos = escape_idx + 1;
                            break 'special;
                        }
                        '^'
                    }
                    _ => {
                        pos = idx;
                        break 'special;
                    }
                };

                if offset_start == usize::MAX {
                    offset_start = idx;
                }
                offset_end = idx;
                skipped_ws = usize::MAX;

                if !buf.is_empty() {
                    buf.push(content);
                }
            }

            let run = mask.plain_len(input.get(pos..).unwrap_or_default());
            if run != 0 {
                if offset_start == usize::MAX {
                    offset_start = pos;
                }
                if !buf.is_empty() {
                    buf.push_str(source.get(pos..pos + run));
                }
                pos += run;
                offset_end = pos - 1;
                skipped_ws = usize::MAX;
            }
        };

        self.pos = pos;

        if offset_start != usize::MAX {
            self.last_token_end = offset_end;
        }

        let (text, start, end) = if !buf.is_empty() {
            (buf.into_text(), offset_start, offset_end)
        } else if offset_start != usize::MAX {
            (
                TokenText::Borrowed(source.get(offset_start..=offset_end).unwrap_or_default()),
                offset_start,
                offset_end,
            )
        } else {
            (TokenText::Borrowed(""), last_idx, last_idx)
        };
        Some(Token {
            text,
            start,
            end,
            stop_char,
        })
    }

    #[inline]
    pub(crate) fn token_until_lf(&mut self, last_stop_char: &mut StopChar) -> Option<Token<'x>> {
        if last_stop_char != &StopChar::Lf {
            self.token()
                .inspect(|token| *last_stop_char = token.stop_char)
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn parse_value_until_lf<T>(
        &mut self,
        separator: StopChar,
        last_stop_char: &mut StopChar,
    ) -> Option<Option<T>>
    where
        T: IanaParse + 'static,
    {
        if *last_stop_char != separator {
            self.token_until_lf(last_stop_char)
                .map(|token| T::parse(token.text.as_ref()))
        } else {
            None
        }
    }

    #[inline(always)]
    pub(crate) fn value_token(
        &mut self,
        encoding: Option<Encoding>,
        payload: &mut Option<Vec<u8>>,
    ) -> Option<Token<'x>> {
        if encoding == Some(Encoding::Base64) {
            self.base64_token(payload)
        } else {
            self.token()
        }
    }

    #[inline(never)]
    fn base64_token(&mut self, payload: &mut Option<Vec<u8>>) -> Option<Token<'x>> {
        if let Some((token, next, bytes)) = self.folded_base64() {
            self.pos = next;
            self.last_token_end = token.end;
            *payload = Some(bytes);
            return Some(token);
        }
        self.token()
    }

    fn folded_base64(&self) -> Option<(Token<'x>, usize, Vec<u8>)> {
        if self.mode.0 & !Mode::PLAIN_VALUE.0 != 0 {
            return None;
        }
        let start = self.pos;
        let value = self.input.get(start..)?;
        let mut bytes = Vec::new();
        let folded = base64::STANDARD.decode_folded(value, &mut bytes).ok()?;
        if folded.next != folded.end
            && self.mode.contains(Mode::UNFOLD_B64)
            && self.is_base64_continuation(start + folded.next - 1)
        {
            return None;
        }
        let span = FoldedContent(value.get(..folded.end)?).span();
        if span.is_empty() {
            return None;
        }
        if bytes.capacity() > 2 * bytes.len() + SPARE_BYTES {
            bytes.shrink_to_fit();
        }
        let (first, end) = (start + span.start, start + span.end);
        Some((
            Token {
                text: TokenText::Borrowed(self.source.get(first..end)?),
                start: first,
                end: end - 1,
                stop_char: StopChar::Lf,
            },
            start + folded.next,
            bytes,
        ))
    }

    pub(crate) fn seek_lf(&mut self) -> bool {
        loop {
            match self.token() {
                Some(Token {
                    stop_char: StopChar::Lf,
                    ..
                }) => return true,
                None => return false,
                _ => {}
            }
        }
    }

    pub(crate) fn seek_value_or_eol(&mut self) -> StopChar {
        loop {
            match self.token() {
                Some(Token {
                    stop_char: StopChar::Colon,
                    ..
                }) => return StopChar::Colon,
                Some(Token {
                    stop_char: StopChar::Lf,
                    ..
                })
                | None => return StopChar::Lf,
                _ => {}
            }
        }
    }

    pub(crate) fn seek_param_value_or_eol(&mut self) -> StopChar {
        loop {
            match self.token() {
                Some(Token {
                    stop_char: stop_char @ (StopChar::Colon | StopChar::Semicolon | StopChar::Equal),
                    ..
                }) => return stop_char,
                Some(Token {
                    stop_char: StopChar::Lf,
                    ..
                })
                | None => return StopChar::Lf,
                _ => {}
            }
        }
    }
}

struct FoldedContent<'x>(&'x [u8]);

impl FoldedContent<'_> {
    fn span(&self) -> Range<usize> {
        let mut rest = self.0;
        loop {
            rest = match rest {
                [b'\r', b'\n', b' ' | b'\t', tail @ ..] | [b'\n', b' ' | b'\t', tail @ ..] => tail,
                _ => break,
            };
        }
        let first = self.0.len() - rest.len();
        loop {
            rest = match rest {
                [head @ .., b'\r', b'\n', b' ' | b'\t'] => head,
                [head @ .., b'\n', b' ' | b'\t'] => head,
                _ => return first..first + rest.len(),
            };
        }
    }
}

#[derive(Default)]
struct OwnedText(String);

impl OwnedText {
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline(always)]
    fn last(&self) -> Option<u8> {
        self.0.as_bytes().last().copied()
    }

    #[inline(always)]
    fn push(&mut self, ch: char) {
        self.0.push(ch);
    }

    #[inline(always)]
    fn push_str(&mut self, run: Option<&str>) {
        self.0.push_str(run.unwrap_or_default());
    }

    #[inline(always)]
    fn start(&mut self, prefix: Option<&str>) {
        self.push_str(prefix);
    }

    #[inline(always)]
    fn into_text<'x>(self) -> TokenText<'x> {
        TokenText::Owned(self.0)
    }

    #[inline(always)]
    fn restore_whitespace(&mut self, skipped: Option<&[u8]>) {
        self.0.extend(
            skipped
                .unwrap_or_default()
                .iter()
                .filter_map(|ch| match ch {
                    b' ' => Some(' '),
                    b'\t' => Some('\t'),
                    _ => None,
                }),
        );
    }
}

impl TokenText<'_> {
    #[inline(always)]
    pub(crate) fn as_str(&self) -> &str {
        match self {
            TokenText::Borrowed(text) => text,
            TokenText::Owned(text) => text,
        }
    }

    #[inline(always)]
    pub(crate) fn into_string(self) -> String {
        match self {
            TokenText::Borrowed(text) => text.to_owned(),
            TokenText::Owned(text) => text,
        }
    }
}

impl Deref for TokenText<'_> {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl AsRef<[u8]> for TokenText<'_> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl From<String> for TokenText<'_> {
    fn from(text: String) -> Self {
        TokenText::Owned(text)
    }
}

impl<'x> Token<'x> {
    pub fn into_string(self) -> String {
        self.text.into_string()
    }
}

