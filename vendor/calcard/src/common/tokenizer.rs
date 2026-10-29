/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{Parser, common::IanaParse};
use std::borrow::Cow;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Token<'x> {
    pub(crate) text: Cow<'x, [u8]>,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) stop_char: StopChar,
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

impl<'x> Parser<'x> {
    pub(crate) fn expect_iana_token(&mut self) {
        self.stop_colon = true;
        self.stop_semicolon = true;
        self.stop_comma = true;
        self.stop_equal = true;
        self.unfold_qp = false;
        self.unfold_b64 = false;
        self.unquote = true;
        self.stop_dot = false;
        self.skip_ws = true;
        self.strip_ctl = false;
    }

    pub(crate) fn expect_single_value(&mut self) {
        self.stop_colon = false;
        self.stop_comma = false;
        self.stop_equal = false;
        self.stop_semicolon = false;
        self.unquote = false;
        self.unfold_qp = false;
        self.unfold_b64 = false;
        self.stop_dot = false;
        self.skip_ws = false;
        self.strip_ctl = false;
    }

    pub(crate) fn expect_multi_value_comma(&mut self) {
        self.stop_colon = false;
        self.stop_comma = true;
        self.stop_equal = false;
        self.stop_semicolon = false;
        self.unquote = false;
        self.unfold_qp = false;
        self.unfold_b64 = false;
        self.stop_dot = false;
        self.skip_ws = true;
        self.strip_ctl = false;
    }

    pub(crate) fn expect_multi_value_semicolon(&mut self) {
        self.stop_colon = false;
        self.stop_comma = false;
        self.stop_equal = false;
        self.stop_semicolon = true;
        self.unquote = false;
        self.unfold_qp = false;
        self.unfold_b64 = false;
        self.stop_dot = false;
        self.skip_ws = false;
        self.strip_ctl = false;
    }

    pub(crate) fn expect_multi_value_semicolon_and_comma(&mut self) {
        self.stop_colon = false;
        self.stop_comma = true;
        self.stop_equal = false;
        self.stop_semicolon = true;
        self.unquote = false;
        self.unfold_qp = false;
        self.unfold_b64 = false;
        self.stop_dot = false;
        self.skip_ws = false;
        self.strip_ctl = false;
    }

    pub(crate) fn expect_param_value(&mut self) {
        self.stop_colon = true;
        self.stop_semicolon = true;
        self.stop_comma = true;
        self.stop_equal = false;
        self.unfold_qp = false;
        self.unfold_b64 = false;
        self.unquote = true;
        self.stop_dot = false;
        self.skip_ws = true;
        self.strip_ctl = true;
    }

    pub(crate) fn expect_rrule_value(&mut self) {
        self.stop_colon = true;
        self.stop_comma = true;
        self.stop_equal = true;
        self.stop_semicolon = true;
        self.unquote = false;
        self.unfold_qp = false;
        self.unfold_b64 = false;
        self.stop_dot = false;
        self.skip_ws = true;
        self.strip_ctl = false;
    }

    fn try_unfold(&mut self) -> bool {
        if let Some((_, next)) = self.iter.peek()
            && (**next == b' ' || **next == b'\t')
        {
            self.iter.next();
            return true;
        }
        false
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

    pub(crate) fn token(&mut self) -> Option<Token<'x>> {
        let mut offset_start = usize::MAX;
        let mut offset_end = usize::MAX;
        let mut last_idx = 0;
        let mut in_quote = false;
        let stop_char;
        let mut buf: Vec<u8> = vec![];
        let mut skipped_ws = usize::MAX;

        'outer: loop {
            let (idx, ch) = if let Some(next) = self.iter.next() {
                next
            } else if offset_start != usize::MAX {
                stop_char = StopChar::Lf;
                break;
            } else {
                return None;
            };
            last_idx = idx;

            match ch {
                b' ' | b'\t' => {
                    // Ignore leading and trailing whitespace (unless in a quoted string)
                    if in_quote || !self.skip_ws || buf.last().is_some_and(|lch| lch != ch) {
                        if offset_start == usize::MAX {
                            offset_start = idx;
                        }
                        offset_end = idx;
                        skipped_ws = usize::MAX;

                        if !buf.is_empty() {
                            buf.push(*ch);
                        }
                    } else if skipped_ws == usize::MAX {
                        skipped_ws = idx;
                    }
                }
                b'\r' => {}
                b'\n' => {
                    if self.unfold_qp
                        && buf.last().or_else(|| self.input.get(offset_end)).copied() == Some(b'=')
                    {
                        offset_end = idx;

                        if !buf.is_empty() {
                            buf.push(*ch);
                        }
                    } else if self.try_unfold() {
                        if buf.is_empty() && offset_start != usize::MAX {
                            buf.extend_from_slice(&self.input[offset_start..=offset_end]);
                        }

                        if skipped_ws != usize::MAX && !buf.is_empty() {
                            buf.extend(
                                self.input[skipped_ws..idx]
                                    .iter()
                                    .filter(|ch| matches!(ch, b' ' | b'\t')),
                            );
                        }
                        skipped_ws = usize::MAX;
                    } else if self.unfold_b64 && self.is_base64_continuation(idx) {
                        if buf.is_empty() && offset_start != usize::MAX {
                            buf.extend_from_slice(&self.input[offset_start..=offset_end]);
                        }
                        skipped_ws = usize::MAX;
                    } else {
                        stop_char = StopChar::Lf;
                        break;
                    }
                }
                b'\\' => {
                    let mut next_ch = b'\\';
                    let mut next_offset_end = idx;
                    while let Some((idx, ch)) = self.iter.next() {
                        match ch {
                            b'\t' | b'\r' => {}
                            b'\n' => {
                                if self.try_unfold() {
                                    if let Some((idx, ch)) = self.iter.next() {
                                        next_ch = *ch;
                                        next_offset_end = idx;
                                        break;
                                    }
                                } else {
                                    stop_char = StopChar::Lf;
                                    offset_end = idx - 1;
                                    break 'outer;
                                }
                            }
                            _ => {
                                next_ch = *ch;
                                next_offset_end = idx;
                                break;
                            }
                        }
                    }
                    if offset_start != usize::MAX {
                        if buf.is_empty() {
                            buf.extend_from_slice(&self.input[offset_start..=offset_end]);
                        }

                        if skipped_ws != usize::MAX {
                            buf.extend(
                                self.input[skipped_ws..idx]
                                    .iter()
                                    .filter(|ch| matches!(ch, b' ' | b'\t')),
                            );
                        }
                    } else {
                        offset_start = next_offset_end;
                    }
                    skipped_ws = usize::MAX;
                    buf.push(match next_ch {
                        b'n' | b'N' => b'\n',
                        b'r' | b'R' => b'\r',
                        _ => next_ch,
                    });
                    offset_end = next_offset_end;
                }
                b'"' if self.unquote => {
                    in_quote = !in_quote;
                }
                b':' if !in_quote && self.stop_colon => {
                    stop_char = StopChar::Colon;
                    break;
                }
                b';' if !in_quote && self.stop_semicolon => {
                    stop_char = StopChar::Semicolon;
                    break;
                }
                b',' if !in_quote && self.stop_comma => {
                    stop_char = StopChar::Comma;
                    break;
                }
                b'=' if !in_quote && self.stop_equal => {
                    stop_char = StopChar::Equal;
                    break;
                }
                b'.' if !in_quote && self.stop_dot => {
                    stop_char = StopChar::Dot;
                    break;
                }
                0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F if self.strip_ctl => {
                    if buf.is_empty() && offset_start != usize::MAX {
                        buf.extend_from_slice(&self.input[offset_start..=offset_end]);
                    }
                }
                _ => {
                    if offset_start == usize::MAX {
                        offset_start = idx;
                    }
                    offset_end = idx;
                    skipped_ws = usize::MAX;

                    if !buf.is_empty() {
                        buf.push(*ch);
                    }
                }
            }
        }

        if offset_start != usize::MAX {
            self.last_token_end = offset_end;
        }

        if buf.is_empty() {
            if offset_start != usize::MAX {
                Some(Token {
                    text: Cow::Borrowed(&self.input[offset_start..=offset_end]),
                    start: offset_start,
                    end: offset_end,
                    stop_char,
                })
            } else {
                Some(Token {
                    text: Cow::Borrowed(b"".as_ref()),
                    start: last_idx,
                    end: last_idx,
                    stop_char,
                })
            }
        } else {
            Some(Token {
                text: Cow::Owned(buf),
                start: offset_start,
                end: offset_end,
                stop_char,
            })
        }
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

impl<'x> Token<'x> {
    pub fn new(text: Cow<'x, [u8]>) -> Self {
        Self {
            text,
            start: 0,
            end: 0,
            stop_char: StopChar::Lf,
        }
    }

    pub fn into_string(self) -> String {
        String::from_utf8(self.text.into_owned())
            .unwrap_or_else(|err| String::from_utf8_lossy(&err.into_bytes()).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum TextOwner {
        Borrowed(&'static str),
        Owned(String),
    }

    #[test]
    fn test_tokenizer() {
        for (input, expected, disable_stop) in [
            (
                concat!(
                    "NOTE:This is a long descrip\n",
                    " tion that exists o\n",
                    " n a long line.",
                ),
                vec![
                    (TextOwner::Borrowed("NOTE"), StopChar::Colon),
                    (
                        TextOwner::Owned(
                            "This is a long description that exists on a long line.".into(),
                        ),
                        StopChar::Lf,
                    ),
                ],
                b"".as_slice(),
            ),
            (
                concat!(
                    "this is a text value\n",
                    "this is one value,this is another\n",
                    "this is a single value\\, with a comma encoded\n"
                ),
                vec![
                    (TextOwner::Borrowed("this is a text value"), StopChar::Lf),
                    (TextOwner::Borrowed("this is one value"), StopChar::Comma),
                    (TextOwner::Borrowed("this is another"), StopChar::Lf),
                    (
                        TextOwner::Owned("this is a single value, with a comma encoded".into()),
                        StopChar::Lf,
                    ),
                ],
                b"".as_slice(),
            ),
            (
                "N;ALTID=1;LANGUAGE=en:Yamada;Taro;;;",
                vec![
                    (TextOwner::Borrowed("N"), StopChar::Semicolon),
                    (TextOwner::Borrowed("ALTID"), StopChar::Equal),
                    (TextOwner::Borrowed("1"), StopChar::Semicolon),
                    (TextOwner::Borrowed("LANGUAGE"), StopChar::Equal),
                    (TextOwner::Borrowed("en"), StopChar::Colon),
                    (TextOwner::Borrowed("Yamada"), StopChar::Semicolon),
                    (TextOwner::Borrowed("Taro"), StopChar::Semicolon),
                    (TextOwner::Borrowed(""), StopChar::Semicolon),
                    (TextOwner::Borrowed(""), StopChar::Semicolon),
                ],
                b"".as_slice(),
            ),
            (
                "N;SORT-AS=\"Mann,James\":de Mann;Henry,James;;",
                vec![
                    (TextOwner::Borrowed("N"), StopChar::Semicolon),
                    (TextOwner::Borrowed("SORT-AS"), StopChar::Equal),
                    (TextOwner::Borrowed("Mann,James"), StopChar::Colon),
                    (TextOwner::Borrowed("de Mann"), StopChar::Semicolon),
                    (TextOwner::Borrowed("Henry"), StopChar::Comma),
                    (TextOwner::Borrowed("James"), StopChar::Semicolon),
                    (TextOwner::Borrowed(""), StopChar::Semicolon),
                ],
                b"".as_slice(),
            ),
            (
                "  hello\\ nworld\\\\",
                vec![(TextOwner::Owned("hello nworld\\".into()), StopChar::Lf)],
                b"".as_slice(),
            ),
            (
                concat!(
                    "X-ABC-MMSUBJ;VALUE=URI;FMTTYPE=audio/basic:http://www.example.\n",
                    " org/mysubj.au"
                ),
                vec![
                    (TextOwner::Borrowed("X-ABC-MMSUBJ"), StopChar::Semicolon),
                    (TextOwner::Borrowed("VALUE"), StopChar::Equal),
                    (TextOwner::Borrowed("URI"), StopChar::Semicolon),
                    (TextOwner::Borrowed("FMTTYPE"), StopChar::Equal),
                    (TextOwner::Borrowed("audio/basic"), StopChar::Colon),
                    (TextOwner::Borrowed("http"), StopChar::Colon),
                    (
                        TextOwner::Owned("//www.example.org/mysubj.au".into()),
                        StopChar::Lf,
                    ),
                ],
                b"".as_slice(),
            ),
            (
                "RDATE;VALUE=DATE:19970304,19970504,19970704,19970904",
                vec![
                    (TextOwner::Borrowed("RDATE"), StopChar::Semicolon),
                    (TextOwner::Borrowed("VALUE"), StopChar::Equal),
                    (TextOwner::Borrowed("DATE"), StopChar::Colon),
                    (TextOwner::Borrowed("19970304"), StopChar::Comma),
                    (TextOwner::Borrowed("19970504"), StopChar::Comma),
                    (TextOwner::Borrowed("19970704"), StopChar::Comma),
                    (TextOwner::Borrowed("19970904"), StopChar::Lf),
                ],
                b"".as_slice(),
            ),
            (
                " BEGIN; ::\n \n \n test",
                vec![
                    (TextOwner::Borrowed("BEGIN"), StopChar::Semicolon),
                    (TextOwner::Borrowed(""), StopChar::Colon),
                    (TextOwner::Borrowed(""), StopChar::Colon),
                    (TextOwner::Borrowed("test"), StopChar::Lf),
                ],
                b"".as_slice(),
            ),
            (
                concat!(
                    "DESCRIPTION;Sunday - Partly cloudy with a 20 percent chance of snow show",
                    "ers. Highs in the lower to mid 40s.\\n<a href=\\\"http://www.wunderground.c",
                    "om/US/WA/Leavenworth.html\\\">More Information</a>"
                ),
                vec![
                    (TextOwner::Borrowed("DESCRIPTION"), StopChar::Semicolon),
                    (
                        TextOwner::Owned(
                            concat!(
                                "Sunday - Partly cloudy with a 20 percent ",
                                "chance of snow showers. Highs in the lower ",
                                "to mid 40s.\n<a href=\"http://www.wunderground.com",
                                "/US/WA/Leavenworth.html\">More Information</a>"
                            )
                            .into(),
                        ),
                        StopChar::Lf,
                    ),
                ],
                b"=:".as_slice(),
            ),
            (
                concat!(
                    "ATTACH;FMTTYPE=text/plain;ENCODING=BASE64;VALUE=BINARY:VGhlIH\n",
                    " F1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4"
                ),
                vec![
                    (TextOwner::Borrowed("ATTACH"), StopChar::Semicolon),
                    (TextOwner::Borrowed("FMTTYPE"), StopChar::Equal),
                    (TextOwner::Borrowed("text/plain"), StopChar::Semicolon),
                    (TextOwner::Borrowed("ENCODING"), StopChar::Equal),
                    (TextOwner::Borrowed("BASE64"), StopChar::Semicolon),
                    (TextOwner::Borrowed("VALUE"), StopChar::Equal),
                    (TextOwner::Borrowed("BINARY"), StopChar::Colon),
                    (
                        TextOwner::Owned(
                            "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4".into(),
                        ),
                        StopChar::Lf,
                    ),
                ],
                b"".as_slice(),
            ),
            (
                concat!(
                    "DESCRIPTION;ALTREP=\"cid:part1.0001@example.org\":The Fall'98 Wild\n",
                    " Wizards Conference - - Las Vegas\\, NV\\, USA"
                ),
                vec![
                    (TextOwner::Borrowed("DESCRIPTION"), StopChar::Semicolon),
                    (TextOwner::Borrowed("ALTREP"), StopChar::Equal),
                    (
                        TextOwner::Borrowed("cid:part1.0001@example.org"),
                        StopChar::Colon,
                    ),
                    (
                        TextOwner::Owned(
                            "The Fall'98 WildWizards Conference - - Las Vegas, NV, USA".to_string(),
                        ),
                        StopChar::Lf,
                    ),
                ],
                b"".as_slice(),
            ),
            (
                concat!(
                    "ATTENDEE;DELEGATED-FROM=\"mailto:jsmith@example.com\":mailto:\n",
                    " jdoe@example.com"
                ),
                vec![
                    (TextOwner::Borrowed("ATTENDEE"), StopChar::Semicolon),
                    (TextOwner::Borrowed("DELEGATED-FROM"), StopChar::Equal),
                    (
                        TextOwner::Borrowed("mailto:jsmith@example.com"),
                        StopChar::Colon,
                    ),
                    (TextOwner::Borrowed("mailto"), StopChar::Colon),
                    (TextOwner::Borrowed("jdoe@example.com"), StopChar::Lf),
                ],
                b"".as_slice(),
            ),
            (
                concat!(
                    "ATTENDEE;DELEGATED-TO=\"mailto:jdoe@example.com\",\"mailto:jqpublic\n",
                    " @example.com\":mailto:jsmith@example.com"
                ),
                vec![
                    (TextOwner::Borrowed("ATTENDEE"), StopChar::Semicolon),
                    (TextOwner::Borrowed("DELEGATED-TO"), StopChar::Equal),
                    (
                        TextOwner::Borrowed("mailto:jdoe@example.com"),
                        StopChar::Comma,
                    ),
                    (
                        TextOwner::Owned("mailto:jqpublic@example.com".into()),
                        StopChar::Colon,
                    ),
                    (TextOwner::Borrowed("mailto"), StopChar::Colon),
                    (TextOwner::Borrowed("jsmith@example.com"), StopChar::Lf),
                ],
                b"".as_slice(),
            ),
            (
                "CATEGORIES:cat1  ,  cat2,   cat3",
                vec![
                    (TextOwner::Borrowed("CATEGORIES"), StopChar::Colon),
                    (TextOwner::Borrowed("cat1"), StopChar::Comma),
                    (TextOwner::Borrowed("cat2"), StopChar::Comma),
                    (TextOwner::Borrowed("cat3"), StopChar::Lf),
                ],
                b"".as_slice(),
            ),
            (
                concat!("SUMMARY:Meeting\n", "\n\n", "BEGIN:VALARM"),
                vec![
                    (TextOwner::Borrowed("SUMMARY"), StopChar::Colon),
                    (TextOwner::Borrowed("Meeting"), StopChar::Lf),
                    (TextOwner::Borrowed(""), StopChar::Lf),
                    (TextOwner::Borrowed(""), StopChar::Lf),
                    (TextOwner::Borrowed("BEGIN"), StopChar::Colon),
                    (TextOwner::Borrowed("VALARM"), StopChar::Lf),
                ],
                b"".as_slice(),
            ),
            (
                concat!(
                    "FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:=D0=B3=D0=BE=D1=80=20",
                    "=D0=97=D0=B0=D0=BE=D1=80=D1=81=D0=81=D0=\n",
                    "=BA=\n",
                    "=D1=96=\n",
                    " xyz =\n",
                    "=D1=96\n"
                ),
                vec![
                    (TextOwner::Borrowed("FN"), StopChar::Semicolon),
                    (TextOwner::Borrowed("CHARSET"), StopChar::Equal),
                    (TextOwner::Borrowed("UTF-8"), StopChar::Semicolon),
                    (TextOwner::Borrowed("ENCODING"), StopChar::Equal),
                    (TextOwner::Borrowed("QUOTED-PRINTABLE"), StopChar::Colon),
                    (
                        TextOwner::Borrowed(concat!(
                            "=D0=B3=D0=BE=D1=80=20=D0=97=D0=B0=D0=BE=D1=80",
                            "=D1=81=D0=81=D0=\n=BA=\n=D1=96=\n xyz =\n=D1=96"
                        )),
                        StopChar::Lf,
                    ),
                ],
                b"".as_slice(),
            ),
            (
                concat!(
                    "ADR;LABEL=\"Mr. John Q. Public, Esq.\\nMail Drop: TNE QB\\n123\n",
                    " Main Street\\nAny Town, CA  91921-1234\\nU.S.A.\":\n",
                    " ;;123 Main Street;Any Town;CA;91921-1234;U.S.A."
                ),
                vec![
                    (TextOwner::Borrowed("ADR"), StopChar::Semicolon),
                    (TextOwner::Borrowed("LABEL"), StopChar::Equal),
                    (
                        TextOwner::Owned(
                            concat!(
                                "Mr. John Q. Public, Esq.\nMail Drop: TNE QB\n",
                                "123Main Street\nAny Town, CA  91921-1234\nU.S.A."
                            )
                            .into(),
                        ),
                        StopChar::Colon,
                    ),
                    (TextOwner::Borrowed(""), StopChar::Semicolon),
                    (TextOwner::Borrowed(""), StopChar::Semicolon),
                    (TextOwner::Borrowed("123 Main Street"), StopChar::Semicolon),
                    (TextOwner::Borrowed("Any Town"), StopChar::Semicolon),
                    (TextOwner::Borrowed("CA"), StopChar::Semicolon),
                    (TextOwner::Borrowed("91921-1234"), StopChar::Semicolon),
                    (TextOwner::Borrowed("U.S.A."), StopChar::Lf),
                ],
                b"".as_slice(),
            ),
            (
                "\\",
                vec![(TextOwner::Owned("\\".into()), StopChar::Lf)],
                b"".as_slice(),
            ),
            (
                "\\n",
                vec![(TextOwner::Owned("\n".into()), StopChar::Lf)],
                b"".as_slice(),
            ),
            (
                "\\nhello",
                vec![(TextOwner::Owned("\nhello".into()), StopChar::Lf)],
                b"".as_slice(),
            ),
            (
                ";;\nEND:VCARD\n",
                vec![
                    (TextOwner::Borrowed(""), StopChar::Semicolon),
                    (TextOwner::Borrowed(""), StopChar::Semicolon),
                    (TextOwner::Borrowed(""), StopChar::Lf),
                    (TextOwner::Borrowed("END"), StopChar::Colon),
                    (TextOwner::Borrowed("VCARD"), StopChar::Lf),
                ],
                b"".as_slice(),
            ),
            ("", vec![], b"".as_slice()),
        ] {
            let mut parser = Parser::new(input);
            let mut tokens = vec![];
            parser.skip_ws = true;
            for ch in disable_stop {
                match ch {
                    b'=' => {
                        parser.stop_equal = false;
                    }
                    b':' => {
                        parser.stop_colon = false;
                    }
                    _ => {}
                }
            }

            while let Some(token) = parser.token() {
                if token.text.eq_ignore_ascii_case(b"quoted-printable") {
                    parser.stop_colon = false;
                    parser.stop_comma = false;
                    parser.stop_equal = false;
                    parser.unquote = false;
                    parser.unfold_qp = true;
                    parser.stop_semicolon = true;
                    parser.skip_ws = false;
                }
                let text = match token.text {
                    Cow::Borrowed(text) => TextOwner::Borrowed(std::str::from_utf8(text).unwrap()),
                    Cow::Owned(text) => TextOwner::Owned(String::from_utf8(text).unwrap()),
                };
                tokens.push((text, token.stop_char));
            }
            assert_eq!(tokens, expected, "failed for input: {:?}", input);
        }
    }
}
