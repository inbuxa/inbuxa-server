/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::{request::parser::Rfc5321Parser, *};
use memchr::memchr2;
use std::slice::Iter;

pub const MAX_RESPONSE_LENGTH: usize = 4096;
const MULTILINE_RESERVE: usize = 128;
const CONTINUATION_RESERVE: usize = 64;

#[derive(Default)]
pub struct ResponseReceiver {
    buf: Vec<u8>,
    code: u16,
    esc: [u8; 3],
    esc_cur: [u8; 3],
    esc_restore: [u8; 10],
    esc_pos: usize,
    is_last: bool,
    pos: usize,
}

impl ResponseReceiver {
    pub fn from_code(code: u16) -> Self {
        Self {
            code,
            esc: [0u8; 3],
            esc_cur: [0u8; 3],
            esc_restore: [0u8; 10],
            esc_pos: 0,
            pos: 3,
            is_last: false,
            buf: Vec::new(),
        }
    }

    pub fn parse(&mut self, bytes: &mut Iter<'_, u8>) -> Result<Response<String>, Error> {
        let mut rest = bytes.as_slice();
        let result = loop {
            if self.pos > 6 {
                let end = line_end(rest);
                if end != 0 {
                    let available = MAX_RESPONSE_LENGTH.saturating_sub(self.buf.len());
                    if end <= available {
                        let (run, tail) = rest.split_at(end);
                        self.buf.extend_from_slice(run);
                        rest = tail;
                    } else {
                        let (run, tail) = rest.split_at(available);
                        self.buf.extend_from_slice(run);
                        rest = tail.get(1..).unwrap_or_default();
                        break Err(Error::ResponseTooLong);
                    }
                }
            } else if self.pos == 0
                && let [d0, d1, d2, sep, tail @ ..] = rest
                && d0.is_ascii_digit()
                && d1.is_ascii_digit()
                && d2.is_ascii_digit()
                && matches!(*sep, b' ' | b'-')
            {
                if self.buf.is_empty() {
                    self.code = self
                        .code
                        .saturating_mul(10)
                        .saturating_add((d0 - b'0') as u16)
                        .saturating_mul(10)
                        .saturating_add((d1 - b'0') as u16)
                        .saturating_mul(10)
                        .saturating_add((d2 - b'0') as u16);
                    if *sep == b'-' {
                        self.buf.reserve(MULTILINE_RESERVE);
                    }
                }
                self.is_last |= *sep == b' ';
                self.pos = 4;
                rest = tail;
                continue;
            } else if self.pos == 4 && self.esc_pos == 0 {
                if let Some(ch) = rest.first()
                    && !matches!(ch, b'0'..=b'9' | b'.' | b'\r' | b'\n')
                    && self.buf.len() < MAX_RESPONSE_LENGTH
                {
                    self.pos = 7;
                    continue;
                }
                if let [class, b'.', subject, b'.', detail, separator, tail @ ..] = rest
                    && class.is_ascii_digit()
                    && subject.is_ascii_digit()
                    && detail.is_ascii_digit()
                    && matches!(*separator, b' ' | b'\r')
                {
                    self.esc = [class - b'0', subject - b'0', detail - b'0'];
                    self.pos = 7;
                    rest = tail;
                    continue;
                }
            }

            let [ch, tail @ ..] = rest else {
                break Err(Error::NeedsMoreData { bytes_left: 0 });
            };
            let ch = *ch;
            rest = tail;

            match self.pos {
                0..=2 => {
                    if ch.is_ascii_digit() {
                        if self.buf.is_empty() {
                            self.code = self
                                .code
                                .saturating_mul(10)
                                .saturating_add((ch - b'0') as u16);
                        }
                        self.pos += 1;
                    } else {
                        break Err(Error::SyntaxError {
                            syntax: "Invalid response code",
                        });
                    }
                }
                3 => match ch {
                    b' ' => {
                        self.is_last = true;
                        self.pos += 1;
                    }
                    b'-' => {
                        if self.buf.is_empty() {
                            self.buf.reserve(MULTILINE_RESERVE);
                        }
                        self.pos += 1;
                    }
                    b'\r' => (),
                    b'\n' => {
                        self.is_last = true;
                    }
                    _ => {
                        break Err(Error::SyntaxError {
                            syntax: "Invalid response separator",
                        });
                    }
                },
                4..=6 => {
                    let mut do_restore = false;

                    match ch {
                        b'0'..=b'9' => {
                            let code = &mut self.esc_cur[self.pos - 4];
                            if *code < 100 {
                                if let Some(restore) = self.esc_restore.get_mut(self.esc_pos) {
                                    *restore = ch;
                                    *code = code.saturating_mul(10).saturating_add(ch - b'0');
                                    self.esc_pos += 1;
                                } else {
                                    do_restore = true;
                                }
                            } else {
                                do_restore = true;
                            }
                        }
                        b'.' if self.pos < 6 => {
                            if let Some(restore) = self.esc_restore.get_mut(self.esc_pos) {
                                *restore = ch;
                                self.pos += 1;
                                self.esc_pos += 1;
                            } else {
                                do_restore = true;
                            }
                        }
                        b' ' | b'\r' | b'\n' if self.pos == 6 => {
                            self.esc = self.esc_cur;
                            self.esc_cur.fill(0);
                            self.pos = 7;
                            self.esc_pos = 0;
                        }
                        _ => {
                            do_restore = true;
                        }
                    }
                    if do_restore {
                        if self.esc_pos > 0 {
                            self.buf
                                .extend_from_slice(&self.esc_restore[..self.esc_pos]);
                        }
                        self.buf.push(ch);
                        self.pos = 7;
                        self.esc_pos = 0;
                        self.esc_cur.fill(0);
                    }
                }
                _ => (),
            }

            if ch == b'\n' {
                if self.is_last {
                    break Ok(Response {
                        code: self.code,
                        esc: self.esc,
                        message: std::mem::take(&mut self.buf).into_string(),
                    });
                } else {
                    self.buf.reserve(CONTINUATION_RESERVE);
                    self.buf.push(b'\n');
                    self.pos = 0;
                }
            }
        };
        *bytes = rest.iter();
        result
    }

    pub fn reset(&mut self) {
        self.is_last = false;
        self.code = 0;
        self.esc.fill(0);
        self.esc_cur.fill(0);
        self.pos = 0;
        self.esc_pos = 0;
        self.buf.clear();
    }
}

impl EhloResponse<String> {
    fn parse_first_line(
        rest: &mut &[u8],
        bytes_left: usize,
        hostname: &mut String,
    ) -> Result<bool, Error> {
        let mut code: u16 = 0;
        for _ in 0..3 {
            let [ch, tail @ ..] = *rest else {
                return Err(Error::NeedsMoreData { bytes_left });
            };
            *rest = tail;
            if !ch.is_ascii_digit() {
                return Err(Error::SyntaxError {
                    syntax: "unexpected token",
                });
            }
            code = code.saturating_mul(10).saturating_add((ch - b'0') as u16);
        }

        if code != 250 {
            return Err(Error::InvalidResponse { code });
        }

        let [separator, tail @ ..] = *rest else {
            return Err(Error::NeedsMoreData { bytes_left });
        };
        *rest = tail;
        let eol = match *separator {
            b' ' => true,
            b'-' => false,
            b'\n' => return Ok(true),
            _ => {
                return Err(Error::SyntaxError {
                    syntax: "unexpected token",
                });
            }
        };

        let mut buf = Vec::new();
        loop {
            let end = rest
                .iter()
                .position(|&ch| matches!(ch, b' ' | b'\r' | b'\n'))
                .unwrap_or(rest.len());
            if end > MAX_RESPONSE_LENGTH.saturating_sub(buf.len()) {
                *rest = rest
                    .get(MAX_RESPONSE_LENGTH.saturating_sub(buf.len()) + 1..)
                    .unwrap_or_default();
                return Err(Error::ResponseTooLong);
            }
            let (run, tail) = rest.split_at(end);
            buf.extend_from_slice(run);
            let [ch, tail @ ..] = tail else {
                *rest = tail;
                return Err(Error::NeedsMoreData { bytes_left });
            };
            *rest = tail;
            match *ch {
                b'\r' => (),
                b'\n' => break,
                _ => {
                    let Some(lf) = rest.iter().position(|&ch| ch == b'\n') else {
                        *rest = &[];
                        return Err(Error::NeedsMoreData { bytes_left });
                    };
                    *rest = rest.get(lf + 1..).unwrap_or_default();
                    break;
                }
            }
        }

        *hostname = buf.into_string();
        Ok(eol)
    }

    pub fn parse(bytes: &mut Iter<'_, u8>) -> Result<Self, Error> {
        let bytes_left = bytes.len();
        let mut response = EhloResponse::default();
        let mut rest = bytes.as_slice();
        let first_line = Self::parse_first_line(&mut rest, bytes_left, &mut response.hostname);
        *bytes = rest.iter();
        let mut eol = first_line?;

        let mut parser = Rfc5321Parser::new(bytes);
        parser.bytes_left = bytes_left;

        while !eol {
            let mut code: u16 = 0;
            for _ in 0..3 {
                match parser.read_char()? {
                    ch @ b'0'..=b'9' => {
                        code = code.saturating_mul(10).saturating_add((ch - b'0') as u16);
                    }
                    _ => {
                        return Err(Error::SyntaxError {
                            syntax: "unexpected token",
                        });
                    }
                }
            }

            if code != 250 {
                return Err(Error::InvalidResponse { code });
            }

            match parser.read_char()? {
                b' ' => {
                    eol = true;
                }
                b'-' => (),
                b'\n' if code < 600 => {
                    break;
                }
                _ => {
                    return Err(Error::SyntaxError {
                        syntax: "unexpected token",
                    });
                }
            }

            response.capabilities |= match parser.hashed_value_long()? {
                _8BITMIME => EXT_8BIT_MIME,
                ATRN => EXT_ATRN,
                AUTH => {
                    while parser.stop_char != LF {
                        if let Some(mechanism) = parser.mechanism()? {
                            response.auth_mechanisms |= mechanism;
                        }
                    }

                    EXT_AUTH
                }
                BINARYMIME => EXT_BINARY_MIME,
                BURL => EXT_BURL,
                CHECKPOINT => EXT_CHECKPOINT,
                CHUNKING => EXT_CHUNKING,
                CONNEG => EXT_CONNEG,
                CONPERM => EXT_CONPERM,
                DELIVERBY => {
                    response.deliver_by = if parser.stop_char != LF {
                        let db = parser.size()?;
                        if db != usize::MAX { db as u64 } else { 0 }
                    } else {
                        0
                    };
                    EXT_DELIVER_BY
                }
                DSN => EXT_DSN,
                ENHANCEDSTATUSCO
                    if parser.stop_char.eq_ignore_ascii_case(&b'D')
                        && parser.read_char()?.eq_ignore_ascii_case(&b'E')
                        && parser.read_char()?.eq_ignore_ascii_case(&b'S') =>
                {
                    EXT_ENHANCED_STATUS_CODES
                }
                ETRN => EXT_ETRN,
                EXPN => EXT_EXPN,
                VRFY => EXT_VRFY,
                FUTURERELEASE => {
                    let max_interval = if parser.stop_char != LF {
                        parser.size()?
                    } else {
                        0
                    };
                    let max_datetime = if parser.stop_char != LF {
                        parser.timestamp()?
                    } else {
                        0
                    };

                    response.future_release_interval = if max_interval != usize::MAX {
                        max_interval as u64
                    } else {
                        0
                    };
                    response.future_release_datetime = if max_datetime != i64::MAX {
                        max_datetime.max(0) as u64
                    } else {
                        0
                    };
                    EXT_FUTURE_RELEASE
                }
                HELP => EXT_HELP,
                MT_PRIORITY => {
                    response.mt_priority = if parser.stop_char != LF {
                        match parser.hashed_value_long()? {
                            MIXER => MtPriority::Mixer,
                            STANAG4406 => MtPriority::Stanag4406,
                            NSEP => MtPriority::Nsep,
                            _ => MtPriority::Mixer,
                        }
                    } else {
                        MtPriority::Mixer
                    };
                    EXT_MT_PRIORITY
                }
                MTRK => EXT_MTRK,
                NO_SOLICITING => {
                    response.no_soliciting = if parser.stop_char != LF {
                        let text = parser.text()?;
                        if !text.is_empty() {
                            text.into_owned().into()
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    EXT_NO_SOLICITING
                }
                ONEX => EXT_ONEX,
                PIPELINING => EXT_PIPELINING,
                REQUIRETLS => EXT_REQUIRE_TLS,
                RRVS => EXT_RRVS,
                SIZE => {
                    response.size = if parser.stop_char != LF {
                        let size = parser.size()?;
                        if size != usize::MAX { size } else { 0 }
                    } else {
                        0
                    };
                    EXT_SIZE
                }
                SMTPUTF8 => EXT_SMTP_UTF8,
                STARTTLS => EXT_START_TLS,
                VERB => EXT_VERB,
                _ => 0,
            };
            parser.seek_lf()?;
        }

        Ok(response)
    }
}

#[inline(always)]
fn line_end(bytes: &[u8]) -> usize {
    memchr2(b'\r', b'\n', bytes).unwrap_or(bytes.len())
}

