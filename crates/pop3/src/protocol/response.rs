/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{Mechanism, dot_stuffer::DotStuffer};
use std::borrow::Cow;
use utils::chained_bytes::ChainedBytes;

const STATUS_LINE_LEN: usize = 32;
const STUFFING_RESERVE_DIVISOR: usize = 64;
const BLANK_LINE_TAIL_LEN: usize = 3;
const CRLF_LEN: usize = 2;
const LIST_NUMBER_LEN: usize = 6;
const ERR_PREFIX: &[u8] = b"-ERR ";
const SYS_TEMP_CODE: &[u8] = b"[SYS/TEMP] ";

pub trait ListValue {
    const LEN_HINT: usize;

    fn write_value(&self, buf: &mut Vec<u8>);
}

impl ListValue for u32 {
    const LEN_HINT: usize = 8;

    fn write_value(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(itoa::Buffer::new().format(*self).as_bytes());
    }
}

pub struct UniqueId {
    pub uid_validity: u32,
    pub uid: u32,
}

impl ListValue for UniqueId {
    const LEN_HINT: usize = 20;

    fn write_value(&self, buf: &mut Vec<u8>) {
        self.uid_validity.write_value(buf);
        self.uid.write_value(buf);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageEnd {
    AsIs,
    BlankLine,
}

pub enum Response<'x, T> {
    Ok(Cow<'static, str>),
    Err(Cow<'static, str>),
    List(Vec<T>),
    Message(ChainedBytes<'x>, MessageEnd),
    Capability {
        mechanisms: Vec<Mechanism>,
        stls: bool,
    },
}

impl<'x, T> Response<'x, T> {
    pub fn message(raw_message: ChainedBytes<'x>, body_offset: usize, lines: Option<u32>) -> Self {
        let Some(lines) = lines else {
            return Response::Message(raw_message, MessageEnd::AsIs);
        };
        let len = raw_message.len();
        let body_offset = body_offset.min(len);
        let end = if body_offset == len && !ends_with_blank_line(&raw_message) {
            MessageEnd::BlankLine
        } else {
            MessageEnd::AsIs
        };
        let body_lines = raw_message
            .view(body_offset..len)
            .unwrap_or_default()
            .line_prefix_len(lines as usize);
        Response::Message(
            raw_message
                .view(0..body_offset + body_lines)
                .unwrap_or(raw_message),
            end,
        )
    }
}

pub struct MessageWriter<'x> {
    current: &'x [u8],
    next: &'x [u8],
    stuffer: Option<DotStuffer>,
    end: MessageEnd,
    chunk_len: usize,
}

impl<'x> MessageWriter<'x> {
    pub fn new(
        bytes: ChainedBytes<'x>,
        end: MessageEnd,
        buf: &mut Vec<u8>,
        chunk_len: usize,
    ) -> Self {
        let mut octets = DotStuffer::wire_len(&bytes);
        if end == MessageEnd::BlankLine {
            octets += CRLF_LEN;
        }
        buf.reserve(
            octets.min(chunk_len)
                + bytes.len().min(chunk_len) / STUFFING_RESERVE_DIVISOR
                + STATUS_LINE_LEN,
        );
        buf.extend_from_slice(b"+OK ");
        buf.extend_from_slice(itoa::Buffer::new().format(octets).as_bytes());
        buf.extend_from_slice(b" octets\r\n");
        let [current, next] = bytes.segments();
        MessageWriter {
            current,
            next,
            stuffer: Some(DotStuffer::default()),
            end,
            chunk_len,
        }
    }

    pub fn fill(&mut self, buf: &mut Vec<u8>) -> bool {
        loop {
            let Some(stuffer) = &mut self.stuffer else {
                return true;
            };
            if buf.len() >= self.chunk_len {
                return false;
            }
            if self.current.is_empty() {
                if self.next.is_empty() {
                    if let Some(stuffer) = self.stuffer.take() {
                        stuffer.finish(buf, self.end);
                    }
                    return true;
                }
                self.current = std::mem::take(&mut self.next);
            }
            let take = self
                .current
                .len()
                .min(self.chunk_len.saturating_sub(buf.len()));
            let (slice, rest) = self
                .current
                .split_at_checked(take)
                .unwrap_or((self.current, &[]));
            stuffer.push(buf, slice);
            self.current = rest;
        }
    }
}

fn ends_with_blank_line(bytes: &ChainedBytes<'_>) -> bool {
    let len = bytes.len();
    bytes
        .get(len.saturating_sub(BLANK_LINE_TAIL_LEN)..len)
        .is_some_and(|tail| {
            matches!(
                tail.as_ref(),
                [b'\n'] | [b'\r', b'\n'] | [.., b'\n', b'\n'] | [.., b'\n', b'\r', b'\n']
            )
        })
}

impl<T: ListValue> Response<'_, T> {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Response::Ok(message) => {
                let mut buf = Vec::with_capacity(message.len() + 6);
                buf.extend_from_slice(b"+OK ");
                buf.extend_from_slice(message.as_bytes());
                buf.extend_from_slice(b"\r\n");
                buf
            }
            Response::Err(message) => serialize_err(b"", message),
            Response::List(values) => {
                let mut buf = Vec::with_capacity(
                    values.len() * (LIST_NUMBER_LEN + T::LEN_HINT + CRLF_LEN) + STATUS_LINE_LEN,
                );
                let mut number = itoa::Buffer::new();
                buf.extend_from_slice(b"+OK ");
                buf.extend_from_slice(number.format(values.len()).as_bytes());
                buf.extend_from_slice(b" messages\r\n");
                for (num, value) in values.iter().enumerate() {
                    buf.extend_from_slice(number.format(num + 1).as_bytes());
                    buf.push(b' ');
                    value.write_value(&mut buf);
                    buf.extend_from_slice(b"\r\n");
                }
                buf.extend_from_slice(b".\r\n");
                buf
            }
            Response::Message(bytes, end) => {
                let mut buf = Vec::new();
                MessageWriter::new(*bytes, *end, &mut buf, usize::MAX).fill(&mut buf);
                buf
            }
            Response::Capability { mechanisms, stls } => {
                let mut buf = Vec::with_capacity(256);
                buf.extend_from_slice(b"+OK Capability list follows\r\n");
                if !mechanisms.is_empty() {
                    if mechanisms.contains(&Mechanism::Plain) {
                        buf.extend_from_slice(b"USER\r\n");
                    }
                    buf.extend_from_slice(b"SASL");
                    for mechanism in mechanisms {
                        buf.extend_from_slice(b" ");
                        buf.extend_from_slice(mechanism.as_str().as_bytes());
                    }
                    buf.extend_from_slice(b"\r\n");
                }

                if *stls {
                    buf.extend_from_slice(b"STLS\r\n");
                }

                for capa in [
                    "TOP",
                    "RESP-CODES",
                    "PIPELINING",
                    "EXPIRE NEVER",
                    "UIDL",
                    "UTF8",
                    concat!("IMPLEMENTATION ", types::brand_server!()),
                ] {
                    buf.extend_from_slice(capa.as_bytes());
                    buf.extend_from_slice(b"\r\n");
                }

                buf.extend_from_slice(b".\r\n");
                buf
            }
        }
    }
}

impl Mechanism {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mechanism::Plain => "PLAIN",
            Mechanism::CramMd5 => "CRAM-MD5",
            Mechanism::DigestMd5 => "DIGEST-MD5",
            Mechanism::ScramSha1 => "SCRAM-SHA-1",
            Mechanism::ScramSha256 => "SCRAM-SHA-256",
            Mechanism::Apop => "APOP",
            Mechanism::Ntlm => "NTLM",
            Mechanism::Gssapi => "GSSAPI",
            Mechanism::Anonymous => "ANONYMOUS",
            Mechanism::External => "EXTERNAL",
            Mechanism::OAuthBearer => "OAUTHBEARER",
            Mechanism::XOauth2 => "XOAUTH2",
        }
    }
}

pub trait SerializeResponse {
    fn serialize(&self) -> Vec<u8>;
}

impl SerializeResponse for trc::Error {
    fn serialize(&self) -> Vec<u8> {
        let code: &[u8] = match self.as_ref() {
            trc::EventType::Limit(
                trc::LimitEvent::TooManyRequests
                | trc::LimitEvent::ConcurrentRequest
                | trc::LimitEvent::MemoryBudget,
            ) => SYS_TEMP_CODE,
            _ => b"",
        };
        serialize_err(
            code,
            self.value_as_str(trc::Key::Details)
                .unwrap_or_else(|| self.as_ref().message()),
        )
    }
}

fn serialize_err(code: &[u8], message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ERR_PREFIX.len() + code.len() + message.len() + CRLF_LEN);
    buf.extend_from_slice(ERR_PREFIX);
    buf.extend_from_slice(code);
    buf.extend_from_slice(message.as_bytes());
    buf.extend_from_slice(b"\r\n");
    buf
}

#[cfg(test)]
mod tests {
    use super::Response;
    use crate::protocol::Mechanism;
    use utils::chained_bytes::ChainedBytes;

    #[test]
    fn serialize_response() {
        for (cmd, expected) in [
            (
                Response::Ok("message 1 deleted".into()),
                "+OK message 1 deleted\r\n",
            ),
            (
                Response::Err("permission denied".into()),
                "-ERR permission denied\r\n",
            ),
            (
                Response::List(vec![100, 200, 300]),
                "+OK 3 messages\r\n1 100\r\n2 200\r\n3 300\r\n.\r\n",
            ),
            (
                Response::Capability {
                    mechanisms: vec![Mechanism::Plain, Mechanism::CramMd5],
                    stls: true,
                },
                concat!(
                    "+OK Capability list follows\r\n",
                    "USER\r\n",
                    "SASL PLAIN CRAM-MD5\r\n",
                    "STLS\r\n",
                    "TOP\r\n",
                    "RESP-CODES\r\n",
                    "PIPELINING\r\n",
                    "EXPIRE NEVER\r\n",
                    "UIDL\r\n",
                    "UTF8\r\n",
                    concat!("IMPLEMENTATION ", types::brand_server!(), "\r\n.\r\n")
                ),
            ),
            (
                Response::message(
                    ChainedBytes::chain(b"Subject: test\r\n\r\n.\r\n", b"test.\r\n.test\r\na"),
                    17,
                    None,
                ),
                "+OK 37 octets\r\nSubject: test\r\n\r\n..\r\ntest.\r\n..test\r\na\r\n.\r\n",
            ),
            (
                Response::message(
                    ChainedBytes::chain(b"Subject: test\r\n\r\n.\r\n", b"test.\r\n.test\r\na"),
                    17,
                    Some(0),
                ),
                "+OK 17 octets\r\nSubject: test\r\n\r\n.\r\n",
            ),
            (
                Response::message(
                    ChainedBytes::chain(b"Subject: test\r\n\r\n.\r\n", b"test.\r\n.test\r\na"),
                    17,
                    Some(2),
                ),
                "+OK 27 octets\r\nSubject: test\r\n\r\n..\r\ntest.\r\n.\r\n",
            ),
            (
                Response::message(
                    ChainedBytes::chain(b"Subject: test\r\n\r\n.\r\n", b"test.\r\n.test\r\na"),
                    17,
                    Some(100),
                ),
                "+OK 37 octets\r\nSubject: test\r\n\r\n..\r\ntest.\r\n..test\r\na\r\n.\r\n",
            ),
            (
                Response::message(ChainedBytes::new(b"Subject: test\n\nbody\n"), 15, None),
                "+OK 23 octets\r\nSubject: test\r\n\r\nbody\r\n.\r\n",
            ),
            (
                Response::message(
                    ChainedBytes::new(b"Subject: test\n\n.leading dot\n"),
                    15,
                    Some(1),
                ),
                "+OK 31 octets\r\nSubject: test\r\n\r\n..leading dot\r\n.\r\n",
            ),
            (
                Response::message(ChainedBytes::new(b".dot\r\nSubject: test\r\n"), 21, Some(3)),
                "+OK 23 octets\r\n..dot\r\nSubject: test\r\n\r\n.\r\n",
            ),
        ] {
            assert_eq!(expected, String::from_utf8(cmd.serialize()).unwrap());
        }
    }
}
