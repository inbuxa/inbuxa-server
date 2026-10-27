/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::headers::HeaderRef;
use encodify::{base64, qp};
use mail_parser::{HeaderName, MessageParser, MessagePart, PartId};
use std::ops::Range;

const MAX_LINE_LEN: usize = 998;
const QP_SLACK_DIVISOR: usize = 4;

#[derive(Default)]
pub(crate) struct Edits<'x> {
    headers: Vec<(PartId, Vec<HeaderRef<'x>>)>,
    bodies: Vec<(PartId, BodyEdit<'x>)>,
    hidden: Vec<Range<PartId>>,
}

#[derive(Clone, Copy)]
pub(crate) struct BodyEdit<'x> {
    pub(crate) text: &'x str,
    pub(crate) kind: BodyKind,
    pub(crate) format: BodyFormat,
    pub(crate) encoding: TransferEncoding,
    pub(crate) encoded_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyKind {
    Text,
    Html,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyFormat {
    Content,
    Entity { body_start: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransferEncoding {
    Identity,
    QuotedPrintable,
    Base64,
}

impl TransferEncoding {
    pub(crate) fn select(text: &str) -> (Self, usize) {
        let bytes = text.as_bytes();
        if bytes.is_ascii() && !has_long_line(bytes) {
            return (TransferEncoding::Identity, bytes.len());
        }
        let base64_len = base64::MIME.encoded_len(bytes.len());
        let qp_limit = base64_len.saturating_add(base64_len / QP_SLACK_DIVISOR);
        match qp::BODY.encoded_len_within(bytes, qp_limit) {
            Some(qp_len) => (TransferEncoding::QuotedPrintable, qp_len),
            None => (TransferEncoding::Base64, base64_len),
        }
    }

    pub(crate) fn select_entity(entity: &str) -> (BodyFormat, Self, usize) {
        let verbatim = (
            BodyFormat::Entity { body_start: 0 },
            TransferEncoding::Identity,
            entity.len(),
        );
        let Some(message) = MessageParser::new().parse_headers(entity) else {
            return verbatim;
        };
        let part = message.root_part();
        let is_composite = part.content_type().is_some_and(|content_type| {
            hashify::set_ignore_case!(content_type.ctype().as_bytes(), "multipart", "message")
        });
        if is_composite
            || part
                .headers()
                .value(HeaderName::ContentTransferEncoding)
                .is_some()
        {
            return verbatim;
        }
        let body_start = part.offset_body() as usize;
        let Some(body) = entity.get(body_start..) else {
            return verbatim;
        };
        match TransferEncoding::select(body) {
            (TransferEncoding::Identity, _) => verbatim,
            (encoding, encoded_len) => (
                BodyFormat::Entity { body_start },
                encoding,
                body_start + encoded_len,
            ),
        }
    }

    pub(crate) fn header_value(self) -> Option<&'static str> {
        match self {
            TransferEncoding::Identity => None,
            TransferEncoding::QuotedPrintable => Some("quoted-printable"),
            TransferEncoding::Base64 => Some("base64"),
        }
    }

    pub(crate) fn write(self, text: &str, out: &mut Vec<u8>) {
        match self {
            TransferEncoding::Identity => out.extend_from_slice(text.as_bytes()),
            TransferEncoding::QuotedPrintable => {
                qp::BODY.encode_append(text, out);
            }
            TransferEncoding::Base64 => {
                base64::MIME.encode_append(text, out);
            }
        }
    }
}

fn has_long_line(bytes: &[u8]) -> bool {
    if bytes.len() <= MAX_LINE_LEN {
        return false;
    }
    let mut line_start = 0;
    memchr::memchr_iter(b'\n', bytes).any(|line_end| {
        let is_long = line_end - line_start > MAX_LINE_LEN;
        line_start = line_end + 1;
        is_long
    }) || bytes.len() - line_start > MAX_LINE_LEN
}

impl<'x> Edits<'x> {
    #[inline(always)]
    pub(crate) fn headers(&self, part: PartId) -> Option<&[HeaderRef<'x>]> {
        if self.headers.is_empty() {
            return None;
        }
        self.headers
            .iter()
            .find(|(id, _)| *id == part)
            .map(|(_, headers)| headers.as_slice())
    }

    pub(crate) fn headers_mut(&mut self, part: MessagePart<'x>) -> &mut Vec<HeaderRef<'x>> {
        let id = part.id();
        let index = match self.headers.iter().position(|(edited, _)| *edited == id) {
            Some(index) => index,
            None => {
                self.headers
                    .push((id, part.headers().iter().map(HeaderRef::Parsed).collect()));
                self.headers.len() - 1
            }
        };
        &mut self.headers[index].1
    }

    pub(crate) fn set_headers(&mut self, part: PartId, headers: Vec<HeaderRef<'x>>) {
        match self.headers.iter_mut().find(|(id, _)| *id == part) {
            Some((_, edited)) => *edited = headers,
            None => self.headers.push((part, headers)),
        }
    }

    #[inline(always)]
    pub(crate) fn body(&self, part: PartId) -> Option<&BodyEdit<'x>> {
        if self.bodies.is_empty() {
            return None;
        }
        self.bodies
            .iter()
            .find(|(id, _)| *id == part)
            .map(|(_, body)| body)
    }

    pub(crate) fn set_body(&mut self, part: PartId, body: BodyEdit<'x>) {
        match self.bodies.iter_mut().find(|(id, _)| *id == part) {
            Some((_, edited)) => *edited = body,
            None => self.bodies.push((part, body)),
        }
    }

    pub(crate) fn hide(&mut self, range: Range<PartId>) {
        if range.is_empty() {
            return;
        }
        self.headers.retain(|(id, _)| !range.contains(id));
        self.bodies.retain(|(id, _)| !range.contains(id));
        self.hidden.retain(|hidden| !range.contains(&hidden.start));
        self.hidden.push(range);
    }

    #[inline(always)]
    pub(crate) fn hidden_end(&self, part: PartId) -> Option<PartId> {
        if self.hidden.is_empty() {
            return None;
        }
        self.hidden
            .iter()
            .find(|hidden| hidden.contains(&part))
            .map(|hidden| hidden.end)
    }

    pub(crate) fn touches(&self, range: &Range<PartId>) -> bool {
        self.headers.iter().any(|(id, _)| range.contains(id))
            || self.bodies.iter().any(|(id, _)| range.contains(id))
    }
}
