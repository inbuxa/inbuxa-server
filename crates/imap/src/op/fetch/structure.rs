/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{section::MessageSections, source::DecodedSources};
use email::message::metadata::{
    AddressHeader, AddressItem, Addresses, ArchivedMessageMetadata, ContentTypeView, EnvelopeView,
    HeaderMatcher, MAX_NESTING, Mailbox, MessageView, Occurrence, PartKind, PartView, RawMessage,
};
use imap_proto::protocol::{
    fetch::{BodyContents, Section},
    push_int, quoted_or_literal_encoded_string, quoted_or_literal_encoded_string_or_nil,
    quoted_or_literal_raw_string, quoted_or_literal_raw_string_or_nil, quoted_rfc2822,
};
use utils::chained_bytes::ChainedBytes;

const DUMMY_ADDRESS: Mailbox<'static> = Mailbox {
    name: None,
    address: Some("unknown@localhost"),
};
const DEFAULT_TRANSFER_ENCODING: &str = "7bit";
const DEFAULT_TEXT_SUBTYPE: &str = "plain";
const DEFAULT_MULTIPART_SUBTYPE: &str = "mixed";
const DEFAULT_MESSAGE_SUBTYPE: &str = "rfc822";
const DEFAULT_TEXT_PARAMS: &[u8] = b"(\"charset\" \"us-ascii\")";
const EMPTY_ENVELOPE: &[u8] = b"(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";
const EMPTY_BODY: &[u8] = b"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0)";
const EMPTY_BODY_EXTENDED: &[u8] =
    b"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0 NIL NIL NIL NIL)";
const MESSAGE_FRAME: u32 = u32::MAX;
const NO_PARENT: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary<T> {
    Found(T),
    Missing,
    UnknownCte,
}

impl<T> Binary<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Binary<U> {
        match self {
            Binary::Found(value) => Binary::Found(f(value)),
            Binary::Missing => Binary::Missing,
            Binary::UnknownCte => Binary::UnknownCte,
        }
    }
}

pub trait ImapMetadata {
    fn write_envelope(&self, buf: &mut Vec<u8>, is_utf8: bool);
    fn write_structure(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool);
    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
    );
    fn header<'x>(&self, raw: RawMessage<'x>) -> Option<ChainedBytes<'x>>;
    fn body_section<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[Section],
        partial: Option<(u32, u32)>,
        matcher: Option<&HeaderMatcher>,
    ) -> Option<BodyContents<'x>>;
    fn binary<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[u32],
        partial: Option<(u32, u32)>,
    ) -> Binary<BodyContents<'x>>;
    fn binary_size(&self, sections: &[u32]) -> Binary<usize>;
}

impl ImapMetadata for ArchivedMessageMetadata {
    fn write_envelope(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        self.root().envelope().write_imap(buf, is_utf8);
    }

    fn write_structure(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool) {
        self.root().write_structure(buf, is_extended, is_utf8);
    }

    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
    ) {
        self.root()
            .write_header_fields(buf, headers, section, matcher);
    }

    fn header<'x>(&self, raw: RawMessage<'x>) -> Option<ChainedBytes<'x>> {
        self.root().header(raw)
    }

    fn body_section<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[Section],
        partial: Option<(u32, u32)>,
        matcher: Option<&HeaderMatcher>,
    ) -> Option<BodyContents<'x>> {
        self.root()
            .body_section(raw, sources, sections, partial, matcher)
    }

    fn binary<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[u32],
        partial: Option<(u32, u32)>,
    ) -> Binary<BodyContents<'x>> {
        self.root().binary(raw, sources, sections, partial)
    }

    fn binary_size(&self, sections: &[u32]) -> Binary<usize> {
        self.root().binary_size(sections)
    }
}

#[derive(Clone, Copy)]
struct Frame {
    part: u32,
    next: u32,
}

struct FrameStack {
    frames: [Frame; MAX_NESTING],
    len: usize,
}

impl FrameStack {
    fn new() -> Self {
        FrameStack {
            frames: [Frame { part: 0, next: 0 }; MAX_NESTING],
            len: 0,
        }
    }

    fn push(&mut self, frame: Frame) -> bool {
        match self.frames.get_mut(self.len) {
            Some(slot) => {
                *slot = frame;
                self.len += 1;
                true
            }
            None => false,
        }
    }

    fn top(&mut self) -> Option<&mut Frame> {
        self.frames.get_mut(self.len.checked_sub(1)?)
    }

    fn pop(&mut self) -> Option<Frame> {
        let frame = *self.frames.get(self.len.checked_sub(1)?)?;
        self.len -= 1;
        Some(frame)
    }
}

trait StructureWriter {
    fn write_structure(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool);
}

impl StructureWriter for MessageView<'_> {
    fn write_structure(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool) {
        let meta = self.metadata();
        let empty_body = if is_extended {
            EMPTY_BODY_EXTENDED
        } else {
            EMPTY_BODY
        };
        let mut stack = FrameStack::new();
        let mut next = Some((self.root_part(), NO_PARENT));

        loop {
            if let Some((part, parent)) = next.take() {
                match part.kind() {
                    PartKind::Multipart => {
                        buf.push(b'(');
                        if stack.push(Frame {
                            part: part.id(),
                            next: 0,
                        }) {
                            continue;
                        }
                        buf.extend_from_slice(empty_body);
                        part.write_multipart_tail(buf, is_extended, is_utf8);
                    }
                    PartKind::Message => {
                        buf.push(b'(');
                        let nested = part.nested();
                        let content_type = part.content_type();
                        part.write_message_head(
                            buf,
                            content_type
                                .as_ref()
                                .and_then(|content_type| content_type.message_subtype())
                                .unwrap_or(DEFAULT_MESSAGE_SUBTYPE),
                            content_type,
                            nested.map(|nested| nested.envelope()),
                            is_utf8,
                        );
                        match nested {
                            Some(nested)
                                if stack.push(Frame {
                                    part: part.id(),
                                    next: MESSAGE_FRAME,
                                }) =>
                            {
                                next = Some((nested.root_part(), NO_PARENT));
                                continue;
                            }
                            _ => {
                                buf.extend_from_slice(empty_body);
                                part.write_message_tail(buf, is_extended, is_utf8);
                            }
                        }
                    }
                    _ => part.write_leaf(buf, parent, empty_body, is_extended, is_utf8),
                }
            }

            let Some(frame) = stack.top() else {
                return;
            };
            let Some(part) = meta.part(frame.part) else {
                stack.pop();
                continue;
            };
            if frame.next != MESSAGE_FRAME
                && let Some(child) = part.child(frame.next as usize)
            {
                frame.next += 1;
                next = Some((child, frame.part));
                continue;
            }
            let has_children = frame.next != 0;
            stack.pop();
            if part.is_message() {
                part.write_message_tail(buf, is_extended, is_utf8);
            } else {
                if !has_children {
                    buf.extend_from_slice(empty_body);
                }
                part.write_multipart_tail(buf, is_extended, is_utf8);
            }
        }
    }
}

trait ImapEnvelope {
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool);
}

impl ImapEnvelope for EnvelopeView<'_> {
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        buf.push(b'(');
        match self.datetime() {
            Some(date) => quoted_rfc2822(buf, &date),
            None => quoted_or_literal_encoded_string_or_nil(buf, self.date_raw(), is_utf8),
        }
        buf.push(b' ');
        quoted_or_literal_encoded_string_or_nil(buf, self.subject(), is_utf8);

        let from = self
            .addresses(AddressHeader::From, Occurrence::All)
            .visible();
        from.write_imap_or(buf, None, is_utf8);
        self.addresses(AddressHeader::Sender, Occurrence::All)
            .visible()
            .or(from)
            .write_imap_or(buf, None, is_utf8);
        self.addresses(AddressHeader::ReplyTo, Occurrence::All)
            .visible()
            .or(from)
            .write_imap_or(buf, None, is_utf8);
        for header in [AddressHeader::To, AddressHeader::Cc, AddressHeader::Bcc] {
            self.addresses(header, Occurrence::All)
                .visible()
                .write_imap_or(buf, Some(b"NIL"), is_utf8);
        }

        let in_reply_to = self.in_reply_to();
        buf.push(b' ');
        quoted_or_literal_raw_string_or_nil(
            buf,
            if in_reply_to.is_present() && in_reply_to.is_empty() {
                Some("")
            } else {
                in_reply_to.joined_bracketed()
            },
            is_utf8,
        );
        let message_id = self.message_id();
        buf.push(b' ');
        quoted_or_literal_raw_string_or_nil(
            buf,
            if message_id.is_present() && message_id.is_empty() {
                Some("")
            } else {
                message_id.last_bracketed()
            },
            is_utf8,
        );
        buf.push(b')');
    }
}

trait ImapAddresses: Sized {
    fn visible(self) -> Option<Self>;
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool);
}

impl ImapAddresses for Addresses<'_> {
    fn visible(self) -> Option<Self> {
        self.has_imap_address().then_some(self)
    }

    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        buf.push(b'(');
        for item in self.iter() {
            match item {
                AddressItem::Mailbox(mailbox) => mailbox.write_imap(buf, is_utf8),
                AddressItem::Group(group) => {
                    buf.extend_from_slice(b"(NIL NIL ");
                    if let Some(name) = group.name {
                        quoted_or_literal_encoded_string(buf, name, is_utf8);
                    } else {
                        buf.extend_from_slice(b"\"\"");
                    }
                    buf.extend_from_slice(b" NIL)");
                    for mailbox in group.members.mailboxes() {
                        mailbox.write_imap(buf, is_utf8);
                    }
                    buf.extend_from_slice(b"(NIL NIL NIL NIL)");
                }
            }
        }
        buf.push(b')');
    }
}

trait ImapAddressField {
    fn write_imap_or(self, buf: &mut Vec<u8>, fallback: Option<&[u8]>, is_utf8: bool);
}

impl ImapAddressField for Option<Addresses<'_>> {
    fn write_imap_or(self, buf: &mut Vec<u8>, fallback: Option<&[u8]>, is_utf8: bool) {
        buf.push(b' ');
        match (self, fallback) {
            (Some(addresses), _) => addresses.write_imap(buf, is_utf8),
            (None, Some(fallback)) => buf.extend_from_slice(fallback),
            (None, None) => {
                buf.push(b'(');
                DUMMY_ADDRESS.write_imap(buf, is_utf8);
                buf.push(b')');
            }
        }
    }
}

trait ImapMailbox {
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool);
}

impl ImapMailbox for Mailbox<'_> {
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        let Some(address) = self.address else {
            return;
        };
        buf.push(b'(');
        if let Some(name) = self.name {
            quoted_or_literal_encoded_string(buf, name, is_utf8);
        } else {
            buf.extend_from_slice(b"NIL");
        }

        let addr = if let Some((route, addr)) = address.split_once(':') {
            buf.push(b' ');
            quoted_or_literal_raw_string(buf, route, is_utf8);
            buf.push(b' ');
            addr
        } else {
            buf.extend_from_slice(b" NIL ");
            address
        };

        if let Some((local, host)) = addr.rsplit_once('@') {
            quoted_or_literal_raw_string(buf, local, is_utf8);
            buf.push(b' ');
            quoted_or_literal_raw_string(buf, host, is_utf8);
        } else {
            quoted_or_literal_raw_string(buf, address, is_utf8);
            buf.extend_from_slice(b" \"\"");
        }
        buf.push(b')');
    }
}

trait ImapContentType {
    fn write_parameters(&self, buf: &mut Vec<u8>, is_utf8: bool);
    fn message_subtype(&self) -> Option<&str>;
}

impl ImapContentType for ContentTypeView<'_> {
    fn message_subtype(&self) -> Option<&str> {
        self.subtype().filter(|subtype| {
            self.ctype().eq_ignore_ascii_case("message") && subtype.is_message_subtype()
        })
    }

    fn write_parameters(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        for (pos, (key, value)) in self.attributes().enumerate() {
            if pos > 0 {
                buf.push(b' ');
            }
            quoted_or_literal_raw_string(buf, key, is_utf8);
            buf.push(b' ');
            quoted_or_literal_encoded_string(buf, value, is_utf8);
        }
    }
}

#[derive(Clone, Copy)]
enum LeafMedia<'a> {
    Text {
        subtype: &'a str,
        params: Option<ContentTypeView<'a>>,
    },
    Message {
        subtype: &'a str,
        params: Option<ContentTypeView<'a>>,
    },
    Basic {
        ctype: &'a str,
        subtype: &'a str,
        params: ContentTypeView<'a>,
    },
}

trait ImapPart {
    fn is_digest(&self) -> bool;
    fn leaf_media(&self, parent: u32) -> LeafMedia<'_>;
    fn write_fields(
        &self,
        buf: &mut Vec<u8>,
        params: Option<ContentTypeView<'_>>,
        default_params: &[u8],
        is_utf8: bool,
    );
    fn write_extension(&self, buf: &mut Vec<u8>, is_utf8: bool);
    fn write_leaf(
        &self,
        buf: &mut Vec<u8>,
        parent: u32,
        empty_body: &[u8],
        is_extended: bool,
        is_utf8: bool,
    );
    fn write_message_head(
        &self,
        buf: &mut Vec<u8>,
        subtype: &str,
        params: Option<ContentTypeView<'_>>,
        envelope: Option<EnvelopeView<'_>>,
        is_utf8: bool,
    );
    fn write_message_tail(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool);
    fn write_multipart_tail(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool);
}

impl ImapPart for PartView<'_> {
    fn is_digest(&self) -> bool {
        self.content_type()
            .and_then(|content_type| content_type.subtype())
            .is_some_and(|subtype| subtype.eq_ignore_ascii_case("digest"))
    }

    fn leaf_media(&self, parent: u32) -> LeafMedia<'_> {
        let Some(content_type) = self.content_type() else {
            return if self
                .metadata()
                .part(parent)
                .is_some_and(|parent| parent.is_digest())
            {
                LeafMedia::Message {
                    subtype: DEFAULT_MESSAGE_SUBTYPE,
                    params: None,
                }
            } else {
                LeafMedia::Text {
                    subtype: DEFAULT_TEXT_SUBTYPE,
                    params: None,
                }
            };
        };
        let ctype = content_type.ctype();
        let Some(subtype) = content_type
            .subtype()
            .filter(|subtype| !subtype.is_empty() && !ctype.is_empty())
        else {
            return LeafMedia::Text {
                subtype: DEFAULT_TEXT_SUBTYPE,
                params: None,
            };
        };
        if ctype.eq_ignore_ascii_case("text") {
            LeafMedia::Text {
                subtype,
                params: Some(content_type),
            }
        } else if ctype.eq_ignore_ascii_case("multipart") {
            LeafMedia::Text {
                subtype: DEFAULT_TEXT_SUBTYPE,
                params: Some(content_type),
            }
        } else if ctype.eq_ignore_ascii_case("message") && subtype.is_message_subtype() {
            LeafMedia::Message {
                subtype,
                params: Some(content_type),
            }
        } else if !ctype.is_media_token() || !subtype.is_media_token() {
            LeafMedia::Text {
                subtype: DEFAULT_TEXT_SUBTYPE,
                params: None,
            }
        } else {
            LeafMedia::Basic {
                ctype,
                subtype,
                params: content_type,
            }
        }
    }

    fn write_fields(
        &self,
        buf: &mut Vec<u8>,
        params: Option<ContentTypeView<'_>>,
        default_params: &[u8],
        is_utf8: bool,
    ) {
        match params.filter(|content_type| content_type.has_attributes()) {
            Some(content_type) => {
                buf.push(b'(');
                content_type.write_parameters(buf, is_utf8);
                buf.push(b')');
            }
            None => buf.extend_from_slice(default_params),
        }
        buf.push(b' ');
        quoted_or_literal_encoded_string_or_nil(buf, self.content_id_bracketed(), is_utf8);
        buf.push(b' ');
        quoted_or_literal_encoded_string_or_nil(buf, self.content_description(), is_utf8);
        buf.push(b' ');
        quoted_or_literal_encoded_string(
            buf,
            self.content_transfer_encoding()
                .unwrap_or(DEFAULT_TRANSFER_ENCODING),
            is_utf8,
        );
        buf.push(b' ');
        push_int(buf, self.body_range().len());
    }

    fn write_extension(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        if let Some(disposition) = self.content_disposition() {
            buf.push(b'(');
            quoted_or_literal_raw_string(buf, disposition.ctype(), is_utf8);
            if disposition.has_attributes() {
                buf.extend_from_slice(b" (");
                disposition.write_parameters(buf, is_utf8);
                buf.extend_from_slice(b"))");
            } else {
                buf.extend_from_slice(b" NIL)");
            }
        } else {
            buf.extend_from_slice(b"NIL");
        }
        let languages = self.content_language();
        match languages.len() {
            0 => buf.extend_from_slice(b" NIL"),
            1 => {
                buf.push(b' ');
                quoted_or_literal_raw_string(
                    buf,
                    languages.iter().next().unwrap_or_default(),
                    is_utf8,
                );
            }
            _ => {
                buf.extend_from_slice(b" (");
                for (pos, language) in languages.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b' ');
                    }
                    quoted_or_literal_raw_string(buf, language, is_utf8);
                }
                buf.push(b')');
            }
        }
        buf.push(b' ');
        quoted_or_literal_raw_string_or_nil(buf, self.content_location(), is_utf8);
    }

    fn write_leaf(
        &self,
        buf: &mut Vec<u8>,
        parent: u32,
        empty_body: &[u8],
        is_extended: bool,
        is_utf8: bool,
    ) {
        buf.push(b'(');
        match self.leaf_media(parent) {
            LeafMedia::Text { subtype, params } => {
                buf.extend_from_slice(b"\"text\" ");
                quoted_or_literal_raw_string(buf, subtype, is_utf8);
                buf.push(b' ');
                self.write_fields(buf, params, DEFAULT_TEXT_PARAMS, is_utf8);
                buf.push(b' ');
                push_int(buf, self.lines());
            }
            LeafMedia::Message { subtype, params } => {
                self.write_message_head(buf, subtype, params, None, is_utf8);
                buf.extend_from_slice(empty_body);
                buf.push(b' ');
                push_int(buf, self.lines());
            }
            LeafMedia::Basic {
                ctype,
                subtype,
                params,
            } => {
                quoted_or_literal_raw_string(buf, ctype, is_utf8);
                buf.push(b' ');
                quoted_or_literal_raw_string(buf, subtype, is_utf8);
                buf.push(b' ');
                self.write_fields(buf, Some(params), b"NIL", is_utf8);
            }
        }
        if is_extended {
            buf.push(b' ');
            quoted_or_literal_raw_string_or_nil(buf, self.content_md5(), is_utf8);
            buf.push(b' ');
            self.write_extension(buf, is_utf8);
        }
        buf.push(b')');
    }

    fn write_message_head(
        &self,
        buf: &mut Vec<u8>,
        subtype: &str,
        params: Option<ContentTypeView<'_>>,
        envelope: Option<EnvelopeView<'_>>,
        is_utf8: bool,
    ) {
        buf.extend_from_slice(b"\"message\" ");
        quoted_or_literal_raw_string(buf, subtype, is_utf8);
        buf.push(b' ');
        self.write_fields(buf, params, b"NIL", is_utf8);
        buf.push(b' ');
        match envelope {
            Some(envelope) => envelope.write_imap(buf, is_utf8),
            None => buf.extend_from_slice(EMPTY_ENVELOPE),
        }
        buf.push(b' ');
    }

    fn write_message_tail(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool) {
        buf.push(b' ');
        push_int(buf, self.lines());
        if is_extended {
            buf.push(b' ');
            quoted_or_literal_raw_string_or_nil(buf, self.content_md5(), is_utf8);
            buf.push(b' ');
            self.write_extension(buf, is_utf8);
        }
        buf.push(b')');
    }

    fn write_multipart_tail(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool) {
        let content_type = self.content_type();
        buf.push(b' ');
        quoted_or_literal_raw_string(
            buf,
            content_type
                .and_then(|content_type| content_type.subtype())
                .filter(|subtype| !subtype.is_empty())
                .unwrap_or(DEFAULT_MULTIPART_SUBTYPE),
            is_utf8,
        );
        if is_extended {
            match content_type.filter(|content_type| content_type.has_attributes()) {
                Some(content_type) => {
                    buf.extend_from_slice(b" (");
                    content_type.write_parameters(buf, is_utf8);
                    buf.push(b')');
                }
                None => buf.extend_from_slice(b" NIL"),
            }
            buf.push(b' ');
            self.write_extension(buf, is_utf8);
        }
        buf.push(b')');
    }
}

trait MediaToken {
    fn is_message_subtype(&self) -> bool;
    fn is_media_token(&self) -> bool;
}

impl MediaToken for str {
    fn is_message_subtype(&self) -> bool {
        self.eq_ignore_ascii_case("rfc822") || self.eq_ignore_ascii_case("global")
    }

    fn is_media_token(&self) -> bool {
        !self.is_empty() && !self.contains('\0')
    }
}

