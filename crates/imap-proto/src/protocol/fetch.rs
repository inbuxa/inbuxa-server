/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use crate::protocol::push_int;
use compact_str::CompactString;

use super::{
    Flag, ObjectId, Sequence, WriteLiteral, literal_string, quoted_or_literal_string,
    quoted_timestamp,
};
use std::borrow::{Borrow, Cow};
use utils::chained_bytes::ChainedBytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub sequence_set: Sequence,
    pub attributes: Vec<Attribute>,
    pub changed_since: Option<u64>,
    pub include_vanished: bool,
}

impl Flag {
    pub fn write_fetch_item<F: Borrow<Flag>>(
        buf: &mut Vec<u8>,
        flags: impl IntoIterator<Item = F>,
    ) {
        buf.extend_from_slice(b"FLAGS (");
        for (pos, flag) in flags
            .into_iter()
            .filter(|flag| flag.borrow().is_serializable())
            .enumerate()
        {
            if pos > 0 {
                buf.push(b' ');
            }
            flag.borrow().serialize(buf);
        }
        buf.push(b')');
    }
}

impl Attribute {
    pub fn header_fields(&self) -> Option<&[String]> {
        match self {
            Attribute::BodySection { sections, .. } => match sections.last() {
                Some(Section::HeaderFields { fields, .. }) => Some(fields),
                _ => None,
            },
            _ => None,
        }
    }
}

impl Arguments {
    pub fn sets_seen(&self) -> bool {
        self.attributes.iter().any(|attribute| {
            matches!(
                attribute,
                Attribute::BodySection { peek: false, .. }
                    | Attribute::Binary { peek: false, .. }
                    | Attribute::Rfc822
                    | Attribute::Rfc822Text
            )
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchItem<'x> {
    pub id: u32,
    pub is_uidonly: bool,
    pub items: Vec<DataItem<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    Envelope,
    Flags,
    InternalDate,
    Rfc822,
    Rfc822Size,
    Rfc822Header,
    Rfc822Text,
    Body,
    BodyStructure,
    BodySection {
        peek: bool,
        sections: Vec<Section>,
        partial: Option<(u32, u32)>,
    },
    Uid,
    Binary {
        peek: bool,
        sections: Vec<u32>,
        partial: Option<(u32, u32)>,
    },
    BinarySize {
        sections: Vec<u32>,
    },
    Preview {
        lazy: bool,
    },
    ModSeq,
    ObjectId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Section {
    Part { num: u32 },
    Header,
    HeaderFields { not: bool, fields: Vec<String> },
    Text,
    Mime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataItem<'x> {
    Binary {
        sections: Cow<'x, [u32]>,
        offset: Option<u32>,
        contents: BodyContents<'x>,
    },
    BinarySize {
        sections: Cow<'x, [u32]>,
        size: usize,
    },
    BodySection {
        sections: Cow<'x, [Section]>,
        origin_octet: Option<u32>,
        contents: BodyContents<'x>,
    },
    Flags {
        flags: Vec<Flag>,
    },
    InternalDate {
        date: i64,
    },
    Uid {
        uid: u32,
    },
    Rfc822 {
        contents: ChainedBytes<'x>,
    },
    Rfc822Header {
        contents: ChainedBytes<'x>,
    },
    Rfc822Size {
        size: usize,
    },
    Rfc822Text {
        contents: ChainedBytes<'x>,
    },
    Preview {
        contents: Option<Cow<'x, [u8]>>,
    },
    ModSeq {
        modseq: u64,
    },
    ObjectId(ObjectId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyContents<'x> {
    Text(Cow<'x, str>),
    Bytes(ChainedBytes<'x>),
    Owned(Vec<u8>),
}

impl<'x> BodyContents<'x> {
    pub fn as_chained(&self) -> ChainedBytes<'_> {
        match self {
            BodyContents::Text(text) => ChainedBytes::new(text.as_bytes()),
            BodyContents::Bytes(bytes) => *bytes,
            BodyContents::Owned(bytes) => ChainedBytes::new(bytes),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            BodyContents::Text(text) => text.len(),
            BodyContents::Bytes(bytes) => bytes.len(),
            BodyContents::Owned(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn partial(self, partial: Option<(u32, u32)>) -> Self {
        let Some((start, len)) = partial else {
            return self;
        };
        let start = start as usize;
        let end = start.saturating_add(len as usize);
        match self {
            BodyContents::Bytes(bytes) => {
                BodyContents::Bytes(bytes.view(start..end.min(bytes.len())).unwrap_or_default())
            }
            BodyContents::Owned(mut bytes) => {
                bytes.truncate(end);
                bytes.drain(..start.min(bytes.len()));
                BodyContents::Owned(bytes)
            }
            BodyContents::Text(text) => BodyContents::Owned(
                text.as_bytes()
                    .get(start..end.min(text.len()))
                    .unwrap_or_default()
                    .to_vec(),
            ),
        }
    }
}

impl<'x> From<Cow<'x, [u8]>> for BodyContents<'x> {
    fn from(bytes: Cow<'x, [u8]>) -> Self {
        match bytes {
            Cow::Borrowed(bytes) => BodyContents::Bytes(ChainedBytes::new(bytes)),
            Cow::Owned(bytes) => BodyContents::Owned(bytes),
        }
    }
}

impl Section {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            Section::Part { num } => {
                push_int(buf, *num);
            }
            Section::Header => {
                buf.extend_from_slice(b"HEADER");
            }
            Section::HeaderFields { not, fields } => {
                if !not {
                    buf.extend_from_slice(b"HEADER.FIELDS (");
                } else {
                    buf.extend_from_slice(b"HEADER.FIELDS.NOT (");
                }
                for (pos, field) in fields.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b' ');
                    }
                    let start = buf.len();
                    buf.extend_from_slice(field.as_bytes());
                    let is_atom = buf.get_mut(start..).is_some_and(|written| {
                        let mut is_atom = !written.is_empty();
                        for ch in written.iter_mut() {
                            is_atom &= ATOM_CHAR[*ch as usize];
                            ch.make_ascii_uppercase();
                        }
                        is_atom
                    });
                    if !is_atom {
                        buf.truncate(start);
                        quoted_or_literal_string(buf, &field.to_ascii_uppercase());
                    }
                }
                buf.push(b')');
            }
            Section::Text => {
                buf.extend_from_slice(b"TEXT");
            }
            Section::Mime => {
                buf.extend_from_slice(b"MIME");
            }
        };
    }
}

impl DataItem<'_> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            DataItem::Binary {
                sections,
                offset,
                contents,
            } => {
                buf.extend_from_slice(b"BINARY[");
                for (pos, section) in sections.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b'.');
                    }
                    push_int(buf, *section);
                }
                if let Some(offset) = offset {
                    buf.extend_from_slice(b"]<");
                    push_int(buf, *offset);
                    buf.extend_from_slice(b"> ");
                } else {
                    buf.extend_from_slice(b"] ");
                }
                if let BodyContents::Text(text) = contents {
                    literal_string(buf, text.as_bytes());
                } else {
                    buf.push(b'~');
                    contents.as_chained().write_literal(buf);
                }
            }
            DataItem::BinarySize { sections, size } => {
                buf.extend_from_slice(b"BINARY.SIZE[");
                for (pos, section) in sections.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b'.');
                    }
                    push_int(buf, *section);
                }
                buf.extend_from_slice(b"] ");
                push_int(buf, *size);
            }
            DataItem::BodySection {
                sections,
                origin_octet,
                contents,
            } => {
                buf.extend_from_slice(b"BODY[");
                for (pos, section) in sections.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b'.');
                    }
                    section.serialize(buf);
                }
                if let Some(origin_octet) = origin_octet {
                    buf.extend_from_slice(b"]<");
                    push_int(buf, *origin_octet);
                    buf.extend_from_slice(b"> ");
                } else {
                    buf.extend_from_slice(b"] ");
                }
                contents.as_chained().write_literal(buf);
            }
            DataItem::Flags { flags } => Flag::write_fetch_item(buf, flags),
            DataItem::InternalDate { date } => {
                buf.extend_from_slice(b"INTERNALDATE ");
                quoted_timestamp(buf, *date);
            }
            DataItem::Uid { uid } => {
                buf.extend_from_slice(b"UID ");
                push_int(buf, *uid);
            }
            DataItem::Rfc822 { contents } => {
                buf.extend_from_slice(b"RFC822 ");
                contents.write_literal(buf);
            }
            DataItem::Rfc822Header { contents } => {
                buf.extend_from_slice(b"RFC822.HEADER ");
                contents.write_literal(buf);
            }
            DataItem::Rfc822Size { size } => {
                buf.extend_from_slice(b"RFC822.SIZE ");
                push_int(buf, *size);
            }
            DataItem::Rfc822Text { contents } => {
                buf.extend_from_slice(b"RFC822.TEXT ");
                contents.write_literal(buf);
            }
            DataItem::Preview { contents } => {
                buf.extend_from_slice(b"PREVIEW ");
                if let Some(contents) = contents {
                    literal_string(buf, contents);
                } else {
                    buf.extend_from_slice(b"NIL");
                }
            }
            DataItem::ModSeq { modseq } => {
                buf.extend_from_slice(b"MODSEQ (");
                push_int(buf, *modseq);
                buf.push(b')');
            }
            DataItem::ObjectId(object_id) => {
                object_id.serialize(buf);
            }
        }
    }
}

impl FetchItem<'_> {
    pub fn write_open(buf: &mut Vec<u8>, id: u32, is_uidonly: bool) {
        buf.extend_from_slice(b"* ");
        push_int(buf, id);
        buf.extend_from_slice(if is_uidonly {
            b" UIDFETCH (".as_slice()
        } else {
            b" FETCH (".as_slice()
        });
    }

    pub fn write_close(buf: &mut Vec<u8>) {
        buf.extend_from_slice(b")\r\n");
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        Self::write_open(buf, self.id, self.is_uidonly);
        for (pos, item) in self.items.iter().enumerate() {
            if pos > 0 {
                buf.push(b' ');
            }
            item.serialize(buf);
        }
        Self::write_close(buf);
    }
}

const fn atom_char_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut ch = 0x21;
    while ch < 0x7f {
        table[ch] = !matches!(
            ch as u8,
            b'(' | b')' | b'{' | b'%' | b'*' | b'"' | b'\\' | b']'
        );
        ch += 1;
    }
    table
}

static ATOM_CHAR: [bool; 256] = atom_char_table();

const SECTION_FRAMING_LEN: usize = 20;
const ITEM_FRAMING_LEN: usize = 16;
const INT_LEN: usize = 11;
const SIZE_LEN: usize = 20;
const OBJECT_ID_LEN: usize = 96;

impl Section {
    fn size_hint(&self) -> usize {
        match self {
            Section::Part { .. } => INT_LEN,
            Section::Header => 6,
            Section::HeaderFields { fields, .. } => {
                SECTION_FRAMING_LEN + fields.iter().map(|field| field.len() + 1).sum::<usize>()
            }
            Section::Text | Section::Mime => 4,
        }
    }
}

impl DataItem<'_> {
    fn size_hint(&self) -> usize {
        match self {
            DataItem::Binary {
                sections, contents, ..
            } => ITEM_FRAMING_LEN + sections.len() * INT_LEN + INT_LEN + contents.len(),
            DataItem::BinarySize { sections, .. } => {
                ITEM_FRAMING_LEN + sections.len() * INT_LEN + SIZE_LEN
            }
            DataItem::BodySection {
                sections, contents, ..
            } => {
                ITEM_FRAMING_LEN
                    + sections
                        .iter()
                        .map(|section| section.size_hint() + 1)
                        .sum::<usize>()
                    + INT_LEN
                    + contents.len()
            }
            DataItem::Flags { flags } => ITEM_FRAMING_LEN + flags.len() * 16,
            DataItem::InternalDate { .. } => ITEM_FRAMING_LEN + 28,
            DataItem::Uid { .. } => ITEM_FRAMING_LEN,
            DataItem::Rfc822 { contents }
            | DataItem::Rfc822Header { contents }
            | DataItem::Rfc822Text { contents } => ITEM_FRAMING_LEN + INT_LEN + contents.len(),
            DataItem::Rfc822Size { .. } => ITEM_FRAMING_LEN + SIZE_LEN,
            DataItem::Preview { contents } => {
                ITEM_FRAMING_LEN
                    + contents
                        .as_ref()
                        .map_or(0, |contents| contents.len() + INT_LEN)
            }
            DataItem::ModSeq { .. } => ITEM_FRAMING_LEN + SIZE_LEN,
            DataItem::ObjectId(_) => OBJECT_ID_LEN,
        }
    }
}

impl FetchItem<'_> {
    pub(crate) fn size_hint(&self) -> usize {
        ITEM_FRAMING_LEN
            + self
                .items
                .iter()
                .map(|item| item.size_hint() + 1)
                .sum::<usize>()
    }
}

