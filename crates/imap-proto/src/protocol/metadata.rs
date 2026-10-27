/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{literal_string, literal8_string, push_int, quoted_mailbox_name, quoted_string};
use compact_str::CompactString;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetArguments {
    pub tag: CompactString,
    pub mailbox_name: CompactString,
    pub max_size: Option<u32>,
    pub depth: Depth,
    pub entries: Vec<Entry<'static>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetArguments {
    pub tag: CompactString,
    pub mailbox_name: CompactString,
    pub entries: Vec<EntryValue<'static>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Depth {
    #[default]
    Zero,
    One,
    Infinity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Shared,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entry<'x> {
    pub scope: Scope,
    pub path: Cow<'x, str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryValue<'x> {
    pub entry: Entry<'x>,
    pub value: Option<Cow<'x, [u8]>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response<'x> {
    pub mailbox_name: &'x str,
    pub entries: Vec<EntryValue<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsolicitedResponse<'x> {
    pub mailbox_name: &'x str,
    pub entries: Vec<Entry<'x>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataCode {
    LongEntries(u32),
    MaxSize(u32),
    TooMany,
    NoPrivate,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Shared => "/shared",
            Scope::Private => "/private",
        }
    }
}

impl Entry<'_> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        let scope = self.scope.as_str();
        if self.path.bytes().all(is_astring_char) {
            buf.extend_from_slice(scope.as_bytes());
            buf.extend_from_slice(self.path.as_bytes());
        } else {
            quoted_string(buf, &[scope, &self.path].concat());
        }
    }
}

impl EntryValue<'_> {
    pub fn into_owned(self) -> EntryValue<'static> {
        EntryValue {
            entry: Entry {
                scope: self.entry.scope,
                path: Cow::Owned(self.entry.path.into_owned()),
            },
            value: self.value.map(|value| Cow::Owned(value.into_owned())),
        }
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        self.entry.serialize(buf);
        buf.push(b' ');
        match self.value.as_deref() {
            Some(value) if value.iter().all(|ch| (0x20..0x7f).contains(ch)) => {
                quoted_string(buf, std::str::from_utf8(value).unwrap_or_default())
            }
            Some(value) if value.contains(&0) => literal8_string(buf, value),
            Some(value) => literal_string(buf, value),
            None => buf.extend_from_slice(b"NIL"),
        }
    }
}

impl Response<'_> {
    pub fn serialize(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        serialize_entry_values(buf, self.mailbox_name, &self.entries, is_utf8);
    }
}

pub(crate) fn serialize_entry_values(
    buf: &mut Vec<u8>,
    mailbox_name: &str,
    entries: &[EntryValue<'_>],
    is_utf8: bool,
) {
    buf.extend_from_slice(b"* METADATA ");
    quoted_mailbox_name(buf, mailbox_name, is_utf8);
    buf.extend_from_slice(b" (");
    for (pos, entry) in entries.iter().enumerate() {
        if pos > 0 {
            buf.push(b' ');
        }
        entry.serialize(buf);
    }
    buf.extend_from_slice(b")\r\n");
}

impl UnsolicitedResponse<'_> {
    pub fn serialize(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        buf.extend_from_slice(b"* METADATA ");
        quoted_mailbox_name(buf, self.mailbox_name, is_utf8);
        for entry in &self.entries {
            buf.push(b' ');
            entry.serialize(buf);
        }
        buf.extend_from_slice(b"\r\n");
    }
}

impl MetadataCode {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_str().as_bytes());
        if let MetadataCode::LongEntries(size) | MetadataCode::MaxSize(size) = self {
            buf.push(b' ');
            push_int(buf, *size);
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MetadataCode::LongEntries(_) => "METADATA LONGENTRIES",
            MetadataCode::MaxSize(_) => "METADATA MAXSIZE",
            MetadataCode::TooMany => "METADATA TOOMANY",
            MetadataCode::NoPrivate => "METADATA NOPRIVATE",
        }
    }
}

fn is_astring_char(ch: u8) -> bool {
    ch > 0x20 && ch < 0x7f && !matches!(ch, b'(' | b')' | b'{' | b'"' | b'\\' | b'%' | b'*')
}

