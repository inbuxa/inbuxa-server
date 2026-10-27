/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use compact_str::CompactString;

use super::{
    ImapResponse, MailboxObjectId, ObjectId,
    metadata::{Entry, EntryValue, serialize_entry_values},
    quoted_mailbox_name, quoted_string,
    status::{Status, StatusItem},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arguments {
    Basic {
        tag: CompactString,
        reference_name: CompactString,
        mailbox_name: CompactString,
    },
    Extended {
        tag: CompactString,
        reference_name: CompactString,
        mailbox_name: Vec<CompactString>,
        selection_options: Vec<SelectionOption>,
        return_options: Vec<ReturnOption>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub is_rev2: bool,
    pub is_utf8: bool,
    pub is_lsub: bool,
    pub list_items: Vec<ListItem>,
    pub status_items: Vec<StatusItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionOption {
    Subscribed,
    Remote,
    RecursiveMatch,
    SpecialUse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnOption {
    Subscribed,
    Children,
    Status(Vec<Status>),
    SpecialUse,
    Metadata(Vec<Entry<'static>>),
    ObjectId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribute {
    NoInferiors,
    NoSelect,
    Marked,
    Unmarked,
    NonExistent,
    HasChildren,
    HasNoChildren,
    Subscribed,
    Remote,
    All,
    Archive,
    Drafts,
    Flagged,
    Junk,
    Sent,
    Trash,
    Important,
    Memos,
    Scheduled,
    Snoozed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildInfo {
    Subscribed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tag {
    ChildInfo(Vec<ChildInfo>),
    OldName(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListItem {
    pub mailbox_name: CompactString,
    pub attributes: Vec<Attribute>,
    pub tags: Vec<Tag>,
    pub objectid: Option<MailboxObjectId>,
    pub metadata: Option<Box<[EntryValue<'static>]>>,
}

impl Arguments {
    pub fn is_separator_query(&self) -> bool {
        match self {
            Arguments::Basic {
                mailbox_name,
                reference_name,
                ..
            } => mailbox_name.is_empty() && reference_name.is_empty(),
            Arguments::Extended {
                mailbox_name,
                reference_name,
                ..
            } => {
                reference_name.is_empty()
                    && mailbox_name
                        .iter()
                        .all(|mailbox_name| mailbox_name.is_empty())
            }
        }
    }

    pub fn requests_objectid(&self) -> bool {
        match self {
            Arguments::Basic { .. } => false,
            Arguments::Extended { return_options, .. } => {
                return_options.iter().any(|option| match option {
                    ReturnOption::ObjectId => true,
                    ReturnOption::Status(status) => status.contains(&Status::ObjectId),
                    _ => false,
                })
            }
        }
    }

    pub fn returns_objectid(&self) -> bool {
        matches!(self, Arguments::Extended { return_options, .. } if return_options.contains(&ReturnOption::ObjectId))
    }

    pub fn unwrap_tag(self) -> CompactString {
        match self {
            Arguments::Basic { tag, .. } => tag,
            Arguments::Extended { tag, .. } => tag,
        }
    }
}

impl Attribute {
    pub fn is_rev1(&self) -> bool {
        matches!(
            self,
            Attribute::NoInferiors | Attribute::NoSelect | Attribute::Marked | Attribute::Unmarked
        )
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }

    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Attribute::NoInferiors => b"\\NoInferiors",
            Attribute::NoSelect => b"\\NoSelect",
            Attribute::Marked => b"\\Marked",
            Attribute::Unmarked => b"\\Unmarked",
            Attribute::NonExistent => b"\\NonExistent",
            Attribute::HasChildren => b"\\HasChildren",
            Attribute::HasNoChildren => b"\\HasNoChildren",
            Attribute::Subscribed => b"\\Subscribed",
            Attribute::Remote => b"\\Remote",
            Attribute::All => b"\\All",
            Attribute::Archive => b"\\Archive",
            Attribute::Drafts => b"\\Drafts",
            Attribute::Flagged => b"\\Flagged",
            Attribute::Junk => b"\\Junk",
            Attribute::Sent => b"\\Sent",
            Attribute::Trash => b"\\Trash",
            Attribute::Important => b"\\Important",
            Attribute::Memos => b"\\Memos",
            Attribute::Scheduled => b"\\Scheduled",
            Attribute::Snoozed => b"\\Snoozed",
        }
    }
}

impl TryFrom<&str> for Attribute {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hashify::map!(value.as_bytes(), Attribute,
            "archive" => Attribute::Archive,
            "drafts" => Attribute::Drafts,
            "junk" => Attribute::Junk,
            "sent" => Attribute::Sent,
            "trash" => Attribute::Trash,
            "important" => Attribute::Important,
            "memos" => Attribute::Memos,
            "scheduled" => Attribute::Scheduled,
            "snoozed" => Attribute::Snoozed,
        )
        .copied()
        .ok_or(())
    }
}

impl ChildInfo {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.push(b'\"');
        buf.extend_from_slice(match self {
            ChildInfo::Subscribed => b"SUBSCRIBED",
        });
        buf.push(b'\"');
    }
}

impl Tag {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            Tag::ChildInfo(child_info) => {
                buf.extend_from_slice(b"\"CHILDINFO\" (");
                for (pos, child_info) in child_info.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b' ');
                    }
                    child_info.serialize(buf);
                }
                buf.push(b')');
            }
            Tag::OldName(old_name) => {
                buf.extend_from_slice(b"\"OLDNAME\" (");
                quoted_string(buf, old_name);
                buf.push(b')');
            }
        }
    }
}

impl ListItem {
    pub fn new(name: impl Into<CompactString>) -> Self {
        ListItem {
            mailbox_name: name.into(),
            attributes: Vec::new(),
            tags: Vec::new(),
            objectid: None,
            metadata: None,
        }
    }

    pub fn serialize(&self, buf: &mut Vec<u8>, is_rev2: bool, is_utf8: bool, is_lsub: bool) {
        if !is_lsub {
            buf.extend_from_slice(b"* LIST (");
        } else {
            buf.extend_from_slice(b"* LSUB (");
        }
        for (pos, attr) in self.attributes.iter().enumerate() {
            if pos > 0 {
                buf.push(b' ');
            }
            attr.serialize(buf);
        }
        buf.extend_from_slice(b") \"/\" ");

        // RFC 9051 5.1 drops modified UTF-7, so a rev2 or UTF8=ACCEPT client is sent
        // the name as stored. OLDNAME is reserved for RENAME and for Net-Unicode
        // normalization (RFC 9051 6.3.9.7), neither of which a re-encoding is.
        quoted_mailbox_name(buf, &self.mailbox_name, is_rev2 || is_utf8);

        if !self.tags.is_empty() || self.objectid.is_some() {
            buf.extend_from_slice(b" (");
            for (pos, tag) in self.tags.iter().enumerate() {
                if pos > 0 {
                    buf.push(b' ');
                }
                tag.serialize(buf);
            }
            if let Some(objectid) = &self.objectid {
                if !self.tags.is_empty() {
                    buf.push(b' ');
                }
                buf.extend_from_slice(b"\"OBJECTID\" ");
                ObjectId::from(*objectid).serialize_kvpairs(buf);
            }
            buf.extend_from_slice(b")\r\n");
        } else {
            buf.extend_from_slice(b"\r\n");
        }

        if let Some(metadata) = self.metadata.as_deref()
            && !metadata.is_empty()
        {
            serialize_entry_values(buf, &self.mailbox_name, metadata, is_rev2 || is_utf8);
        }
    }
}

impl ImapResponse for Response {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        let mut status_items = self.status_items.iter().peekable();
        for list_item in &self.list_items {
            list_item.serialize(buf, self.is_rev2, self.is_utf8, self.is_lsub);
            if let Some(status_item) = status_items
                .next_if(|status_item| status_item.mailbox_name == list_item.mailbox_name)
            {
                status_item.serialize(buf, self.is_rev2);
            }
        }
        for status_item in status_items {
            status_item.serialize(buf, self.is_rev2);
        }
    }

    fn size_hint(&self) -> usize {
        const LIST_FRAMING_LEN: usize = 24;
        const ATTRIBUTE_LEN: usize = 16;
        const TAG_LEN: usize = 24;
        const OBJECT_ID_LEN: usize = 56;
        const STATUS_FRAMING_LEN: usize = 24;
        const STATUS_ITEM_LEN: usize = 24;
        const METADATA_FRAMING_LEN: usize = 20;
        const METADATA_ENTRY_LEN: usize = 16;

        self.list_items
            .iter()
            .map(|item| {
                LIST_FRAMING_LEN
                    + item.mailbox_name.len() * 2
                    + item.attributes.len() * ATTRIBUTE_LEN
                    + item.tags.len() * TAG_LEN
                    + if item.objectid.is_some() {
                        OBJECT_ID_LEN
                    } else {
                        0
                    }
                    + match item.metadata.as_deref() {
                        Some(metadata) if !metadata.is_empty() => {
                            METADATA_FRAMING_LEN
                                + item.mailbox_name.len() * 2
                                + metadata
                                    .iter()
                                    .map(|entry| {
                                        METADATA_ENTRY_LEN
                                            + entry.entry.path.len()
                                            + entry.value.as_ref().map_or(0, |value| value.len())
                                    })
                                    .sum::<usize>()
                        }
                        _ => 0,
                    }
            })
            .sum::<usize>()
            + self
                .status_items
                .iter()
                .map(|item| {
                    STATUS_FRAMING_LEN
                        + item.mailbox_name.len() * 2
                        + item.items.len() * STATUS_ITEM_LEN
                })
                .sum::<usize>()
    }
}

