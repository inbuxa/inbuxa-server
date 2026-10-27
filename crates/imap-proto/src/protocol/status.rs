/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use crate::protocol::push_int;
use compact_str::CompactString;

use super::{ObjectId, quoted_mailbox_name};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub mailbox_name: CompactString,
    pub items: Vec<Status>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    Messages,
    UidNext,
    UidValidity,
    Unseen,
    Deleted,
    Size,
    Recent,
    HighestModSeq,
    ObjectId,
    DeletedStorage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusItem {
    pub mailbox_name: CompactString,
    pub items: Vec<(Status, StatusItemType)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusItemType {
    Number(u64),
    String(String),
    ObjectId(ObjectId),
}

impl StatusItem {
    pub fn serialize(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        buf.extend_from_slice(b"* STATUS ");
        quoted_mailbox_name(buf, &self.mailbox_name, is_utf8);
        buf.extend_from_slice(b" (");
        for (pos, (status_item, value)) in self.items.iter().enumerate() {
            if pos > 0 {
                buf.push(b' ');
            }

            buf.extend_from_slice(match status_item {
                Status::Messages => b"MESSAGES ",
                Status::UidNext => b"UIDNEXT ",
                Status::UidValidity => b"UIDVALIDITY ",
                Status::Unseen => b"UNSEEN ",
                Status::Deleted => b"DELETED ",
                Status::Size => b"SIZE ",
                Status::HighestModSeq => b"HIGHESTMODSEQ ",
                Status::ObjectId => b"OBJECTID ",
                Status::Recent => b"RECENT ",
                Status::DeletedStorage => b"DELETED-STORAGE ",
            });

            match value {
                StatusItemType::Number(num) => {
                    push_int(buf, *num);
                }
                StatusItemType::String(str) => {
                    buf.push(b'(');
                    buf.extend_from_slice(str.as_bytes());
                    buf.push(b')');
                }
                StatusItemType::ObjectId(object_id) => {
                    object_id.serialize_kvpairs(buf);
                }
            }
        }
        buf.extend_from_slice(b")\r\n");
    }
}

