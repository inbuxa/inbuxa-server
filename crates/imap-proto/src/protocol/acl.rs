/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::CompactString;

use super::{quoted_mailbox_name, quoted_string};
use std::fmt::Display;
use types::acl::Acl;
use utils::map::bitmap::Bitmap;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Rights {
    Lookup,
    Read,
    Seen,
    Write,
    Insert,
    Post,
    CreateMailbox,
    DeleteMailbox,
    DeleteMessages,
    Expunge,
    Annotate,
    Administer,
}

const ACL_RIGHTS: [(&[Acl], Rights); 12] = [
    (&[Acl::Read], Rights::Lookup),
    (&[Acl::ReadItems], Rights::Read),
    (&[Acl::ModifyItems], Rights::Seen),
    (&[Acl::ModifyItems], Rights::Write),
    (&[Acl::AddItems], Rights::Insert),
    (&[Acl::Submit], Rights::Post),
    (&[Acl::CreateChild], Rights::CreateMailbox),
    (&[Acl::Delete, Acl::Modify], Rights::DeleteMailbox),
    (&[Acl::RemoveItems], Rights::DeleteMessages),
    (&[Acl::RemoveItems], Rights::Expunge),
    (&[Acl::ModifyMetadata], Rights::Annotate),
    (&[Acl::Share], Rights::Administer),
];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ModRights {
    pub op: ModRightsOp,
    pub rights: Vec<Rights>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ModRightsOp {
    Add,
    Remove,
    Replace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub mailbox_name: CompactString,
    pub identifier: Option<CompactString>,
    pub mod_rights: Option<ModRights>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAclResponse {
    pub mailbox_name: CompactString,
    pub permissions: Vec<(String, Vec<Rights>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRightsResponse {
    pub mailbox_name: CompactString,
    pub identifier: CompactString,
    pub permissions: Vec<Vec<Rights>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyRightsResponse {
    pub mailbox_name: CompactString,
    pub rights: Vec<Rights>,
}

impl GetAclResponse {
    pub fn into_bytes(self, is_utf8: bool) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.mailbox_name.len() + 10 * self.permissions.len() * 5);
        buf.extend_from_slice(b"* ACL ");
        quoted_mailbox_name(&mut buf, &self.mailbox_name, is_utf8);
        for (identifier, rights) in self.permissions {
            buf.push(b' ');
            quoted_string(&mut buf, &identifier);
            buf.push(b' ');

            for right in rights {
                buf.push(right.to_char());
            }
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

impl ListRightsResponse {
    pub fn into_bytes(self, is_utf8: bool) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            self.mailbox_name.len() + self.identifier.len() + 10 * self.permissions.len() * 5,
        );
        buf.extend_from_slice(b"* LISTRIGHTS ");
        quoted_mailbox_name(&mut buf, &self.mailbox_name, is_utf8);
        buf.push(b' ');
        quoted_string(&mut buf, &self.identifier);
        for rights in self.permissions {
            buf.push(b' ');
            for right in rights {
                buf.push(right.to_char());
            }
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

impl MyRightsResponse {
    pub fn into_bytes(self, is_utf8: bool) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.mailbox_name.len() + 10 + self.rights.len());
        buf.extend_from_slice(b"* MYRIGHTS ");
        quoted_mailbox_name(&mut buf, &self.mailbox_name, is_utf8);
        buf.push(b' ');
        for right in self.rights {
            buf.push(right.to_char());
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

impl Rights {
    pub fn from_acl(acl: Bitmap<Acl>) -> impl Iterator<Item = Rights> {
        ACL_RIGHTS
            .iter()
            .filter(move |(acls, _)| acls.iter().any(|item| acl.contains(*item)))
            .map(|(_, right)| *right)
    }

    pub fn to_acl(&self) -> &'static [Acl] {
        match self {
            Rights::Lookup => &[Acl::Read],
            Rights::Read => &[Acl::ReadItems],
            Rights::Seen | Rights::Write => &[Acl::ModifyItems],
            Rights::Insert => &[Acl::AddItems],
            Rights::Post => &[Acl::Submit],
            Rights::CreateMailbox => &[Acl::CreateChild],
            Rights::DeleteMailbox => &[Acl::Delete, Acl::Modify],
            Rights::DeleteMessages | Rights::Expunge => &[Acl::RemoveItems],
            Rights::Annotate => &[Acl::ModifyMetadata],
            Rights::Administer => &[Acl::Share],
        }
    }

    pub fn to_char(&self) -> u8 {
        match self {
            Rights::Lookup => b'l',
            Rights::Read => b'r',
            Rights::Seen => b's',
            Rights::Write => b'w',
            Rights::Insert => b'i',
            Rights::Post => b'p',
            Rights::CreateMailbox => b'k',
            Rights::DeleteMailbox => b'x',
            Rights::DeleteMessages => b't',
            Rights::Expunge => b'e',
            Rights::Annotate => b'n',
            Rights::Administer => b'a',
        }
    }
}

impl Display for Rights {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rights::Lookup => write!(f, "l"),
            Rights::Read => write!(f, "r"),
            Rights::Seen => write!(f, "s"),
            Rights::Write => write!(f, "w"),
            Rights::Insert => write!(f, "i"),
            Rights::Post => write!(f, "p"),
            Rights::CreateMailbox => write!(f, "k"),
            Rights::DeleteMailbox => write!(f, "x"),
            Rights::DeleteMessages => write!(f, "t"),
            Rights::Expunge => write!(f, "e"),
            Rights::Annotate => write!(f, "n"),
            Rights::Administer => write!(f, "a"),
        }
    }
}

