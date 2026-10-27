/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::index::PresenceFlags;
use store::{
    Deserialize, Serialize,
    write::{Archive, ArchiveBytes, Archiver, BatchBuilder, MergeResult},
};
use trc::AddContext;
use types::{acl::AclGrant, collection::SyncCollection, field::Field, special_use::SpecialUse};

pub mod destroy;
pub mod index;
pub mod lookup;
pub mod manage;
pub mod role;

pub const INBOX_ID: u32 = 0;
pub const TRASH_ID: u32 = 1;
pub const JUNK_ID: u32 = 2;
pub const DRAFTS_ID: u32 = 3;
pub const SENT_ID: u32 = 4;
pub const ARCHIVE_ID: u32 = 5;

const ROLE_MASK: u16 = 0x000F;
pub(crate) const METADATA_SHIFT: u32 = 4;
pub(crate) const METADATA_MASK: u16 = 0x00F0;

const _: () = assert!(((Mailbox::TRACKED.bits() as u16) << METADATA_SHIFT) & !METADATA_MASK == 0);

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct Mailbox {
    pub name: String,
    pub parent_id: u32,
    pub sort_order: Option<u32>,
    pub uid_validity: u32,
    pub subscribers: Vec<u32>,
    pub acls: Vec<AclGrant>,
    pub flags: u16,
}

impl Mailbox {
    pub fn new(name: impl Into<String>) -> Self {
        Mailbox {
            name: name.into(),
            parent_id: 0,
            sort_order: None,
            uid_validity: rand::random::<u32>(),
            subscribers: vec![],
            acls: vec![],
            flags: 0,
        }
    }

    pub fn with_role(mut self, role: SpecialUse) -> Self {
        self.set_role(role);
        self
    }

    pub fn role(&self) -> SpecialUse {
        Self::role_of(self.flags)
    }

    pub fn set_role(&mut self, role: SpecialUse) {
        self.flags = (self.flags & !ROLE_MASK) | u16::from(role.id());
    }

    fn role_of(flags: u16) -> SpecialUse {
        SpecialUse::from_id((flags & ROLE_MASK) as u8)
    }

    pub fn with_parent_id(mut self, parent_id: u32) -> Self {
        self.parent_id = parent_id;
        self
    }

    pub fn with_sort_order(mut self, sort_order: u32) -> Self {
        self.sort_order = Some(sort_order);
        self
    }

    pub fn with_subscriber(mut self, subscriber: u32) -> Self {
        self.subscribers.push(subscriber);
        self
    }

    pub fn add_subscriber(&mut self, subscriber: u32) -> bool {
        if !self.subscribers.contains(&subscriber) {
            self.subscribers.push(subscriber);
            true
        } else {
            false
        }
    }

    pub fn remove_subscriber(&mut self, subscriber: u32) {
        self.subscribers.retain(|&x| x != subscriber);
    }

    pub fn is_subscribed(&self, subscriber: u32) -> bool {
        self.subscribers.contains(&subscriber)
    }
}

impl ArchivedMailbox {
    pub fn role(&self) -> SpecialUse {
        Mailbox::role_of(self.flags.to_native())
    }

    pub fn is_subscribed(&self, subscriber: u32) -> bool {
        self.subscribers.iter().any(|x| u32::from(x) == subscriber)
    }
}

pub fn merge_subscription(batch: &mut BatchBuilder, subscriber: u32, subscribe: bool) {
    batch.log_container_update(SyncCollection::Email);
    batch.merge_fnc(Field::ARCHIVE, move |_, bytes| {
        let Some(bytes) = bytes else {
            return Err(trc::StoreEvent::AssertValueFailed
                .into_err()
                .details("Mailbox no longer exists.")
                .caused_by(trc::location!()));
        };

        let mut mailbox = <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes)
            .and_then(|archive| archive.deserialize::<Mailbox>())
            .caused_by(trc::location!())?;

        let changed = if subscribe {
            mailbox.add_subscriber(subscriber)
        } else {
            let was_subscribed = mailbox.is_subscribed(subscriber);
            mailbox.remove_subscriber(subscriber);
            was_subscribed
        };

        if changed {
            Archiver::new(mailbox).serialize().map(MergeResult::Update)
        } else {
            Ok(MergeResult::Skip)
        }
    });
}

