/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    mailbox::{ArchivedMailbox, METADATA_MASK, METADATA_SHIFT, Mailbox},
    message::messagedata::{HAS_JMAP_METADATA, MessageData},
    sieve::{ArchivedSieveScript, SieveScript},
};
use common::storage::{index::PresenceFlags, metadata::MetadataPresence};
use store::{
    Deserialize,
    write::{BatchBuilder, MergeResult},
};
use types::{
    collection::{Collection, SyncCollection},
    field::Field,
    metadata::MetadataKinds,
};

impl MessageData {
    pub const TRACKED_METADATA: MetadataKinds = MetadataKinds::JMAP;

    pub fn metadata_kinds(&self) -> MetadataKinds {
        Self::metadata_kinds_of(self.keywords)
    }

    pub fn set_metadata_kinds(&mut self, kinds: MetadataKinds) {
        if kinds.intersects(Self::TRACKED_METADATA) {
            self.keywords |= HAS_JMAP_METADATA;
        } else {
            self.keywords &= !HAS_JMAP_METADATA;
        }
    }

    pub(crate) fn has_metadata(keywords: u32) -> bool {
        keywords & HAS_JMAP_METADATA != 0
    }

    pub(crate) fn metadata_kinds_of(keywords: u32) -> MetadataKinds {
        if Self::has_metadata(keywords) {
            MetadataKinds::JMAP
        } else {
            MetadataKinds::NONE
        }
    }
}

impl Mailbox {
    pub fn metadata_kinds(&self) -> MetadataKinds {
        Self::metadata_kinds_of(self.flags)
    }

    fn metadata_kinds_of(flags: u16) -> MetadataKinds {
        tracked_kinds(
            ((flags & METADATA_MASK) >> METADATA_SHIFT) as u8,
            Self::TRACKED,
        )
    }
}

impl PresenceFlags for Mailbox {
    const COLLECTION: Collection = Collection::Mailbox;
    const TRACKED: MetadataKinds = MetadataKinds::JMAP.union(MetadataKinds::IMAP);

    fn set_metadata_kinds(&mut self, kinds: MetadataKinds) {
        self.flags = (self.flags & !METADATA_MASK)
            | (u16::from(kinds.bits() & Self::TRACKED.bits()) << METADATA_SHIFT);
    }
}

impl ArchivedMailbox {
    pub fn metadata_kinds(&self) -> MetadataKinds {
        Mailbox::metadata_kinds_of(self.flags.to_native())
    }
}

impl SieveScript {
    pub fn metadata_kinds(&self) -> MetadataKinds {
        tracked_kinds(self.metadata_flags, Self::TRACKED)
    }
}

impl PresenceFlags for SieveScript {
    const COLLECTION: Collection = Collection::SieveScript;
    const TRACKED: MetadataKinds = MetadataKinds::JMAP;

    fn set_metadata_kinds(&mut self, kinds: MetadataKinds) {
        self.metadata_flags = kinds.bits() & Self::TRACKED.bits();
    }
}

impl ArchivedSieveScript {
    pub fn metadata_kinds(&self) -> MetadataKinds {
        tracked_kinds(self.metadata_flags, SieveScript::TRACKED)
    }
}

fn tracked_kinds(flags: u8, tracked: MetadataKinds) -> MetadataKinds {
    MetadataKinds::from_bits(flags & tracked.bits()).unwrap_or_default()
}

fn tracked_target(presence: MetadataPresence, tracked: MetadataKinds) -> MetadataKinds {
    tracked_kinds(presence.after.bits(), tracked)
}

fn merge_metadata_kinds(batch: &mut BatchBuilder, account_id: u32, kinds: MetadataKinds) {
    let group = SyncCollection::Email.change_group();
    batch.merge_fnc(Field::ARCHIVE, move |ids, bytes| {
        apply_metadata_kinds(bytes, kinds, ids.change_id(account_id, group))
    });
}

fn apply_metadata_kinds(
    bytes: Option<&[u8]>,
    kinds: MetadataKinds,
    change_id: Option<u64>,
) -> trc::Result<MergeResult> {
    let change_id = change_id.ok_or_else(|| {
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("No change id was allocated for the message presence update.")
            .caused_by(trc::location!())
    })?;
    let bytes = bytes.ok_or_else(|| {
        trc::StoreEvent::AssertValueFailed
            .into_err()
            .details("Message no longer exists.")
            .caused_by(trc::location!())
    })?;
    let mut data = MessageData::deserialize(bytes)?;
    let keywords = data.keywords;
    data.set_metadata_kinds(kinds);
    if data.keywords != keywords {
        data.serialize_with_change_id(change_id)
            .map(MergeResult::Update)
    } else {
        Ok(MergeResult::Skip)
    }
}

pub fn update_email_presence(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    current: MetadataKinds,
    presence: MetadataPresence,
) {
    let target = tracked_target(presence, MessageData::TRACKED_METADATA);
    if presence.has_changed_for(MessageData::TRACKED_METADATA)
        || tracked_kinds(current.bits(), MessageData::TRACKED_METADATA) != target
    {
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email)
            .with_document(document_id);
        merge_metadata_kinds(batch, account_id, target);
    }
}

