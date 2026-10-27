/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    METADATA_KINDS,
    calendar::{ArchivedCalendarEvent, Calendar, CalendarEvent},
    contact::{AddressBook, ArchivedContactCard, ContactCard},
    file::{ArchivedFileNode, FileNode},
};
use common::storage::{
    dav::FilePresence,
    index::{GroupwareWrite, PresenceFlags, RewritePresence, rewrite_archive},
};
use store::write::{Archive, BatchBuilder};
use trc::AddContext;
use types::{collection::Collection, metadata::MetadataKinds};

impl PresenceFlags for Calendar {
    const COLLECTION: Collection = Collection::Calendar;
    const TRACKED: MetadataKinds = METADATA_KINDS;

    fn set_metadata_kinds(&mut self, kinds: MetadataKinds) {
        self.presence = kinds.bits() & Self::TRACKED.bits();
    }
}

impl PresenceFlags for AddressBook {
    const COLLECTION: Collection = Collection::AddressBook;
    const TRACKED: MetadataKinds = METADATA_KINDS;

    fn set_metadata_kinds(&mut self, kinds: MetadataKinds) {
        self.presence = kinds.bits() & Self::TRACKED.bits();
    }
}

impl RewritePresence for CalendarEvent {
    fn rewrite_presence(
        current: &Archive<&ArchivedCalendarEvent>,
        kinds: MetadataKinds,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if current.inner.metadata_kinds() == tracked_kinds(kinds.bits()) {
            return Ok(());
        }
        let mut event = current
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        event.set_metadata_kinds(kinds);
        rewrite_archive(
            current,
            GroupwareWrite::meta_only(event, current.inner),
            Collection::CalendarEvent,
            account_id,
            document_id,
            batch,
        )
    }
}

impl RewritePresence for ContactCard {
    fn rewrite_presence(
        current: &Archive<&ArchivedContactCard>,
        kinds: MetadataKinds,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if current.inner.metadata_kinds() == tracked_kinds(kinds.bits()) {
            return Ok(());
        }
        let mut card = current
            .deserialize::<ContactCard>()
            .caused_by(trc::location!())?;
        card.set_metadata_kinds(kinds);
        rewrite_archive(
            current,
            GroupwareWrite::meta_only(card, current.inner),
            Collection::ContactCard,
            account_id,
            document_id,
            batch,
        )
    }
}

impl FileNode {
    pub fn rewrite_presence(
        current: &Archive<&ArchivedFileNode>,
        presence: FilePresence,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if current.inner.presence() == presence {
            return Ok(());
        }
        let mut node = current
            .deserialize::<FileNode>()
            .caused_by(trc::location!())?;
        node.set_presence(presence);
        rewrite_archive(
            current,
            node,
            Collection::FileNode,
            account_id,
            document_id,
            batch,
        )
    }
}

pub(crate) fn tracked_kinds(bits: u8) -> MetadataKinds {
    MetadataKinds::from_bits(bits & METADATA_KINDS.bits()).unwrap_or(MetadataKinds::NONE)
}

