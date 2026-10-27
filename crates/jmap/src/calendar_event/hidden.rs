/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    blob::embedded::EmbeddedBlobIds,
    calendar_event::{EventValue, JSCalendarEntries},
};
use calcard::{
    icalendar::ICalendar,
    jscalendar::{JSCalendar, JSCalendarProperty, import::ImportOptions},
};
use groupware::calendar::{
    hidden::{HiddenAdditions, HiddenParticipantsMerge},
    identity::CalendarAddresses,
    participants::VisibleParticipants,
};
use jmap_tools::{Key, Value};
use types::{blob::BlobId, collection::Collection, id::Id};

pub(super) struct HiddenParticipants<'x> {
    full: JSCalendar<'x, Id, BlobId>,
}

impl<'x> HiddenParticipants<'x> {
    pub fn hide(group: &mut JSCalendar<'x, Id, BlobId>, identities: &CalendarAddresses) -> Self {
        let full = group.clone();
        for entry in group.entries_mut() {
            entry.retain_visible_participants(identities);
        }
        HiddenParticipants { full }
    }

    pub fn merge(
        mut self,
        before: &JSCalendar<'x, Id, BlobId>,
        after: JSCalendar<'x, Id, BlobId>,
    ) -> (JSCalendar<'x, Id, BlobId>, HiddenAdditions) {
        let mut additions = HiddenAdditions::default();
        let before_entries = before
            .0
            .as_object_and_get(&Key::Property(JSCalendarProperty::Entries))
            .and_then(Value::as_array)
            .unwrap_or_default();
        let after_entries = after
            .0
            .into_object()
            .and_then(|mut group| group.remove(&Key::Property(JSCalendarProperty::Entries)))
            .and_then(Value::into_array)
            .unwrap_or_default();
        for ((full_entry, before_entry), after_entry) in self
            .full
            .entries_mut()
            .iter_mut()
            .zip(before_entries)
            .zip(after_entries)
        {
            let entry_additions = full_entry.merge_visible_changes(before_entry, after_entry);
            additions.base |= entry_additions.base;
            additions.overrides |= entry_additions.overrides;
            additions.ignored += entry_additions.ignored;
        }
        (self.full, additions)
    }
}

pub(super) fn visible_overrides(
    view: ICalendar,
    identities: &CalendarAddresses,
    account_id: u32,
    document_id: u32,
) -> EventValue<'static> {
    view.into_jscalendar_with::<Id, BlobId, _>(
        ImportOptions::new()
            .include_ical_components(false)
            .return_first(true)
            .with_blob_id_generator(EmbeddedBlobIds::new(
                account_id,
                Collection::CalendarEvent,
                document_id,
            )),
    )
    .ok()
    .and_then(|event| {
        let mut event = event.into_inner();
        event.retain_visible_participants(identities);
        event.into_object()
    })
    .and_then(|mut event| event.remove(&Key::Property(JSCalendarProperty::RecurrenceOverrides)))
    .unwrap_or(Value::Null)
}
