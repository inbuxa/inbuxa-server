/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::identity::CalendarAddresses;
use calcard::{
    icalendar::{
        ArchivedICalendarEntry, ArchivedICalendarParameterValue,
        ArchivedICalendarParticipationRole, ArchivedICalendarProperty, ArchivedICalendarValue,
        ICalendarEntry, ICalendarParameterName, ICalendarParameterValue,
        ICalendarParticipationRole, ICalendarProperty,
    },
    jscalendar::{JSCalendarParticipantRole, JSCalendarProperty, JSCalendarValue},
};
use jmap_tools::{JsonPointer, JsonPointerHandler, JsonPointerItem, Key, Map, Value};
use std::borrow::Cow;
use types::{blob::BlobId, id::Id};

type EventKey<'x> = Key<'x, JSCalendarProperty<Id>>;
type EventMap<'x> = Map<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
type EventValue<'x> = Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
type EventPointerItem = JsonPointerItem<JSCalendarProperty<Id>>;

pub trait ParticipantVisibility {
    fn is_visible_participant(&self, identities: &CalendarAddresses) -> bool;
}

pub trait VisibleParticipants {
    fn retain_visible_participants(&mut self, identities: &CalendarAddresses);
}

impl ParticipantVisibility for ICalendarEntry {
    fn is_visible_participant(&self, identities: &CalendarAddresses) -> bool {
        self.name != ICalendarProperty::Attendee
            || self.parameters(&ICalendarParameterName::Role).any(|role| {
                matches!(
                    role,
                    ICalendarParameterValue::Role(ICalendarParticipationRole::Owner)
                )
            })
            || self
                .calendar_address()
                .is_some_and(|address| identities.contains(address))
    }
}

impl ParticipantVisibility for ArchivedICalendarEntry {
    fn is_visible_participant(&self, identities: &CalendarAddresses) -> bool {
        !matches!(self.name, ArchivedICalendarProperty::Attendee)
            || self.has_owner_role()
            || self
                .values
                .first()
                .and_then(|value| value.as_text())
                .is_some_and(|address| identities.contains(address))
    }
}

pub(crate) trait ArchivedParticipantEntry {
    fn has_owner_role(&self) -> bool;

    fn name_and_address(&self) -> impl Iterator<Item = &str>;
}

impl ArchivedParticipantEntry for ArchivedICalendarEntry {
    fn has_owner_role(&self) -> bool {
        self.parameters(&ICalendarParameterName::Role).any(|role| {
            matches!(
                role,
                ArchivedICalendarParameterValue::Role(ArchivedICalendarParticipationRole::Owner)
            )
        })
    }

    fn name_and_address(&self) -> impl Iterator<Item = &str> {
        self.values
            .iter()
            .filter_map(|value| match value {
                ArchivedICalendarValue::Text(value) => Some(value.as_str()),
                ArchivedICalendarValue::Uri(uri) => uri.as_str(),
                _ => None,
            })
            .chain(
                self.parameters(&ICalendarParameterName::Cn)
                    .filter_map(|value| match value {
                        ArchivedICalendarParameterValue::Text(value) => Some(value.as_str()),
                        _ => None,
                    }),
            )
    }
}

impl ParticipantVisibility for EventValue<'_> {
    fn is_visible_participant(&self, identities: &CalendarAddresses) -> bool {
        self.is_owner()
            || self
                .calendar_address()
                .is_some_and(|address| identities.contains(&address))
    }
}

impl VisibleParticipants for EventValue<'_> {
    fn retain_visible_participants(&mut self, identities: &CalendarAddresses) {
        let Some(event) = self.as_object_mut() else {
            return;
        };
        let participants_key = Key::Property(JSCalendarProperty::Participants);
        let position = event
            .as_vec()
            .iter()
            .position(|(key, _)| key == &participants_key);
        let mut participants = position.map(|position| event.as_mut_vec().remove(position));
        let base = participants
            .as_ref()
            .and_then(|(_, participants)| participants.as_object());
        let base_hidden = base.map_or_else(Vec::new, |base| base.hidden_ids(identities));
        let base_visible = base.map_or_else(Vec::new, |base| base.visible_addresses(identities));

        if let Some(overrides) = event
            .get_mut(&Key::Property(JSCalendarProperty::RecurrenceOverrides))
            .and_then(Value::as_object_mut)
        {
            overrides.as_mut_vec().retain_mut(|(_, patch)| {
                let Some(patch) = patch.as_object_mut() else {
                    return true;
                };
                let is_empty = patch.is_empty();
                patch.retain_visible_patches(base, &base_hidden, identities);
                patch.retain_visible_patch_delegations(&base_visible, identities);
                is_empty || !patch.is_empty()
            });
        }

        if let Some(ical) = event.get_mut(&Key::Property(JSCalendarProperty::ICalendar)) {
            ical.remove_participant_properties(&base_hidden);
        }

        if let (Some(position), Some((key, mut value))) = (position, participants.take()) {
            if let Some(participants) = value.as_object_mut() {
                participants.remove_hidden(identities);
                participants.retain_visible_delegations(identities);
            }
            if value
                .as_object()
                .is_none_or(|participants| !participants.is_empty())
            {
                let position = position.min(event.len());
                event.as_mut_vec().insert(position, (key, value));
            }
        }
    }
}

pub(crate) trait ParticipantObject {
    fn is_owner(&self) -> bool;

    fn calendar_address(&self) -> Option<Cow<'_, str>>;
}

impl ParticipantObject for EventValue<'_> {
    fn is_owner(&self) -> bool {
        self.as_object_and_get(&Key::Property(JSCalendarProperty::Roles))
            .is_some_and(EventValue::has_owner_role)
    }

    fn calendar_address(&self) -> Option<Cow<'_, str>> {
        self.as_object_and_get(&Key::Property(JSCalendarProperty::CalendarAddress))
            .and_then(Value::as_str)
    }
}

trait OwnerRole {
    fn has_owner_role(&self) -> bool;
}

impl OwnerRole for EventValue<'_> {
    fn has_owner_role(&self) -> bool {
        self.as_object_and_get(&Key::Property(JSCalendarProperty::ParticipantRole(
            JSCalendarParticipantRole::Owner,
        )))
        .and_then(Value::as_bool)
        .unwrap_or_default()
    }
}

trait ParticipantMap<'x> {
    fn hidden_ids(&self, identities: &CalendarAddresses) -> Vec<Cow<'_, str>>;

    fn visible_addresses(&self, identities: &CalendarAddresses) -> Vec<Cow<'_, str>>;

    fn retain_visible_delegations(&mut self, identities: &CalendarAddresses);

    fn remove_hidden(&mut self, identities: &CalendarAddresses);

    fn participant(&self, id: &str) -> Option<&EventValue<'x>>;
}

impl<'x> ParticipantMap<'x> for EventMap<'x> {
    fn hidden_ids(&self, identities: &CalendarAddresses) -> Vec<Cow<'_, str>> {
        self.iter()
            .filter(|(_, participant)| !participant.is_visible_participant(identities))
            .map(|(key, _)| key.to_string())
            .collect()
    }

    fn visible_addresses(&self, identities: &CalendarAddresses) -> Vec<Cow<'_, str>> {
        self.iter()
            .filter(|(_, participant)| participant.is_visible_participant(identities))
            .filter_map(|(_, participant)| participant.calendar_address())
            .collect()
    }

    fn retain_visible_delegations(&mut self, identities: &CalendarAddresses) {
        if !self.values().any(EventValue::has_delegates) {
            return;
        }
        let participants = self.as_mut_vec();
        for index in 0..participants.len() {
            let (before, rest) = participants.split_at_mut(index);
            let Some(((_, participant), after)) = rest.split_first_mut() else {
                break;
            };
            participant.retain_visible_delegations(|address| {
                identities.contains(address) || {
                    let address = CalendarAddresses::normalize(address);
                    before
                        .iter()
                        .chain(after.iter())
                        .filter_map(|(_, participant)| participant.calendar_address())
                        .any(|own| CalendarAddresses::normalize(&own) == address)
                }
            });
        }
    }

    fn remove_hidden(&mut self, identities: &CalendarAddresses) {
        self.as_mut_vec()
            .retain(|(_, participant)| participant.is_visible_participant(identities));
    }

    fn participant(&self, id: &str) -> Option<&EventValue<'x>> {
        self.as_vec()
            .iter()
            .find(|(key, _)| key.to_string() == id)
            .map(|(_, participant)| participant)
    }
}

trait ParticipantDelegations {
    fn has_delegates(&self) -> bool;

    fn retain_visible_delegations(&mut self, is_visible: impl Fn(&str) -> bool + Copy);

    fn retain_visible_delegates(&mut self, is_visible: impl Fn(&str) -> bool + Copy) -> bool;
}

impl ParticipantDelegations for EventValue<'_> {
    fn has_delegates(&self) -> bool {
        self.as_object()
            .is_some_and(|participant| participant.keys().any(EventKey::is_delegation))
    }

    fn retain_visible_delegations(&mut self, is_visible: impl Fn(&str) -> bool + Copy) {
        if let Some(participant) = self.as_object_mut() {
            participant.as_mut_vec().retain_mut(|(key, value)| {
                !key.is_delegation() || value.retain_visible_delegates(is_visible)
            });
        }
    }

    fn retain_visible_delegates(&mut self, is_visible: impl Fn(&str) -> bool + Copy) -> bool {
        match self {
            Value::Str(address) => is_visible(address),
            Value::Array(addresses) => {
                addresses
                    .retain(|address| address.as_str().is_none_or(|address| is_visible(&address)));
                !addresses.is_empty()
            }
            Value::Object(addresses) => {
                addresses
                    .as_mut_vec()
                    .retain(|(address, _)| is_visible(&address.to_string()));
                !addresses.is_empty()
            }
            _ => true,
        }
    }
}

trait VisibleAddress {
    fn is_visible_address(&self, visible: &[Cow<'_, str>], identities: &CalendarAddresses) -> bool;
}

impl VisibleAddress for str {
    fn is_visible_address(&self, visible: &[Cow<'_, str>], identities: &CalendarAddresses) -> bool {
        let address = CalendarAddresses::normalize(self);
        visible
            .iter()
            .any(|visible| CalendarAddresses::normalize(visible) == address)
            || identities.contains(&address)
    }
}

trait ParticipantPatch<'x> {
    fn retain_visible_patches(
        &mut self,
        base: Option<&EventMap<'x>>,
        base_hidden: &[Cow<'_, str>],
        identities: &CalendarAddresses,
    );

    fn retain_visible_patch_delegations(
        &mut self,
        base_visible: &[Cow<'_, str>],
        identities: &CalendarAddresses,
    );

    fn participant_patches<'y>(
        &'y self,
        id: &'y str,
    ) -> impl Iterator<Item = (&'y [EventPointerItem], &'y EventValue<'x>)>
    where
        'x: 'y;
}

impl<'x> ParticipantPatch<'x> for EventMap<'x> {
    fn retain_visible_patches(
        &mut self,
        base: Option<&EventMap<'x>>,
        base_hidden: &[Cow<'_, str>],
        identities: &CalendarAddresses,
    ) {
        if let Some(participants) = self.get_mut(&Key::Property(JSCalendarProperty::Participants))
            && let Some(map) = participants.as_object_mut()
        {
            map.remove_hidden(identities);
            if map.is_empty() {
                *participants = Value::Null;
            }
        }

        let mut ids = self
            .iter()
            .filter_map(|(key, _)| key.participant_pointer())
            .map(|(id, _)| id.into_owned())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();

        let mut hidden = Cow::Borrowed(base_hidden);
        for id in ids {
            let base_participant = base.and_then(|base| base.participant(&id));
            let is_base_visible = base_participant
                .is_some_and(|participant| participant.is_visible_participant(identities));
            let replacement = self
                .participant_patches(&id)
                .find(|(pointer, _)| pointer.is_empty())
                .map(|(_, value)| value);
            let is_visible = match replacement {
                Some(replacement) => replacement.is_visible_participant(identities),
                None => base_participant.is_some_and(|participant| {
                    participant.is_patched_visible(self.participant_patches(&id), identities)
                }),
            };
            let new_patch = match (is_base_visible, is_visible) {
                (true, true) => continue,
                (false, true) if replacement.is_some() => {
                    hidden
                        .to_mut()
                        .retain(|hidden_id| hidden_id.as_ref() != id.as_str());
                    continue;
                }
                (false, true) => base_participant.map(|participant| {
                    let mut participant = participant.clone();
                    for (pointer, value) in self.participant_patches(&id) {
                        participant.patch_jptr(pointer.iter().peekable(), value.clone());
                    }
                    participant
                }),
                (true, false) => Some(Value::Null),
                (false, false) => None,
            };

            self.as_mut_vec().retain(|(key, _)| {
                key.participant_pointer()
                    .is_none_or(|(patch_id, _)| patch_id != id.as_str())
            });
            if new_patch.as_ref().is_some_and(|patch| !patch.is_null()) {
                hidden
                    .to_mut()
                    .retain(|hidden_id| hidden_id.as_ref() != id.as_str());
            } else if !hidden
                .iter()
                .any(|hidden_id| hidden_id.as_ref() == id.as_str())
            {
                hidden.to_mut().push(Cow::Owned(id.clone()));
            }
            if let Some(new_patch) = new_patch {
                self.insert_unchecked(
                    Key::Property(JSCalendarProperty::Pointer(JsonPointer::new(vec![
                        JsonPointerItem::Key(Key::Property(JSCalendarProperty::Participants)),
                        JsonPointerItem::Key(Key::Owned(id)),
                    ]))),
                    new_patch,
                );
            }
        }

        if let Some(ical) = self.get_mut(&Key::Property(JSCalendarProperty::ICalendar)) {
            ical.remove_participant_properties(&hidden);
        }
    }

    fn retain_visible_patch_delegations(
        &mut self,
        base_visible: &[Cow<'_, str>],
        identities: &CalendarAddresses,
    ) {
        let participants_key = Key::Property(JSCalendarProperty::Participants);
        if !self.iter().any(|(key, value)| {
            if key == &participants_key {
                value.as_object().is_some_and(|participants| {
                    participants.values().any(EventValue::has_delegates)
                })
            } else {
                match key.participant_pointer() {
                    Some((_, [])) => value.has_delegates(),
                    Some((_, [delegation, ..])) => delegation.is_delegation(),
                    _ => false,
                }
            }
        }) {
            return;
        }

        let mut visible = Cow::Borrowed(base_visible);
        for (key, value) in self.iter() {
            if key == &participants_key {
                if let Some(participants) = value.as_object() {
                    visible.to_mut().extend(
                        participants
                            .visible_addresses(identities)
                            .into_iter()
                            .map(|address| Cow::Owned(address.into_owned())),
                    );
                }
            } else if matches!(key.participant_pointer(), Some((_, [])))
                && value.is_visible_participant(identities)
                && let Some(address) = value.calendar_address()
            {
                visible.to_mut().push(Cow::Owned(address.into_owned()));
            }
        }

        let is_visible = |address: &str| address.is_visible_address(&visible, identities);
        self.as_mut_vec().retain_mut(|(key, value)| {
            if key == &participants_key {
                if let Some(participants) = value.as_object_mut() {
                    participants.retain_visible_delegations(identities);
                }
            } else if let Some((_, pointer)) = key.participant_pointer() {
                match pointer {
                    [] => value.retain_visible_delegations(is_visible),
                    [delegation] if delegation.is_delegation() => {
                        if !value.retain_visible_delegates(is_visible) {
                            *value = Value::Null;
                        }
                    }
                    [delegation, delegate] if delegation.is_delegation() => {
                        return delegate.as_address().is_none_or(|delegate| {
                            delegate.is_visible_address(&visible, identities)
                        });
                    }
                    _ => {}
                }
            }
            true
        });
    }

    fn participant_patches<'y>(
        &'y self,
        id: &'y str,
    ) -> impl Iterator<Item = (&'y [EventPointerItem], &'y EventValue<'x>)>
    where
        'x: 'y,
    {
        self.iter().filter_map(move |(key, value)| {
            key.participant_pointer()
                .filter(|(patch_id, _)| patch_id == id)
                .map(|(_, pointer)| (pointer, value))
        })
    }
}

trait PatchedParticipant {
    fn is_patched_visible<'a, 'v: 'a>(
        &'a self,
        patches: impl Iterator<Item = (&'a [EventPointerItem], &'a EventValue<'v>)>,
        identities: &CalendarAddresses,
    ) -> bool;
}

impl PatchedParticipant for EventValue<'_> {
    fn is_patched_visible<'a, 'v: 'a>(
        &'a self,
        patches: impl Iterator<Item = (&'a [EventPointerItem], &'a EventValue<'v>)>,
        identities: &CalendarAddresses,
    ) -> bool {
        let mut is_owner = self.is_owner();
        let mut address = self.calendar_address();

        for (pointer, value) in patches {
            match pointer {
                [roles] if roles.is_property(&JSCalendarProperty::Roles) => {
                    is_owner = value.has_owner_role();
                }
                [roles, role]
                    if roles.is_property(&JSCalendarProperty::Roles)
                        && role.is_property(&JSCalendarProperty::ParticipantRole(
                            JSCalendarParticipantRole::Owner,
                        )) =>
                {
                    is_owner = value.as_bool().unwrap_or_default();
                }
                [calendar_address]
                    if calendar_address.is_property(&JSCalendarProperty::CalendarAddress) =>
                {
                    address = value.as_str();
                }
                _ => {}
            }
        }

        is_owner || address.is_some_and(|address| identities.contains(&address))
    }
}

pub(crate) trait ParticipantPointer {
    fn participant_pointer(&self) -> Option<(Cow<'_, str>, &[EventPointerItem])>;
}

impl ParticipantPointer for EventKey<'_> {
    fn participant_pointer(&self) -> Option<(Cow<'_, str>, &[EventPointerItem])> {
        let Key::Property(JSCalendarProperty::Pointer(pointer)) = self else {
            return None;
        };
        match pointer.as_slice() {
            [participants, id, rest @ ..]
                if participants.is_property(&JSCalendarProperty::Participants) =>
            {
                let id = match id {
                    JsonPointerItem::Key(key) => key.to_string(),
                    JsonPointerItem::Number(number) => Cow::Owned(number.to_string()),
                    JsonPointerItem::Root
                    | JsonPointerItem::Wildcard
                    | JsonPointerItem::Invalid(_) => return None,
                };
                Some((id, rest))
            }
            _ => None,
        }
    }
}

trait PointerProperty {
    fn is_property(&self, property: &JSCalendarProperty<Id>) -> bool;

    fn as_address(&self) -> Option<Cow<'_, str>>;
}

impl PointerProperty for EventPointerItem {
    fn is_property(&self, property: &JSCalendarProperty<Id>) -> bool {
        matches!(self, JsonPointerItem::Key(Key::Property(item)) if item == property)
    }

    fn as_address(&self) -> Option<Cow<'_, str>> {
        match self {
            JsonPointerItem::Key(key) => Some(key.to_string()),
            _ => None,
        }
    }
}

trait DelegationKey {
    fn is_delegation(&self) -> bool;
}

impl DelegationKey for EventKey<'_> {
    fn is_delegation(&self) -> bool {
        matches!(
            self,
            Key::Property(JSCalendarProperty::DelegatedTo | JSCalendarProperty::DelegatedFrom)
        )
    }
}

impl DelegationKey for EventPointerItem {
    fn is_delegation(&self) -> bool {
        self.is_property(&JSCalendarProperty::DelegatedTo)
            || self.is_property(&JSCalendarProperty::DelegatedFrom)
    }
}

trait ICalendarProperties {
    fn remove_participant_properties(&mut self, hidden: &[Cow<'_, str>]);
}

impl ICalendarProperties for EventValue<'_> {
    fn remove_participant_properties(&mut self, hidden: &[Cow<'_, str>]) {
        if hidden.is_empty() {
            return;
        }
        if let Some(converted_properties) = self
            .as_object_mut()
            .and_then(|ical| ical.get_mut(&Key::Property(JSCalendarProperty::ConvertedProperties)))
            .and_then(Value::as_object_mut)
        {
            converted_properties.as_mut_vec().retain(|(key, _)| {
                key.to_string()
                    .strip_prefix("participants/")
                    .and_then(|pointer| pointer.split('/').next())
                    .is_none_or(|id| {
                        let id = if id.contains('~') {
                            Cow::Owned(id.replace("~1", "/").replace("~0", "~"))
                        } else {
                            Cow::Borrowed(id)
                        };
                        !hidden
                            .iter()
                            .any(|hidden_id| hidden_id.as_ref() == id.as_ref())
                    })
            });
        }
    }
}

