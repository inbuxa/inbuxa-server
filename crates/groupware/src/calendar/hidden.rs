/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    identity::CalendarAddresses,
    participants::{ParticipantObject, ParticipantPointer},
    rights::EventValueCompare,
};
use ahash::AHashSet;
use calcard::jscalendar::{JSCalendarProperty, JSCalendarValue};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map, Value};
use store::rand;
use types::{blob::BlobId, id::Id};

type EventKey<'x> = Key<'x, JSCalendarProperty<Id>>;
type EventMap<'x> = Map<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
type EventValue<'x> = Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HiddenAdditions {
    pub base: bool,
    pub overrides: bool,
    pub ignored: usize,
}

pub trait HiddenParticipantsMerge<'x> {
    fn merge_visible_changes(
        &mut self,
        before: &EventValue<'x>,
        after: EventValue<'x>,
    ) -> HiddenAdditions;
}

#[derive(Default)]
struct ParticipantRegistry {
    ids: AHashSet<String>,
    addresses: AHashSet<String>,
    renamed: Vec<(String, Option<String>)>,
    ignored: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParticipantScope {
    Base,
    Occurrence,
}

struct OccurrenceBase<'a, 'x> {
    full: Option<&'a EventMap<'x>>,
    visible: Option<&'a EventMap<'x>>,
}

impl<'x> HiddenParticipantsMerge<'x> for EventValue<'x> {
    fn merge_visible_changes(
        &mut self,
        before: &EventValue<'x>,
        after: EventValue<'x>,
    ) -> HiddenAdditions {
        let mut additions = HiddenAdditions::default();
        let (Some(full), Some(before), Value::Object(mut after)) =
            (self.as_object_mut(), before.as_object(), after)
        else {
            return additions;
        };
        let participants_key = Key::Property(JSCalendarProperty::Participants);
        let overrides_key = Key::Property(JSCalendarProperty::RecurrenceOverrides);
        let after_participants = after.remove(&participants_key);
        let after_overrides = after.remove(&overrides_key);
        let mut registry = ParticipantRegistry::new(full);

        for key in before.keys().filter(|key| {
            **key != participants_key && **key != overrides_key && !after.contains_key(key)
        }) {
            full.remove(key);
        }
        for (key, value) in after.into_vec() {
            match before.get(&key) {
                Some(before_value) if before_value.same_value(&value) => {}
                Some(before_value) if key == Key::Property(JSCalendarProperty::ICalendar) => {
                    match full.get_mut(&key) {
                        Some(full_value) => full_value.merge_object(before_value, value),
                        None => {
                            full.insert(key, value);
                        }
                    }
                }
                _ => {
                    full.insert(key, value);
                }
            }
        }

        let before_participants = before.get(&participants_key);
        let before_overrides = before.get(&overrides_key);
        let has_override_changes = !after_overrides.as_ref().same_value(&before_overrides);
        let visible_participants = has_override_changes
            .then(|| {
                after_participants
                    .as_ref()
                    .and_then(Value::as_object)
                    .cloned()
            })
            .flatten();
        if !after_participants.as_ref().same_value(&before_participants) {
            let full_participants = full
                .insert_or_get_mut(participants_key.clone(), Value::Object(Map::new()))
                .as_object_mut();
            if let Some(full_participants) = full_participants {
                additions.base = registry.merge_participants(
                    full_participants,
                    before_participants.and_then(Value::as_object),
                    after_participants
                        .and_then(Value::into_object)
                        .unwrap_or_default(),
                    ParticipantScope::Base,
                );
            }
            if full
                .get(&participants_key)
                .and_then(Value::as_object)
                .is_some_and(Map::is_empty)
            {
                full.remove(&participants_key);
            }
        }

        if has_override_changes {
            let mut full_overrides = full
                .remove(&overrides_key)
                .and_then(Value::into_object)
                .unwrap_or_default();
            additions.overrides = registry.merge_overrides(
                &mut full_overrides,
                before_overrides.and_then(Value::as_object),
                after_overrides
                    .and_then(Value::into_object)
                    .unwrap_or_default(),
                OccurrenceBase {
                    full: full.get(&participants_key).and_then(Value::as_object),
                    visible: visible_participants.as_ref(),
                },
            );
            if !full_overrides.is_empty() {
                full.insert(overrides_key, Value::Object(full_overrides));
            }
        }

        additions.ignored = registry.ignored;
        additions
    }
}

impl ParticipantRegistry {
    fn new(full: &EventMap<'_>) -> Self {
        let mut registry = ParticipantRegistry::default();
        if let Some(participants) = full
            .get(&Key::Property(JSCalendarProperty::Participants))
            .and_then(Value::as_object)
        {
            registry.extend(participants);
        }
        for patch in full
            .get(&Key::Property(JSCalendarProperty::RecurrenceOverrides))
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|overrides| overrides.values())
            .filter_map(Value::as_object)
        {
            for (key, value) in patch.iter() {
                if *key == Key::Property(JSCalendarProperty::Participants) {
                    if let Some(participants) = value.as_object() {
                        registry.extend(participants);
                    }
                } else if let Some((id, pointer)) = key.participant_pointer() {
                    if pointer.is_empty() {
                        registry.register_address(value);
                    }
                    registry.register_id(&id);
                }
            }
        }
        registry
    }

    fn extend(&mut self, participants: &EventMap<'_>) {
        for (id, participant) in participants.iter() {
            self.register_id(&id.to_string());
            self.register_address(participant);
        }
    }

    fn register_id(&mut self, id: &str) {
        if !self.ids.contains(id) {
            self.ids.insert(id.to_string());
        }
    }

    fn register_address(&mut self, participant: &EventValue<'_>) {
        if let Some(address) = participant.calendar_address() {
            self.addresses
                .insert(CalendarAddresses::normalize(&address).into_owned());
        }
    }

    fn has_id(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    fn has_address(&self, participant: &EventValue<'_>) -> bool {
        participant.calendar_address().is_some_and(|address| {
            self.addresses
                .contains(CalendarAddresses::normalize(&address).as_ref())
        })
    }

    fn fresh_id(&mut self) -> String {
        loop {
            let id = format!("{:x}", rand::random::<u64>());
            if !self.ids.contains(&id) {
                self.ids.insert(id.clone());
                return id;
            }
        }
    }

    fn admit<'x>(
        &mut self,
        id: EventKey<'x>,
        participant: &EventValue<'x>,
        is_taken: bool,
        scope: ParticipantScope,
    ) -> Option<EventKey<'x>> {
        let name = id.to_string();
        if self.has_address(participant) {
            self.ignored += 1;
            if scope == ParticipantScope::Base {
                self.renamed.push((name.into_owned(), None));
            }
            return None;
        }
        self.register_address(participant);
        if is_taken || self.has_id(&name) {
            let fresh_id = self.fresh_id();
            if scope == ParticipantScope::Base {
                self.renamed
                    .push((name.into_owned(), Some(fresh_id.clone())));
            }
            Some(Key::Owned(fresh_id))
        } else {
            self.ids.insert(name.into_owned());
            Some(id)
        }
    }

    fn renamed_id(&self, id: &str) -> Option<Option<&str>> {
        self.renamed
            .iter()
            .find(|(old_id, _)| old_id == id)
            .map(|(_, new_id)| new_id.as_deref())
    }

    fn rename_patch_keys<'x>(&self, patch: EventMap<'x>) -> EventMap<'x> {
        if self.renamed.is_empty() {
            return patch;
        }
        let mut renamed = Map::with_capacity(patch.len());
        for (key, value) in patch.into_vec() {
            let target = key
                .participant_pointer()
                .and_then(|(id, rest)| Some((self.renamed_id(&id)?.map(str::to_string), rest)))
                .map(|(new_id, rest)| {
                    new_id.map(|new_id| {
                        let mut items = Vec::with_capacity(rest.len() + 2);
                        items.push(JsonPointerItem::Key(Key::Property(
                            JSCalendarProperty::Participants,
                        )));
                        items.push(JsonPointerItem::Key(Key::Owned(new_id)));
                        items.extend(rest.iter().cloned());
                        Key::Property(JSCalendarProperty::Pointer(JsonPointer::new(items)))
                    })
                });
            match target {
                Some(Some(key)) => renamed.insert_unchecked(key, value),
                Some(None) => {}
                None => renamed.insert_unchecked(key, value),
            }
        }
        renamed
    }

    fn rename_participant_ids<'x>(&self, participants: EventMap<'x>) -> EventMap<'x> {
        if self.renamed.is_empty() {
            return participants;
        }
        let mut renamed = Map::with_capacity(participants.len());
        for (id, participant) in participants.into_vec() {
            match self.renamed_id(&id.to_string()) {
                Some(Some(new_id)) => {
                    renamed.insert_unchecked(Key::Owned(new_id.to_string()), participant)
                }
                Some(None) => {}
                None => renamed.insert_unchecked(id, participant),
            }
        }
        renamed
    }

    fn merge_participants<'x>(
        &mut self,
        full: &mut EventMap<'x>,
        before: Option<&EventMap<'x>>,
        after: EventMap<'x>,
        scope: ParticipantScope,
    ) -> bool {
        let mut has_additions = false;
        if let Some(before) = before {
            for id in before.keys().filter(|id| !after.contains_key(id)) {
                full.remove(id);
            }
        }
        for (id, participant) in after.into_vec() {
            match before.and_then(|before| before.get(&id)) {
                Some(before_participant) if before_participant.same_value(&participant) => {}
                Some(before_participant) => match full.get_mut(&id) {
                    Some(full_participant) => {
                        full_participant.merge_object(before_participant, participant)
                    }
                    None => {
                        full.insert(id, participant);
                    }
                },
                None => {
                    has_additions = true;
                    let is_taken = full.contains_key(&id);
                    if let Some(id) = self.admit(id, &participant, is_taken, scope) {
                        full.insert(id, participant);
                    }
                }
            }
        }
        has_additions
    }

    fn merge_overrides<'x>(
        &mut self,
        full: &mut EventMap<'x>,
        before: Option<&EventMap<'x>>,
        after: EventMap<'x>,
        base: OccurrenceBase<'_, 'x>,
    ) -> bool {
        let mut has_additions = false;
        if let Some(before) = before {
            for (recurrence_id, before_patch) in before
                .iter()
                .filter(|(recurrence_id, _)| !after.contains_key(recurrence_id))
            {
                let is_empty = match full.get_mut(recurrence_id).and_then(Value::as_object_mut) {
                    Some(full_patch) => {
                        for key in before_patch.as_object().into_iter().flat_map(Map::keys) {
                            full_patch.remove(key);
                        }
                        full_patch.is_empty()
                    }
                    None => false,
                };
                if is_empty {
                    full.remove(recurrence_id);
                }
            }
        }

        for (recurrence_id, after_patch) in after.into_vec() {
            let before_patch = before.and_then(|before| before.get(&recurrence_id));
            if before_patch.is_some_and(|before_patch| before_patch.same_value(&after_patch)) {
                continue;
            }
            let Value::Object(after_patch) = after_patch else {
                full.insert(recurrence_id, after_patch);
                continue;
            };
            let before_patch = before_patch.and_then(Value::as_object);
            match full.get_mut(&recurrence_id).and_then(Value::as_object_mut) {
                Some(full_patch) => {
                    has_additions |= self.merge_patch(full_patch, before_patch, after_patch, &base);
                }
                None => {
                    let mut full_patch = Map::new();
                    has_additions |=
                        self.merge_patch(&mut full_patch, before_patch, after_patch, &base);
                    full.insert(recurrence_id, Value::Object(full_patch));
                }
            }
        }
        has_additions
    }

    fn merge_patch<'x>(
        &mut self,
        full: &mut EventMap<'x>,
        before: Option<&EventMap<'x>>,
        after: EventMap<'x>,
        base: &OccurrenceBase<'_, 'x>,
    ) -> bool {
        let mut has_additions = false;
        let after = self.rename_patch_keys(after);
        if let Some(before) = before {
            for key in before.keys().filter(|key| !after.contains_key(key)) {
                full.remove(key);
            }
        }
        for (key, value) in after.into_vec() {
            let before_value = before.and_then(|before| before.get(&key));
            if before_value.is_some_and(|before_value| before_value.same_value(&value)) {
                continue;
            }
            if key == Key::Property(JSCalendarProperty::Participants) {
                let Value::Object(participants) = value else {
                    full.insert(key, value);
                    continue;
                };
                let participants = self.rename_participant_ids(participants);
                let has_occurrence_set = matches!(full.get(&key), Some(Value::Object(_)));
                let visible = if has_occurrence_set {
                    before_value.and_then(Value::as_object)
                } else {
                    full.insert(
                        key.clone(),
                        Value::Object(base.full.cloned().unwrap_or_default()),
                    );
                    base.visible
                };
                if let Some(full_participants) = full.get_mut(&key).and_then(Value::as_object_mut) {
                    has_additions |= self.merge_participants(
                        full_participants,
                        visible,
                        participants,
                        ParticipantScope::Occurrence,
                    );
                }
                continue;
            }

            let added_id = before_value
                .is_none()
                .then(|| key.participant_pointer())
                .flatten()
                .filter(|(_, pointer)| pointer.is_empty() && value.as_object().is_some())
                .map(|(id, _)| id.into_owned())
                .filter(|id| {
                    base.visible
                        .is_none_or(|visible| !visible.keys().any(|key| key.to_string() == *id))
                });
            match added_id {
                Some(id) => {
                    has_additions = true;
                    let is_taken = full.contains_key(&key)
                        || base.full.is_some_and(|participants| {
                            participants.keys().any(|key| key.to_string() == id)
                        });
                    if let Some(id) = self.admit(
                        Key::Owned(id),
                        &value,
                        is_taken,
                        ParticipantScope::Occurrence,
                    ) {
                        let id = match id {
                            Key::Owned(id) => id,
                            id => id.to_string().into_owned(),
                        };
                        full.remove_participant_patches(&id);
                        full.insert(participant_key(id), value);
                    }
                }
                None => match (before_value, full.get_mut(&key)) {
                    (Some(before_value), Some(full_value)) => {
                        full_value.merge_object(before_value, value)
                    }
                    _ => {
                        if let Some((id, [])) = key.participant_pointer() {
                            let id = id.into_owned();
                            full.remove_participant_patches(&id);
                        }
                        full.insert(key, value);
                    }
                },
            }
        }
        has_additions
    }
}

trait ParticipantPatches {
    fn remove_participant_patches(&mut self, id: &str);
}

impl ParticipantPatches for EventMap<'_> {
    fn remove_participant_patches(&mut self, id: &str) {
        self.as_mut_vec().retain(|(key, _)| {
            key.participant_pointer()
                .is_none_or(|(patch_id, pointer)| pointer.is_empty() || patch_id != id)
        });
    }
}

trait ThreeWayMerge<'x> {
    fn merge_object(&mut self, before: &EventValue<'x>, after: EventValue<'x>);
}

impl<'x> ThreeWayMerge<'x> for EventValue<'x> {
    fn merge_object(&mut self, before: &EventValue<'x>, after: EventValue<'x>) {
        let after = match (self.as_object_mut(), before.as_object(), after) {
            (Some(full), Some(before), Value::Object(after)) => {
                for key in before.keys().filter(|key| !after.contains_key(key)) {
                    full.remove(key);
                }
                for (key, value) in after.into_vec() {
                    match before.get(&key) {
                        Some(before_value) if before_value.same_value(&value) => {}
                        Some(before_value) => match full.get_mut(&key) {
                            Some(full_value) => full_value.merge_object(before_value, value),
                            None => {
                                full.insert(key, value);
                            }
                        },
                        None => {
                            full.insert(key, value);
                        }
                    }
                }
                return;
            }
            (_, _, after) => after,
        };
        *self = after;
    }
}

fn participant_key(id: String) -> EventKey<'static> {
    Key::Property(JSCalendarProperty::Pointer(JsonPointer::new(vec![
        JsonPointerItem::Key(Key::Property(JSCalendarProperty::Participants)),
        JsonPointerItem::Key(Key::Owned(id)),
    ])))
}

