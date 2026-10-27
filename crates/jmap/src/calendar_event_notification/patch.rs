/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::jscalendar::{JSCalendar, JSCalendarProperty, JSCalendarValue};
use jmap_tools::{Key, Map, Value};
use types::{blob::BlobId, id::Id};

type EventMap = Map<'static, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;

pub trait JSCalendarPatch {
    fn patch_to(&self, after: &Self) -> Self;
}

impl JSCalendarPatch for JSCalendar<'static, Id, BlobId> {
    fn patch_to(&self, after: &Self) -> Self {
        let empty = EventMap::new();
        let mut patch = EventMap::new();
        diff_objects(
            &mut String::new(),
            self.0.as_object().unwrap_or(&empty),
            after.0.as_object().unwrap_or(&empty),
            &mut patch,
        );
        JSCalendar(Value::Object(patch))
    }
}

fn diff_objects(prefix: &mut String, before: &EventMap, after: &EventMap, patch: &mut EventMap) {
    for (key, before_value) in before.iter() {
        match after.get(key) {
            Some(after_value) if after_value == before_value => {}
            Some(Value::Object(after_object))
                if let Value::Object(before_object) = before_value
                    && !after_object.adds_null(before_object) =>
            {
                let len = prefix.len();
                prefix.push_segment(&key.to_string());
                prefix.push('/');
                diff_objects(prefix, before_object, after_object, patch);
                prefix.truncate(len);
            }
            Some(after_value) => {
                patch.insert_unchecked(prefix.patch_key(key), after_value.clone());
            }
            None => {
                patch.insert_unchecked(prefix.patch_key(key), Value::Null);
            }
        }
    }
    for (key, after_value) in after.iter().filter(|(key, _)| !before.contains_key(key)) {
        patch.insert_unchecked(prefix.patch_key(key), after_value.clone());
    }
}

trait NullMembers {
    fn adds_null(&self, before: &Self) -> bool;
}

impl NullMembers for EventMap {
    fn adds_null(&self, before: &Self) -> bool {
        self.iter().any(|(key, value)| {
            matches!(value, Value::Null) && !matches!(before.get(key), Some(Value::Null))
        })
    }
}

trait PatchPointer {
    fn patch_key(
        &self,
        key: &Key<'static, JSCalendarProperty<Id>>,
    ) -> Key<'static, JSCalendarProperty<Id>>;

    fn push_segment(&mut self, segment: &str);
}

impl PatchPointer for String {
    fn patch_key(
        &self,
        key: &Key<'static, JSCalendarProperty<Id>>,
    ) -> Key<'static, JSCalendarProperty<Id>> {
        let segment = key.to_string();
        if self.is_empty() && !segment.contains(['~', '/']) {
            key.clone()
        } else {
            let mut pointer = String::with_capacity(self.len() + segment.len() + 2);
            pointer.push_str(self);
            pointer.push_segment(&segment);
            Key::Owned(pointer)
        }
    }

    fn push_segment(&mut self, segment: &str) {
        for ch in segment.chars() {
            match ch {
                '~' => self.push_str("~0"),
                '/' => self.push_str("~1"),
                ch => self.push(ch),
            }
        }
    }
}

