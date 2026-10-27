/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jscalendar::{JSCalendarId, JSCalendarProperty, JSCalendarType, JSCalendarValue, Uuid5};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map, Value};
use std::{
    mem::{self, discriminant},
    str::FromStr,
};
use uuid::fmt::Hyphenated;

pub(crate) trait JSCalendarKeyExt<I: JSCalendarId> {
    fn is_forbidden_override_key(&self) -> bool;
    fn is_ignored_override_key(&self) -> bool;
    fn is_series_converted_property(&self) -> bool;
    fn is_uuid5_of(&self, value: &[u8]) -> bool;
    fn matches_pointer_item(&self, item: &JsonPointerItem<JSCalendarProperty<I>>) -> bool;
    fn pointer_index(&self) -> Option<u64>;
    fn same_key(&self, other: &Key<'_, JSCalendarProperty<I>>) -> bool;
    fn same_data_key(&self, other: &Key<'_, JSCalendarProperty<I>>) -> bool;
}

pub(crate) trait JSCalendarMapExt {
    fn is_type_or_untyped(&self, types: &[JSCalendarType]) -> bool;
}

pub(crate) trait JSCalendarObjectExt<'x, I: JSCalendarId, B: JSCalendarId> {
    fn key_position(&self, key: &Key<'_, JSCalendarProperty<I>>) -> Option<usize>;
    fn lookup(
        &self,
        key: &Key<'_, JSCalendarProperty<I>>,
    ) -> Option<&Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>>;
    fn lookup_mut(
        &mut self,
        key: &Key<'_, JSCalendarProperty<I>>,
    ) -> Option<&mut Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>>;
    fn upsert(
        &mut self,
        key: Key<'x, JSCalendarProperty<I>>,
        value: Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
    ) -> Option<Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>>;
    fn upsert_or_get_mut(
        &mut self,
        key: Key<'x, JSCalendarProperty<I>>,
        value: impl FnOnce() -> Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
    ) -> &mut Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>;
    fn contains_true(&self, key: &Key<'_, JSCalendarProperty<I>>) -> bool;
}

pub(crate) trait JSCalendarValueExt<I: JSCalendarId>: Sized {
    fn apply_jsprop(&mut self, pointer: &[JsonPointerItem<JSCalendarProperty<I>>], patch: Self);
}

pub trait JSCalendarPatch {
    fn is_instance_patch(&self) -> bool;
}

impl<I: JSCalendarId> JSCalendarKeyExt<I> for Key<'_, JSCalendarProperty<I>> {
    fn is_forbidden_override_key(&self) -> bool {
        match self {
            Key::Property(JSCalendarProperty::Pointer(pointer)) => {
                JSCalendarProperty::is_forbidden_override_pointer(pointer)
            }
            Key::Property(property) => property.is_forbidden_override_patch(),
            _ => false,
        }
    }

    fn is_ignored_override_key(&self) -> bool {
        matches!(
            self,
            Key::Property(property) if property.is_forbidden_override_patch()
                || matches!(property, JSCalendarProperty::Excluded)
        )
    }

    fn is_series_converted_property(&self) -> bool {
        let first = match self {
            Key::Property(JSCalendarProperty::Pointer(ptr)) => {
                return matches!(
                    ptr.iter()
                        .find(|item| !matches!(item, JsonPointerItem::Root)),
                    Some(JsonPointerItem::Key(Key::Property(
                        JSCalendarProperty::RecurrenceOverrides
                            | JSCalendarProperty::RecurrenceRule
                    )))
                );
            }
            Key::Property(property) => {
                return matches!(
                    property,
                    JSCalendarProperty::RecurrenceOverrides | JSCalendarProperty::RecurrenceRule
                );
            }
            Key::Borrowed(key) => key.split('/').next(),
            Key::Owned(key) => key.split('/').next(),
        };

        matches!(
            first.and_then(|name| JSCalendarProperty::<I>::from_str(name).ok()),
            Some(JSCalendarProperty::RecurrenceOverrides | JSCalendarProperty::RecurrenceRule)
        )
    }

    fn is_uuid5_of(&self, value: &[u8]) -> bool {
        let name = self.to_string();
        name.len() == Hyphenated::LENGTH && {
            let mut buffer = [0u8; Hyphenated::LENGTH];
            value.uuid5_hyphenated(&mut buffer) == name.as_ref()
        }
    }

    fn matches_pointer_item(&self, item: &JsonPointerItem<JSCalendarProperty<I>>) -> bool {
        match item {
            JsonPointerItem::Key(item) => item.same_key(self),
            JsonPointerItem::Number(number) => self.pointer_index() == Some(*number),
            JsonPointerItem::Root | JsonPointerItem::Wildcard | JsonPointerItem::Invalid(_) => {
                false
            }
        }
    }

    fn pointer_index(&self) -> Option<u64> {
        let name = self.as_string_key()?;
        (!name.is_empty()
            && name.bytes().all(|byte| byte.is_ascii_digit())
            && (name == "0" || !name.starts_with('0')))
        .then(|| name.parse().ok())
        .flatten()
    }

    #[inline(always)]
    fn same_key(&self, other: &Key<'_, JSCalendarProperty<I>>) -> bool {
        match (self, other) {
            (Key::Property(a), Key::Property(b)) if !a.has_data() && !b.has_data() => {
                discriminant(a) == discriminant(b)
            }
            _ => self.same_data_key(other),
        }
    }

    #[inline(never)]
    fn same_data_key(&self, other: &Key<'_, JSCalendarProperty<I>>) -> bool {
        self == other
    }
}

impl<'x, I: JSCalendarId, B: JSCalendarId> JSCalendarObjectExt<'x, I, B>
    for Map<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>
{
    #[inline]
    fn key_position(&self, key: &Key<'_, JSCalendarProperty<I>>) -> Option<usize> {
        self.as_vec().iter().position(|(k, _)| k.same_key(key))
    }

    #[inline]
    fn lookup(
        &self,
        key: &Key<'_, JSCalendarProperty<I>>,
    ) -> Option<&Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>> {
        self.as_vec()
            .iter()
            .find_map(|(k, v)| k.same_key(key).then_some(v))
    }

    #[inline]
    fn lookup_mut(
        &mut self,
        key: &Key<'_, JSCalendarProperty<I>>,
    ) -> Option<&mut Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>> {
        self.as_mut_vec()
            .iter_mut()
            .find_map(|(k, v)| k.same_key(key).then_some(v))
    }

    #[inline]
    fn upsert(
        &mut self,
        key: Key<'x, JSCalendarProperty<I>>,
        value: Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
    ) -> Option<Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>> {
        match self.lookup_mut(&key) {
            Some(current) => Some(mem::replace(current, value)),
            None => {
                self.insert_unchecked(key, value);
                None
            }
        }
    }

    #[inline]
    fn upsert_or_get_mut(
        &mut self,
        key: Key<'x, JSCalendarProperty<I>>,
        value: impl FnOnce() -> Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
    ) -> &mut Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>> {
        let position = match self.key_position(&key) {
            Some(position) => position,
            None => {
                self.insert_unchecked(key, value());
                self.len() - 1
            }
        };
        &mut self.as_mut_vec()[position].1
    }

    #[inline]
    fn contains_true(&self, key: &Key<'_, JSCalendarProperty<I>>) -> bool {
        self.as_vec()
            .iter()
            .any(|(k, v)| matches!(v, Value::Bool(true)) && k.same_key(key))
    }
}

impl<I: JSCalendarId, B: JSCalendarId> JSCalendarMapExt
    for Map<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>>
{
    fn is_type_or_untyped(&self, types: &[JSCalendarType]) -> bool {
        match self.lookup(&Key::Property(JSCalendarProperty::Type)) {
            None => true,
            Some(Value::Element(JSCalendarValue::Type(typ))) => types.contains(typ),
            Some(_) => false,
        }
    }
}

impl<I: JSCalendarId, B: JSCalendarId> JSCalendarPatch
    for Value<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>>
{
    fn is_instance_patch(&self) -> bool {
        self.as_object().is_some_and(|patch| {
            let excluded = Key::Property(JSCalendarProperty::Excluded);
            !patch.contains_true(&excluded)
                && patch
                    .keys()
                    .any(|key| !key.same_key(&excluded) && !key.is_forbidden_override_key())
        })
    }
}

impl<I: JSCalendarId, B: JSCalendarId> JSCalendarValueExt<I>
    for Value<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>>
{
    fn apply_jsprop(&mut self, pointer: &[JsonPointerItem<JSCalendarProperty<I>>], patch: Self) {
        let (Some((last, parents)), false) = (pointer.split_last(), patch.is_null()) else {
            return;
        };
        let mut current = self;
        for item in parents {
            let Value::Object(obj) = current else {
                return;
            };
            let Some(next) = obj
                .iter_mut()
                .find_map(|(key, value)| key.matches_pointer_item(item).then_some(value))
            else {
                return;
            };
            current = next;
        }
        let Value::Object(obj) = current else {
            return;
        };
        if obj.iter().any(|(key, _)| key.matches_pointer_item(last)) {
            return;
        }
        let key = match last {
            JsonPointerItem::Key(key) => key.clone(),
            JsonPointerItem::Number(number) => Key::Owned(number.to_string()),
            JsonPointerItem::Root | JsonPointerItem::Wildcard | JsonPointerItem::Invalid(_) => {
                return;
            }
        };
        obj.insert_unchecked(key, patch);
    }
}

impl<I: JSCalendarId> JSCalendarProperty<I> {
    pub(crate) fn is_series_property(&self) -> bool {
        matches!(
            self,
            JSCalendarProperty::RecurrenceRule
                | JSCalendarProperty::RecurrenceOverrides
                | JSCalendarProperty::RecurrenceId
                | JSCalendarProperty::RecurrenceIdTimeZone
                | JSCalendarProperty::Excluded
        )
    }

    pub(crate) fn is_member_map(&self) -> bool {
        matches!(
            self,
            JSCalendarProperty::Participants
                | JSCalendarProperty::Locations
                | JSCalendarProperty::VirtualLocations
                | JSCalendarProperty::Alerts
                | JSCalendarProperty::Links
                | JSCalendarProperty::RelatedTo
        )
    }

    pub(crate) fn member_pointer<const N: usize>(
        &self,
        keys: [Key<'static, JSCalendarProperty<I>>; N],
    ) -> Key<'static, JSCalendarProperty<I>> {
        let mut items = Vec::with_capacity(N + 1);
        items.push(JsonPointerItem::Key(Key::Property(self.clone())));
        items.extend(keys.into_iter().map(|key| match key.pointer_index() {
            Some(index) => JsonPointerItem::Number(index),
            None => JsonPointerItem::Key(key),
        }));
        Key::Property(JSCalendarProperty::Pointer(JsonPointer::new(items)))
    }
}
