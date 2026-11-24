/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    jmap::{
        IntoValue, JmapValue, JsonPointerPatch, MaybeUnpatched, PatchResult, RegistryJsonPatch,
    },
    pickle::{Pickle, PickledStream},
    schema::prelude::SocketAddr,
    types::{
        EnumImpl, error::PatchError, ipaddr::IpAddr, ipmask::IpAddrOrMask,
        string::StringValidatorResult,
    },
};
use jmap_tools::{JsonPointerItem, Key, Value};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
    ser::SerializeMap,
};
use std::{
    borrow::Cow,
    fmt::{self, Debug},
    marker::PhantomData,
    str::FromStr,
};
use types::id::Id;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Map<T: MapItem>(Vec<T>);

impl<T: MapItem> Map<T> {
    pub fn new(items: Vec<T>) -> Self {
        Self(items)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    #[inline(always)]
    pub fn contains(&self, item: &T) -> bool {
        self.0.contains(item)
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline(always)]
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }

    #[inline(always)]
    pub fn inner_mut(&mut self) -> &mut Vec<T> {
        &mut self.0
    }

    #[inline(always)]
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    #[inline(always)]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.iter_mut()
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    #[inline(always)]
    pub fn push(&mut self, item: T) {
        if !self.0.contains(&item) {
            self.0.push(item);
        }
    }

    #[inline(always)]
    pub fn push_unchecked(&mut self, item: T) {
        self.0.push(item);
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

impl<T> Pickle for Map<T>
where
    T: Pickle + MapItem,
{
    fn pickle(&self, out: &mut Vec<u8>) {
        (self.0.len() as u32).pickle(out);
        for item in &self.0 {
            item.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let len = u32::unpickle(stream)? as usize;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            // inbuxa: a value this build doesn't know (a permission or event
            // added by a newer version) is left out instead of failing the
            // whole object, so a rollback still loads its roles
            if let Some(item) = T::unpickle_item(stream)? {
                vec.push(item);
            }
        }
        Some(Self(vec))
    }
}

impl<V: IntoValue + MapItem> IntoValue for Map<V> {
    fn into_value(self) -> JmapValue<'static> {
        let mut map = jmap_tools::Map::with_capacity(self.0.len());
        for v in self.0 {
            let key = match v.into_string() {
                Cow::Borrowed(s) => Key::Borrowed(s),
                Cow::Owned(s) => Key::Owned(s),
            };
            map.insert_unchecked(key, Value::Bool(true));
        }

        JmapValue::Object(map)
    }
}

impl<T: MapItem + Default> RegistryJsonPatch for Map<T> {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (pointer.next(), value) {
            (Some(JsonPointerItem::Number(idx)), Value::Null | Value::Bool(false)) => {
                let key = T::try_from_integer(*idx);

                if !pointer.has_next()
                    && let Some(key) = key
                {
                    self.0.retain(|item| item != &key);
                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (Some(JsonPointerItem::Key(key)), Value::Null | Value::Bool(false)) => {
                let key = T::try_from_string(key.to_string().as_ref());

                if !pointer.has_next()
                    && let Some(key) = key
                {
                    self.0.retain(|item| item != &key);
                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (Some(JsonPointerItem::Key(key)), Value::Bool(true)) => {
                let raw = key.to_string().into_owned();
                let key = added_key::<T>(&pointer, raw.as_ref(), None)
                    .map_err(|err| PatchError::new(pointer.clone(), err))?;

                if !pointer.has_next()
                    && let Some(key) = key
                {
                    if !self.0.contains(&key) {
                        self.0.push(key);
                    }

                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (Some(JsonPointerItem::Number(idx)), Value::Bool(true)) => {
                let idx = *idx;
                let key = added_key::<T>(&pointer, &idx.to_string(), Some(idx))
                    .map_err(|err| PatchError::new(pointer.clone(), err))?;
                if !pointer.has_next()
                    && let Some(key) = key
                {
                    if !self.0.contains(&key) {
                        self.0.push(key);
                    }

                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (None, Value::Object(items)) => {
                // inbuxa: #608: a value the set already holds is kept as it
                // is, so one stored before validation applied doesn't block
                // every later edit; only values being added are validated.
                let current = std::mem::take(&mut self.0);
                for (key, value) in items.into_vec() {
                    let Value::Bool(is_set) = value else {
                        return Err(PatchError::new(
                            pointer.clone(),
                            "Invalid key for object property",
                        ));
                    };
                    let raw = key.to_string();
                    let key = match T::try_from_string(raw.as_ref()) {
                        Some(key) if !is_set || current.contains(&key) => Some(key),
                        _ if !is_set => None,
                        _ => added_key::<T>(&pointer, raw.as_ref(), None)
                            .map_err(|err| PatchError::new(pointer.clone(), err))?,
                    };
                    let Some(key) = key else {
                        return Err(PatchError::new(
                            pointer.clone(),
                            "Invalid key for object property",
                        ));
                    };
                    if is_set && !self.0.contains(&key) {
                        self.0.push(key);
                    }
                }
                return Ok(MaybeUnpatched::Patched);
            }
            _ => {}
        }

        Err(PatchError::new(
            pointer,
            "Invalid value for object property",
        ))
    }
}

/// inbuxa: #608: a key being added to a set, after the field's validators
/// (an email set takes only addresses, a domain set only domains). A
/// validator may also rewrite the value (lowercase, trimmed). `Ok(None)` is
/// a key the set's type can't hold.
fn added_key<T: MapItem>(
    pointer: &JsonPointerPatch<'_>,
    raw: &str,
    integer: Option<u64>,
) -> Result<Option<T>, &'static str> {
    let validators = pointer.validators();
    if validators.is_empty() {
        return Ok(match integer {
            Some(idx) => T::try_from_integer(idx),
            None => T::try_from_string(raw),
        });
    }

    let mut value = raw.to_string();
    for validator in validators {
        match validator.validate(&value) {
            StringValidatorResult::Valid => {}
            StringValidatorResult::Replace(new_value) => value = new_value,
            StringValidatorResult::Invalid(err) => return Err(err),
        }
    }
    Ok(T::try_from_string(&value))
}

impl<T: MapItem> Serialize for Map<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for item in &self.0 {
            map.serialize_entry(&item.as_string() as &str, &true)?;
        }
        map.end()
    }
}

impl<'de, T: MapItem> Deserialize<'de> for Map<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MapVisitor<T>(PhantomData<T>);

        impl<'de, T: MapItem> Visitor<'de> for MapVisitor<T> {
            type Value = Map<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map of string keys to booleans or nulls")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut items = Vec::with_capacity(map.size_hint().unwrap_or(0));

                while let Some(key) = map.next_key::<Cow<'de, str>>()? {
                    let value: Option<bool> = map.next_value()?;

                    if value == Some(true) {
                        let item = T::try_from_string(&key)
                            .ok_or_else(|| de::Error::custom(format!("invalid map key: {key}")))?;
                        if !items.contains(&item) {
                            items.push(item);
                        }
                    }
                }

                Ok(Map(items))
            }
        }

        deserializer.deserialize_map(MapVisitor(PhantomData))
    }
}

pub trait MapItem: Sized + PartialEq + Eq + Debug {
    fn try_from_string(value: &str) -> Option<Self>;
    fn try_from_integer(value: u64) -> Option<Self>;
    fn into_string(self) -> Cow<'static, str>;
    fn as_string(&self) -> Cow<'_, str>;
}

impl MapItem for String {
    fn try_from_string(value: &str) -> Option<Self> {
        let value = value.trim();
        if !value.is_empty() {
            Some(value.to_string())
        } else {
            None
        }
    }

    fn try_from_integer(value: u64) -> Option<Self> {
        Some(value.to_string())
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self)
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.as_str())
    }
}

impl MapItem for Id {
    fn try_from_string(value: &str) -> Option<Self> {
        Id::from_str(value).ok()
    }

    fn try_from_integer(value: u64) -> Option<Self> {
        Id::from_str(&value.to_string()).ok()
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self.as_string())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.as_string())
    }
}

impl<T: EnumImpl> MapItem for T {
    fn try_from_string(value: &str) -> Option<Self> {
        Self::parse(value)
    }

    fn try_from_integer(_: u64) -> Option<Self> {
        None
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Borrowed(self.as_str())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.as_str())
    }
}

impl MapItem for IpAddr {
    fn try_from_string(value: &str) -> Option<Self> {
        Self::from_str(value).ok()
    }

    fn try_from_integer(_: u64) -> Option<Self> {
        None
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.to_string())
    }
}

impl MapItem for IpAddrOrMask {
    fn try_from_string(value: &str) -> Option<Self> {
        Self::from_str(value).ok()
    }

    fn try_from_integer(_: u64) -> Option<Self> {
        None
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.to_string())
    }
}

impl MapItem for SocketAddr {
    fn try_from_string(value: &str) -> Option<Self> {
        Self::from_str(value).ok()
    }

    fn try_from_integer(_: u64) -> Option<Self> {
        None
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.to_string())
    }
}

impl MapItem for u64 {
    fn try_from_string(value: &str) -> Option<Self> {
        value.parse().ok()
    }

    fn try_from_integer(value: u64) -> Option<Self> {
        Some(value)
    }

    fn into_string(self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }

    fn as_string(&self) -> Cow<'_, str> {
        Cow::Owned(self.to_string())
    }
}

impl<T: MapItem> From<Vec<T>> for Map<T> {
    fn from(vec: Vec<T>) -> Self {
        Self(vec)
    }
}

impl<T: MapItem> IntoIterator for Map<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        jmap::JsonPointerPatch, schema::prelude::Property, types::string::StringValidator,
    };
    use jmap_tools::JsonPointer;

    fn patch_member(ptr_str: &str) -> Map<Id> {
        let mut map = Map::<Id>::default();
        let ptr = JsonPointer::<Property>::parse(ptr_str);
        let pointer = JsonPointerPatch::new(&ptr);
        map.patch(pointer, Value::Bool(true)).expect("patch failed");
        map
    }

    /// A permission list stored by a newer version: the unknown id is left
    /// out and the fields after it still read (rollback to an older build).
    #[test]
    fn unpickle_skips_unknown_enum_ids() {
        use crate::{pickle::PickledStream, schema::enums::Permission};
        use utils::map::vec_map::VecMap;

        let unknown = u16::MAX - 1;
        assert!(Permission::from_id(unknown).is_none());
        let mut out = vec![0u8];
        3u32.pickle(&mut out);
        Permission::Authenticate.pickle(&mut out);
        unknown.pickle(&mut out);
        Permission::SysScheduledReportUpdate.pickle(&mut out);
        2u32.pickle(&mut out);
        unknown.pickle(&mut out);
        7u64.pickle(&mut out);
        Permission::AuthenticateWithAlias.pickle(&mut out);
        9u64.pickle(&mut out);
        "after".to_string().pickle(&mut out);

        let mut stream = PickledStream::new(&out).unwrap();
        let map = Map::<Permission>::unpickle(&mut stream).unwrap();
        assert_eq!(
            map.0,
            vec![
                Permission::Authenticate,
                Permission::SysScheduledReportUpdate
            ]
        );
        let vec_map = VecMap::<Permission, u64>::unpickle(&mut stream).unwrap();
        assert_eq!(vec_map.len(), 1);
        assert_eq!(vec_map.get(&Permission::AuthenticateWithAlias), Some(&9));
        assert_eq!(String::unpickle(&mut stream).as_deref(), Some("after"));

        // A list cut short is still refused
        let mut stream = PickledStream::new(&out[..4]).unwrap();
        assert!(Map::<Permission>::unpickle(&mut stream).is_none());
    }

    #[test]
    fn patch_map_id_digit_keys() {
        for id in [0u64, 28, 29, 70, 861, 954, 957, 30554] {
            let id = Id::new(id);
            let key = id.as_string();
            let map = patch_member(&key);
            assert_eq!(map.0, vec![id], "id {} via key '{key}'", id.id());
        }
    }

    fn email_set(values: &[&str]) -> Map<String> {
        Map::new(values.iter().map(|v| v.to_string()).collect())
    }

    fn patch_with(
        map: &mut Map<String>,
        ptr: &str,
        validators: &[StringValidator],
        value: JmapValue<'static>,
    ) -> Result<(), String> {
        // "" is the whole set: the pointer is past the property's name
        let whole = ptr.is_empty();
        let ptr = JsonPointer::<Property>::parse(if whole { "contact" } else { ptr });
        let mut pointer = JsonPointerPatch::new(&ptr).with_validators(validators);
        if whole {
            pointer.next();
        }
        map.patch(pointer, value)
            .map(|_| ())
            .map_err(|err| format!("{err:?}"))
    }

    fn object(keys: &[(&str, bool)]) -> JmapValue<'static> {
        let mut map = jmap_tools::Map::with_capacity(keys.len());
        for (key, set) in keys {
            map.insert_unchecked(Key::Owned(key.to_string()), Value::Bool(*set));
        }
        Value::Object(map)
    }

    /// #608: a set's validators apply to each value added, by key or as a
    /// whole set, and may rewrite it.
    #[test]
    fn set_keys_are_validated() {
        let email = [StringValidator::Email];
        let mut map = Map::<String>::default();
        patch_with(&mut map, "Admin@Example.org", &email, Value::Bool(true)).unwrap();
        assert_eq!(map, email_set(&["admin@example.org"]));
        assert!(patch_with(&mut map, "mailto:x@example.org", &email, Value::Bool(true)).is_err());
        assert!(patch_with(&mut map, "not an address", &email, Value::Bool(true)).is_err());
        assert!(patch_with(&mut map, "7", &email, Value::Bool(true)).is_err());
        assert_eq!(map, email_set(&["admin@example.org"]));

        let mut map = Map::<String>::default();
        assert!(
            patch_with(
                &mut map,
                "",
                &email,
                object(&[("ok@example.org", true), ("bad", true)])
            )
            .is_err()
        );
        let mut map = Map::<String>::default();
        patch_with(&mut map, "", &email, object(&[("OK@example.org", true)])).unwrap();
        assert_eq!(map, email_set(&["ok@example.org"]));

        let domain = [StringValidator::Domain];
        let mut map = Map::<String>::default();
        patch_with(&mut map, "Example.ORG", &domain, Value::Bool(true)).unwrap();
        assert_eq!(map, email_set(&["example.org"]));
        assert!(patch_with(&mut map, "bad..name", &domain, Value::Bool(true)).is_err());

        // A set with no validators takes what it always took
        let mut map = Map::<String>::default();
        patch_with(&mut map, "anything at all", &[], Value::Bool(true)).unwrap();
        assert_eq!(map, email_set(&["anything at all"]));
    }

    /// #608 / #535: a value stored before validation applied stays through
    /// an edit that sends the whole set back, and can still be removed.
    #[test]
    fn stored_values_survive_whole_set_edits() {
        let email = [StringValidator::Email];
        let mut map = email_set(&["mailto:old@example.org"]);
        patch_with(
            &mut map,
            "",
            &email,
            object(&[("mailto:old@example.org", true), ("new@example.org", true)]),
        )
        .unwrap();
        assert_eq!(
            map,
            email_set(&["mailto:old@example.org", "new@example.org"])
        );

        // A new invalid value is still refused alongside it
        let mut map = email_set(&["mailto:old@example.org"]);
        assert!(
            patch_with(
                &mut map,
                "",
                &email,
                object(&[
                    ("mailto:old@example.org", true),
                    ("mailto:new@example.org", true)
                ]),
            )
            .is_err()
        );

        // Removing it needs no validation, by key or as a whole set
        let mut map = email_set(&["mailto:old@example.org", "a@example.org"]);
        patch_with(&mut map, "mailto:old@example.org", &email, Value::Null).unwrap();
        assert_eq!(map, email_set(&["a@example.org"]));
        let mut map = email_set(&["mailto:old@example.org", "a@example.org"]);
        patch_with(
            &mut map,
            "",
            &email,
            object(&[("mailto:old@example.org", false), ("a@example.org", true)]),
        )
        .unwrap();
        assert_eq!(map, email_set(&["a@example.org"]));
    }

    /// #608: the generated property patch passes each set's validators on,
    /// for an email set and a domain set.
    #[test]
    fn object_sets_apply_their_validators() {
        use crate::{
            jmap::RegistryJsonPropertyPatch,
            schema::structs::{AcmeProvider, Domain},
        };
        let patch_acme = |provider: &mut AcmeProvider, ptr: &str| {
            let ptr = JsonPointer::<Property>::parse(ptr);
            provider
                .patch_property(JsonPointerPatch::new(&ptr), Value::Bool(true))
                .is_ok()
        };
        let mut provider = AcmeProvider::default();
        assert!(patch_acme(&mut provider, "contact/Admin@Example.org"));
        assert!(!patch_acme(
            &mut provider,
            "contact/mailto:admin@example.org"
        ));
        assert_eq!(provider.contact, email_set(&["admin@example.org"]));

        let mut domain = Domain::default();
        let ptr = JsonPointer::<Property>::parse("aliases/not a domain");
        assert!(
            domain
                .patch_property(JsonPointerPatch::new(&ptr), Value::Bool(true))
                .is_err()
        );
        let ptr = JsonPointer::<Property>::parse("aliases/Mail.Example.org");
        domain
            .patch_property(JsonPointerPatch::new(&ptr), Value::Bool(true))
            .unwrap();
        assert_eq!(domain.aliases, email_set(&["mail.example.org"]));
    }
}
