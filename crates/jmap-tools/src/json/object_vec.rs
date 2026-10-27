/*
 * SPDX-FileCopyrightText: 2021 Pascal Seitz <pascal.seitz@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(clippy::useless_conversion)]
#![allow(clippy::useless_asref)]

use crate::{
    Value,
    json::key::Key,
    json::value::{Element, Property},
    pointer::NumberKey,
};
use std::mem::replace;

const NAMED_KEY_CAPACITY: usize = 24;

/// Represents a JSON key/value type.
///
/// For performance reasons we use a Vec instead of a Hashmap.
/// This comes with a tradeoff of slower key accesses as we need to iterate and compare.
///
/// The ObjectAsVec struct is a wrapper around a Vec of (&str, Value) pairs.
/// It provides methods to make it easy to migrate from serde_json::Value::Object or
/// serde_json::Map.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct ObjectAsVec<'ctx, P: Property, E: Element>(
    pub(crate) Vec<(Key<'ctx, P>, Value<'ctx, P, E>)>,
);

impl<'ctx, P: Property, E: Element> From<Vec<(Key<'ctx, P>, Value<'ctx, P, E>)>>
    for ObjectAsVec<'ctx, P, E>
{
    fn from(vec: Vec<(Key<'ctx, P>, Value<'ctx, P, E>)>) -> Self {
        ObjectAsVec(vec)
    }
}

impl<'ctx, P: Property, E: Element> FromIterator<(Key<'ctx, P>, Value<'ctx, P, E>)>
    for ObjectAsVec<'ctx, P, E>
{
    fn from_iter<T: IntoIterator<Item = (Key<'ctx, P>, Value<'ctx, P, E>)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'ctx, P: Property, E: Element> ObjectAsVec<'ctx, P, E> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Access to the underlying Vec.
    ///
    /// # Note
    /// Since KeyStrType can be changed via a feature flag avoid using `as_vec` and use other
    /// methods instead. This could be a problem with feature unification, when one crate uses it
    /// as `&str` and another uses it as `Cow<str>`, both will get `Cow<str>`
    #[inline]
    pub fn as_vec(&self) -> &Vec<(Key<'ctx, P>, Value<'ctx, P, E>)> {
        &self.0
    }

    #[inline]
    pub fn as_mut_vec(&mut self) -> &mut Vec<(Key<'ctx, P>, Value<'ctx, P, E>)> {
        &mut self.0
    }

    /// Access to the underlying Vec. Keys are normalized to Cow.
    #[inline]
    pub fn into_vec(self) -> Vec<(Key<'ctx, P>, Value<'ctx, P, E>)> {
        self.0
    }

    /// Returns a reference to the value corresponding to the key.
    ///
    /// ## Performance
    /// As this is backed by a Vec, this searches linearly through the Vec as may be much more
    /// expensive than a `Hashmap` for larger Objects.
    #[inline]
    pub fn get(&self, key: &Key<'_, P>) -> Option<&Value<'ctx, P, E>> {
        self.position(key)
            .and_then(|pos| self.0.get(pos))
            .map(|(_, v)| v)
    }

    #[inline]
    pub(crate) fn position(&self, key: &Key<'_, P>) -> Option<usize> {
        let mut keys = self.0.iter().map(|(k, _)| k);
        match key {
            Key::Property(property) => keys.position(|k| match k {
                Key::Property(word) => word.key_eq(property),
                Key::Borrowed(text) => property.key_eq_str(text),
                Key::Owned(text) => property.key_eq_str(text),
            }),
            Key::Borrowed(text) => keys.position(|k| k.matches_str(text)),
            Key::Owned(text) => keys.position(|k| k.matches_str(text)),
        }
    }

    #[inline]
    pub fn get_ignore_case(&self, key: &str) -> Option<&Value<'ctx, P, E>> {
        self.0.iter().find_map(|(k, v)| {
            if k.to_string().eq_ignore_ascii_case(key) {
                Some(v)
            } else {
                None
            }
        })
    }

    /// Returns a mutable reference to the value corresponding to the key, if it exists.
    ///
    /// ## Performance
    /// As this is backed by a Vec, this searches linearly through the Vec as may be much more
    /// expensive than a `Hashmap` for larger Objects.
    #[inline]
    pub fn get_mut(&mut self, key: &Key<'ctx, P>) -> Option<&mut Value<'ctx, P, E>> {
        self.position(key)
            .and_then(|pos| self.0.get_mut(pos))
            .map(|(_, v)| v)
    }

    /// Returns the key-value pair corresponding to the supplied key.
    ///
    /// ## Performance
    /// As this is backed by a Vec, this searches linearly through the Vec as may be much more
    /// expensive than a `Hashmap` for larger Objects.
    #[inline]
    pub fn get_key_value(&self, key: &Key<'_, P>) -> Option<(&Key<'_, P>, &Value<'ctx, P, E>)> {
        self.position(key)
            .and_then(|pos| self.0.get(pos))
            .map(|(k, v)| (k, v))
    }

    /// An iterator visiting all key-value pairs
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&Key<'ctx, P>, &Value<'ctx, P, E>)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    #[inline]
    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&mut Key<'ctx, P>, &mut Value<'ctx, P, E>)> {
        self.0.iter_mut().map(|(k, v)| (k, v))
    }

    /// Returns the number of elements in the object
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the object contains no elements
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// An iterator visiting all keys
    #[inline]
    pub fn keys(&self) -> impl Iterator<Item = &Key<'ctx, P>> {
        self.0.iter().map(|(k, _)| k)
    }

    /// An iterator visiting all values
    #[inline]
    pub fn values(&self) -> impl Iterator<Item = &Value<'ctx, P, E>> {
        self.0.iter().map(|(_, v)| v)
    }

    /// Returns true if the object contains a value for the specified key.
    ///
    /// ## Performance
    /// As this is backed by a Vec, this searches linearly through the Vec as may be much more
    /// expensive than a `Hashmap` for larger Objects.
    #[inline]
    pub fn contains_key(&self, key: &Key<'ctx, P>) -> bool {
        self.position(key).is_some()
    }

    #[inline]
    pub fn contains_key_value(&self, key: &Key<'ctx, P>, value: &Value<'ctx, P, E>) -> bool {
        self.0.iter().any(|(k, v)| k == key && v == value)
    }

    #[inline]
    pub fn contains_any_key(&self, keys: &[Key<'ctx, P>]) -> bool {
        self.0.iter().any(|(k, _)| keys.contains(k))
    }

    pub fn remove(&mut self, key: &Key<'ctx, P>) -> Option<Value<'ctx, P, E>> {
        self.position(key).map(|pos| self.0.swap_remove(pos).1)
    }

    /// Inserts a key-value pair into the object.
    /// If the object did not have this key present, `None` is returned.
    /// If the object did have this key present, the value is updated, and the old value is
    /// returned.
    ///
    /// ## Performance
    /// This operation is linear in the size of the Vec because it potentially requires iterating
    /// through all elements to find a matching key.
    #[inline]
    pub fn insert(
        &mut self,
        key: impl Into<Key<'ctx, P>>,
        value: impl Into<Value<'ctx, P, E>>,
    ) -> Option<Value<'ctx, P, E>> {
        let key = key.into();
        match self.position(&key).and_then(|pos| self.0.get_mut(pos)) {
            Some((_, v)) => Some(replace(v, value.into())),
            None => {
                self.0.push((key, value.into()));
                None
            }
        }
    }

    /// Inserts a key-value pair into the object if the key does not yet exist, otherwise returns a
    /// mutable reference to the existing value.
    ///
    /// ## Performance
    /// This operation might be linear in the size of the Vec because it requires iterating through
    /// all elements to find a matching key, and might add to the end if not found.
    #[inline]
    pub fn insert_or_get_mut(
        &mut self,
        key: impl Into<Key<'ctx, P>>,
        value: impl Into<Value<'ctx, P, E>>,
    ) -> &mut Value<'ctx, P, E> {
        let key = key.into();
        let pos = match self.position(&key) {
            Some(pos) => pos,
            None => {
                self.0.push((key, value.into()));
                self.0.len() - 1
            }
        };
        &mut self.0[pos].1
    }

    #[inline]
    pub fn insert_unchecked(
        &mut self,
        key: impl Into<Key<'ctx, P>>,
        value: impl Into<Value<'ctx, P, E>>,
    ) {
        self.0.push((key.into(), value.into()));
    }

    #[inline]
    pub fn with_key_value(
        mut self,
        key: impl Into<Key<'ctx, P>>,
        value: impl Into<Value<'ctx, P, E>>,
    ) -> Self {
        self.insert_unchecked(key, value);
        self
    }

    pub fn insert_named(&mut self, key: Option<String>, value: Value<'ctx, P, E>) -> String {
        let mut number = NumberKey::default();
        let suffix = number.format(self.0.len() as u64 + 1);
        let mut key = key.unwrap_or_else(|| {
            let mut key = String::with_capacity(NAMED_KEY_CAPACITY);
            key.push('k');
            key.push_str(suffix);
            key
        });

        if self.contains_key(&Key::Borrowed(key.as_str())) {
            key.push('-');
            key.push_str(suffix);
        }

        self.0.push((Key::Owned(key.clone()), value));
        key
    }

    #[inline]
    pub fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (Key<'ctx, P>, Value<'ctx, P, E>)>,
    {
        self.0.extend(iter);
    }

    /// Inserts a key-value pair into the object and returns the mutable reference of the inserted
    /// value.
    ///
    /// ## Note
    /// The key must not exist in the object. If the key already exists, the object will contain
    /// multiple keys afterwards.
    ///
    /// ## Performance
    /// This operation is amortized constant time, worst case linear time in the size of the Vec
    /// because it potentially requires a reallocation to grow the Vec.
    #[inline]
    pub fn insert_unchecked_and_get_mut(
        &mut self,
        key: impl Into<Key<'ctx, P>>,
        value: impl Into<Value<'ctx, P, E>>,
    ) -> &mut Value<'ctx, P, E> {
        let key = key.into();
        self.0.push((key, value.into()));
        let idx = self.0.len() - 1;
        &mut self.0[idx].1
    }
}

impl<'ctx, P: Property, E: Element<Property = P>> ObjectAsVec<'ctx, P, E> {
    pub fn into_expanded_boolean_set(self) -> impl Iterator<Item = Key<'ctx, P>> {
        self.into_vec()
            .into_iter()
            .filter_map(|(key, value)| value.as_bool().filter(|&b| b).map(|_| key))
    }
}

impl<'ctx, P: Property, E: Element> From<ObjectAsVec<'ctx, P, E>>
    for serde_json::Map<String, serde_json::Value>
{
    fn from(val: ObjectAsVec<'ctx, P, E>) -> Self {
        val.iter()
            .map(|(key, val)| (key.to_string().into_owned(), val.into()))
            .collect()
    }
}
impl<'ctx, P: Property, E: Element> From<&ObjectAsVec<'ctx, P, E>>
    for serde_json::Map<String, serde_json::Value>
{
    fn from(val: &ObjectAsVec<'ctx, P, E>) -> Self {
        val.iter()
            .map(|(key, val)| (key.to_string().into_owned(), val.into()))
            .collect()
    }
}
