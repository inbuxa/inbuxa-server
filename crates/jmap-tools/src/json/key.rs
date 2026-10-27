/*
 * SPDX-FileCopyrightText: 2021 Pascal Seitz <pascal.seitz@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::json::value::Property;
use serde::de::{self, DeserializeSeed, Visitor};
use serde::{Serialize, Serializer};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub enum Key<'x, P: Property> {
    Property(P),
    Borrowed(&'x str),
    Owned(String),
}

pub(crate) struct DeserializationContext<'x, P: Property> {
    pub parent_key: Option<&'x Key<'x, P>>,
}

impl<'de, 'x, P: Property> DeserializeSeed<'de> for DeserializationContext<'x, P> {
    type Value = Key<'de, P>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(KeyVisitor { context: &self })
    }
}

struct KeyVisitor<'x, P: Property> {
    context: &'x DeserializationContext<'x, P>,
}

impl<'de, 'x, P: Property> Visitor<'de> for KeyVisitor<'x, P> {
    type Value = Key<'de, P>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_borrowed_str<ERR>(self, value: &'de str) -> Result<Self::Value, ERR>
    where
        ERR: de::Error,
    {
        match P::try_parse(self.context.parent_key, value) {
            Some(word) => Ok(Key::Property(word)),
            None => Ok(Key::Borrowed(value)),
        }
    }

    fn visit_str<ERR>(self, value: &str) -> Result<Self::Value, ERR>
    where
        ERR: de::Error,
    {
        match P::try_parse(self.context.parent_key, value) {
            Some(word) => Ok(Key::Property(word)),
            None => Ok(Key::Owned(value.to_owned())),
        }
    }

    fn visit_string<ERR>(self, value: String) -> Result<Self::Value, ERR>
    where
        ERR: de::Error,
    {
        match P::try_parse(self.context.parent_key, &value) {
            Some(word) => Ok(Key::Property(word)),
            None => Ok(Key::Owned(value)),
        }
    }
}

pub(crate) struct OpaqueKey<P: Property>(pub PhantomData<P>);

impl<'de, P: Property> DeserializeSeed<'de> for OpaqueKey<P> {
    type Value = Key<'de, P>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de, P: Property> Visitor<'de> for OpaqueKey<P> {
    type Value = Key<'de, P>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_borrowed_str<ERR>(self, value: &'de str) -> Result<Self::Value, ERR>
    where
        ERR: de::Error,
    {
        Ok(Key::Borrowed(value))
    }

    fn visit_str<ERR>(self, value: &str) -> Result<Self::Value, ERR>
    where
        ERR: de::Error,
    {
        Ok(Key::Owned(value.to_owned()))
    }

    fn visit_string<ERR>(self, value: String) -> Result<Self::Value, ERR>
    where
        ERR: de::Error,
    {
        Ok(Key::Owned(value))
    }
}

impl<P: Property> Serialize for Key<'_, P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Key::Property(property) => property.serialize_text(serializer),
            Key::Borrowed(text) => serializer.serialize_str(text),
            Key::Owned(text) => serializer.serialize_str(text),
        }
    }
}

impl<P: Property> PartialEq for Key<'_, P> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        match other {
            Key::Property(property) => self.matches_property(property),
            Key::Borrowed(text) => self.matches_str(text),
            Key::Owned(text) => self.matches_str(text),
        }
    }
}

impl<P: Property> Eq for Key<'_, P> {}

impl<P: Property> Hash for Key<'_, P> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Key::Property(word) => word.key_hash(state),
            Key::Borrowed(s) => s.hash(state),
            Key::Owned(s) => s.hash(state),
        }
    }
}

impl<P: Property> PartialOrd for Key<'_, P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P: Property> Ord for Key<'_, P> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl<P: Property> PartialEq<&str> for Key<'_, P> {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.matches_str(other)
    }
}

impl<'x, P: Property> From<&'x str> for Key<'x, P> {
    fn from(s: &'x str) -> Self {
        match P::try_parse(None, s) {
            Some(word) => Key::Property(word),
            None => Key::Borrowed(s),
        }
    }
}

impl<'x, P: Property> From<Key<'x, P>> for Cow<'x, str> {
    fn from(s: Key<'x, P>) -> Self {
        match s {
            Key::Borrowed(s) => Cow::Borrowed(s),
            Key::Owned(s) => Cow::Owned(s),
            Key::Property(word) => word.to_cow(),
        }
    }
}

impl<'x, P: Property> From<Cow<'x, str>> for Key<'x, P> {
    fn from(s: Cow<'x, str>) -> Self {
        match s {
            Cow::Borrowed(s) => Key::Borrowed(s),
            Cow::Owned(s) => Key::Owned(s),
        }
    }
}

impl<P: Property> Key<'_, P> {
    #[inline]
    pub(crate) fn matches_property(&self, property: &P) -> bool {
        match self {
            Key::Property(word) => word.key_eq(property),
            Key::Borrowed(text) => property.key_eq_str(text),
            Key::Owned(text) => property.key_eq_str(text),
        }
    }

    #[inline]
    pub(crate) fn is_opaque(&self) -> bool {
        matches!(self, Key::Property(property) if property.is_opaque())
    }

    #[inline]
    pub(crate) fn matches_str(&self, text: &str) -> bool {
        match self {
            Key::Property(word) => word.key_eq_str(text),
            Key::Borrowed(other) => *other == text,
            Key::Owned(other) => other == text,
        }
    }

    pub fn to_string(&self) -> Cow<'_, str> {
        match self {
            Key::Borrowed(s) => Cow::Borrowed(s),
            Key::Owned(s) => Cow::Borrowed(s.as_str()),
            Key::Property(word) => word.to_cow(),
        }
    }

    pub fn into_string(self) -> String {
        match self {
            Key::Borrowed(s) => s.to_owned(),
            Key::Owned(s) => s,
            Key::Property(word) => word.to_cow().into_owned(),
        }
    }

    pub fn try_into_property(self) -> Option<P> {
        match self {
            Key::Property(word) => Some(word),
            _ => None,
        }
    }

    pub fn into_owned(self) -> Key<'static, P> {
        match self {
            Key::Borrowed(s) => Key::Owned(s.to_owned()),
            Key::Owned(s) => Key::Owned(s),
            Key::Property(word) => Key::Property(word),
        }
    }

    pub fn to_owned(&self) -> Key<'static, P> {
        match self {
            Key::Borrowed(s) => Key::Owned(s.to_string()),
            Key::Owned(s) => Key::Owned(s.clone()),
            Key::Property(word) => Key::Property(word.clone()),
        }
    }

    pub fn as_property(&self) -> Option<&P> {
        match self {
            Key::Property(word) => Some(word),
            _ => None,
        }
    }

    pub fn as_string_key(&self) -> Option<&str> {
        match self {
            Key::Borrowed(s) => Some(s),
            Key::Owned(s) => Some(s.as_str()),
            Key::Property(_) => None,
        }
    }
}

impl<'x, P: Property> From<P> for Key<'x, P> {
    fn from(word: P) -> Self {
        Key::Property(word)
    }
}

