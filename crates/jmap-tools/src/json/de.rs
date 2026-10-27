/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::value::Value;
use crate::json::key::{self, Key, OpaqueKey};
use crate::json::object_vec::ObjectAsVec;
use crate::{Element, Property};
use serde::de::{Deserialize, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::borrow::Cow;
use std::marker::PhantomData;
use std::mem;

type Member<'de, P, E> = (Key<'de, P>, Value<'de, P, E>);

struct Scratch<'de, P: Property, E: Element> {
    members: Vec<Member<'de, P, E>>,
    items: Vec<Value<'de, P, E>>,
    opaque: bool,
}

impl<P: Property, E: Element> Scratch<'_, P, E> {
    fn new() -> Self {
        Scratch {
            members: Vec::new(),
            items: Vec::new(),
            opaque: false,
        }
    }
}

impl<'de, P: Property, E: Element<Property = P>> Scratch<'de, P, E> {
    #[cold]
    #[inline(never)]
    fn opaque_seq<V>(&mut self, mut visitor: V) -> Result<Value<'de, P, E>, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let outer = mem::replace(&mut self.opaque, true);
        let start = self.items.len();

        while let Some(item) = visitor.next_element_seed(ValueSeed {
            parent_key: None,
            scratch: &mut *self,
        })? {
            self.items.push(item);
        }

        self.opaque = outer;
        Ok(Value::Array(self.items.split_off(start)))
    }

    #[cold]
    #[inline(never)]
    fn opaque_map<V>(&mut self, mut visitor: V) -> Result<Value<'de, P, E>, V::Error>
    where
        V: MapAccess<'de>,
    {
        let outer = mem::replace(&mut self.opaque, true);
        let start = self.members.len();

        while let Some(key) = visitor.next_key_seed(OpaqueKey(PhantomData))? {
            let value = visitor.next_value_seed(ValueSeed {
                parent_key: None,
                scratch: &mut *self,
            })?;

            self.members.push((key, value));
        }

        self.opaque = outer;
        Ok(Value::Object(ObjectAsVec(self.members.split_off(start))))
    }
}

struct ValueSeed<'s, 'k, 'de, P: Property, E: Element> {
    parent_key: Option<&'k Key<'k, P>>,
    scratch: &'s mut Scratch<'de, P, E>,
}

impl<'de, P: Property, E: Element<Property = P>> Deserialize<'de> for Value<'de, P, E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ValueSeed {
            parent_key: None,
            scratch: &mut Scratch::new(),
        }
        .deserialize(deserializer)
    }
}

impl<'de, P: Property, E: Element<Property = P>> DeserializeSeed<'de>
    for ValueSeed<'_, '_, 'de, P, E>
{
    type Value = Value<'de, P, E>;

    #[inline]
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de, P: Property, E: Element<Property = P>> ValueSeed<'_, '_, 'de, P, E> {
    #[inline]
    fn string(&self, text: &str) -> Option<E> {
        self.parent_key
            .filter(|key| !key.is_opaque())
            .and_then(|key| E::try_parse::<P>(key, text))
    }
}

impl<'de, P: Property, E: Element<Property = P>> Visitor<'de> for ValueSeed<'_, '_, 'de, P, E> {
    type Value = Value<'de, P, E>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    #[inline]
    fn visit_bool<ERR>(self, value: bool) -> Result<Value<'de, P, E>, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Bool(value))
    }

    #[inline]
    fn visit_i64<ERR>(self, value: i64) -> Result<Value<'de, P, E>, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    #[inline]
    fn visit_u64<ERR>(self, value: u64) -> Result<Value<'de, P, E>, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    #[inline]
    fn visit_f64<ERR>(self, value: f64) -> Result<Value<'de, P, E>, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Number(value.into()))
    }

    #[inline]
    fn visit_string<ERR>(self, v: String) -> Result<Self::Value, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(match self.string(&v) {
            Some(element) => Value::Element(element),
            None => Value::Str(Cow::Owned(v)),
        })
    }

    #[inline]
    fn visit_str<ERR>(self, v: &str) -> Result<Self::Value, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(match self.string(v) {
            Some(element) => Value::Element(element),
            None => Value::Str(Cow::Owned(v.to_owned())),
        })
    }

    #[inline]
    fn visit_borrowed_str<ERR>(self, v: &'de str) -> Result<Self::Value, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(match self.string(v) {
            Some(element) => Value::Element(element),
            None => Value::Str(Cow::Borrowed(v)),
        })
    }

    #[inline]
    fn visit_none<ERR>(self) -> Result<Value<'de, P, E>, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Null)
    }

    #[inline]
    fn visit_i8<ERR>(self, v: i8) -> Result<Self::Value, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Number((v as i64).into()))
    }

    #[inline]
    fn visit_i16<ERR>(self, v: i16) -> Result<Self::Value, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Number((v as i64).into()))
    }

    #[inline]
    fn visit_i32<ERR>(self, v: i32) -> Result<Self::Value, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Number((v as i64).into()))
    }

    #[inline]
    fn visit_u8<ERR>(self, v: u8) -> Result<Self::Value, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Number((v as u64).into()))
    }

    #[inline]
    fn visit_u16<ERR>(self, v: u16) -> Result<Self::Value, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Number((v as u64).into()))
    }

    #[inline]
    fn visit_u32<ERR>(self, v: u32) -> Result<Self::Value, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Number((v as u64).into()))
    }

    #[inline]
    fn visit_f32<ERR>(self, v: f32) -> Result<Self::Value, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Number((v as f64).into()))
    }

    #[inline]
    fn visit_some<D>(self, deserializer: D) -> Result<Value<'de, P, E>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.deserialize(deserializer)
    }

    #[inline]
    fn visit_unit<ERR>(self) -> Result<Value<'de, P, E>, ERR>
    where
        ERR: serde::de::Error,
    {
        Ok(Value::Null)
    }

    #[inline]
    fn visit_seq<V>(self, mut visitor: V) -> Result<Value<'de, P, E>, V::Error>
    where
        V: SeqAccess<'de>,
    {
        if self.parent_key.is_some_and(Key::is_opaque) {
            return self.scratch.opaque_seq(visitor);
        }

        let start = self.scratch.items.len();

        while let Some(elem) = visitor.next_element_seed(ValueSeed {
            parent_key: self.parent_key,
            scratch: &mut *self.scratch,
        })? {
            self.scratch.items.push(elem);
        }

        Ok(Value::Array(self.scratch.items.split_off(start)))
    }

    #[inline]
    fn visit_map<V>(self, mut visitor: V) -> Result<Value<'de, P, E>, V::Error>
    where
        V: MapAccess<'de>,
    {
        if self.scratch.opaque || self.parent_key.is_some_and(Key::is_opaque) {
            return self.scratch.opaque_map(visitor);
        }

        let start = self.scratch.members.len();

        while let Some(key) = visitor.next_key_seed(key::DeserializationContext {
            parent_key: self.parent_key,
        })? {
            let value = visitor.next_value_seed(ValueSeed {
                parent_key: Some(&key),
                scratch: &mut *self.scratch,
            })?;

            self.scratch.members.push((key, value));
        }

        Ok(Value::Object(ObjectAsVec(
            self.scratch.members.split_off(start),
        )))
    }
}


