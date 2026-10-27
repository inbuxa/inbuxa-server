/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, JsonPointer, JsonPointerItem, Property, Value};
use std::{io::Write, iter::repeat_n};

pub(crate) mod ordered;
pub(crate) mod text;

const KEY_CAPACITY: usize = 16;

macro_rules! property_names {
    ($property:ident, $($name:literal => $variant:ident,)*) => {
        pub(crate) fn parse_name(s: &str) -> Option<Self> {
            hashify::fnc_map!(s.as_bytes(),
                $($name => Some($property::$variant),)*
                "metadata" => Some($property::Metadata),
                "privateMetadata" => Some($property::PrivateMetadata),
                _ => None,
            )
        }

        pub(crate) fn parse_nested_name(s: &str) -> Option<Self> {
            hashify::fnc_map!(s.as_bytes(),
                $($name => Some($property::$variant),)*
                _ => None,
            )
        }
    };
}

pub(crate) use property_names;

pub(crate) trait JSPropPointer<P: Property> {
    fn parse_jsprop_value<E: Element<Property = P>>(
        &self,
        json: &str,
    ) -> Option<Value<'static, P, E>>;
}

impl<P: Property> JSPropPointer<P> for JsonPointer<P> {
    fn parse_jsprop_value<E: Element<Property = P>>(
        &self,
        json: &str,
    ) -> Option<Value<'static, P, E>> {
        let items = self.as_slice();
        if items
            .iter()
            .any(|item| matches!(item, JsonPointerItem::Root | JsonPointerItem::Wildcard))
        {
            return Value::parse_json(json).ok().map(Value::into_owned);
        }

        let mut wrapped = Vec::with_capacity(json.len() + items.len() * KEY_CAPACITY);
        for item in items {
            wrapped.push(b'{');
            match item {
                JsonPointerItem::Key(key) => serde_json::to_writer(&mut wrapped, key).ok()?,
                JsonPointerItem::Number(number) => write!(wrapped, "\"{number}\"").ok()?,
                JsonPointerItem::Root | JsonPointerItem::Wildcard | JsonPointerItem::Invalid(_) => {
                    return None;
                }
            }
            wrapped.push(b':');
        }
        wrapped.extend_from_slice(json.as_bytes());
        wrapped.extend(repeat_n(b'}', items.len()));

        let mut value = Value::<P, E>::parse_json(std::str::from_utf8(&wrapped).ok()?).ok()?;
        for _ in items {
            let [(_, inner)] = <[_; 1]>::try_from(value.into_object()?.into_vec()).ok()?;
            value = inner;
        }
        Some(value.into_owned())
    }
}
