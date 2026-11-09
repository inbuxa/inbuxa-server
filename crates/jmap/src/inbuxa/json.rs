/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// The 27.1 series keeps this in its relay module, which this series lacks;
// the store check, store snapshot and blob store change handlers share it.

use jmap_tools::{Key, Map, Property, Value};
use std::borrow::Cow;

/// A JSON value as a JMAP one, its object keys kept as plain keys.
pub(super) fn json_to_value<P, E>(json: serde_json::Value) -> Value<'static, P, E>
where
    P: Property,
    E: jmap_tools::Element<Property = P>,
{
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(n) = n.as_u64() {
                Value::Number(n.into())
            } else if let Some(n) = n.as_i64() {
                Value::Number(n.into())
            } else {
                Value::Number(n.as_f64().unwrap_or_default().into())
            }
        }
        serde_json::Value::String(s) => Value::Str(Cow::Owned(s)),
        serde_json::Value::Array(items) => {
            Value::Array(items.into_iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, value) in map {
                out.insert_unchecked(Key::Owned(key), json_to_value(value));
            }
            Value::Object(out)
        }
    }
}
