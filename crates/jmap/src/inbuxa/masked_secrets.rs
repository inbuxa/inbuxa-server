/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A stored secret reads back as `****` (`MASKED_PASSWORD`), so a client
//! that writes back what it read sends `****` where the secret was. That is
//! never saved as the secret. Written straight at a secret, it means "keep
//! the stored one"; anywhere else (a create, a variant switch, a whole
//! object replaced) the write is refused, since there is no stored secret
//! it could stand for.
//!
//! Accounts are left to their own credential checks, which already keep a
//! credential written back as `****`.

use jmap_proto::error::set::SetError;
use jmap_tools::{JsonPointer, JsonPointerItem, Key};
use registry::{
    jmap::JmapValue,
    schema::prelude::{MASKED_PASSWORD, Property},
};

fn is_secret_key(key: &Key<'_, Property>) -> bool {
    match key {
        Key::Property(property) => *property == Property::Secret,
        Key::Borrowed(name) => *name == "secret",
        Key::Owned(name) => name == "secret",
    }
}

fn is_masked(value: &JmapValue<'_>) -> bool {
    value.as_str().is_some_and(|value| value == MASKED_PASSWORD)
}

/// Whether `value` holds `****` as a secret anywhere inside it.
pub fn holds_masked_secret(value: &JmapValue<'_>) -> bool {
    match value {
        JmapValue::Object(map) => map.iter().any(|(key, value)| {
            (is_secret_key(key) && is_masked(value)) || holds_masked_secret(value)
        }),
        JmapValue::Array(items) => items.iter().any(holds_masked_secret),
        _ => false,
    }
}

/// Whether a patch at `pointer` writes `****` straight at a secret: the
/// client sent back what it read, so the stored secret stays.
pub fn keeps_stored_secret(pointer: &JsonPointer<Property>, value: &JmapValue<'_>) -> bool {
    is_masked(value)
        && matches!(pointer.last(), Some(JsonPointerItem::Key(key)) if is_secret_key(key))
}

/// The top-level property a write at `pointer` goes to, for the error.
pub fn top_level_property(pointer: &JsonPointer<Property>) -> Option<Property> {
    pointer.iter().find_map(|item| match item {
        JsonPointerItem::Key(Key::Property(property)) => Some(property.clone()),
        _ => None,
    })
}

/// For a whole-object write (a create or a variant switch): the first
/// top-level property holding `****` as a secret, if any.
pub fn masked_secret_in_object(value: &JmapValue<'_>) -> Option<Option<Property>> {
    let map = value.as_object()?;
    map.iter().find_map(|(key, value)| {
        ((is_secret_key(key) && is_masked(value)) || holds_masked_secret(value)).then(
            || match key {
                Key::Property(property) => Some(property.clone()),
                _ => None,
            },
        )
    })
}

pub fn masked_secret_error(property: Option<Property>) -> SetError<Property> {
    let error = SetError::invalid_properties().with_description(concat!(
        "\"****\" stands for a stored secret and can't be saved as one. ",
        "Send the secret itself, or leave the field out to keep the stored one."
    ));
    match property {
        Some(property) => error.with_property(property),
        None => error,
    }
}
