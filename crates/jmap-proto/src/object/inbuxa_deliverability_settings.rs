/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:DeliverabilitySettings/get` and `/set` under `urn:inbuxa:jmap`:
//! which of the built-in blocklists the deliverability check leaves out
//! (deliverability spec, DL-6), and, read only, what the lists are.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct DeliverabilitySettings;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeliverabilitySettingsProperty {
    Id,
    DisabledLists,
    Lists,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeliverabilitySettingsValue {
    Id(Id),
}

impl Property for DeliverabilitySettingsProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside the lists stay plain keys
        match parent {
            None => DeliverabilitySettingsProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            DeliverabilitySettingsProperty::Id => "id",
            DeliverabilitySettingsProperty::DisabledLists => "disabledLists",
            DeliverabilitySettingsProperty::Lists => "lists",
        }
        .into()
    }
}

impl DeliverabilitySettingsProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => DeliverabilitySettingsProperty::Id,
            b"disabledLists" => DeliverabilitySettingsProperty::DisabledLists,
            b"lists" => DeliverabilitySettingsProperty::Lists,
        )
    }
}

impl FromStr for DeliverabilitySettingsProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DeliverabilitySettingsProperty::parse(s).ok_or(())
    }
}

impl Element for DeliverabilitySettingsValue {
    type Property = DeliverabilitySettingsProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(DeliverabilitySettingsProperty::Id) => Id::from_str(value)
                .ok()
                .map(DeliverabilitySettingsValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            DeliverabilitySettingsValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for DeliverabilitySettings {
    type Property = DeliverabilitySettingsProperty;

    type Element = DeliverabilitySettingsValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = DeliverabilitySettingsProperty::Id;
}

impl From<Id> for DeliverabilitySettingsValue {
    fn from(id: Id) -> Self {
        DeliverabilitySettingsValue::Id(id)
    }
}

impl JmapObjectId for DeliverabilitySettingsValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            DeliverabilitySettingsValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            DeliverabilitySettingsValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = DeliverabilitySettingsValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for DeliverabilitySettingsProperty {
    fn as_id(&self) -> Option<Id> {
        None
    }

    fn as_any_id(&self) -> Option<AnyId> {
        None
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, _: AnyId) -> bool {
        false
    }
}
