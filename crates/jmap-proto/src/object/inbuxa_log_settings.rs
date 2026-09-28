/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:LogSettings/get` and `/set` under `urn:inbuxa:jmap`: how long
//! rotated log files are kept (personal-data catalog spec, D1). A singleton,
//! id `singleton`.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct LogSettings;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogSettingsProperty {
    Id,
    KeepForDays,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogSettingsValue {
    Id(Id),
}

impl Property for LogSettingsProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        LogSettingsProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            LogSettingsProperty::Id => "id",
            LogSettingsProperty::KeepForDays => "keepForDays",
        }
        .into()
    }
}

impl LogSettingsProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => LogSettingsProperty::Id,
            b"keepForDays" => LogSettingsProperty::KeepForDays,
        )
    }
}

impl FromStr for LogSettingsProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        LogSettingsProperty::parse(s).ok_or(())
    }
}

impl Element for LogSettingsValue {
    type Property = LogSettingsProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(LogSettingsProperty::Id) => {
                Id::from_str(value).ok().map(LogSettingsValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            LogSettingsValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for LogSettings {
    type Property = LogSettingsProperty;

    type Element = LogSettingsValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = LogSettingsProperty::Id;
}

impl From<Id> for LogSettingsValue {
    fn from(id: Id) -> Self {
        LogSettingsValue::Id(id)
    }
}

impl JmapObjectId for LogSettingsValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            LogSettingsValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            LogSettingsValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = LogSettingsValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for LogSettingsProperty {
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
