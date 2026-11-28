/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:CountSettings/get` and `/set` under `urn:inbuxa:jmap`: the
//! opt-in count (count spec). A singleton, id `singleton`.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct CountSettings;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CountSettingsProperty {
    Id,
    Enabled,
    Decided,
    Endpoint,
    InstallId,
    LastCheckIn,
    Preview,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CountSettingsValue {
    Id(Id),
}

impl Property for CountSettingsProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        CountSettingsProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            CountSettingsProperty::Id => "id",
            CountSettingsProperty::Enabled => "enabled",
            CountSettingsProperty::Decided => "decided",
            CountSettingsProperty::Endpoint => "endpoint",
            CountSettingsProperty::InstallId => "installId",
            CountSettingsProperty::LastCheckIn => "lastCheckIn",
            CountSettingsProperty::Preview => "preview",
        }
        .into()
    }
}

impl CountSettingsProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => CountSettingsProperty::Id,
            b"enabled" => CountSettingsProperty::Enabled,
            b"decided" => CountSettingsProperty::Decided,
            b"endpoint" => CountSettingsProperty::Endpoint,
            b"installId" => CountSettingsProperty::InstallId,
            b"lastCheckIn" => CountSettingsProperty::LastCheckIn,
            b"preview" => CountSettingsProperty::Preview,
        )
    }
}

impl CountSettingsProperty {
    /// CNT-3, CNT-5: the server's to say; `/set` refuses them.
    pub fn is_server_set(&self) -> bool {
        matches!(
            self,
            CountSettingsProperty::InstallId
                | CountSettingsProperty::LastCheckIn
                | CountSettingsProperty::Preview
        )
    }
}

impl FromStr for CountSettingsProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CountSettingsProperty::parse(s).ok_or(())
    }
}

impl Element for CountSettingsValue {
    type Property = CountSettingsProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(CountSettingsProperty::Id) => {
                Id::from_str(value).ok().map(CountSettingsValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            CountSettingsValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for CountSettings {
    type Property = CountSettingsProperty;

    type Element = CountSettingsValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = CountSettingsProperty::Id;
}

impl From<Id> for CountSettingsValue {
    fn from(id: Id) -> Self {
        CountSettingsValue::Id(id)
    }
}

impl JmapObjectId for CountSettingsValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            CountSettingsValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            CountSettingsValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = CountSettingsValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for CountSettingsProperty {
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
