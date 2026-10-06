/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:DlpSettings/get` and `/set` under `urn:inbuxa:jmap`: the DLP
//! settings singleton (dlp-and-mail-flow-rules spec, §2.6): how many days
//! held mail waits for a reviewer before it goes back to the sender.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct DlpSettings;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DlpSettingsProperty {
    Id,
    KeepHeldDays,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DlpSettingsValue {
    Id(Id),
}

impl Property for DlpSettingsProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        DlpSettingsProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            DlpSettingsProperty::Id => "id",
            DlpSettingsProperty::KeepHeldDays => "keepHeldDays",
        }
        .into()
    }
}

impl DlpSettingsProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => DlpSettingsProperty::Id,
            b"keepHeldDays" => DlpSettingsProperty::KeepHeldDays,
        )
    }
}

impl FromStr for DlpSettingsProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DlpSettingsProperty::parse(s).ok_or(())
    }
}

impl Element for DlpSettingsValue {
    type Property = DlpSettingsProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(DlpSettingsProperty::Id) => {
                Id::from_str(value).ok().map(DlpSettingsValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            DlpSettingsValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for DlpSettings {
    type Property = DlpSettingsProperty;

    type Element = DlpSettingsValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = DlpSettingsProperty::Id;
}

impl From<Id> for DlpSettingsValue {
    fn from(id: Id) -> Self {
        DlpSettingsValue::Id(id)
    }
}

impl JmapObjectId for DlpSettingsValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            DlpSettingsValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            DlpSettingsValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = DlpSettingsValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for DlpSettingsProperty {
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
