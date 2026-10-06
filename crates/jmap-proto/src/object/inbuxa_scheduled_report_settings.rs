/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:ScheduledReportSettings/get` and `/set` under `urn:inbuxa:jmap`:
//! who scheduled reports come from (scheduled-reports spec, RP-20).

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct ScheduledReportSettings;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScheduledReportSettingsProperty {
    Id,
    FromName,
    FromAddress,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScheduledReportSettingsValue {
    Id(Id),
}

impl Property for ScheduledReportSettingsProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside objects (the schedule, a run) stay plain keys
        match parent {
            None => ScheduledReportSettingsProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ScheduledReportSettingsProperty::Id => "id",
            ScheduledReportSettingsProperty::FromName => "fromName",
            ScheduledReportSettingsProperty::FromAddress => "fromAddress",
        }
        .into()
    }
}

impl ScheduledReportSettingsProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => ScheduledReportSettingsProperty::Id,
            b"fromName" => ScheduledReportSettingsProperty::FromName,
            b"fromAddress" => ScheduledReportSettingsProperty::FromAddress,
        )
    }
}

impl FromStr for ScheduledReportSettingsProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ScheduledReportSettingsProperty::parse(s).ok_or(())
    }
}

impl Element for ScheduledReportSettingsValue {
    type Property = ScheduledReportSettingsProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(ScheduledReportSettingsProperty::Id) => Id::from_str(value)
                .ok()
                .map(ScheduledReportSettingsValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ScheduledReportSettingsValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for ScheduledReportSettings {
    type Property = ScheduledReportSettingsProperty;

    type Element = ScheduledReportSettingsValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = ScheduledReportSettingsProperty::Id;
}

impl From<Id> for ScheduledReportSettingsValue {
    fn from(id: Id) -> Self {
        ScheduledReportSettingsValue::Id(id)
    }
}

impl JmapObjectId for ScheduledReportSettingsValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            ScheduledReportSettingsValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            ScheduledReportSettingsValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = ScheduledReportSettingsValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for ScheduledReportSettingsProperty {
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
