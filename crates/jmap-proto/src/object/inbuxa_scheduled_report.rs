/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:ScheduledReport/get` and `/set` under `urn:inbuxa:jmap`: reports
//! the server builds and mails on a schedule, the weekly digest among them
//! (scheduled-reports spec).

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct ScheduledReport;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScheduledReportProperty {
    Id,
    Name,
    Enabled,
    BuiltIn,
    Sections,
    Schedule,
    Recipients,
    AttachCsv,
    MemberTenantId,
    CreatedAt,
    NextRunAt,
    Runs,
    SendNow,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScheduledReportValue {
    Id(Id),
}

impl Property for ScheduledReportProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside objects (the schedule, a run) stay plain keys
        match parent {
            None => ScheduledReportProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ScheduledReportProperty::Id => "id",
            ScheduledReportProperty::Name => "name",
            ScheduledReportProperty::Enabled => "enabled",
            ScheduledReportProperty::BuiltIn => "builtIn",
            ScheduledReportProperty::Sections => "sections",
            ScheduledReportProperty::Schedule => "schedule",
            ScheduledReportProperty::Recipients => "recipients",
            ScheduledReportProperty::AttachCsv => "attachCsv",
            ScheduledReportProperty::MemberTenantId => "memberTenantId",
            ScheduledReportProperty::CreatedAt => "createdAt",
            ScheduledReportProperty::NextRunAt => "nextRunAt",
            ScheduledReportProperty::Runs => "runs",
            ScheduledReportProperty::SendNow => "sendNow",
        }
        .into()
    }
}

impl ScheduledReportProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::fnc_map!(value.as_bytes(),
            b"id" => Some(ScheduledReportProperty::Id),
            b"name" => Some(ScheduledReportProperty::Name),
            b"enabled" => Some(ScheduledReportProperty::Enabled),
            b"builtIn" => Some(ScheduledReportProperty::BuiltIn),
            b"sections" => Some(ScheduledReportProperty::Sections),
            b"schedule" => Some(ScheduledReportProperty::Schedule),
            b"recipients" => Some(ScheduledReportProperty::Recipients),
            b"attachCsv" => Some(ScheduledReportProperty::AttachCsv),
            b"memberTenantId" => Some(ScheduledReportProperty::MemberTenantId),
            b"createdAt" => Some(ScheduledReportProperty::CreatedAt),
            b"nextRunAt" => Some(ScheduledReportProperty::NextRunAt),
            b"runs" => Some(ScheduledReportProperty::Runs),
            b"sendNow" => Some(ScheduledReportProperty::SendNow),
            _ => None,
        )
    }
}

impl FromStr for ScheduledReportProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ScheduledReportProperty::parse(s).ok_or(())
    }
}

impl Element for ScheduledReportValue {
    type Property = ScheduledReportProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(ScheduledReportProperty::Id) => {
                Id::from_str(value).ok().map(ScheduledReportValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ScheduledReportValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for ScheduledReport {
    type Property = ScheduledReportProperty;

    type Element = ScheduledReportValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = ScheduledReportProperty::Id;
}

impl From<Id> for ScheduledReportValue {
    fn from(id: Id) -> Self {
        ScheduledReportValue::Id(id)
    }
}

impl JmapObjectId for ScheduledReportValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            ScheduledReportValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            ScheduledReportValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = ScheduledReportValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for ScheduledReportProperty {
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
