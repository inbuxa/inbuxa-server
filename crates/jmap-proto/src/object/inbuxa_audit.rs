/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The audit log's JMAP objects under `urn:inbuxa:jmap`
//! (`inbuxa-drafts/specs/audit-hold-lock.md`, AU-9 to AU-11):
//!
//! - `inbuxa:AuditEvent/get` and `/query`: the records, read-only.
//! - `inbuxa:AuditSettings/get` and `/set`: how long records are kept.
//! - `inbuxa:AuditExport/set`: create one to get a file of the records a
//!   filter matches.
//! - `inbuxa:AuditVerification/set`: create one to recheck every chain.
//!
//! They share one set of properties. Nested values (an event's actor, its
//! target and changes, an export's filter) are plain JSON objects.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct AuditEvent;

#[derive(Debug, Clone, Default)]
pub struct AuditSettings;

#[derive(Debug, Clone, Default)]
pub struct AuditExport;

#[derive(Debug, Clone, Default)]
pub struct AuditVerification;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditProperty {
    Id,
    // AuditEvent
    At,
    Node,
    Actor,
    Via,
    RemoteIp,
    Action,
    Target,
    Changes,
    Details,
    Reason,
    Outcome,
    // AuditSettings
    KeepForDays,
    // AuditExport
    Format,
    Filter,
    BlobId,
    Count,
    Size,
    Sha256,
    // AuditVerification
    Verified,
    Chains,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditValue {
    Id(Id),
}

impl Property for AuditProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Only the objects' own properties: keys inside a filter, an actor
        // or a target stay plain keys
        match parent {
            None => AuditProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            AuditProperty::Id => "id",
            AuditProperty::At => "at",
            AuditProperty::Node => "node",
            AuditProperty::Actor => "actor",
            AuditProperty::Via => "via",
            AuditProperty::RemoteIp => "remoteIp",
            AuditProperty::Action => "action",
            AuditProperty::Target => "target",
            AuditProperty::Changes => "changes",
            AuditProperty::Details => "details",
            AuditProperty::Reason => "reason",
            AuditProperty::Outcome => "outcome",
            AuditProperty::KeepForDays => "keepForDays",
            AuditProperty::Format => "format",
            AuditProperty::Filter => "filter",
            AuditProperty::BlobId => "blobId",
            AuditProperty::Count => "count",
            AuditProperty::Size => "size",
            AuditProperty::Sha256 => "sha256",
            AuditProperty::Verified => "verified",
            AuditProperty::Chains => "chains",
        }
        .into()
    }
}

impl AuditProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => AuditProperty::Id,
            b"at" => AuditProperty::At,
            b"node" => AuditProperty::Node,
            b"actor" => AuditProperty::Actor,
            b"via" => AuditProperty::Via,
            b"remoteIp" => AuditProperty::RemoteIp,
            b"action" => AuditProperty::Action,
            b"target" => AuditProperty::Target,
            b"changes" => AuditProperty::Changes,
            b"details" => AuditProperty::Details,
            b"reason" => AuditProperty::Reason,
            b"outcome" => AuditProperty::Outcome,
            b"keepForDays" => AuditProperty::KeepForDays,
            b"format" => AuditProperty::Format,
            b"filter" => AuditProperty::Filter,
            b"blobId" => AuditProperty::BlobId,
            b"count" => AuditProperty::Count,
            b"size" => AuditProperty::Size,
            b"sha256" => AuditProperty::Sha256,
            b"verified" => AuditProperty::Verified,
            b"chains" => AuditProperty::Chains,
        )
    }
}

impl FromStr for AuditProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AuditProperty::parse(s).ok_or(())
    }
}

impl Element for AuditValue {
    type Property = AuditProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(AuditProperty::Id) => Id::from_str(value).ok().map(AuditValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            AuditValue::Id(id) => id.to_string().into(),
        }
    }
}

/// One condition of an `inbuxa:AuditEvent/query` filter. Several in one
/// filter object must all hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditFilter {
    /// From this time on (UTC date).
    After(String),
    /// Before this time (UTC date).
    Before(String),
    ActorId(Id),
    Action(String),
    TargetKind(String),
    TargetId(String),
    AccountId(Id),
    TenantId(Id),
    Outcome(String),
    RemoteIp(String),
    Text(String),
    _T(String),
}

impl Default for AuditFilter {
    fn default() -> Self {
        AuditFilter::_T(String::new())
    }
}

impl<'de> DeserializeArguments<'de> for AuditFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"after" => {
                *self = AuditFilter::After(map.next_value()?);
            },
            b"before" => {
                *self = AuditFilter::Before(map.next_value()?);
            },
            b"actorId" => {
                *self = AuditFilter::ActorId(map.next_value()?);
            },
            b"action" => {
                *self = AuditFilter::Action(map.next_value()?);
            },
            b"targetKind" => {
                *self = AuditFilter::TargetKind(map.next_value()?);
            },
            b"targetId" => {
                *self = AuditFilter::TargetId(map.next_value()?);
            },
            b"accountId" => {
                *self = AuditFilter::AccountId(map.next_value()?);
            },
            b"tenantId" => {
                *self = AuditFilter::TenantId(map.next_value()?);
            },
            b"outcome" => {
                *self = AuditFilter::Outcome(map.next_value()?);
            },
            b"remoteIp" => {
                *self = AuditFilter::RemoteIp(map.next_value()?);
            },
            b"text" => {
                *self = AuditFilter::Text(map.next_value()?);
            },
            _ => {
                *self = AuditFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

/// Events sort newest first, by `at`; nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditComparator {
    At,
    _T(String),
}

impl Default for AuditComparator {
    fn default() -> Self {
        AuditComparator::_T(String::new())
    }
}

impl<'de> DeserializeArguments<'de> for AuditComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            *self = if value == "at" {
                AuditComparator::At
            } else {
                AuditComparator::_T(value.into_owned())
            };
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

macro_rules! audit_object {
    ($object:ty, $filter:ty, $comparator:ty) => {
        impl JmapObject for $object {
            type Property = AuditProperty;

            type Element = AuditValue;

            type Id = Id;

            type Filter = $filter;

            type Comparator = $comparator;

            type GetArguments = ();

            type SetArguments<'de> = ();

            type QueryArguments = ();

            type CopyArguments = ();

            type ParseArguments = ();

            const ID_PROPERTY: Self::Property = AuditProperty::Id;
        }
    };
}

audit_object!(AuditEvent, AuditFilter, AuditComparator);
audit_object!(AuditSettings, (), ());
audit_object!(AuditExport, (), ());
audit_object!(AuditVerification, (), ());

impl From<Id> for AuditValue {
    fn from(id: Id) -> Self {
        AuditValue::Id(id)
    }
}

impl JmapObjectId for AuditValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            AuditValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            AuditValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = AuditValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for AuditProperty {
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
