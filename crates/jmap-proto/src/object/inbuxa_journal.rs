/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Journal/get` and `/set` under `urn:inbuxa:jmap`: journals
//! (journaling spec, JR-9, JR-12). What a journal has taken stays when the
//! journal changes or goes; each entry keeps its own retention.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct Journal;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JournalProperty {
    Id,
    Name,
    Description,
    Enabled,
    /// `outgoing`, `incoming`, `internal` or `any`.
    Direction,
    /// Everyone, or chosen accounts, groups, domains and tenants.
    Scope,
    /// How long an entry is kept; each keeps what it was written with.
    RetentionDays,
    /// Whether entries go into the built-in journal.
    BuiltIn,
    /// An outside archive's journal address.
    ArchiveAddress,
    /// Reports the archive didn't take: how many, when and why last.
    ArchiveFailures,
    CreatedBy,
    CreatedAt,
    UpdatedAt,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JournalValue {
    Id(Id),
}

impl Property for JournalProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside the scope stay plain keys
        match parent {
            None => JournalProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            JournalProperty::Id => "id",
            JournalProperty::Name => "name",
            JournalProperty::Description => "description",
            JournalProperty::Enabled => "enabled",
            JournalProperty::Direction => "direction",
            JournalProperty::Scope => "scope",
            JournalProperty::RetentionDays => "retentionDays",
            JournalProperty::BuiltIn => "builtIn",
            JournalProperty::ArchiveAddress => "archiveAddress",
            JournalProperty::ArchiveFailures => "archiveFailures",
            JournalProperty::CreatedBy => "createdBy",
            JournalProperty::CreatedAt => "createdAt",
            JournalProperty::UpdatedAt => "updatedAt",
        }
        .into()
    }
}

impl JournalProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => JournalProperty::Id,
            b"name" => JournalProperty::Name,
            b"description" => JournalProperty::Description,
            b"enabled" => JournalProperty::Enabled,
            b"direction" => JournalProperty::Direction,
            b"scope" => JournalProperty::Scope,
            b"retentionDays" => JournalProperty::RetentionDays,
            b"builtIn" => JournalProperty::BuiltIn,
            b"archiveAddress" => JournalProperty::ArchiveAddress,
            b"archiveFailures" => JournalProperty::ArchiveFailures,
            b"createdBy" => JournalProperty::CreatedBy,
            b"createdAt" => JournalProperty::CreatedAt,
            b"updatedAt" => JournalProperty::UpdatedAt,
        )
    }
}

impl FromStr for JournalProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        JournalProperty::parse(s).ok_or(())
    }
}

impl Element for JournalValue {
    type Property = JournalProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(JournalProperty::Id) => Id::from_str(value).ok().map(JournalValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            JournalValue::Id(id) => id.to_string().into(),
        }
    }
}

/// The set call's own argument: why, for the audit log.
#[derive(Debug, Clone, Default)]
pub struct JournalSetArguments {
    pub reason: Option<String>,
}

impl<'de> DeserializeArguments<'de> for JournalSetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "reason" {
            self.reason = map.next_value()?;
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

impl JmapObject for Journal {
    type Property = JournalProperty;

    type Element = JournalValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = JournalSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = JournalProperty::Id;
}

impl From<Id> for JournalValue {
    fn from(id: Id) -> Self {
        JournalValue::Id(id)
    }
}

impl JmapObjectId for JournalValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            JournalValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            JournalValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = JournalValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for JournalProperty {
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
