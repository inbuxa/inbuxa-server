/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:MailRule/get` and `/set` under `urn:inbuxa:jmap`: mail flow rules
//! and DLP rules (dlp-and-mail-flow-rules spec, §2.2). `kind` says which,
//! and which permissions reach it. The set call's `reason` argument, if
//! given, goes into the audit log with the change.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct MailRule;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailRuleProperty {
    Id,
    Name,
    Description,
    /// `dlp` or `transport`.
    Kind,
    Enabled,
    /// Lower runs first.
    Priority,
    /// `outgoing`, `incoming` or `any`.
    Direction,
    Conditions,
    Exceptions,
    Actions,
    StopProcessing,
    CreatedBy,
    CreatedAt,
    UpdatedAt,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailRuleValue {
    Id(Id),
}

impl Property for MailRuleProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside conditions and actions stay plain keys
        match parent {
            None => MailRuleProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            MailRuleProperty::Id => "id",
            MailRuleProperty::Name => "name",
            MailRuleProperty::Description => "description",
            MailRuleProperty::Kind => "kind",
            MailRuleProperty::Enabled => "enabled",
            MailRuleProperty::Priority => "priority",
            MailRuleProperty::Direction => "direction",
            MailRuleProperty::Conditions => "conditions",
            MailRuleProperty::Exceptions => "exceptions",
            MailRuleProperty::Actions => "actions",
            MailRuleProperty::StopProcessing => "stopProcessing",
            MailRuleProperty::CreatedBy => "createdBy",
            MailRuleProperty::CreatedAt => "createdAt",
            MailRuleProperty::UpdatedAt => "updatedAt",
        }
        .into()
    }
}

impl MailRuleProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => MailRuleProperty::Id,
            b"name" => MailRuleProperty::Name,
            b"description" => MailRuleProperty::Description,
            b"kind" => MailRuleProperty::Kind,
            b"enabled" => MailRuleProperty::Enabled,
            b"priority" => MailRuleProperty::Priority,
            b"direction" => MailRuleProperty::Direction,
            b"conditions" => MailRuleProperty::Conditions,
            b"exceptions" => MailRuleProperty::Exceptions,
            b"actions" => MailRuleProperty::Actions,
            b"stopProcessing" => MailRuleProperty::StopProcessing,
            b"createdBy" => MailRuleProperty::CreatedBy,
            b"createdAt" => MailRuleProperty::CreatedAt,
            b"updatedAt" => MailRuleProperty::UpdatedAt,
        )
    }
}

impl FromStr for MailRuleProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MailRuleProperty::parse(s).ok_or(())
    }
}

impl Element for MailRuleValue {
    type Property = MailRuleProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(MailRuleProperty::Id) => Id::from_str(value).ok().map(MailRuleValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            MailRuleValue::Id(id) => id.to_string().into(),
        }
    }
}

/// The set call's own argument: why, for the audit log.
#[derive(Debug, Clone, Default)]
pub struct MailRuleSetArguments {
    pub reason: Option<String>,
}

impl<'de> DeserializeArguments<'de> for MailRuleSetArguments {
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

impl JmapObject for MailRule {
    type Property = MailRuleProperty;

    type Element = MailRuleValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = MailRuleSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = MailRuleProperty::Id;
}

impl From<Id> for MailRuleValue {
    fn from(id: Id) -> Self {
        MailRuleValue::Id(id)
    }
}

impl JmapObjectId for MailRuleValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            MailRuleValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            MailRuleValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = MailRuleValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for MailRuleProperty {
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
