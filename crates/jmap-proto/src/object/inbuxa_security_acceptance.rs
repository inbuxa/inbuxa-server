/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:SecurityAcceptance/get` and `/set` under `urn:inbuxa:jmap`: the
//! security to-do items an administrator accepted, with why (security
//! to-do list spec, SS-23 to SS-26). Created and destroyed, never updated.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct SecurityAcceptance;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityAcceptanceProperty {
    Id,
    /// `SS-1` to `SS-18`.
    Check,
    Subject,
    AcceptedValue,
    Note,
    AcceptedBy,
    AcceptedAt,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityAcceptanceValue {
    Id(Id),
}

impl Property for SecurityAcceptanceProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside acceptedValue stay plain keys
        match parent {
            None => SecurityAcceptanceProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            SecurityAcceptanceProperty::Id => "id",
            SecurityAcceptanceProperty::Check => "check",
            SecurityAcceptanceProperty::Subject => "subject",
            SecurityAcceptanceProperty::AcceptedValue => "acceptedValue",
            SecurityAcceptanceProperty::Note => "note",
            SecurityAcceptanceProperty::AcceptedBy => "acceptedBy",
            SecurityAcceptanceProperty::AcceptedAt => "acceptedAt",
        }
        .into()
    }
}

impl SecurityAcceptanceProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => SecurityAcceptanceProperty::Id,
            b"check" => SecurityAcceptanceProperty::Check,
            b"subject" => SecurityAcceptanceProperty::Subject,
            b"acceptedValue" => SecurityAcceptanceProperty::AcceptedValue,
            b"note" => SecurityAcceptanceProperty::Note,
            b"acceptedBy" => SecurityAcceptanceProperty::AcceptedBy,
            b"acceptedAt" => SecurityAcceptanceProperty::AcceptedAt,
        )
    }
}

impl FromStr for SecurityAcceptanceProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SecurityAcceptanceProperty::parse(s).ok_or(())
    }
}

impl Element for SecurityAcceptanceValue {
    type Property = SecurityAcceptanceProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(SecurityAcceptanceProperty::Id) => {
                Id::from_str(value).ok().map(SecurityAcceptanceValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            SecurityAcceptanceValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for SecurityAcceptance {
    type Property = SecurityAcceptanceProperty;

    type Element = SecurityAcceptanceValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = SecurityAcceptanceProperty::Id;
}

impl From<Id> for SecurityAcceptanceValue {
    fn from(id: Id) -> Self {
        SecurityAcceptanceValue::Id(id)
    }
}

impl JmapObjectId for SecurityAcceptanceValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            SecurityAcceptanceValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            SecurityAcceptanceValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = SecurityAcceptanceValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for SecurityAcceptanceProperty {
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
