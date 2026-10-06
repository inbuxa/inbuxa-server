/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:LegalHold/get` and `/set` under `urn:inbuxa:jmap`: legal holds
//! (audit-hold-lock spec, LH-1 to LH-14). Creating one places the hold;
//! updating renames it, widens its range or scope, or releases it with
//! `released: true`. There is no destroy: a released hold stays listed. The
//! set call's `reason` argument says why, for the audit log (AU-12);
//! creating takes it as a property too.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct LegalHold;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegalHoldProperty {
    Id,
    /// The case name.
    Name,
    /// A matter or ticket number.
    Reference,
    Description,
    /// `{server, accounts, groups, domains, tenants}`.
    Scope,
    /// The range's start, a UTC date, or null.
    From,
    /// The range's end, a UTC date, or null.
    To,
    /// Why it was placed (create only; later reasons are the audit log's).
    Reason,
    PlacedAt,
    PlacedBy,
    /// Set to true to release it.
    Released,
    ReleasedAt,
    ReleasedBy,
    ReleaseReason,
    /// LH-9: accounts it covers now, deleted ones it keeps included.
    AccountsCovered,
    /// LH-9: archived items it keeps, and their size in bytes.
    ItemsHeld,
    SizeHeld,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegalHoldValue {
    Id(Id),
}

impl Property for LegalHoldProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside the scope stay plain keys
        match parent {
            None => LegalHoldProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            LegalHoldProperty::Id => "id",
            LegalHoldProperty::Name => "name",
            LegalHoldProperty::Reference => "reference",
            LegalHoldProperty::Description => "description",
            LegalHoldProperty::Scope => "scope",
            LegalHoldProperty::From => "from",
            LegalHoldProperty::To => "to",
            LegalHoldProperty::Reason => "reason",
            LegalHoldProperty::PlacedAt => "placedAt",
            LegalHoldProperty::PlacedBy => "placedBy",
            LegalHoldProperty::Released => "released",
            LegalHoldProperty::ReleasedAt => "releasedAt",
            LegalHoldProperty::ReleasedBy => "releasedBy",
            LegalHoldProperty::ReleaseReason => "releaseReason",
            LegalHoldProperty::AccountsCovered => "accountsCovered",
            LegalHoldProperty::ItemsHeld => "itemsHeld",
            LegalHoldProperty::SizeHeld => "sizeHeld",
        }
        .into()
    }
}

impl LegalHoldProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => LegalHoldProperty::Id,
            b"name" => LegalHoldProperty::Name,
            b"reference" => LegalHoldProperty::Reference,
            b"description" => LegalHoldProperty::Description,
            b"scope" => LegalHoldProperty::Scope,
            b"from" => LegalHoldProperty::From,
            b"to" => LegalHoldProperty::To,
            b"reason" => LegalHoldProperty::Reason,
            b"placedAt" => LegalHoldProperty::PlacedAt,
            b"placedBy" => LegalHoldProperty::PlacedBy,
            b"released" => LegalHoldProperty::Released,
            b"releasedAt" => LegalHoldProperty::ReleasedAt,
            b"releasedBy" => LegalHoldProperty::ReleasedBy,
            b"releaseReason" => LegalHoldProperty::ReleaseReason,
            b"accountsCovered" => LegalHoldProperty::AccountsCovered,
            b"itemsHeld" => LegalHoldProperty::ItemsHeld,
            b"sizeHeld" => LegalHoldProperty::SizeHeld,
        )
    }
}

impl FromStr for LegalHoldProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        LegalHoldProperty::parse(s).ok_or(())
    }
}

impl Element for LegalHoldValue {
    type Property = LegalHoldProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(LegalHoldProperty::Id) => Id::from_str(value).ok().map(LegalHoldValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            LegalHoldValue::Id(id) => id.to_string().into(),
        }
    }
}

/// The get call's own argument: only the active holds covering an account,
/// through any route (LH-2), for the console's Held badge (LH-14).
#[derive(Debug, Clone, Default)]
pub struct LegalHoldGetArguments {
    pub covering_account: Option<Id>,
}

impl<'de> DeserializeArguments<'de> for LegalHoldGetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "coveringAccount" {
            self.covering_account = map.next_value()?;
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

/// The set call's own arguments: why (AU-12).
#[derive(Debug, Clone, Default)]
pub struct LegalHoldSetArguments {
    pub reason: Option<String>,
}

impl<'de> DeserializeArguments<'de> for LegalHoldSetArguments {
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

impl JmapObject for LegalHold {
    type Property = LegalHoldProperty;

    type Element = LegalHoldValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = LegalHoldGetArguments;

    type SetArguments<'de> = LegalHoldSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = LegalHoldProperty::Id;
}

impl From<Id> for LegalHoldValue {
    fn from(id: Id) -> Self {
        LegalHoldValue::Id(id)
    }
}

impl JmapObjectId for LegalHoldValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            LegalHoldValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            LegalHoldValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = LegalHoldValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for LegalHoldProperty {
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
