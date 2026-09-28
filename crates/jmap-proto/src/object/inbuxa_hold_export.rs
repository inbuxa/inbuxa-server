/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:HoldExport/get` and `/set` under `urn:inbuxa:jmap`: collecting
//! what a legal hold keeps as a ZIP (audit-hold-lock spec, LH-12). Creating
//! one starts it; it runs in the background, and `get` says when it's ready
//! and which blob to download. The set call's `reason` says why (AU-12).

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct HoldExport;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HoldExportProperty {
    Id,
    HoldId,
    AccountIds,
    Reason,
    Status,
    CreatedAt,
    CreatedBy,
    FinishedAt,
    BlobId,
    Size,
    Items,
    Sha256,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HoldExportValue {
    Id(Id),
}

impl Property for HoldExportProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        match parent {
            None => HoldExportProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            HoldExportProperty::Id => "id",
            HoldExportProperty::HoldId => "holdId",
            HoldExportProperty::AccountIds => "accountIds",
            HoldExportProperty::Reason => "reason",
            HoldExportProperty::Status => "status",
            HoldExportProperty::CreatedAt => "createdAt",
            HoldExportProperty::CreatedBy => "createdBy",
            HoldExportProperty::FinishedAt => "finishedAt",
            HoldExportProperty::BlobId => "blobId",
            HoldExportProperty::Size => "size",
            HoldExportProperty::Items => "items",
            HoldExportProperty::Sha256 => "sha256",
            HoldExportProperty::Error => "error",
        }
        .into()
    }
}

impl HoldExportProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => HoldExportProperty::Id,
            b"holdId" => HoldExportProperty::HoldId,
            b"accountIds" => HoldExportProperty::AccountIds,
            b"reason" => HoldExportProperty::Reason,
            b"status" => HoldExportProperty::Status,
            b"createdAt" => HoldExportProperty::CreatedAt,
            b"createdBy" => HoldExportProperty::CreatedBy,
            b"finishedAt" => HoldExportProperty::FinishedAt,
            b"blobId" => HoldExportProperty::BlobId,
            b"size" => HoldExportProperty::Size,
            b"items" => HoldExportProperty::Items,
            b"sha256" => HoldExportProperty::Sha256,
            b"error" => HoldExportProperty::Error,
        )
    }
}

impl FromStr for HoldExportProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HoldExportProperty::parse(s).ok_or(())
    }
}

impl Element for HoldExportValue {
    type Property = HoldExportProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(HoldExportProperty::Id) => Id::from_str(value).ok().map(HoldExportValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            HoldExportValue::Id(id) => id.to_string().into(),
        }
    }
}

/// The set call's own arguments: why (AU-12).
#[derive(Debug, Clone, Default)]
pub struct HoldExportSetArguments {
    pub reason: Option<String>,
}

impl<'de> DeserializeArguments<'de> for HoldExportSetArguments {
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

impl JmapObject for HoldExport {
    type Property = HoldExportProperty;

    type Element = HoldExportValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = HoldExportSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = HoldExportProperty::Id;
}

impl From<Id> for HoldExportValue {
    fn from(id: Id) -> Self {
        HoldExportValue::Id(id)
    }
}

impl JmapObjectId for HoldExportValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            HoldExportValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            HoldExportValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = HoldExportValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for HoldExportProperty {
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
