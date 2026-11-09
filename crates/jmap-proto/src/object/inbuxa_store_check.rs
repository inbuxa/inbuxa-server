/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:StoreCheck/get` and `/set` under `urn:inbuxa:jmap`: checking that
//! the store has every blob its data needs (store-check spec, SV-1).
//! Creating one starts it; it runs in the background, and `get` says how
//! far it got and what it found. An update with `action: "stop"` stops it.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct StoreCheck;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StoreCheckProperty {
    Id,
    Mode,
    BlobsPerSecond,
    BytesPerSecond,
    Status,
    CreatedAt,
    CreatedBy,
    FinishedAt,
    Node,
    Progress,
    BlobsChecked,
    LinksChecked,
    BytesRead,
    MessagesChecked,
    Missing,
    Damaged,
    Unlinked,
    Unreadable,
    Problems,
    Error,
    Action,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StoreCheckValue {
    Id(Id),
}

impl Property for StoreCheckProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        match parent {
            None => StoreCheckProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            StoreCheckProperty::Id => "id",
            StoreCheckProperty::Mode => "mode",
            StoreCheckProperty::BlobsPerSecond => "blobsPerSecond",
            StoreCheckProperty::BytesPerSecond => "bytesPerSecond",
            StoreCheckProperty::Status => "status",
            StoreCheckProperty::CreatedAt => "createdAt",
            StoreCheckProperty::CreatedBy => "createdBy",
            StoreCheckProperty::FinishedAt => "finishedAt",
            StoreCheckProperty::Node => "node",
            StoreCheckProperty::Progress => "progress",
            StoreCheckProperty::BlobsChecked => "blobsChecked",
            StoreCheckProperty::LinksChecked => "linksChecked",
            StoreCheckProperty::BytesRead => "bytesRead",
            StoreCheckProperty::MessagesChecked => "messagesChecked",
            StoreCheckProperty::Missing => "missing",
            StoreCheckProperty::Damaged => "damaged",
            StoreCheckProperty::Unlinked => "unlinked",
            StoreCheckProperty::Unreadable => "unreadable",
            StoreCheckProperty::Problems => "problems",
            StoreCheckProperty::Error => "error",
            StoreCheckProperty::Action => "action",
        }
        .into()
    }
}

impl StoreCheckProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => StoreCheckProperty::Id,
            b"mode" => StoreCheckProperty::Mode,
            b"blobsPerSecond" => StoreCheckProperty::BlobsPerSecond,
            b"bytesPerSecond" => StoreCheckProperty::BytesPerSecond,
            b"status" => StoreCheckProperty::Status,
            b"createdAt" => StoreCheckProperty::CreatedAt,
            b"createdBy" => StoreCheckProperty::CreatedBy,
            b"finishedAt" => StoreCheckProperty::FinishedAt,
            b"node" => StoreCheckProperty::Node,
            b"progress" => StoreCheckProperty::Progress,
            b"blobsChecked" => StoreCheckProperty::BlobsChecked,
            b"linksChecked" => StoreCheckProperty::LinksChecked,
            b"bytesRead" => StoreCheckProperty::BytesRead,
            b"messagesChecked" => StoreCheckProperty::MessagesChecked,
            b"missing" => StoreCheckProperty::Missing,
            b"damaged" => StoreCheckProperty::Damaged,
            b"unlinked" => StoreCheckProperty::Unlinked,
            b"unreadable" => StoreCheckProperty::Unreadable,
            b"problems" => StoreCheckProperty::Problems,
            b"error" => StoreCheckProperty::Error,
            b"action" => StoreCheckProperty::Action,
        )
    }
}

impl FromStr for StoreCheckProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        StoreCheckProperty::parse(s).ok_or(())
    }
}

impl Element for StoreCheckValue {
    type Property = StoreCheckProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(StoreCheckProperty::Id) => {
                Id::from_str(value).ok().map(StoreCheckValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            StoreCheckValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for StoreCheck {
    type Property = StoreCheckProperty;

    type Element = StoreCheckValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = StoreCheckProperty::Id;
}

impl From<Id> for StoreCheckValue {
    fn from(id: Id) -> Self {
        StoreCheckValue::Id(id)
    }
}

impl JmapObjectId for StoreCheckValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            StoreCheckValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            StoreCheckValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = StoreCheckValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for StoreCheckProperty {
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
