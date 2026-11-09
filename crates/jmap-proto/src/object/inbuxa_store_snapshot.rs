/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:StoreSnapshot/get` and `/set` under `urn:inbuxa:jmap`: a snapshot
//! of the store, taken without stopping the server (store-snapshot spec,
//! SN-1). Creating one takes it in the background; `get` lists the
//! snapshots on disk and says how the one being taken stands. Destroying one
//! deletes its directory.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct StoreSnapshot;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StoreSnapshotProperty {
    Id,
    Status,
    CreatedAt,
    CreatedBy,
    FinishedAt,
    Node,
    Name,
    Path,
    Holds,
    Size,
    BlobFiles,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StoreSnapshotValue {
    Id(Id),
}

impl Property for StoreSnapshotProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        match parent {
            None => StoreSnapshotProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            StoreSnapshotProperty::Id => "id",
            StoreSnapshotProperty::Status => "status",
            StoreSnapshotProperty::CreatedAt => "createdAt",
            StoreSnapshotProperty::CreatedBy => "createdBy",
            StoreSnapshotProperty::FinishedAt => "finishedAt",
            StoreSnapshotProperty::Node => "node",
            StoreSnapshotProperty::Name => "name",
            StoreSnapshotProperty::Path => "path",
            StoreSnapshotProperty::Holds => "holds",
            StoreSnapshotProperty::Size => "size",
            StoreSnapshotProperty::BlobFiles => "blobFiles",
            StoreSnapshotProperty::Error => "error",
        }
        .into()
    }
}

impl StoreSnapshotProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => StoreSnapshotProperty::Id,
            b"status" => StoreSnapshotProperty::Status,
            b"createdAt" => StoreSnapshotProperty::CreatedAt,
            b"createdBy" => StoreSnapshotProperty::CreatedBy,
            b"finishedAt" => StoreSnapshotProperty::FinishedAt,
            b"node" => StoreSnapshotProperty::Node,
            b"name" => StoreSnapshotProperty::Name,
            b"path" => StoreSnapshotProperty::Path,
            b"holds" => StoreSnapshotProperty::Holds,
            b"size" => StoreSnapshotProperty::Size,
            b"blobFiles" => StoreSnapshotProperty::BlobFiles,
            b"error" => StoreSnapshotProperty::Error,
        )
    }
}

impl FromStr for StoreSnapshotProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        StoreSnapshotProperty::parse(s).ok_or(())
    }
}

impl Element for StoreSnapshotValue {
    type Property = StoreSnapshotProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(StoreSnapshotProperty::Id) => {
                Id::from_str(value).ok().map(StoreSnapshotValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            StoreSnapshotValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for StoreSnapshot {
    type Property = StoreSnapshotProperty;

    type Element = StoreSnapshotValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = StoreSnapshotProperty::Id;
}

impl From<Id> for StoreSnapshotValue {
    fn from(id: Id) -> Self {
        StoreSnapshotValue::Id(id)
    }
}

impl JmapObjectId for StoreSnapshotValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            StoreSnapshotValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            StoreSnapshotValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = StoreSnapshotValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for StoreSnapshotProperty {
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
