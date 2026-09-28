/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:InventorySnapshot/get` under `urn:inbuxa:jmap`: dated copies of
//! the evaluated inventory (personal-data catalog spec, §6). The id is the
//! time taken; `ids: null` lists every snapshot kept, newest first.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct InventorySnapshot;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InventorySnapshotProperty {
    Id,
    TakenAt,
    Trigger,
    Summary,
    Inventory,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InventorySnapshotValue {
    Id(Id),
}

impl Property for InventorySnapshotProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        InventorySnapshotProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            InventorySnapshotProperty::Id => "id",
            InventorySnapshotProperty::TakenAt => "takenAt",
            InventorySnapshotProperty::Trigger => "trigger",
            InventorySnapshotProperty::Summary => "summary",
            InventorySnapshotProperty::Inventory => "inventory",
        }
        .into()
    }
}

impl InventorySnapshotProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => InventorySnapshotProperty::Id,
            b"takenAt" => InventorySnapshotProperty::TakenAt,
            b"trigger" => InventorySnapshotProperty::Trigger,
            b"summary" => InventorySnapshotProperty::Summary,
            b"inventory" => InventorySnapshotProperty::Inventory,
        )
    }
}

impl FromStr for InventorySnapshotProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        InventorySnapshotProperty::parse(s).ok_or(())
    }
}

impl Element for InventorySnapshotValue {
    type Property = InventorySnapshotProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(InventorySnapshotProperty::Id) => {
                Id::from_str(value).ok().map(InventorySnapshotValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            InventorySnapshotValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for InventorySnapshot {
    type Property = InventorySnapshotProperty;

    type Element = InventorySnapshotValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = InventorySnapshotProperty::Id;
}

impl From<Id> for InventorySnapshotValue {
    fn from(id: Id) -> Self {
        InventorySnapshotValue::Id(id)
    }
}

impl JmapObjectId for InventorySnapshotValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            InventorySnapshotValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            InventorySnapshotValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = InventorySnapshotValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for InventorySnapshotProperty {
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
