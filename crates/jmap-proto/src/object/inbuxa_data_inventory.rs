/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:DataInventory/get` under `urn:inbuxa:jmap`: the personal-data
//! catalog evaluated against this server's live settings (personal-data
//! catalog spec, §6). A singleton, id `singleton`; read-only.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct DataInventory;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataInventoryProperty {
    Id,
    EvaluatedAt,
    CatalogVersion,
    Summary,
    Items,
    Processors,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataInventoryValue {
    Id(Id),
}

impl Property for DataInventoryProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        DataInventoryProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            DataInventoryProperty::Id => "id",
            DataInventoryProperty::EvaluatedAt => "evaluatedAt",
            DataInventoryProperty::CatalogVersion => "catalogVersion",
            DataInventoryProperty::Summary => "summary",
            DataInventoryProperty::Items => "items",
            DataInventoryProperty::Processors => "processors",
        }
        .into()
    }
}

impl DataInventoryProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => DataInventoryProperty::Id,
            b"evaluatedAt" => DataInventoryProperty::EvaluatedAt,
            b"catalogVersion" => DataInventoryProperty::CatalogVersion,
            b"summary" => DataInventoryProperty::Summary,
            b"items" => DataInventoryProperty::Items,
            b"processors" => DataInventoryProperty::Processors,
        )
    }
}

impl FromStr for DataInventoryProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DataInventoryProperty::parse(s).ok_or(())
    }
}

impl Element for DataInventoryValue {
    type Property = DataInventoryProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(DataInventoryProperty::Id) => {
                Id::from_str(value).ok().map(DataInventoryValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            DataInventoryValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for DataInventory {
    type Property = DataInventoryProperty;

    type Element = DataInventoryValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = DataInventoryProperty::Id;
}

impl From<Id> for DataInventoryValue {
    fn from(id: Id) -> Self {
        DataInventoryValue::Id(id)
    }
}

impl JmapObjectId for DataInventoryValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            DataInventoryValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            DataInventoryValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = DataInventoryValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for DataInventoryProperty {
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
