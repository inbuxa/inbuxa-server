/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:DeletedAccount/get` and `/set` under `urn:inbuxa:jmap`: deleted
//! accounts kept for their period, listed, restored or destroyed for good
//! (undelete spec, UD-15 to UD-17).

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    types::date::UTCDate,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct DeletedAccount;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeletedAccountProperty {
    Id,
    Name,
    Addresses,
    MemberTenantId,
    DeletedAt,
    KeptUntil,
    Restore,
    Password,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeletedAccountValue {
    Id(Id),
    Date(UTCDate),
}

impl Property for DeletedAccountProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        DeletedAccountProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            DeletedAccountProperty::Id => "id",
            DeletedAccountProperty::Name => "name",
            DeletedAccountProperty::Addresses => "addresses",
            DeletedAccountProperty::MemberTenantId => "memberTenantId",
            DeletedAccountProperty::DeletedAt => "deletedAt",
            DeletedAccountProperty::KeptUntil => "keptUntil",
            DeletedAccountProperty::Restore => "restore",
            DeletedAccountProperty::Password => "password",
        }
        .into()
    }
}

impl DeletedAccountProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => DeletedAccountProperty::Id,
            b"name" => DeletedAccountProperty::Name,
            b"addresses" => DeletedAccountProperty::Addresses,
            b"memberTenantId" => DeletedAccountProperty::MemberTenantId,
            b"deletedAt" => DeletedAccountProperty::DeletedAt,
            b"keptUntil" => DeletedAccountProperty::KeptUntil,
            b"restore" => DeletedAccountProperty::Restore,
            b"password" => DeletedAccountProperty::Password,
        )
    }
}

impl FromStr for DeletedAccountProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DeletedAccountProperty::parse(s).ok_or(())
    }
}

impl Element for DeletedAccountValue {
    type Property = DeletedAccountProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(DeletedAccountProperty::Id | DeletedAccountProperty::MemberTenantId) => {
                Id::from_str(value).ok().map(DeletedAccountValue::Id)
            }
            Key::Property(DeletedAccountProperty::DeletedAt | DeletedAccountProperty::KeptUntil) => {
                UTCDate::from_str(value).ok().map(DeletedAccountValue::Date)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            DeletedAccountValue::Id(id) => id.to_string().into(),
            DeletedAccountValue::Date(date) => date.to_string().into(),
        }
    }
}

impl JmapObject for DeletedAccount {
    type Property = DeletedAccountProperty;

    type Element = DeletedAccountValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = DeletedAccountProperty::Id;
}

impl From<Id> for DeletedAccountValue {
    fn from(id: Id) -> Self {
        DeletedAccountValue::Id(id)
    }
}

impl JmapObjectId for DeletedAccountValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            DeletedAccountValue::Id(id) => Some(*id),
            _ => None,
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            DeletedAccountValue::Id(id) => Some(AnyId::Id(*id)),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = DeletedAccountValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for DeletedAccountProperty {
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
