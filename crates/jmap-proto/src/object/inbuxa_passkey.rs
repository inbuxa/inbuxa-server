/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Passkey/get` and `/set` under `urn:inbuxa:jmap`: an account's
//! passkeys (passkeys spec, PK-5 to PK-16). The request's `accountId` names
//! the account whose passkeys these are.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct Passkey;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PasskeyProperty {
    Id,
    AccountId,
    Name,
    State,
    RegistrationUrl,
    RpId,
    Usable,
    BackedUp,
    Transports,
    CreatedAt,
    LastUsedAt,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PasskeyValue {
    Id(Id),
}

impl Property for PasskeyProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        match parent {
            None => PasskeyProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            PasskeyProperty::Id => "id",
            PasskeyProperty::AccountId => "accountId",
            PasskeyProperty::Name => "name",
            PasskeyProperty::State => "state",
            PasskeyProperty::RegistrationUrl => "registrationUrl",
            PasskeyProperty::RpId => "rpId",
            PasskeyProperty::Usable => "usable",
            PasskeyProperty::BackedUp => "backedUp",
            PasskeyProperty::Transports => "transports",
            PasskeyProperty::CreatedAt => "createdAt",
            PasskeyProperty::LastUsedAt => "lastUsedAt",
        }
        .into()
    }
}

impl PasskeyProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => PasskeyProperty::Id,
            b"accountId" => PasskeyProperty::AccountId,
            b"name" => PasskeyProperty::Name,
            b"state" => PasskeyProperty::State,
            b"registrationUrl" => PasskeyProperty::RegistrationUrl,
            b"rpId" => PasskeyProperty::RpId,
            b"usable" => PasskeyProperty::Usable,
            b"backedUp" => PasskeyProperty::BackedUp,
            b"transports" => PasskeyProperty::Transports,
            b"createdAt" => PasskeyProperty::CreatedAt,
            b"lastUsedAt" => PasskeyProperty::LastUsedAt,
        )
    }
}

impl FromStr for PasskeyProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PasskeyProperty::parse(s).ok_or(())
    }
}

impl Element for PasskeyValue {
    type Property = PasskeyProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(PasskeyProperty::Id | PasskeyProperty::AccountId) => {
                Id::from_str(value).ok().map(PasskeyValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            PasskeyValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for Passkey {
    type Property = PasskeyProperty;

    type Element = PasskeyValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = PasskeyProperty::Id;
}

impl From<Id> for PasskeyValue {
    fn from(id: Id) -> Self {
        PasskeyValue::Id(id)
    }
}

impl JmapObjectId for PasskeyValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            PasskeyValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            PasskeyValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = PasskeyValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for PasskeyProperty {
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
