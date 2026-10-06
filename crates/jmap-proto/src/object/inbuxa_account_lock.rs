/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:AccountLock/get` and `/set` under `urn:inbuxa:jmap`: an account
//! locked, and the people it is handed to (audit-hold-lock spec, AL-1 to
//! AL-12). A lock's id is the locked account's id. Creating one locks the
//! account, updating changes its delegates, destroying unlocks it. The set
//! call's `reason` argument says why, for the audit log (AU-12); creating
//! takes it as a property.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct AccountLock;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AccountLockProperty {
    Id,
    /// The locked account (on create; afterwards the same as `id`).
    AccountId,
    Name,
    /// MA-S: `lock` (the default) or `sharedMailbox`; set on create only.
    Kind,
    Reason,
    LockedAt,
    LockedBy,
    Delegates,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AccountLockValue {
    Id(Id),
}

impl Property for AccountLockProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside a delegate stay plain keys
        match parent {
            None => AccountLockProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            AccountLockProperty::Id => "id",
            AccountLockProperty::AccountId => "accountId",
            AccountLockProperty::Name => "name",
            AccountLockProperty::Kind => "kind",
            AccountLockProperty::Reason => "reason",
            AccountLockProperty::LockedAt => "lockedAt",
            AccountLockProperty::LockedBy => "lockedBy",
            AccountLockProperty::Delegates => "delegates",
        }
        .into()
    }
}

impl AccountLockProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => AccountLockProperty::Id,
            b"accountId" => AccountLockProperty::AccountId,
            b"name" => AccountLockProperty::Name,
            b"kind" => AccountLockProperty::Kind,
            b"reason" => AccountLockProperty::Reason,
            b"lockedAt" => AccountLockProperty::LockedAt,
            b"lockedBy" => AccountLockProperty::LockedBy,
            b"delegates" => AccountLockProperty::Delegates,
        )
    }
}

impl FromStr for AccountLockProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AccountLockProperty::parse(s).ok_or(())
    }
}

impl Element for AccountLockValue {
    type Property = AccountLockProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(AccountLockProperty::Id | AccountLockProperty::AccountId) => {
                Id::from_str(value).ok().map(AccountLockValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            AccountLockValue::Id(id) => id.to_string().into(),
        }
    }
}

/// The set call's own arguments: why (AU-12).
#[derive(Debug, Clone, Default)]
pub struct AccountLockSetArguments {
    pub reason: Option<String>,
}

impl<'de> DeserializeArguments<'de> for AccountLockSetArguments {
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

impl JmapObject for AccountLock {
    type Property = AccountLockProperty;

    type Element = AccountLockValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = AccountLockSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = AccountLockProperty::Id;
}

impl From<Id> for AccountLockValue {
    fn from(id: Id) -> Self {
        AccountLockValue::Id(id)
    }
}

impl JmapObjectId for AccountLockValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            AccountLockValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            AccountLockValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = AccountLockValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for AccountLockProperty {
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
