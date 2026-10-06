/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:SharingPolicy/get` and `/set` under `urn:inbuxa:jmap`: whether
//! people may share their own mail and add other accounts to the webmail
//! (multi-account spec, MA-C). The server's policy has the singleton id;
//! each tenant's has the tenant's id.
//!
//! `tenantId`, `changedAt` and `changedBy` are the server's to say. A client
//! that sets them is answered with `invalidProperties`.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct SharingPolicy;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SharingPolicyProperty {
    Id,
    /// Server-set: the tenant this is the policy of, or null for the server's.
    TenantId,
    /// `enabled` or `disabled`: people may share their own mail folders.
    MailSharing,
    /// `enabled` or `disabled`: people may add other accounts to the webmail.
    AddAccounts,
    ChangedAt,
    ChangedBy,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SharingPolicyValue {
    Id(Id),
}

impl Property for SharingPolicyProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        SharingPolicyProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            SharingPolicyProperty::Id => "id",
            SharingPolicyProperty::TenantId => "tenantId",
            SharingPolicyProperty::MailSharing => "mailSharing",
            SharingPolicyProperty::AddAccounts => "addAccounts",
            SharingPolicyProperty::ChangedAt => "changedAt",
            SharingPolicyProperty::ChangedBy => "changedBy",
        }
        .into()
    }
}

impl SharingPolicyProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => SharingPolicyProperty::Id,
            b"tenantId" => SharingPolicyProperty::TenantId,
            b"mailSharing" => SharingPolicyProperty::MailSharing,
            b"addAccounts" => SharingPolicyProperty::AddAccounts,
            b"changedAt" => SharingPolicyProperty::ChangedAt,
            b"changedBy" => SharingPolicyProperty::ChangedBy,
        )
    }
}

impl SharingPolicyProperty {
    /// Whether this property is the server's to say. A client that sets one
    /// is answered with `invalidProperties`.
    pub fn is_server_set(&self) -> bool {
        matches!(
            self,
            SharingPolicyProperty::TenantId
                | SharingPolicyProperty::ChangedAt
                | SharingPolicyProperty::ChangedBy
        )
    }
}

impl FromStr for SharingPolicyProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SharingPolicyProperty::parse(s).ok_or(())
    }
}

impl Element for SharingPolicyValue {
    type Property = SharingPolicyProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(SharingPolicyProperty::Id) => {
                Id::from_str(value).ok().map(SharingPolicyValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            SharingPolicyValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for SharingPolicy {
    type Property = SharingPolicyProperty;

    type Element = SharingPolicyValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = SharingPolicyProperty::Id;
}

impl From<Id> for SharingPolicyValue {
    fn from(id: Id) -> Self {
        SharingPolicyValue::Id(id)
    }
}

impl JmapObjectId for SharingPolicyValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            SharingPolicyValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            SharingPolicyValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = SharingPolicyValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for SharingPolicyProperty {
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
