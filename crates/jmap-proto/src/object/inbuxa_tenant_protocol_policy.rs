/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:TenantProtocolPolicy/get` and `/set` under `urn:inbuxa:jmap`: one
//! tenant's legacy mail protocols switch (legacy-protocols spec, LP-9 to
//! LP-14). One per tenant; its id is the tenant's id.
//!
//! `tenantId`, `changedAt` and `changedBy` are the server's to say. A client
//! that sets them is answered with `invalidProperties`.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct TenantProtocolPolicy;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TenantProtocolPolicyProperty {
    Id,
    /// Server-set: the tenant this is the switch of.
    TenantId,
    /// The kill-all: `enabled` or `disabled`; reads `disabled` when all
    /// three protocols are off, and sets all three.
    LegacyProtocols,
    /// Each protocol's own switch: `enabled` or `disabled`.
    Imap,
    Pop3,
    ManageSieve,
    ChangedAt,
    ChangedBy,
    /// Server-set: who signed in over a legacy protocol in the last 30
    /// days, and when, for the impact panel (LP-15).
    RecentLegacyUse,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TenantProtocolPolicyValue {
    Id(Id),
}

impl Property for TenantProtocolPolicyProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        TenantProtocolPolicyProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            TenantProtocolPolicyProperty::Id => "id",
            TenantProtocolPolicyProperty::TenantId => "tenantId",
            TenantProtocolPolicyProperty::LegacyProtocols => "legacyProtocols",
            TenantProtocolPolicyProperty::Imap => "imap",
            TenantProtocolPolicyProperty::Pop3 => "pop3",
            TenantProtocolPolicyProperty::ManageSieve => "manageSieve",
            TenantProtocolPolicyProperty::ChangedAt => "changedAt",
            TenantProtocolPolicyProperty::ChangedBy => "changedBy",
            TenantProtocolPolicyProperty::RecentLegacyUse => "recentLegacyUse",
        }
        .into()
    }
}

impl TenantProtocolPolicyProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => TenantProtocolPolicyProperty::Id,
            b"tenantId" => TenantProtocolPolicyProperty::TenantId,
            b"legacyProtocols" => TenantProtocolPolicyProperty::LegacyProtocols,
            b"imap" => TenantProtocolPolicyProperty::Imap,
            b"pop3" => TenantProtocolPolicyProperty::Pop3,
            b"manageSieve" => TenantProtocolPolicyProperty::ManageSieve,
            b"changedAt" => TenantProtocolPolicyProperty::ChangedAt,
            b"changedBy" => TenantProtocolPolicyProperty::ChangedBy,
            b"recentLegacyUse" => TenantProtocolPolicyProperty::RecentLegacyUse,
        )
    }
}

impl TenantProtocolPolicyProperty {
    /// Whether this property is the server's to say. A client that sets one
    /// is answered with `invalidProperties`.
    pub fn is_server_set(&self) -> bool {
        matches!(
            self,
            TenantProtocolPolicyProperty::TenantId
                | TenantProtocolPolicyProperty::ChangedAt
                | TenantProtocolPolicyProperty::ChangedBy
                | TenantProtocolPolicyProperty::RecentLegacyUse
        )
    }
}

impl FromStr for TenantProtocolPolicyProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TenantProtocolPolicyProperty::parse(s).ok_or(())
    }
}

impl Element for TenantProtocolPolicyValue {
    type Property = TenantProtocolPolicyProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(TenantProtocolPolicyProperty::Id) => {
                Id::from_str(value).ok().map(TenantProtocolPolicyValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            TenantProtocolPolicyValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for TenantProtocolPolicy {
    type Property = TenantProtocolPolicyProperty;

    type Element = TenantProtocolPolicyValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = TenantProtocolPolicyProperty::Id;
}

impl From<Id> for TenantProtocolPolicyValue {
    fn from(id: Id) -> Self {
        TenantProtocolPolicyValue::Id(id)
    }
}

impl JmapObjectId for TenantProtocolPolicyValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            TenantProtocolPolicyValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            TenantProtocolPolicyValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = TenantProtocolPolicyValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for TenantProtocolPolicyProperty {
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
