/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:FrontEnds/get` and `/set` under `urn:inbuxa:jmap`: where the
//! server's front ends are (contract C-4). A singleton, id `singleton`.
//!
//! `webmailClientSecret` is write-only. The `environment*` properties,
//! `webmailClientSecretSet`, `changedAt` and `changedBy` are the server's to
//! say; a client that sets them is answered with `invalidProperties`.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct FrontEnds;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FrontEndsProperty {
    Id,
    /// Where INBUXA Admin is served, or null.
    AdminUrl,
    /// Where inbuxa-webmail is served, or null.
    WebmailUrl,
    /// Write-only: the webmail's client secret. Always null when read.
    WebmailClientSecret,
    /// Server-set: whether a webmail client secret is stored.
    WebmailClientSecretSet,
    /// Further origins allowed to call the server from a browser.
    ExtraOrigins,
    /// Server-set: `INBUXA_ADMIN_URL` on this node, or null.
    EnvironmentAdminUrl,
    /// Server-set: `INBUXA_WEBMAIL_URL` on this node, or null.
    EnvironmentWebmailUrl,
    /// Server-set: whether `INBUXA_WEBMAIL_CLIENT_SECRET` is set on this node.
    EnvironmentWebmailClientSecret,
    ChangedAt,
    ChangedBy,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FrontEndsValue {
    Id(Id),
}

impl Property for FrontEndsProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        FrontEndsProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            FrontEndsProperty::Id => "id",
            FrontEndsProperty::AdminUrl => "adminUrl",
            FrontEndsProperty::WebmailUrl => "webmailUrl",
            FrontEndsProperty::WebmailClientSecret => "webmailClientSecret",
            FrontEndsProperty::WebmailClientSecretSet => "webmailClientSecretSet",
            FrontEndsProperty::ExtraOrigins => "extraOrigins",
            FrontEndsProperty::EnvironmentAdminUrl => "environmentAdminUrl",
            FrontEndsProperty::EnvironmentWebmailUrl => "environmentWebmailUrl",
            FrontEndsProperty::EnvironmentWebmailClientSecret => "environmentWebmailClientSecret",
            FrontEndsProperty::ChangedAt => "changedAt",
            FrontEndsProperty::ChangedBy => "changedBy",
        }
        .into()
    }
}

impl FrontEndsProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::fnc_map!(value.as_bytes(),
            b"id" => Some(FrontEndsProperty::Id),
            b"adminUrl" => Some(FrontEndsProperty::AdminUrl),
            b"webmailUrl" => Some(FrontEndsProperty::WebmailUrl),
            b"webmailClientSecret" => Some(FrontEndsProperty::WebmailClientSecret),
            b"webmailClientSecretSet" => Some(FrontEndsProperty::WebmailClientSecretSet),
            b"extraOrigins" => Some(FrontEndsProperty::ExtraOrigins),
            b"environmentAdminUrl" => Some(FrontEndsProperty::EnvironmentAdminUrl),
            b"environmentWebmailUrl" => Some(FrontEndsProperty::EnvironmentWebmailUrl),
            b"environmentWebmailClientSecret" => Some(FrontEndsProperty::EnvironmentWebmailClientSecret),
            b"changedAt" => Some(FrontEndsProperty::ChangedAt),
            b"changedBy" => Some(FrontEndsProperty::ChangedBy),
            _ => None,
        )
    }
}

impl FrontEndsProperty {
    /// Whether this property is the server's to say. A client that sets one
    /// is answered with `invalidProperties`.
    pub fn is_server_set(&self) -> bool {
        matches!(
            self,
            FrontEndsProperty::WebmailClientSecretSet
                | FrontEndsProperty::EnvironmentAdminUrl
                | FrontEndsProperty::EnvironmentWebmailUrl
                | FrontEndsProperty::EnvironmentWebmailClientSecret
                | FrontEndsProperty::ChangedAt
                | FrontEndsProperty::ChangedBy
        )
    }
}

impl FromStr for FrontEndsProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FrontEndsProperty::parse(s).ok_or(())
    }
}

impl Element for FrontEndsValue {
    type Property = FrontEndsProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(FrontEndsProperty::Id) => {
                Id::from_str(value).ok().map(FrontEndsValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            FrontEndsValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for FrontEnds {
    type Property = FrontEndsProperty;

    type Element = FrontEndsValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = FrontEndsProperty::Id;
}

impl From<Id> for FrontEndsValue {
    fn from(id: Id) -> Self {
        FrontEndsValue::Id(id)
    }
}

impl JmapObjectId for FrontEndsValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            FrontEndsValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            FrontEndsValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = FrontEndsValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for FrontEndsProperty {
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
