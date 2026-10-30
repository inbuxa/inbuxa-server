/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Relay/get` and `/set` under `urn:inbuxa:jmap`: the inbuxa Relays
//! this server or cluster links to (docs/spec/features/relay.md, "Registry
//! objects"). A create returns the join token, once. The set call's
//! `reason` argument, if given, goes into the audit log with the change.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct Relay;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayProperty {
    Id,
    Name,
    Description,
    /// The host the downstream dials.
    Address,
    LinkPort,
    Enabled,
    SendThrough,
    InboundOnly,
    /// Its MX preference, where DNS is published (RL-25).
    MxPreference,
    /// What is pushed to the relay.
    Settings,
    SmtpCertificate,
    /// Reads back as `****`.
    SmtpPrivateKey,
    /// When the stored certificate runs out, if it can be read.
    CertificateNotAfter,
    /// Why the last certificate order failed, if it did (RL-27).
    CertificateError,
    /// `waiting`, `expired` or `joined`.
    JoinState,
    JoinExpiresAt,
    JoinedAt,
    /// The relay's link key pin, once joined.
    LinkKeyPin,
    /// Update only: `true` starts a new join, with a new token.
    Rejoin,
    /// In a create or rejoin response only.
    JoinToken,
    /// Each node's link to the relay, and what the relay last said.
    Links,
    CreatedBy,
    CreatedAt,
    UpdatedAt,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayValue {
    Id(Id),
}

impl Property for RelayProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside settings stay plain keys
        match parent {
            None => RelayProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            RelayProperty::Id => "id",
            RelayProperty::Name => "name",
            RelayProperty::Description => "description",
            RelayProperty::Address => "address",
            RelayProperty::LinkPort => "linkPort",
            RelayProperty::Enabled => "enabled",
            RelayProperty::SendThrough => "sendThrough",
            RelayProperty::InboundOnly => "inboundOnly",
            RelayProperty::MxPreference => "mxPreference",
            RelayProperty::Settings => "settings",
            RelayProperty::SmtpCertificate => "smtpCertificate",
            RelayProperty::SmtpPrivateKey => "smtpPrivateKey",
            RelayProperty::CertificateNotAfter => "certificateNotAfter",
            RelayProperty::CertificateError => "certificateError",
            RelayProperty::JoinState => "joinState",
            RelayProperty::JoinExpiresAt => "joinExpiresAt",
            RelayProperty::JoinedAt => "joinedAt",
            RelayProperty::LinkKeyPin => "linkKeyPin",
            RelayProperty::Rejoin => "rejoin",
            RelayProperty::JoinToken => "joinToken",
            RelayProperty::Links => "links",
            RelayProperty::CreatedBy => "createdBy",
            RelayProperty::CreatedAt => "createdAt",
            RelayProperty::UpdatedAt => "updatedAt",
        }
        .into()
    }
}

impl RelayProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => RelayProperty::Id,
            b"name" => RelayProperty::Name,
            b"description" => RelayProperty::Description,
            b"address" => RelayProperty::Address,
            b"linkPort" => RelayProperty::LinkPort,
            b"enabled" => RelayProperty::Enabled,
            b"sendThrough" => RelayProperty::SendThrough,
            b"inboundOnly" => RelayProperty::InboundOnly,
            b"mxPreference" => RelayProperty::MxPreference,
            b"settings" => RelayProperty::Settings,
            b"smtpCertificate" => RelayProperty::SmtpCertificate,
            b"smtpPrivateKey" => RelayProperty::SmtpPrivateKey,
            b"certificateNotAfter" => RelayProperty::CertificateNotAfter,
            b"certificateError" => RelayProperty::CertificateError,
            b"joinState" => RelayProperty::JoinState,
            b"joinExpiresAt" => RelayProperty::JoinExpiresAt,
            b"joinedAt" => RelayProperty::JoinedAt,
            b"linkKeyPin" => RelayProperty::LinkKeyPin,
            b"rejoin" => RelayProperty::Rejoin,
            b"joinToken" => RelayProperty::JoinToken,
            b"links" => RelayProperty::Links,
            b"createdBy" => RelayProperty::CreatedBy,
            b"createdAt" => RelayProperty::CreatedAt,
            b"updatedAt" => RelayProperty::UpdatedAt,
        )
    }
}

impl FromStr for RelayProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RelayProperty::parse(s).ok_or(())
    }
}

impl Element for RelayValue {
    type Property = RelayProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(RelayProperty::Id) => Id::from_str(value).ok().map(RelayValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            RelayValue::Id(id) => id.to_string().into(),
        }
    }
}

/// The set call's own argument: why, for the audit log.
#[derive(Debug, Clone, Default)]
pub struct RelaySetArguments {
    pub reason: Option<String>,
}

impl<'de> DeserializeArguments<'de> for RelaySetArguments {
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

impl JmapObject for Relay {
    type Property = RelayProperty;

    type Element = RelayValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = RelaySetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = RelayProperty::Id;
}

impl From<Id> for RelayValue {
    fn from(id: Id) -> Self {
        RelayValue::Id(id)
    }
}

impl JmapObjectId for RelayValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            RelayValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            RelayValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = RelayValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for RelayProperty {
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
