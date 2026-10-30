/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:RelayMessage/get`, `/query` and `/set` under `urn:inbuxa:jmap`:
//! what waits in a relay's `Inbound` and `Outbound` queues, fetched over
//! this node's link when asked (docs/spec/features/relay.md, "Registry
//! objects"). Never message content. Set only destroys: discards held
//! mail, or cancels an outbound message. The set call's `reason`, if
//! given, goes into the audit log with the change.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct RelayMessage;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayMessageProperty {
    Id,
    /// The `inbuxa:Relay` it is at.
    RelayId,
    /// `inbound` or `outbound`.
    Direction,
    /// Its id at the relay.
    RelayMessageId,
    CreatedAt,
    Size,
    /// RFC 8621 `Envelope`.
    Envelope,
    /// Inbound: `held`, `pending` and so on, as the relay says.
    State,
    ClaimedUntil,
    /// Inbound: the SMTP session it came in on.
    Session,
    DoorChecks,
    /// Outbound: RFC 8621 `DeliveryStatus` per recipient.
    DeliveryStatus,
    NextAttemptAt,
    Attempts,
    ExpiresAt,
    /// Outbound: the message in this server's queue it was handed from.
    QueueId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayMessageValue {
    Id(Id),
}

impl Property for RelayMessageProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside the envelope, session and statuses stay plain keys
        match parent {
            None => RelayMessageProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            RelayMessageProperty::Id => "id",
            RelayMessageProperty::RelayId => "relayId",
            RelayMessageProperty::Direction => "direction",
            RelayMessageProperty::RelayMessageId => "relayMessageId",
            RelayMessageProperty::CreatedAt => "createdAt",
            RelayMessageProperty::Size => "size",
            RelayMessageProperty::Envelope => "envelope",
            RelayMessageProperty::State => "state",
            RelayMessageProperty::ClaimedUntil => "claimedUntil",
            RelayMessageProperty::Session => "session",
            RelayMessageProperty::DoorChecks => "doorChecks",
            RelayMessageProperty::DeliveryStatus => "deliveryStatus",
            RelayMessageProperty::NextAttemptAt => "nextAttemptAt",
            RelayMessageProperty::Attempts => "attempts",
            RelayMessageProperty::ExpiresAt => "expiresAt",
            RelayMessageProperty::QueueId => "queueId",
        }
        .into()
    }
}

impl RelayMessageProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => RelayMessageProperty::Id,
            b"relayId" => RelayMessageProperty::RelayId,
            b"direction" => RelayMessageProperty::Direction,
            b"relayMessageId" => RelayMessageProperty::RelayMessageId,
            b"createdAt" => RelayMessageProperty::CreatedAt,
            b"size" => RelayMessageProperty::Size,
            b"envelope" => RelayMessageProperty::Envelope,
            b"state" => RelayMessageProperty::State,
            b"claimedUntil" => RelayMessageProperty::ClaimedUntil,
            b"session" => RelayMessageProperty::Session,
            b"doorChecks" => RelayMessageProperty::DoorChecks,
            b"deliveryStatus" => RelayMessageProperty::DeliveryStatus,
            b"nextAttemptAt" => RelayMessageProperty::NextAttemptAt,
            b"attempts" => RelayMessageProperty::Attempts,
            b"expiresAt" => RelayMessageProperty::ExpiresAt,
            b"queueId" => RelayMessageProperty::QueueId,
        )
    }
}

impl FromStr for RelayMessageProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RelayMessageProperty::parse(s).ok_or(())
    }
}

impl Element for RelayMessageValue {
    type Property = RelayMessageProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(
                RelayMessageProperty::Id
                | RelayMessageProperty::RelayId
                | RelayMessageProperty::QueueId,
            ) => Id::from_str(value).ok().map(RelayMessageValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            RelayMessageValue::Id(id) => id.to_string().into(),
        }
    }
}

/// One condition of an `inbuxa:RelayMessage/query` filter. Several in one
/// filter object must all hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMessageFilter {
    RelayId(Id),
    /// `inbound` or `outbound`.
    Direction(String),
    _T(String),
}

impl Default for RelayMessageFilter {
    fn default() -> Self {
        RelayMessageFilter::_T(String::new())
    }
}

impl<'de> DeserializeArguments<'de> for RelayMessageFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        match key {
            "relayId" => *self = RelayMessageFilter::RelayId(map.next_value()?),
            "direction" => *self = RelayMessageFilter::Direction(map.next_value()?),
            _ => {
                *self = RelayMessageFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

/// The set call's own argument: why, for the audit log.
#[derive(Debug, Clone, Default)]
pub struct RelayMessageSetArguments {
    pub reason: Option<String>,
}

impl<'de> DeserializeArguments<'de> for RelayMessageSetArguments {
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

impl JmapObject for RelayMessage {
    type Property = RelayMessageProperty;

    type Element = RelayMessageValue;

    type Id = Id;

    type Filter = RelayMessageFilter;

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = RelayMessageSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = RelayMessageProperty::Id;
}

impl From<Id> for RelayMessageValue {
    fn from(id: Id) -> Self {
        RelayMessageValue::Id(id)
    }
}

impl JmapObjectId for RelayMessageValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            RelayMessageValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            RelayMessageValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = RelayMessageValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for RelayMessageProperty {
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
