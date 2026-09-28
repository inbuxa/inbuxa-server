/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:ProtocolPolicy/get` and `/set` under `urn:inbuxa:jmap`: the
//! server-wide legacy mail protocols switch (legacy-protocols spec). A
//! singleton, id `singleton`.
//!
//! Three of its properties are the server's to say, not the client's:
//! `savedListeners` (LP-1), `lockedProtocols` (LP-21) and `wouldClose`
//! (LP-16). A client that sets them is answered with `invalidProperties`.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct ProtocolPolicy;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolPolicyProperty {
    Id,
    /// The kill-all: `enabled` or `disabled`; reads `disabled` when all
    /// three protocols are off, and sets all three.
    LegacyProtocols,
    /// Each protocol's own switch: `enabled` or `disabled`.
    Imap,
    Pop3,
    ManageSieve,
    /// Whether submission closes with it. Forced false while SMTP is locked.
    CloseSubmission,
    /// Server-set: the listeners taken away, for LP-5.
    SavedListeners,
    ChangedAt,
    ChangedBy,
    /// Server-set: the protocols that cannot be closed, so the selector can
    /// render them locked rather than carry its own list (LP-21).
    LockedProtocols,
    /// Server-set: exactly which listeners turning the switch would close,
    /// by name and port, for the confirmation (LP-16).
    WouldClose,
    /// Server-set: who signed in over a legacy protocol in the last 30
    /// days, and when, for the impact panel (LP-15).
    RecentLegacyUse,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolPolicyValue {
    Id(Id),
}

impl Property for ProtocolPolicyProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        ProtocolPolicyProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ProtocolPolicyProperty::Id => "id",
            ProtocolPolicyProperty::LegacyProtocols => "legacyProtocols",
            ProtocolPolicyProperty::Imap => "imap",
            ProtocolPolicyProperty::Pop3 => "pop3",
            ProtocolPolicyProperty::ManageSieve => "manageSieve",
            ProtocolPolicyProperty::CloseSubmission => "closeSubmission",
            ProtocolPolicyProperty::SavedListeners => "savedListeners",
            ProtocolPolicyProperty::ChangedAt => "changedAt",
            ProtocolPolicyProperty::ChangedBy => "changedBy",
            ProtocolPolicyProperty::RecentLegacyUse => "recentLegacyUse",
            ProtocolPolicyProperty::LockedProtocols => "lockedProtocols",
            ProtocolPolicyProperty::WouldClose => "wouldClose",
        }
        .into()
    }
}

impl ProtocolPolicyProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => ProtocolPolicyProperty::Id,
            b"legacyProtocols" => ProtocolPolicyProperty::LegacyProtocols,
            b"imap" => ProtocolPolicyProperty::Imap,
            b"pop3" => ProtocolPolicyProperty::Pop3,
            b"manageSieve" => ProtocolPolicyProperty::ManageSieve,
            b"closeSubmission" => ProtocolPolicyProperty::CloseSubmission,
            b"savedListeners" => ProtocolPolicyProperty::SavedListeners,
            b"changedAt" => ProtocolPolicyProperty::ChangedAt,
            b"changedBy" => ProtocolPolicyProperty::ChangedBy,
            b"recentLegacyUse" => ProtocolPolicyProperty::RecentLegacyUse,
            b"lockedProtocols" => ProtocolPolicyProperty::LockedProtocols,
            b"wouldClose" => ProtocolPolicyProperty::WouldClose,
        )
    }
}

impl ProtocolPolicyProperty {
    /// Whether this property is the server's to say. A client that sets one
    /// is answered with `invalidProperties`.
    pub fn is_server_set(&self) -> bool {
        matches!(
            self,
            ProtocolPolicyProperty::SavedListeners
                | ProtocolPolicyProperty::ChangedAt
                | ProtocolPolicyProperty::ChangedBy
                | ProtocolPolicyProperty::RecentLegacyUse
                | ProtocolPolicyProperty::LockedProtocols
                | ProtocolPolicyProperty::WouldClose
        )
    }
}

impl FromStr for ProtocolPolicyProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ProtocolPolicyProperty::parse(s).ok_or(())
    }
}

impl Element for ProtocolPolicyValue {
    type Property = ProtocolPolicyProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(ProtocolPolicyProperty::Id) => Id::from_str(value).ok().map(ProtocolPolicyValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ProtocolPolicyValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for ProtocolPolicy {
    type Property = ProtocolPolicyProperty;

    type Element = ProtocolPolicyValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = ProtocolPolicyProperty::Id;
}

impl From<Id> for ProtocolPolicyValue {
    fn from(id: Id) -> Self {
        ProtocolPolicyValue::Id(id)
    }
}

impl JmapObjectId for ProtocolPolicyValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            ProtocolPolicyValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            ProtocolPolicyValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = ProtocolPolicyValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for ProtocolPolicyProperty {
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
