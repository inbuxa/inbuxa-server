/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:HeldMessage/get` and `/set` under `urn:inbuxa:jmap`: mail held
//! for review (dlp-and-mail-flow-rules spec, §2.6). Get lists it; `preview`
//! (the text, only when asked for) is recorded as access to someone's mail.
//! Set only updates: `{"decision": "release"}`, or `"reject"` with an
//! optional `note` for the sender. The call's `reason` goes into the audit
//! log and is required.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct HeldMessage;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeldMessageProperty {
    Id,
    Sender,
    Recipients,
    Subject,
    Size,
    Rules,
    Counts,
    HeldAt,
    ExpiresAt,
    Preview,
    Decision,
    Note,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeldMessageValue {
    Id(Id),
}

impl Property for HeldMessageProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside rules and counts stay plain keys
        match parent {
            None => HeldMessageProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            HeldMessageProperty::Id => "id",
            HeldMessageProperty::Sender => "sender",
            HeldMessageProperty::Recipients => "recipients",
            HeldMessageProperty::Subject => "subject",
            HeldMessageProperty::Size => "size",
            HeldMessageProperty::Rules => "rules",
            HeldMessageProperty::Counts => "counts",
            HeldMessageProperty::HeldAt => "heldAt",
            HeldMessageProperty::ExpiresAt => "expiresAt",
            HeldMessageProperty::Preview => "preview",
            HeldMessageProperty::Decision => "decision",
            HeldMessageProperty::Note => "note",
        }
        .into()
    }
}

impl HeldMessageProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => HeldMessageProperty::Id,
            b"sender" => HeldMessageProperty::Sender,
            b"recipients" => HeldMessageProperty::Recipients,
            b"subject" => HeldMessageProperty::Subject,
            b"size" => HeldMessageProperty::Size,
            b"rules" => HeldMessageProperty::Rules,
            b"counts" => HeldMessageProperty::Counts,
            b"heldAt" => HeldMessageProperty::HeldAt,
            b"expiresAt" => HeldMessageProperty::ExpiresAt,
            b"preview" => HeldMessageProperty::Preview,
            b"decision" => HeldMessageProperty::Decision,
            b"note" => HeldMessageProperty::Note,
        )
    }
}

impl FromStr for HeldMessageProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HeldMessageProperty::parse(s).ok_or(())
    }
}

impl Element for HeldMessageValue {
    type Property = HeldMessageProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(HeldMessageProperty::Id) => {
                Id::from_str(value).ok().map(HeldMessageValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            HeldMessageValue::Id(id) => id.to_string().into(),
        }
    }
}

/// The set call's own argument: why, for the audit log (required).
#[derive(Debug, Clone, Default)]
pub struct HeldMessageSetArguments {
    pub reason: Option<String>,
}

impl<'de> DeserializeArguments<'de> for HeldMessageSetArguments {
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

impl JmapObject for HeldMessage {
    type Property = HeldMessageProperty;

    type Element = HeldMessageValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = HeldMessageSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = HeldMessageProperty::Id;
}

impl From<Id> for HeldMessageValue {
    fn from(id: Id) -> Self {
        HeldMessageValue::Id(id)
    }
}

impl JmapObjectId for HeldMessageValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            HeldMessageValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            HeldMessageValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = HeldMessageValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for HeldMessageProperty {
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
