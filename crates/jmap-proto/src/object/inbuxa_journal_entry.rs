/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The journal's JMAP objects under `urn:inbuxa:jmap` (journaling spec,
//! JR-6, JR-15 to JR-17):
//!
//! - `inbuxa:JournalEntry/get` and `/query`: what was journaled, read-only.
//!   `report` (the whole journal report) comes only when asked for.
//! - `inbuxa:JournalExport/set`: create one to get a ZIP of the reports a
//!   filter matches.
//! - `inbuxa:JournalVerification/set`: create one to recheck every chain.
//!
//! They share one set of properties. Nested values (an export's filter, a
//! verification's chains) are plain JSON objects.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct JournalEntry;

#[derive(Debug, Clone, Default)]
pub struct JournalExport;

#[derive(Debug, Clone, Default)]
pub struct JournalVerification;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JournalEntryProperty {
    Id,
    ReceivedAt,
    Direction,
    Sender,
    Authenticated,
    Recipients,
    Subject,
    MessageId,
    JournalIds,
    Held,
    Size,
    Sha256,
    ExpiresAt,
    Report,
    Filter,
    Reason,
    BlobId,
    Count,
    Verified,
    Chains,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JournalEntryValue {
    Id(Id),
}

impl Property for JournalEntryProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside a filter or a chain report stay plain keys
        match parent {
            None => JournalEntryProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            JournalEntryProperty::Id => "id",
            JournalEntryProperty::ReceivedAt => "receivedAt",
            JournalEntryProperty::Direction => "direction",
            JournalEntryProperty::Sender => "sender",
            JournalEntryProperty::Authenticated => "authenticated",
            JournalEntryProperty::Recipients => "recipients",
            JournalEntryProperty::Subject => "subject",
            JournalEntryProperty::MessageId => "messageId",
            JournalEntryProperty::JournalIds => "journalIds",
            JournalEntryProperty::Held => "held",
            JournalEntryProperty::Size => "size",
            JournalEntryProperty::Sha256 => "sha256",
            JournalEntryProperty::ExpiresAt => "expiresAt",
            JournalEntryProperty::Report => "report",
            JournalEntryProperty::Filter => "filter",
            JournalEntryProperty::Reason => "reason",
            JournalEntryProperty::BlobId => "blobId",
            JournalEntryProperty::Count => "count",
            JournalEntryProperty::Verified => "verified",
            JournalEntryProperty::Chains => "chains",
        }
        .into()
    }
}

impl JournalEntryProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => JournalEntryProperty::Id,
            b"receivedAt" => JournalEntryProperty::ReceivedAt,
            b"direction" => JournalEntryProperty::Direction,
            b"sender" => JournalEntryProperty::Sender,
            b"authenticated" => JournalEntryProperty::Authenticated,
            b"recipients" => JournalEntryProperty::Recipients,
            b"subject" => JournalEntryProperty::Subject,
            b"messageId" => JournalEntryProperty::MessageId,
            b"journalIds" => JournalEntryProperty::JournalIds,
            b"held" => JournalEntryProperty::Held,
            b"size" => JournalEntryProperty::Size,
            b"sha256" => JournalEntryProperty::Sha256,
            b"expiresAt" => JournalEntryProperty::ExpiresAt,
            b"report" => JournalEntryProperty::Report,
            b"filter" => JournalEntryProperty::Filter,
            b"reason" => JournalEntryProperty::Reason,
            b"blobId" => JournalEntryProperty::BlobId,
            b"count" => JournalEntryProperty::Count,
            b"verified" => JournalEntryProperty::Verified,
            b"chains" => JournalEntryProperty::Chains,
        )
    }
}

impl FromStr for JournalEntryProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        JournalEntryProperty::parse(s).ok_or(())
    }
}

impl Element for JournalEntryValue {
    type Property = JournalEntryProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(JournalEntryProperty::Id) => {
                Id::from_str(value).ok().map(JournalEntryValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            JournalEntryValue::Id(id) => id.to_string().into(),
        }
    }
}

/// One condition of an `inbuxa:JournalEntry/query` filter. Several in one
/// filter object must all hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalFilter {
    /// From this time on (UTC date).
    After(String),
    /// Before this time (UTC date).
    Before(String),
    /// Part of the sender's address.
    Sender(String),
    /// Part of a recipient's address.
    Recipient(String),
    /// Part of the sender's or a recipient's address.
    Address(String),
    /// `outgoing`, `incoming` or `internal`.
    Direction(String),
    /// Words that must all be in the subject.
    Text(String),
    MessageId(String),
    JournalId(Id),
    _T(String),
}

impl Default for JournalFilter {
    fn default() -> Self {
        JournalFilter::_T(String::new())
    }
}

impl<'de> DeserializeArguments<'de> for JournalFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"after" => {
                *self = JournalFilter::After(map.next_value()?);
            },
            b"before" => {
                *self = JournalFilter::Before(map.next_value()?);
            },
            b"sender" => {
                *self = JournalFilter::Sender(map.next_value()?);
            },
            b"recipient" => {
                *self = JournalFilter::Recipient(map.next_value()?);
            },
            b"address" => {
                *self = JournalFilter::Address(map.next_value()?);
            },
            b"direction" => {
                *self = JournalFilter::Direction(map.next_value()?);
            },
            b"text" => {
                *self = JournalFilter::Text(map.next_value()?);
            },
            b"messageId" => {
                *self = JournalFilter::MessageId(map.next_value()?);
            },
            b"journalId" => {
                *self = JournalFilter::JournalId(map.next_value()?);
            },
            _ => {
                *self = JournalFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

/// Entries sort newest first, by `receivedAt`; nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalComparator {
    ReceivedAt,
    _T(String),
}

impl Default for JournalComparator {
    fn default() -> Self {
        JournalComparator::_T(String::new())
    }
}

impl<'de> DeserializeArguments<'de> for JournalComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            *self = if value == "receivedAt" {
                JournalComparator::ReceivedAt
            } else {
                JournalComparator::_T(value.into_owned())
            };
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

macro_rules! journal_object {
    ($object:ty, $filter:ty, $comparator:ty) => {
        impl JmapObject for $object {
            type Property = JournalEntryProperty;

            type Element = JournalEntryValue;

            type Id = Id;

            type Filter = $filter;

            type Comparator = $comparator;

            type GetArguments = ();

            type SetArguments<'de> = ();

            type QueryArguments = ();

            type CopyArguments = ();

            type ParseArguments = ();

            const ID_PROPERTY: Self::Property = JournalEntryProperty::Id;
        }
    };
}

journal_object!(JournalEntry, JournalFilter, JournalComparator);
journal_object!(JournalExport, (), ());
journal_object!(JournalVerification, (), ());

impl From<Id> for JournalEntryValue {
    fn from(id: Id) -> Self {
        JournalEntryValue::Id(id)
    }
}

impl JmapObjectId for JournalEntryValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            JournalEntryValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            JournalEntryValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = JournalEntryValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for JournalEntryProperty {
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
