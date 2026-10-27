/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Fastmail's published Masked Email API, `MaskedEmail/get` and
//! `MaskedEmail/set` under `https://www.fastmail.com/dev/maskedemail`
//! (masked-email spec, "The two APIs"). The ids are the same as
//! `x:MaskedEmail`'s, so an id is one mask whichever API reads it.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    types::date::UTCDate,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct FastmailMaskedEmail;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FastmailMaskedEmailProperty {
    Id,
    Email,
    State,
    ForDomain,
    Description,
    LastMessageAt,
    CreatedAt,
    CreatedBy,
    Url,
    EmailPrefix,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FastmailMaskedEmailValue {
    Id(Id),
    Date(UTCDate),
}

impl Property for FastmailMaskedEmailProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        FastmailMaskedEmailProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            FastmailMaskedEmailProperty::Id => "id",
            FastmailMaskedEmailProperty::Email => "email",
            FastmailMaskedEmailProperty::State => "state",
            FastmailMaskedEmailProperty::ForDomain => "forDomain",
            FastmailMaskedEmailProperty::Description => "description",
            FastmailMaskedEmailProperty::LastMessageAt => "lastMessageAt",
            FastmailMaskedEmailProperty::CreatedAt => "createdAt",
            FastmailMaskedEmailProperty::CreatedBy => "createdBy",
            FastmailMaskedEmailProperty::Url => "url",
            FastmailMaskedEmailProperty::EmailPrefix => "emailPrefix",
        }
        .into()
    }
}

impl FastmailMaskedEmailProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::fnc_map!(value.as_bytes(),
            b"id" => Some(FastmailMaskedEmailProperty::Id),
            b"email" => Some(FastmailMaskedEmailProperty::Email),
            b"state" => Some(FastmailMaskedEmailProperty::State),
            b"forDomain" => Some(FastmailMaskedEmailProperty::ForDomain),
            b"description" => Some(FastmailMaskedEmailProperty::Description),
            b"lastMessageAt" => Some(FastmailMaskedEmailProperty::LastMessageAt),
            b"createdAt" => Some(FastmailMaskedEmailProperty::CreatedAt),
            b"createdBy" => Some(FastmailMaskedEmailProperty::CreatedBy),
            b"url" => Some(FastmailMaskedEmailProperty::Url),
            b"emailPrefix" => Some(FastmailMaskedEmailProperty::EmailPrefix),
            _ => None,
        )
    }
}

impl FromStr for FastmailMaskedEmailProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FastmailMaskedEmailProperty::parse(s).ok_or(())
    }
}

impl Element for FastmailMaskedEmailValue {
    type Property = FastmailMaskedEmailProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(FastmailMaskedEmailProperty::Id) => {
                Id::from_str(value).ok().map(FastmailMaskedEmailValue::Id)
            }
            Key::Property(
                FastmailMaskedEmailProperty::CreatedAt | FastmailMaskedEmailProperty::LastMessageAt,
            ) => UTCDate::from_str(value)
                .ok()
                .map(FastmailMaskedEmailValue::Date),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            FastmailMaskedEmailValue::Id(id) => id.to_string().into(),
            FastmailMaskedEmailValue::Date(date) => date.to_string().into(),
        }
    }
}

impl JmapObject for FastmailMaskedEmail {
    type Property = FastmailMaskedEmailProperty;

    type Element = FastmailMaskedEmailValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = FastmailMaskedEmailProperty::Id;
}

impl From<Id> for FastmailMaskedEmailValue {
    fn from(id: Id) -> Self {
        FastmailMaskedEmailValue::Id(id)
    }
}

impl JmapObjectId for FastmailMaskedEmailValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            FastmailMaskedEmailValue::Id(id) => Some(*id),
            _ => None,
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            FastmailMaskedEmailValue::Id(id) => Some(AnyId::Id(*id)),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = FastmailMaskedEmailValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for FastmailMaskedEmailProperty {
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
