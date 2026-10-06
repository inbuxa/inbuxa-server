/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Explanation/set` under `urn:inbuxa:jmap`: "Explain this", the
//! local model explaining something in the admin console
//! (`inbuxa-drafts/specs/ai-explain.md`). Created, never stored: `subject`
//! goes in, `text` and its provenance come back.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct Explanation;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExplanationProperty {
    Id,
    Subject,
    Text,
    Model,
    Node,
    ElapsedMs,
    Grounded,
    // inbuxa: EX-27, where the answer came from
    Source,
    AnsweredAt,
    PreparedFor,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExplanationValue {
    Id(Id),
}

impl Property for ExplanationProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Only the object's own properties: a subject's fields (its `id`,
        // `@type`, …) stay plain keys
        match parent {
            None => ExplanationProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ExplanationProperty::Id => "id",
            ExplanationProperty::Subject => "subject",
            ExplanationProperty::Text => "text",
            ExplanationProperty::Model => "model",
            ExplanationProperty::Node => "node",
            ExplanationProperty::ElapsedMs => "elapsedMs",
            ExplanationProperty::Grounded => "grounded",
            ExplanationProperty::Source => "source",
            ExplanationProperty::AnsweredAt => "answeredAt",
            ExplanationProperty::PreparedFor => "preparedFor",
        }
        .into()
    }
}

impl ExplanationProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => ExplanationProperty::Id,
            b"subject" => ExplanationProperty::Subject,
            b"text" => ExplanationProperty::Text,
            b"model" => ExplanationProperty::Model,
            b"node" => ExplanationProperty::Node,
            b"elapsedMs" => ExplanationProperty::ElapsedMs,
            b"grounded" => ExplanationProperty::Grounded,
            b"source" => ExplanationProperty::Source,
            b"answeredAt" => ExplanationProperty::AnsweredAt,
            b"preparedFor" => ExplanationProperty::PreparedFor,
        )
    }
}

impl FromStr for ExplanationProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ExplanationProperty::parse(s).ok_or(())
    }
}

impl Element for ExplanationValue {
    type Property = ExplanationProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(ExplanationProperty::Id) => Id::from_str(value).ok().map(ExplanationValue::Id),
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ExplanationValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for Explanation {
    type Property = ExplanationProperty;

    type Element = ExplanationValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = ExplanationProperty::Id;
}

impl From<Id> for ExplanationValue {
    fn from(id: Id) -> Self {
        ExplanationValue::Id(id)
    }
}

impl JmapObjectId for ExplanationValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            ExplanationValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            ExplanationValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = ExplanationValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for ExplanationProperty {
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
