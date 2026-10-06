/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:AiLimits/get` and `/set` under `urn:inbuxa:jmap`: the fork's
//! limits on AI model calls (AI spam classification spec, "Added by
//! inbuxa-server"). A singleton, id `singleton`.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct AiLimits;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AiLimitsProperty {
    Id,
    SpamMaxAdded,
    SpamMaxSubtracted,
    SpamCallCeiling,
    MaxConcurrentCalls,
    MaxContentBytes,
    FailureBackoff,
    UserCallsPerHour,
    // "Explain this" (ai-explain spec, EX-21)
    ExplainEnabled,
    ExplainModelId,
    ExplainCallsPerHour,
    ExplainCeiling,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AiLimitsValue {
    Id(Id),
}

impl Property for AiLimitsProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        AiLimitsProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            AiLimitsProperty::Id => "id",
            AiLimitsProperty::SpamMaxAdded => "spamMaxAdded",
            AiLimitsProperty::SpamMaxSubtracted => "spamMaxSubtracted",
            AiLimitsProperty::SpamCallCeiling => "spamCallCeiling",
            AiLimitsProperty::MaxConcurrentCalls => "maxConcurrentCalls",
            AiLimitsProperty::MaxContentBytes => "maxContentBytes",
            AiLimitsProperty::FailureBackoff => "failureBackoff",
            AiLimitsProperty::UserCallsPerHour => "userCallsPerHour",
            AiLimitsProperty::ExplainEnabled => "explainEnabled",
            AiLimitsProperty::ExplainModelId => "explainModelId",
            AiLimitsProperty::ExplainCallsPerHour => "explainCallsPerHour",
            AiLimitsProperty::ExplainCeiling => "explainCeiling",
        }
        .into()
    }
}

impl AiLimitsProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => AiLimitsProperty::Id,
            b"spamMaxAdded" => AiLimitsProperty::SpamMaxAdded,
            b"spamMaxSubtracted" => AiLimitsProperty::SpamMaxSubtracted,
            b"spamCallCeiling" => AiLimitsProperty::SpamCallCeiling,
            b"maxConcurrentCalls" => AiLimitsProperty::MaxConcurrentCalls,
            b"maxContentBytes" => AiLimitsProperty::MaxContentBytes,
            b"failureBackoff" => AiLimitsProperty::FailureBackoff,
            b"userCallsPerHour" => AiLimitsProperty::UserCallsPerHour,
            b"explainEnabled" => AiLimitsProperty::ExplainEnabled,
            b"explainModelId" => AiLimitsProperty::ExplainModelId,
            b"explainCallsPerHour" => AiLimitsProperty::ExplainCallsPerHour,
            b"explainCeiling" => AiLimitsProperty::ExplainCeiling,
        )
    }
}

impl FromStr for AiLimitsProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AiLimitsProperty::parse(s).ok_or(())
    }
}

impl Element for AiLimitsValue {
    type Property = AiLimitsProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(AiLimitsProperty::Id | AiLimitsProperty::ExplainModelId) => {
                Id::from_str(value).ok().map(AiLimitsValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            AiLimitsValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for AiLimits {
    type Property = AiLimitsProperty;

    type Element = AiLimitsValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = AiLimitsProperty::Id;
}

impl From<Id> for AiLimitsValue {
    fn from(id: Id) -> Self {
        AiLimitsValue::Id(id)
    }
}

impl JmapObjectId for AiLimitsValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            AiLimitsValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            AiLimitsValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = AiLimitsValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for AiLimitsProperty {
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
