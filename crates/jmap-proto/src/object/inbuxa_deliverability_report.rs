/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:DeliverabilityReport/get` and `/set` under `urn:inbuxa:jmap`:
//! each sending node's last deliverability check (deliverability spec).
//! One per node, written by the server. Creating one asks every node to
//! check itself now (DL-15); nothing is updated or destroyed.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct DeliverabilityReport;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeliverabilityReportProperty {
    Id,
    NodeId,
    Hostname,
    CheckedAt,
    Addresses,
    Domains,
    Certificates,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeliverabilityReportValue {
    Id(Id),
}

impl Property for DeliverabilityReportProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside the addresses, domains and certificates stay plain keys
        match parent {
            None => DeliverabilityReportProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            DeliverabilityReportProperty::Id => "id",
            DeliverabilityReportProperty::NodeId => "nodeId",
            DeliverabilityReportProperty::Hostname => "hostname",
            DeliverabilityReportProperty::CheckedAt => "checkedAt",
            DeliverabilityReportProperty::Addresses => "addresses",
            DeliverabilityReportProperty::Domains => "domains",
            DeliverabilityReportProperty::Certificates => "certificates",
        }
        .into()
    }
}

impl DeliverabilityReportProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => DeliverabilityReportProperty::Id,
            b"nodeId" => DeliverabilityReportProperty::NodeId,
            b"hostname" => DeliverabilityReportProperty::Hostname,
            b"checkedAt" => DeliverabilityReportProperty::CheckedAt,
            b"addresses" => DeliverabilityReportProperty::Addresses,
            b"domains" => DeliverabilityReportProperty::Domains,
            b"certificates" => DeliverabilityReportProperty::Certificates,
        )
    }
}

impl FromStr for DeliverabilityReportProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DeliverabilityReportProperty::parse(s).ok_or(())
    }
}

impl Element for DeliverabilityReportValue {
    type Property = DeliverabilityReportProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(DeliverabilityReportProperty::Id) => {
                Id::from_str(value).ok().map(DeliverabilityReportValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            DeliverabilityReportValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for DeliverabilityReport {
    type Property = DeliverabilityReportProperty;

    type Element = DeliverabilityReportValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = DeliverabilityReportProperty::Id;
}

impl From<Id> for DeliverabilityReportValue {
    fn from(id: Id) -> Self {
        DeliverabilityReportValue::Id(id)
    }
}

impl JmapObjectId for DeliverabilityReportValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            DeliverabilityReportValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            DeliverabilityReportValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = DeliverabilityReportValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for DeliverabilityReportProperty {
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
