/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:ReportExport/set` under `urn:inbuxa:jmap`: a scheduled report
//! for a period as a ZIP of a summary and CSVs, without mailing anyone
//! (scheduled-reports spec, RP-19). Exports aren't kept; `/get` finds none.

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct ReportExport;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReportExportProperty {
    Id,
    ReportId,
    From,
    To,
    BlobId,
    Size,
    Sha256,
    Files,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReportExportValue {
    Id(Id),
}

impl Property for ReportExportProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside the lists stay plain keys
        match parent {
            None => ReportExportProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ReportExportProperty::Id => "id",
            ReportExportProperty::ReportId => "reportId",
            ReportExportProperty::From => "from",
            ReportExportProperty::To => "to",
            ReportExportProperty::BlobId => "blobId",
            ReportExportProperty::Size => "size",
            ReportExportProperty::Sha256 => "sha256",
            ReportExportProperty::Files => "files",
        }
        .into()
    }
}

impl ReportExportProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => ReportExportProperty::Id,
            b"reportId" => ReportExportProperty::ReportId,
            b"from" => ReportExportProperty::From,
            b"to" => ReportExportProperty::To,
            b"blobId" => ReportExportProperty::BlobId,
            b"size" => ReportExportProperty::Size,
            b"sha256" => ReportExportProperty::Sha256,
            b"files" => ReportExportProperty::Files,
        )
    }
}

impl FromStr for ReportExportProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ReportExportProperty::parse(s).ok_or(())
    }
}

impl Element for ReportExportValue {
    type Property = ReportExportProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(ReportExportProperty::Id) => {
                Id::from_str(value).ok().map(ReportExportValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ReportExportValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for ReportExport {
    type Property = ReportExportProperty;

    type Element = ReportExportValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = ReportExportProperty::Id;
}

impl From<Id> for ReportExportValue {
    fn from(id: Id) -> Self {
        ReportExportValue::Id(id)
    }
}

impl JmapObjectId for ReportExportValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            ReportExportValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            ReportExportValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = ReportExportValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for ReportExportProperty {
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
