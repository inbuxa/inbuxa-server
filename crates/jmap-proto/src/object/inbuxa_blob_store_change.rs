/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:BlobStoreChange/get` and `/set` under `urn:inbuxa:jmap`: a change
//! of blob store the server noticed at start-up (blob-store-change spec,
//! BM-2). The server records them; an update with `action: "copy"` copies
//! what the new store lacks from the old one, `action: "stop"` stops that,
//! and destroying one dismisses it (BM-5 to BM-7). A create with a `target`
//! plans one, to copy ahead and `apply` (blob-store-copy-ahead spec). On a
//! resolved change, `action: "cleanUp"` deletes from the old store what the
//! current one has (blob-store-cleanup spec).

use crate::object::{AnyId, JmapObject, JmapObjectId};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct BlobStoreChange;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobStoreChangeProperty {
    Id,
    From,
    To,
    ChangedAt,
    Node,
    Status,
    CopyStartedAt,
    CopyFinishedAt,
    CopyStartedBy,
    CopyNode,
    BlobsPerSecond,
    BytesPerSecond,
    Progress,
    BlobsChecked,
    Copied,
    AlreadyThere,
    BytesCopied,
    Missing,
    Damaged,
    Unreadable,
    Problems,
    Error,
    Action,
    Stage,
    Target,
    CopiedAhead,
    AppliedAt,
    AppliedBy,
    OldStoreKept,
    Cleanup,
    DryRun,
    Confirm,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobStoreChangeValue {
    Id(Id),
}

impl Property for BlobStoreChangeProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        match parent {
            None => BlobStoreChangeProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            BlobStoreChangeProperty::Id => "id",
            BlobStoreChangeProperty::From => "from",
            BlobStoreChangeProperty::To => "to",
            BlobStoreChangeProperty::ChangedAt => "changedAt",
            BlobStoreChangeProperty::Node => "node",
            BlobStoreChangeProperty::Status => "status",
            BlobStoreChangeProperty::CopyStartedAt => "copyStartedAt",
            BlobStoreChangeProperty::CopyFinishedAt => "copyFinishedAt",
            BlobStoreChangeProperty::CopyStartedBy => "copyStartedBy",
            BlobStoreChangeProperty::CopyNode => "copyNode",
            BlobStoreChangeProperty::BlobsPerSecond => "blobsPerSecond",
            BlobStoreChangeProperty::BytesPerSecond => "bytesPerSecond",
            BlobStoreChangeProperty::Progress => "progress",
            BlobStoreChangeProperty::BlobsChecked => "blobsChecked",
            BlobStoreChangeProperty::Copied => "copied",
            BlobStoreChangeProperty::AlreadyThere => "alreadyThere",
            BlobStoreChangeProperty::BytesCopied => "bytesCopied",
            BlobStoreChangeProperty::Missing => "missing",
            BlobStoreChangeProperty::Damaged => "damaged",
            BlobStoreChangeProperty::Unreadable => "unreadable",
            BlobStoreChangeProperty::Problems => "problems",
            BlobStoreChangeProperty::Error => "error",
            BlobStoreChangeProperty::Action => "action",
            BlobStoreChangeProperty::Stage => "stage",
            BlobStoreChangeProperty::Target => "target",
            BlobStoreChangeProperty::CopiedAhead => "copiedAhead",
            BlobStoreChangeProperty::AppliedAt => "appliedAt",
            BlobStoreChangeProperty::AppliedBy => "appliedBy",
            BlobStoreChangeProperty::OldStoreKept => "oldStoreKept",
            BlobStoreChangeProperty::Cleanup => "cleanup",
            BlobStoreChangeProperty::DryRun => "dryRun",
            BlobStoreChangeProperty::Confirm => "confirm",
        }
        .into()
    }
}

impl BlobStoreChangeProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => BlobStoreChangeProperty::Id,
            b"from" => BlobStoreChangeProperty::From,
            b"to" => BlobStoreChangeProperty::To,
            b"changedAt" => BlobStoreChangeProperty::ChangedAt,
            b"node" => BlobStoreChangeProperty::Node,
            b"status" => BlobStoreChangeProperty::Status,
            b"copyStartedAt" => BlobStoreChangeProperty::CopyStartedAt,
            b"copyFinishedAt" => BlobStoreChangeProperty::CopyFinishedAt,
            b"copyStartedBy" => BlobStoreChangeProperty::CopyStartedBy,
            b"copyNode" => BlobStoreChangeProperty::CopyNode,
            b"blobsPerSecond" => BlobStoreChangeProperty::BlobsPerSecond,
            b"bytesPerSecond" => BlobStoreChangeProperty::BytesPerSecond,
            b"progress" => BlobStoreChangeProperty::Progress,
            b"blobsChecked" => BlobStoreChangeProperty::BlobsChecked,
            b"copied" => BlobStoreChangeProperty::Copied,
            b"alreadyThere" => BlobStoreChangeProperty::AlreadyThere,
            b"bytesCopied" => BlobStoreChangeProperty::BytesCopied,
            b"missing" => BlobStoreChangeProperty::Missing,
            b"damaged" => BlobStoreChangeProperty::Damaged,
            b"unreadable" => BlobStoreChangeProperty::Unreadable,
            b"problems" => BlobStoreChangeProperty::Problems,
            b"error" => BlobStoreChangeProperty::Error,
            b"action" => BlobStoreChangeProperty::Action,
            b"stage" => BlobStoreChangeProperty::Stage,
            b"target" => BlobStoreChangeProperty::Target,
            b"copiedAhead" => BlobStoreChangeProperty::CopiedAhead,
            b"appliedAt" => BlobStoreChangeProperty::AppliedAt,
            b"appliedBy" => BlobStoreChangeProperty::AppliedBy,
            b"oldStoreKept" => BlobStoreChangeProperty::OldStoreKept,
            b"cleanup" => BlobStoreChangeProperty::Cleanup,
            b"dryRun" => BlobStoreChangeProperty::DryRun,
            b"confirm" => BlobStoreChangeProperty::Confirm,
        )
    }
}

impl FromStr for BlobStoreChangeProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BlobStoreChangeProperty::parse(s).ok_or(())
    }
}

impl Element for BlobStoreChangeValue {
    type Property = BlobStoreChangeProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(BlobStoreChangeProperty::Id | BlobStoreChangeProperty::Confirm) => {
                Id::from_str(value).ok().map(BlobStoreChangeValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            BlobStoreChangeValue::Id(id) => id.to_string().into(),
        }
    }
}

impl JmapObject for BlobStoreChange {
    type Property = BlobStoreChangeProperty;

    type Element = BlobStoreChangeValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = BlobStoreChangeProperty::Id;
}

impl From<Id> for BlobStoreChangeValue {
    fn from(id: Id) -> Self {
        BlobStoreChangeValue::Id(id)
    }
}

impl JmapObjectId for BlobStoreChangeValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            BlobStoreChangeValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            BlobStoreChangeValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = BlobStoreChangeValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for BlobStoreChangeProperty {
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
