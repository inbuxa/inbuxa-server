/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Migration/get` and `/set` under `urn:inbuxa:jmap`: moving
//! accounts into this server (docs/spec/features/migrations.md). A create
//! records what to move; an update's `action` runs it. The set call's
//! `reason` argument, if given, goes into the audit log with the change.

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct Migration;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MigrationProperty {
    Id,
    Description,
    /// `imap`, `jmap`, `microsoft` or `google` (MG-2).
    SourceKind,
    /// The source's address and login, without its secret.
    Source,
    Accounts,
    /// Create the accounts this server doesn't have yet.
    CreateAccounts,
    /// Accounts moved at once.
    Parallel,
    /// `idle`, `running` or `closed`.
    Status,
    /// `preview`, `move` or `finalPass`: the run going on, or the last one.
    Run,
    /// How the last run ended (MG-6).
    Result,
    Error,
    Progress,
    /// The accounts that didn't finish, and why (MG-9).
    Failures,
    /// The node its work directory is on (MG-11).
    NodeId,
    Heartbeat,
    /// Whether a move has finished once, so a final pass makes sense.
    Moved,
    DiskUsed,
    /// Whether new accounts' passwords wait to be downloaded, once (MG-13).
    PasswordsWaiting,
    /// The last run's report, as CSV, for whoever started the migration.
    ReportBlobId,
    /// Update only: `preview`, `move`, `finalPass`, `stop` or `passwords` (MG-5).
    Action,
    /// Update only: the source's password, API key, client secret or key, kept in memory (MG-12).
    Secret,
    /// In a `passwords` update's response only.
    PasswordsBlobId,
    CreatedAt,
    CreatedBy,
    StartedAt,
    FinishedAt,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MigrationValue {
    Id(Id),
}

impl Property for MigrationProperty {
    fn try_parse(parent: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        // Keys inside source and progress stay plain keys
        match parent {
            None => MigrationProperty::parse(value),
            Some(_) => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            MigrationProperty::Id => "id",
            MigrationProperty::Description => "description",
            MigrationProperty::SourceKind => "sourceKind",
            MigrationProperty::Source => "source",
            MigrationProperty::Accounts => "accounts",
            MigrationProperty::CreateAccounts => "createAccounts",
            MigrationProperty::Parallel => "parallel",
            MigrationProperty::Status => "status",
            MigrationProperty::Run => "run",
            MigrationProperty::Result => "result",
            MigrationProperty::Error => "error",
            MigrationProperty::Progress => "progress",
            MigrationProperty::Failures => "failures",
            MigrationProperty::NodeId => "nodeId",
            MigrationProperty::Heartbeat => "heartbeat",
            MigrationProperty::Moved => "moved",
            MigrationProperty::DiskUsed => "diskUsed",
            MigrationProperty::PasswordsWaiting => "passwordsWaiting",
            MigrationProperty::ReportBlobId => "reportBlobId",
            MigrationProperty::Action => "action",
            MigrationProperty::Secret => "secret",
            MigrationProperty::PasswordsBlobId => "passwordsBlobId",
            MigrationProperty::CreatedAt => "createdAt",
            MigrationProperty::CreatedBy => "createdBy",
            MigrationProperty::StartedAt => "startedAt",
            MigrationProperty::FinishedAt => "finishedAt",
        }
        .into()
    }
}

impl MigrationProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => MigrationProperty::Id,
            b"description" => MigrationProperty::Description,
            b"sourceKind" => MigrationProperty::SourceKind,
            b"source" => MigrationProperty::Source,
            b"accounts" => MigrationProperty::Accounts,
            b"createAccounts" => MigrationProperty::CreateAccounts,
            b"parallel" => MigrationProperty::Parallel,
            b"status" => MigrationProperty::Status,
            b"run" => MigrationProperty::Run,
            b"result" => MigrationProperty::Result,
            b"error" => MigrationProperty::Error,
            b"progress" => MigrationProperty::Progress,
            b"failures" => MigrationProperty::Failures,
            b"nodeId" => MigrationProperty::NodeId,
            b"heartbeat" => MigrationProperty::Heartbeat,
            b"moved" => MigrationProperty::Moved,
            b"diskUsed" => MigrationProperty::DiskUsed,
            b"passwordsWaiting" => MigrationProperty::PasswordsWaiting,
            b"reportBlobId" => MigrationProperty::ReportBlobId,
            b"action" => MigrationProperty::Action,
            b"secret" => MigrationProperty::Secret,
            b"passwordsBlobId" => MigrationProperty::PasswordsBlobId,
            b"createdAt" => MigrationProperty::CreatedAt,
            b"createdBy" => MigrationProperty::CreatedBy,
            b"startedAt" => MigrationProperty::StartedAt,
            b"finishedAt" => MigrationProperty::FinishedAt,
        )
    }
}

impl FromStr for MigrationProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MigrationProperty::parse(s).ok_or(())
    }
}

impl Element for MigrationValue {
    type Property = MigrationProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        match key {
            Key::Property(MigrationProperty::Id) => {
                Id::from_str(value).ok().map(MigrationValue::Id)
            }
            _ => None,
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            MigrationValue::Id(id) => id.to_string().into(),
        }
    }
}

/// The set call's own argument: why, for the audit log.
#[derive(Debug, Clone, Default)]
pub struct MigrationSetArguments {
    pub reason: Option<String>,
}

impl<'de> DeserializeArguments<'de> for MigrationSetArguments {
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

impl JmapObject for Migration {
    type Property = MigrationProperty;

    type Element = MigrationValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = MigrationSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = MigrationProperty::Id;
}

impl From<Id> for MigrationValue {
    fn from(id: Id) -> Self {
        MigrationValue::Id(id)
    }
}

impl JmapObjectId for MigrationValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            MigrationValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            MigrationValue::Id(id) => Some(AnyId::Id(*id)),
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = MigrationValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for MigrationProperty {
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
