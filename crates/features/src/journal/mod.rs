/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Journaling (journaling spec, JR-1 to JR-18): a copy of each message the
//! server queues, with its envelope, kept where nothing in the product
//! changes or removes it before its retention ends.
//!
//! - this module: journals, what makes one valid, and where they're kept;
//! - [`report`]: the journal report around the untouched message (JR-3);
//! - [`entries`]: the built-in journal and its chain (JR-5, JR-6, JR-13).
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`). Every key starts
//! with `J`; journals are `j` + id (u32), as JSON. There are few, so they're
//! read whole.

pub mod archive;
pub mod entries;
pub mod report;

use crate::{hold::Member, mailflow::rules::jmap_ids};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize, de::DeserializeOwned};
use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;

pub(crate) const FEATURE: u8 = b'J';
const KIND_JOURNAL: u8 = b'j';
const CREATE_ATTEMPTS: usize = 5;

/// Retention a journal may be given, in days (settled answer 3).
pub const MIN_RETENTION_DAYS: u32 = 30;
pub const MAX_RETENTION_DAYS: u32 = 3650;
/// Most entries in one scope list.
const MAX_LIST: usize = 5_000;

/// Which way a message goes, from this server's side (JR-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    /// From someone here to at least one recipient elsewhere.
    Outgoing,
    /// From elsewhere to someone here.
    Incoming,
    /// From someone here, to people here only.
    Internal,
    Any,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Outgoing => "outgoing",
            Direction::Incoming => "incoming",
            Direction::Internal => "internal",
            Direction::Any => "any",
        }
    }

    /// A message's direction: `Any` is never one.
    pub fn of(sender_local: bool, any_remote: bool, any_local: bool) -> Direction {
        match (sender_local, any_remote) {
            (true, true) => Direction::Outgoing,
            (true, false) => Direction::Internal,
            (false, _) if any_local => Direction::Incoming,
            // Nobody here on either side: relayed mail counts as outgoing
            (false, _) => Direction::Outgoing,
        }
    }

    fn includes(&self, direction: Direction) -> bool {
        *self == Direction::Any || *self == direction
    }
}

/// Whose mail a journal takes (JR-9): everyone, or people reached through
/// their account, domain, group or tenant. Ids are in the JMAP form.
#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scope {
    #[serde(default)]
    pub everyone: bool,
    #[serde(default, with = "jmap_ids")]
    pub accounts: Vec<u32>,
    #[serde(default, with = "jmap_ids")]
    pub groups: Vec<u32>,
    #[serde(default, with = "jmap_ids")]
    pub domains: Vec<u32>,
    #[serde(default, with = "jmap_ids")]
    pub tenants: Vec<u32>,
}

impl Scope {
    fn lists(&self) -> [&Vec<u32>; 4] {
        [&self.accounts, &self.groups, &self.domains, &self.tenants]
    }

    /// Whether this scope reaches one person here.
    pub fn covers(&self, member: &Member) -> bool {
        self.everyone
            || self.accounts.contains(&member.account)
            || member.domains.iter().any(|d| self.domains.contains(d))
            || member.groups.iter().any(|g| self.groups.contains(g))
            || member.tenant.is_some_and(|t| self.tenants.contains(&t))
    }
}

/// A journal (JR-9): what it takes, and how long its entries are kept.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Journal {
    #[serde(default)]
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub enabled: bool,
    pub direction: Direction,
    pub scope: Scope,
    /// How long an entry this journal writes is kept. An entry keeps the
    /// retention it was written with (JR-12).
    pub retention_days: u32,
    /// Whether entries go into the built-in journal (JR-5).
    #[serde(default = "yes")]
    pub built_in: bool,
    /// An outside archive's journal address, sent each report (JR-7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_address: Option<String>,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
}

/// Why a journal was refused: the property, and what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    pub property: &'static str,
    pub reason: String,
}

fn invalid(property: &'static str, reason: impl Into<String>) -> Result<(), Invalid> {
    Err(Invalid {
        property,
        reason: reason.into(),
    })
}

impl Journal {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.name.trim().is_empty() {
            return invalid("name", "Give the journal a name.");
        }
        if self.name.len() > 200 || self.description.len() > 2_000 {
            return invalid("name", "The name or description is too long.");
        }
        if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&self.retention_days) {
            return invalid(
                "retentionDays",
                format!("Keep entries between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS} days."),
            );
        }
        // Neither is a journal only rules send mail to (JR-10)
        let chosen = self.scope.lists().iter().any(|list| !list.is_empty());
        if self.scope.everyone && chosen {
            return invalid(
                "scope",
                "Journal everyone, or choose accounts, groups, domains or tenants; not both.",
            );
        }
        if !self.built_in && self.archive_address.is_none() {
            return invalid(
                "builtIn",
                "Keep entries in the built-in journal, send them to an archive, or both.",
            );
        }
        if let Some(address) = &self.archive_address
            && !is_address(address)
        {
            return invalid(
                "archiveAddress",
                format!("\"{address}\" isn't an email address."),
            );
        }
        if self.scope.lists().iter().any(|list| list.len() > MAX_LIST) {
            return invalid("scope", format!("Choose at most {MAX_LIST} of each."));
        }
        Ok(())
    }

    /// Whether this journal takes a message going `direction` with these
    /// people here on either side.
    /// Whether only rules send this journal mail (JR-10).
    pub fn rules_only(&self) -> bool {
        !self.scope.everyone && self.scope.lists().iter().all(|list| list.is_empty())
    }

    pub fn takes(&self, direction: Direction, members: &[Member]) -> bool {
        self.enabled
            && self.direction.includes(direction)
            && (self.scope.everyone || members.iter().any(|m| self.scope.covers(m)))
    }
}

fn yes() -> bool {
    true
}

/// An address an archive can be sent to: one `@`, something either side,
/// nothing that would break an envelope.
fn is_address(address: &str) -> bool {
    address.len() <= 320
        && address.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.contains('@')
        })
        && !address
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | ';'))
}

/// A value stored as JSON.
pub(crate) struct Json<T>(pub T);

impl<T: SerdeSerialize> Serialize for Json<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(&self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to serialize a journal record")
                .reason(err)
        })
    }
}

impl<T: DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid journal record")
                .reason(err)
        })
    }
}

fn class(id: u32) -> ValueClass {
    let mut key = Vec::with_capacity(6);
    key.push(FEATURE);
    key.push(KIND_JOURNAL);
    key.extend_from_slice(&id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

fn key(id: u32) -> ValueKey<ValueClass> {
    ValueKey::from(class(id))
}

pub async fn get(data: &Store, id: u32) -> trc::Result<Option<Journal>> {
    Ok(data
        .get_value::<Json<Journal>>(key(id))
        .await
        .caused_by(trc::location!())?
        .map(|Json(journal)| journal))
}

/// Every journal, oldest first.
pub async fn all(data: &Store) -> trc::Result<Vec<Journal>> {
    let mut journals = Vec::new();
    data.iterate(IterateParams::new(key(0), key(u32::MAX)), |_, value| {
        if let Ok(Json(journal)) = Json::<Journal>::deserialize(value) {
            journals.push(journal);
        }
        Ok(true)
    })
    .await
    .caused_by(trc::location!())?;
    journals.sort_by_key(|journal| journal.id);
    Ok(journals)
}

/// Writes a new journal under the next free id, which it returns.
pub async fn create(data: &Store, journal: &Journal) -> trc::Result<u32> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let id = all(data).await?.iter().map(|j| j.id).max().unwrap_or(0) + 1;
        let stored = Journal {
            id,
            ..journal.clone()
        };
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(id), AssertValue::None);
        batch.set(class(id), Json(&stored).serialize()?);
        match data.write(batch.build_all()).await {
            Ok(_) => {
                invalidate();
                return Ok(id);
            }
            Err(err)
                if attempt < CREATE_ATTEMPTS
                    && matches!(
                        err.as_ref(),
                        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                    ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

/// Replaces a stored journal (same id).
pub async fn update(data: &Store, journal: &Journal) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(class(journal.id), Json(journal).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    invalidate();
    Ok(())
}

/// Removes a journal. Its entries stay, each until its own time.
pub async fn delete(data: &Store, id: u32) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.clear(class(id));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    invalidate();
    Ok(())
}

/// How long a node keeps its copy of the journals before reading them again.
pub const TTL: Duration = Duration::from_secs(30);

type Cached = Option<(Instant, Arc<Vec<Journal>>)>;
static CACHE: RwLock<Cached> = RwLock::new(None);

/// Forgets this node's copy, so the next message reads the journals again.
pub fn invalidate() {
    if let Ok(mut cache) = CACHE.write() {
        *cache = None;
    }
}

/// The enabled journals, from this node's copy (refreshed every [`TTL`]).
pub async fn enabled(data: &Store) -> trc::Result<Arc<Vec<Journal>>> {
    if let Ok(cache) = CACHE.read()
        && let Some((at, journals)) = cache.as_ref()
        && at.elapsed() < TTL
    {
        return Ok(journals.clone());
    }
    let journals = Arc::new(
        all(data)
            .await?
            .into_iter()
            .filter(|journal| journal.enabled)
            .collect::<Vec<_>>(),
    );
    if let Ok(mut cache) = CACHE.write() {
        *cache = Some((Instant::now(), journals.clone()));
    }
    Ok(journals)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal(scope: Scope) -> Journal {
        Journal {
            id: 1,
            name: "Finance".into(),
            description: String::new(),
            enabled: true,
            direction: Direction::Any,
            scope,
            retention_days: 365,
            built_in: true,
            archive_address: None,
            created_by: String::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    fn member(account: u32, groups: Vec<u32>) -> Member {
        Member {
            account,
            domains: vec![1],
            groups,
            tenant: None,
        }
    }

    #[test]
    fn scope_is_everyone_or_chosen() {
        assert!(
            journal(Scope {
                everyone: true,
                ..Default::default()
            })
            .validate()
            .is_ok()
        );
        // Nobody chosen: only rules send it mail
        let rules_only = journal(Scope::default());
        assert!(rules_only.validate().is_ok());
        assert!(rules_only.rules_only());
        assert!(!rules_only.takes(Direction::Any, &[member(3, vec![7])]));
        let both = Scope {
            everyone: true,
            groups: vec![4],
            ..Default::default()
        };
        assert_eq!(journal(both).validate().unwrap_err().property, "scope");
    }

    #[test]
    fn destinations() {
        let mut j = journal(Scope {
            everyone: true,
            ..Default::default()
        });
        j.built_in = false;
        assert_eq!(j.validate().unwrap_err().property, "builtIn");
        j.archive_address = Some("journal@archive.example".into());
        assert!(j.validate().is_ok());
        for bad in [
            "archive",
            "a@b",
            "a b@c.example",
            "<a@c.example>",
            "a@b@c.example",
        ] {
            j.archive_address = Some(bad.into());
            assert_eq!(
                j.validate().unwrap_err().property,
                "archiveAddress",
                "{bad}"
            );
        }
        // Stored before destinations existed: the built-in journal
        let old: Journal = serde_json::from_str(
            r#"{"name":"Old","direction":"any","scope":{"everyone":true},"retentionDays":30}"#,
        )
        .unwrap();
        assert!(old.built_in && old.archive_address.is_none());
    }

    #[test]
    fn retention_has_bounds() {
        let mut j = journal(Scope {
            everyone: true,
            ..Default::default()
        });
        j.retention_days = 29;
        assert_eq!(j.validate().unwrap_err().property, "retentionDays");
        j.retention_days = 3651;
        assert!(j.validate().is_err());
        j.retention_days = 3650;
        assert!(j.validate().is_ok());
    }

    #[test]
    fn takes_by_direction_and_member() {
        let mut j = journal(Scope {
            groups: vec![7],
            ..Default::default()
        });
        assert!(j.takes(Direction::Outgoing, &[member(3, vec![7])]));
        assert!(!j.takes(Direction::Outgoing, &[member(3, vec![8])]));
        assert!(!j.takes(Direction::Outgoing, &[]));
        j.direction = Direction::Incoming;
        assert!(!j.takes(Direction::Outgoing, &[member(3, vec![7])]));
        j.enabled = false;
        assert!(!j.takes(Direction::Incoming, &[member(3, vec![7])]));
    }

    #[test]
    fn directions() {
        assert_eq!(Direction::of(true, true, true), Direction::Outgoing);
        assert_eq!(Direction::of(true, false, true), Direction::Internal);
        assert_eq!(Direction::of(false, false, true), Direction::Incoming);
        assert_eq!(Direction::of(false, true, true), Direction::Incoming);
    }

    #[test]
    fn scope_ids_are_jmap_ids() {
        let scope: Scope = serde_json::from_str(r#"{"groups":["b"],"tenants":[7]}"#).unwrap();
        assert_eq!(scope.groups, vec![1]);
        assert_eq!(scope.tenants, vec![7]);
        assert_eq!(
            serde_json::to_value(&scope).unwrap()["tenants"],
            serde_json::json!(["h"])
        );
    }
}
