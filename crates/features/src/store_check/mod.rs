/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Checking the store's blobs (docs/spec/features/store-check.md): the
//! `inbuxa:StoreCheck` objects. A check reports which blobs the server's
//! data needs and doesn't have, and changes nothing. The check itself runs
//! in `services::inbuxa_store_check`; this module keeps what a check is and
//! what it found.
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`), never in the
//! registry (SV-1). Every key starts with `V` (verify), then one byte for
//! the kind:
//!
//! - `c` + check id (u32): a check ([`StoreCheck`]), as JSON;
//! - `p` + check id (u32) + number (u32): one of its problems ([`Problem`]),
//!   as JSON, kept apart so a check stays small however much it found;
//! - `r`: the id of the check that runs now (u32), so only one runs at a
//!   time across the server (SV-2).
//!
//! `Vs` is the store's version (`common::INBUXA_STORE_VERSION_KEY`), so no
//! kind here is `s`. Numbers are big-endian.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize, de::DeserializeOwned};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, SerializeInfallible, Store, U32_LEN,
    ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;

const FEATURE: u8 = b'V';
const KIND_CHECK: u8 = b'c';
const KIND_PROBLEM: u8 = b'p';
const KIND_RUNNING: u8 = b'r';
const CREATE_ATTEMPTS: usize = 5;

/// SV-1: the checks kept; starting another forgets the oldest.
pub const MAX_CHECKS: usize = 20;
/// SV-5: the problems a check keeps; the counts cover all of them.
pub const MAX_PROBLEMS: u64 = 1_000;
/// SV-6: the default limits.
pub const DEFAULT_BLOBS_PER_SECOND: u64 = 1_000;
pub const DEFAULT_BYTES_PER_SECOND: u64 = 20 * 1024 * 1024;
/// SV-8: a running check whose node has been quiet this long has stopped.
pub const STALE_AFTER: u64 = 5 * 60;
const MAX_TEXT: usize = 2_000;

/// SV-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Quick,
    Full,
}

impl Mode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "quick" => Some(Mode::Quick),
            "full" => Some(Mode::Full),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Quick => "quick",
            Mode::Full => "full",
        }
    }
}

/// SV-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Running,
    Done,
    Stopped,
    Failed,
    Interrupted,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Running => "running",
            Status::Done => "done",
            Status::Stopped => "stopped",
            Status::Failed => "failed",
            Status::Interrupted => "interrupted",
        }
    }
}

/// SV-4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProblemKind {
    Missing,
    Damaged,
    Unlinked,
    Unreadable,
}

impl ProblemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProblemKind::Missing => "missing",
            ProblemKind::Damaged => "damaged",
            ProblemKind::Unlinked => "unlinked",
            ProblemKind::Unreadable => "unreadable",
        }
    }
}

/// SV-4: one blob something needs and can't have, as it was found.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    pub kind: ProblemKind,
    /// None for a queued message, which belongs to no account.
    pub account_id: Option<u32>,
    #[serde(default)]
    pub account_name: String,
    /// `email`, `file`, `queuedMessage`, ... (SV-4).
    pub object: String,
    /// The object's id: a document id, a queue id or an archived item's id.
    pub object_id: u64,
    /// The blob id, as hex.
    pub blob_id: String,
    /// Whether the store still has the blob's commit marker.
    pub committed: bool,
    #[serde(default)]
    pub detail: String,
}

/// SV-7: how far a check got and what it found.
#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Progress {
    /// Slices of the blob index done, of 256.
    pub slices: u32,
    pub blobs_checked: u64,
    pub links_checked: u64,
    pub bytes_read: u64,
    pub messages_checked: u64,
    /// Accounts whose mail metadata is checked, of how many (SV-3).
    pub accounts_done: u64,
    pub accounts_total: u64,
    pub missing: u64,
    pub damaged: u64,
    pub unlinked: u64,
    pub unreadable: u64,
}

impl Progress {
    pub fn problems(&self) -> u64 {
        self.missing + self.damaged + self.unlinked + self.unreadable
    }

    pub fn count(&mut self, kind: ProblemKind) {
        match kind {
            ProblemKind::Missing => self.missing += 1,
            ProblemKind::Damaged => self.damaged += 1,
            ProblemKind::Unlinked => self.unlinked += 1,
            ProblemKind::Unreadable => self.unreadable += 1,
        }
    }

    /// 0 to 1: the 256 slices are the first 90%, the mail metadata after
    /// them the rest. A finished check is 1.
    pub fn share(&self, status: Status) -> f64 {
        if status == Status::Done {
            return 1.0;
        }
        let slices = self.slices.min(256) as f64 / 256.0;
        let accounts = if self.accounts_total == 0 {
            0.0
        } else {
            self.accounts_done.min(self.accounts_total) as f64 / self.accounts_total as f64
        };
        slices * 0.9 + accounts * 0.1
    }
}

/// An `inbuxa:StoreCheck` (SV-1).
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreCheck {
    pub id: u32,
    pub mode: Mode,
    pub blobs_per_second: u64,
    pub bytes_per_second: u64,
    pub status: Status,
    pub created_at: u64,
    pub created_by: String,
    pub finished_at: Option<u64>,
    /// The node it runs on.
    pub node_id: u64,
    /// When its node last saved it (SV-7, SV-8).
    pub heartbeat: u64,
    /// SV-8: an administrator asked it to stop; the running node sees it at
    /// its next save.
    #[serde(default)]
    pub stop_requested: bool,
    #[serde(default)]
    pub progress: Progress,
    /// Problems kept, at most [`MAX_PROBLEMS`].
    #[serde(default)]
    pub problems_kept: u64,
    #[serde(default)]
    pub error: Option<String>,
}

impl StoreCheck {
    pub fn new(mode: Mode, created_by: String, node_id: u64, now: u64) -> Self {
        StoreCheck {
            id: 0,
            mode,
            blobs_per_second: DEFAULT_BLOBS_PER_SECOND,
            bytes_per_second: DEFAULT_BYTES_PER_SECOND,
            status: Status::Running,
            created_at: now,
            created_by,
            finished_at: None,
            node_id,
            heartbeat: now,
            stop_requested: false,
            progress: Progress::default(),
            problems_kept: 0,
            error: None,
        }
    }

    /// SV-8: as it reads now. A running check whose node went quiet has
    /// stopped with it, even before anything marked it so.
    pub fn status_at(&self, now: u64) -> Status {
        if self.status == Status::Running && self.heartbeat + STALE_AFTER < now {
            Status::Interrupted
        } else {
            self.status
        }
    }

    pub fn set_error(&mut self, error: &str) {
        self.error = Some(error.trim().chars().take(MAX_TEXT).collect());
    }
}

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<&T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Could not serialize a store check")
                .reason(err)
        })
    }
}

impl<T: DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid store check")
                .reason(err)
        })
    }
}

fn any(key: Vec<u8>) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

fn class(id: u32) -> ValueClass {
    let mut key = Vec::with_capacity(2 + U32_LEN);
    key.extend_from_slice(&[FEATURE, KIND_CHECK]);
    key.extend_from_slice(&id.to_be_bytes());
    any(key)
}

fn problem_class(id: u32, number: u32) -> ValueClass {
    let mut key = Vec::with_capacity(2 + U32_LEN * 2);
    key.extend_from_slice(&[FEATURE, KIND_PROBLEM]);
    key.extend_from_slice(&id.to_be_bytes());
    key.extend_from_slice(&number.to_be_bytes());
    any(key)
}

fn running_class() -> ValueClass {
    any(vec![FEATURE, KIND_RUNNING])
}

pub async fn get(data: &Store, id: u32) -> trc::Result<Option<StoreCheck>> {
    Ok(data
        .get_value::<Json<StoreCheck>>(ValueKey::from(class(id)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(check)| check))
}

/// Every check, oldest first.
pub async fn all(data: &Store) -> trc::Result<Vec<StoreCheck>> {
    let mut checks = Vec::new();
    data.iterate(
        IterateParams::new(ValueKey::from(class(0)), ValueKey::from(class(u32::MAX))),
        |_, value| {
            if let Ok(Json(check)) = Json::<StoreCheck>::deserialize(value) {
                checks.push(check);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    checks.sort_by_key(|c| c.id);
    Ok(checks)
}

/// The id of the check that runs now, if any.
pub async fn running(data: &Store) -> trc::Result<Option<u32>> {
    Ok(data
        .get_value::<u32>(ValueKey::from(running_class()))
        .await
        .caused_by(trc::location!())?)
}

/// SV-2: why a check can't start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// This check runs now.
    Running(u32),
}

/// Writes a new check under the next free id, which it returns, and makes
/// it the one that runs. Refused while another runs (SV-2): a running
/// check whose node went quiet is marked interrupted first (SV-8). The
/// oldest checks past [`MAX_CHECKS`] are forgotten (SV-1).
pub async fn create(
    data: &Store,
    check: &StoreCheck,
    now: u64,
) -> trc::Result<Result<u32, Refusal>> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let checks = all(data).await?;
        let current = running(data).await?;
        if let Some(current) = current {
            match checks.iter().find(|c| c.id == current) {
                Some(c) if c.status_at(now) == Status::Running => {
                    return Ok(Err(Refusal::Running(current)));
                }
                _ => {
                    // Gone, finished or quiet: it no longer holds the place
                    if let Some(c) = checks.iter().find(|c| c.id == current)
                        && c.status == Status::Running
                    {
                        update(data, current, |c| {
                            if c.status != Status::Running {
                                return false;
                            }
                            c.status = Status::Interrupted;
                            c.finished_at = Some(now);
                            true
                        })
                        .await?;
                    }
                    release(data, current).await?;
                }
            }
        }

        let id = checks.iter().map(|c| c.id).max().unwrap_or(0) + 1;
        let stored = StoreCheck {
            id,
            ..check.clone()
        };
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(id), AssertValue::None);
        batch.assert_value(running_class(), AssertValue::None);
        batch.set(class(id), Json(&stored).serialize()?);
        batch.set(running_class(), SerializeInfallible::serialize(&id));
        match data.write(batch.build_all()).await {
            Ok(_) => {
                // SV-1: the newest MAX_CHECKS stay
                let mut checks = checks;
                checks.push(stored);
                let over = checks.len().saturating_sub(MAX_CHECKS);
                for old in checks.iter().take(over) {
                    if old.status != Status::Running {
                        remove(data, old.id).await?;
                    }
                }
                return Ok(Ok(id));
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

/// Lets another check run, if `id` is the one that runs now.
pub async fn release(data: &Store, id: u32) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.assert_value(running_class(), AssertValue::U32(id));
    batch.clear(running_class());
    match data.write(batch.build_all()).await {
        Ok(_) => Ok(()),
        Err(err)
            if matches!(
                err.as_ref(),
                trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
            ) =>
        {
            Ok(())
        }
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

/// A check as stored, with the version [`replace`] checks: a hash of the
/// stored bytes.
struct Versioned(StoreCheck, u64);

impl Deserialize for Versioned {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let Json(check) = Json::<StoreCheck>::deserialize(bytes)?;
        Ok(Versioned(check, xxhash_rust::xxh3::xxh3_64(bytes)))
    }
}

async fn get_versioned(data: &Store, id: u32) -> trc::Result<Option<(StoreCheck, u64)>> {
    Ok(data
        .get_value::<Versioned>(ValueKey::from(class(id)))
        .await
        .caused_by(trc::location!())?
        .map(|Versioned(check, version)| (check, version)))
}

/// Reads a check, changes it with `change`, and writes it back, again if
/// something else wrote it in between (the running node saving progress
/// while an administrator stops it). `change` returns false to leave it as
/// it is. None if there's no such check.
pub async fn update<F>(data: &Store, id: u32, mut change: F) -> trc::Result<Option<StoreCheck>>
where
    F: FnMut(&mut StoreCheck) -> bool,
{
    loop {
        let Some((mut check, version)) = get_versioned(data, id).await? else {
            return Ok(None);
        };
        if !change(&mut check) {
            return Ok(Some(check));
        }
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(id), AssertValue::Hash(version));
        batch.set(class(id), Json(&check).serialize()?);
        match data.write(batch.build_all()).await {
            Ok(_) => return Ok(Some(check)),
            Err(err)
                if matches!(
                    err.as_ref(),
                    trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

/// Keeps problems `first..` of a check (SV-5): the caller numbers them and
/// stops at [`MAX_PROBLEMS`].
pub async fn add_problems(
    data: &Store,
    id: u32,
    first: u64,
    problems: &[Problem],
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    for (n, problem) in problems.iter().enumerate() {
        let number = u32::try_from(first + n as u64).unwrap_or(u32::MAX);
        batch.set(problem_class(id, number), Json(problem).serialize()?);
        if batch.is_large_batch() {
            data.write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            batch = BatchBuilder::new();
        }
    }
    if !batch.is_empty() {
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }
    Ok(())
}

/// A check's kept problems, in the order they were found.
pub async fn problems(data: &Store, id: u32) -> trc::Result<Vec<Problem>> {
    let mut problems = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey::from(problem_class(id, 0)),
            ValueKey::from(problem_class(id, u32::MAX)),
        ),
        |_, value| {
            if let Ok(Json(problem)) = Json::<Problem>::deserialize(value) {
                problems.push(problem);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(problems)
}

/// Forgets a check and its problems (SV-1, SV-10).
pub async fn remove(data: &Store, id: u32) -> trc::Result<()> {
    data.delete_range(
        ValueKey::from(problem_class(id, 0)),
        ValueKey::from(problem_class(id, u32::MAX)),
    )
    .await
    .caused_by(trc::location!())?;
    let mut batch = BatchBuilder::new();
    batch.clear(class(id));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_stay_clear_of_the_store_version() {
        for class in [class(1), problem_class(1, 0), running_class()] {
            let ValueClass::Any(any) = class else {
                unreachable!()
            };
            assert_eq!(any.key[0], b'V');
            assert_ne!(any.key[1], b's');
        }
    }

    #[test]
    fn a_quiet_check_reads_as_interrupted() {
        let check = StoreCheck::new(Mode::Quick, "admin".into(), 1, 1_000);
        assert_eq!(check.status_at(1_000 + STALE_AFTER), Status::Running);
        assert_eq!(check.status_at(1_001 + STALE_AFTER), Status::Interrupted);
        let done = StoreCheck {
            status: Status::Done,
            ..check
        };
        assert_eq!(done.status_at(u64::MAX / 2), Status::Done);
    }

    #[test]
    fn problems_round_trip_as_json() {
        let problem = Problem {
            kind: ProblemKind::Missing,
            account_id: Some(3),
            account_name: "ann@example.org".into(),
            object: "email".into(),
            object_id: 7,
            blob_id: "ab".into(),
            committed: true,
            detail: String::new(),
        };
        let bytes = Json(&problem).serialize().unwrap();
        let Json(back) = Json::<Problem>::deserialize(&bytes).unwrap();
        assert_eq!(back, problem);
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains("\"accountId\":3")
        );
    }
}
