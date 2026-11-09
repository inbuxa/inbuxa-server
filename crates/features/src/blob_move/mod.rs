/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Changing the blob store (docs/spec/features/blob-store-change.md): the
//! `inbuxa:BlobStoreChange` objects. A change is recorded when a node
//! starts with its blob store somewhere else than the store last said
//! (BM-2), and keeps the old store's settings so it can be read through
//! (BM-3) and copied from (BM-5). The copy itself runs in
//! `services::inbuxa_blob_move`; this module keeps what a change is.
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`), never in the
//! registry. Every key starts with `W` (where blobs are), then one byte for
//! the kind:
//!
//! - `l`: where the blob store is now, with its settings ([`Location`]);
//! - `c` + change id (u32): a change ([`BlobStoreChange`]), as JSON;
//! - `p` + change id (u32) + number (u32): one problem its latest copy
//!   found ([`Problem`]);
//! - `r`: the id of the change being copied now (u32), so only one copy
//!   runs at a time across the server (BM-5).
//!
//! Numbers are big-endian.

use registry::schema::structs;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize, de::DeserializeOwned};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, SerializeInfallible, Store, U32_LEN,
    ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;

const FEATURE: u8 = b'W';
const KIND_LOCATION: u8 = b'l';
const KIND_CHANGE: u8 = b'c';
const KIND_PROBLEM: u8 = b'p';
const KIND_RUNNING: u8 = b'r';
const WRITE_ATTEMPTS: usize = 5;

/// The changes kept; recording another forgets the oldest resolved one.
pub const MAX_CHANGES: usize = 20;
/// BM-6: the problems a copy keeps; the counts cover all of them.
pub const MAX_PROBLEMS: u64 = 1_000;
/// BM-5: the default limits, as a store check's.
pub const DEFAULT_BLOBS_PER_SECOND: u64 = 1_000;
pub const DEFAULT_BYTES_PER_SECOND: u64 = 20 * 1024 * 1024;
/// BM-6: a copy whose node has been quiet this long has stopped.
pub const STALE_AFTER: u64 = 5 * 60;
const MAX_TEXT: usize = 2_000;

/// Where the blob store is (BM-1), with the settings that open it.
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
pub struct Location {
    pub location: String,
    pub settings: structs::BlobStore,
}

/// BM-6, BM-4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Recorded; nothing copied yet.
    Pending,
    Copying,
    /// Everything is in the new store: resolved.
    Copied,
    /// A copy ended with blobs it couldn't copy.
    Incomplete,
    Stopped,
    Failed,
    Interrupted,
    /// The blob store went back to where this change moved it from:
    /// resolved (BM-4).
    Reverted,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Copying => "copying",
            Status::Copied => "copied",
            Status::Incomplete => "incomplete",
            Status::Stopped => "stopped",
            Status::Failed => "failed",
            Status::Interrupted => "interrupted",
            Status::Reverted => "reverted",
        }
    }

    /// BM-3: whether the old store is still read through.
    pub fn is_unresolved(&self) -> bool {
        !matches!(self, Status::Copied | Status::Reverted)
    }
}

/// BM-5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProblemKind {
    Missing,
    Damaged,
    Unreadable,
}

impl ProblemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProblemKind::Missing => "missing",
            ProblemKind::Damaged => "damaged",
            ProblemKind::Unreadable => "unreadable",
        }
    }
}

/// BM-5: a blob a copy couldn't copy.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    pub kind: ProblemKind,
    /// The blob's key: a blob id as hex, or a fixed name.
    pub blob_id: String,
    /// `email`, `file`, `queuedMessage`, `archivedItem`, `temporary` or
    /// `fixed`: the first thing found holding it.
    pub holder: String,
    #[serde(default)]
    pub account_id: Option<u32>,
    #[serde(default)]
    pub object_id: Option<u64>,
    #[serde(default)]
    pub detail: String,
}

/// BM-5: how far the latest copy got.
#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Progress {
    /// Slices of the blob index done, of 256.
    pub slices: u32,
    pub blobs_checked: u64,
    pub copied: u64,
    pub already_there: u64,
    pub bytes_copied: u64,
    pub missing: u64,
    pub damaged: u64,
    pub unreadable: u64,
}

impl Progress {
    pub fn problems(&self) -> u64 {
        self.missing + self.damaged + self.unreadable
    }

    pub fn count(&mut self, kind: ProblemKind) {
        match kind {
            ProblemKind::Missing => self.missing += 1,
            ProblemKind::Damaged => self.damaged += 1,
            ProblemKind::Unreadable => self.unreadable += 1,
        }
    }

    /// 0 to 1, by slices of the index.
    pub fn share(&self) -> f64 {
        self.slices.min(256) as f64 / 256.0
    }
}

/// The latest copy of a change (BM-5, BM-6).
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Copy {
    pub started_at: u64,
    pub started_by: String,
    pub node_id: u64,
    pub blobs_per_second: u64,
    pub bytes_per_second: u64,
    /// When its node last saved it.
    pub heartbeat: u64,
    #[serde(default)]
    pub finished_at: Option<u64>,
    #[serde(default)]
    pub stop_requested: bool,
    #[serde(default)]
    pub progress: Progress,
    #[serde(default)]
    pub problems_kept: u64,
    #[serde(default)]
    pub error: Option<String>,
}

/// An `inbuxa:BlobStoreChange`.
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobStoreChange {
    pub id: u32,
    pub from: String,
    pub to: String,
    pub changed_at: u64,
    pub node_id: u64,
    pub status: Status,
    /// The old store's settings, to read it (BM-3) and copy from it (BM-5).
    /// Dropped once the change is resolved; never shown (BM-9).
    #[serde(default)]
    pub old_settings: Option<structs::BlobStore>,
    #[serde(default)]
    pub copy: Option<Copy>,
}

impl BlobStoreChange {
    /// As it reads now: a copy whose node went quiet has stopped with it
    /// (BM-6), even before anything marked it so.
    pub fn status_at(&self, now: u64) -> Status {
        match &self.copy {
            Some(copy) if self.status == Status::Copying && copy.heartbeat + STALE_AFTER < now => {
                Status::Interrupted
            }
            _ => self.status,
        }
    }

    pub fn set_error(&mut self, error: &str) {
        if let Some(copy) = &mut self.copy {
            copy.error = Some(error.trim().chars().take(MAX_TEXT).collect());
        }
    }
}

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<&T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Could not serialize a blob store change")
                .reason(err)
        })
    }
}

impl<T: DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid blob store change")
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

fn location_class() -> ValueClass {
    any(vec![FEATURE, KIND_LOCATION])
}

fn class(id: u32) -> ValueClass {
    let mut key = Vec::with_capacity(2 + U32_LEN);
    key.extend_from_slice(&[FEATURE, KIND_CHANGE]);
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

fn is_assert_failure(err: &trc::Error) -> bool {
    matches!(
        err.as_ref(),
        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
    )
}

/// A value as stored, with a hash of its bytes for a compare-and-set.
struct Versioned<T>(T, u64);

impl<T: DeserializeOwned + Sync + Send> Deserialize for Versioned<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let Json(value) = Json::<T>::deserialize(bytes)?;
        Ok(Versioned(value, xxhash_rust::xxh3::xxh3_64(bytes)))
    }
}

pub async fn get(data: &Store, id: u32) -> trc::Result<Option<BlobStoreChange>> {
    Ok(data
        .get_value::<Json<BlobStoreChange>>(ValueKey::from(class(id)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(change)| change))
}

/// Every change, oldest first.
pub async fn all(data: &Store) -> trc::Result<Vec<BlobStoreChange>> {
    let mut changes = Vec::new();
    data.iterate(
        IterateParams::new(ValueKey::from(class(0)), ValueKey::from(class(u32::MAX))),
        |_, value| {
            if let Ok(Json(change)) = Json::<BlobStoreChange>::deserialize(value) {
                changes.push(change);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    changes.sort_by_key(|c| c.id);
    Ok(changes)
}

/// BM-3, BM-10: the changes still read through, newest first.
pub async fn unresolved(data: &Store) -> trc::Result<Vec<BlobStoreChange>> {
    let mut changes = all(data).await?;
    changes.retain(|c| c.status.is_unresolved() && c.old_settings.is_some());
    changes.reverse();
    Ok(changes)
}

/// Where the store last said the blob store was.
pub async fn location(data: &Store) -> trc::Result<Option<Location>> {
    Ok(data
        .get_value::<Json<Location>>(ValueKey::from(location_class()))
        .await
        .caused_by(trc::location!())?
        .map(|Json(location)| location))
}

/// What [`at_start`] found.
#[derive(Debug, Clone, PartialEq)]
pub enum Started {
    /// The blob store is where it was, or this is the first start that
    /// records it.
    Same,
    /// This node recorded a change, the one with this id (BM-2).
    Changed(u32),
}

/// BM-2, BM-4: at start-up, records where the blob store is and, when it
/// moved, a change from where it was. The first node to start with the new
/// setting records it: the location is written only if it's still what
/// this node read, so the others find the change already there.
pub async fn at_start(
    data: &Store,
    location: String,
    settings: &structs::BlobStore,
    node_id: u64,
    now: u64,
) -> trc::Result<Started> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let last = data
            .get_value::<Versioned<Location>>(ValueKey::from(location_class()))
            .await
            .caused_by(trc::location!())?;
        let here = Location {
            location: location.clone(),
            settings: settings.clone(),
        };

        let mut batch = BatchBuilder::new();
        let mut started = Started::Same;
        let mut forgotten = Vec::new();
        match &last {
            None => {
                batch.assert_value(location_class(), AssertValue::None);
            }
            Some(Versioned(last, version)) if last.location == location => {
                if &last.settings == settings {
                    return Ok(Started::Same);
                }
                // The same place with other credentials or tuning: kept
                // current, for when it's the old store of a later change
                batch.assert_value(location_class(), AssertValue::Hash(*version));
            }
            Some(Versioned(last, version)) => {
                batch.assert_value(location_class(), AssertValue::Hash(*version));
                let changes = all(data).await?;
                let id = changes.iter().map(|c| c.id).max().unwrap_or(0) + 1;

                // BM-4: back where an unresolved change moved away from
                for earlier in changes.iter().filter(|c| {
                    c.status.is_unresolved() && c.status != Status::Copying && c.from == location
                }) {
                    let reverted = BlobStoreChange {
                        status: Status::Reverted,
                        old_settings: None,
                        ..earlier.clone()
                    };
                    batch.set(class(earlier.id), Json(&reverted).serialize()?);
                }

                let change = BlobStoreChange {
                    id,
                    from: last.location.clone(),
                    to: location.clone(),
                    changed_at: now,
                    node_id,
                    status: Status::Pending,
                    old_settings: Some(last.settings.clone()),
                    copy: None,
                };
                batch.assert_value(class(id), AssertValue::None);
                batch.set(class(id), Json(&change).serialize()?);
                started = Started::Changed(id);

                // The oldest resolved changes past MAX_CHANGES are forgotten
                let over = (changes.len() + 1).saturating_sub(MAX_CHANGES);
                for old in changes
                    .iter()
                    .filter(|c| !c.status.is_unresolved())
                    .take(over)
                {
                    batch.clear(class(old.id));
                    forgotten.push(old.id);
                }
            }
        }
        batch.set(location_class(), Json(&here).serialize()?);

        match data.write(batch.build_all()).await {
            Ok(_) => {
                for id in forgotten {
                    remove_problems(data, id).await?;
                }
                return Ok(started);
            }
            // Another node wrote first: read what it recorded
            Err(err) if attempt < WRITE_ATTEMPTS && is_assert_failure(&err) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

/// The id of the change being copied now, if any.
pub async fn running(data: &Store) -> trc::Result<Option<u32>> {
    data.get_value::<u32>(ValueKey::from(running_class()))
        .await
        .caused_by(trc::location!())
}

/// BM-5: why a copy can't start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No such change.
    NotFound,
    /// This change's copy runs now.
    Running(u32),
    /// The change is resolved, or has no old store to copy from.
    Resolved,
}

/// BM-5: marks a change as being copied by `copy` and makes it the one
/// that runs. Refused while another copy runs: one whose node went quiet
/// is marked interrupted first.
pub async fn start_copy(
    data: &Store,
    id: u32,
    copy: Copy,
    now: u64,
) -> trc::Result<Result<BlobStoreChange, Refusal>> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        if let Some(current) = running(data).await? {
            match get(data, current).await? {
                Some(c) if c.status_at(now) == Status::Copying => {
                    return Ok(Err(Refusal::Running(current)));
                }
                Some(c) => {
                    if c.status == Status::Copying {
                        update(data, current, |c| {
                            if c.status != Status::Copying {
                                return false;
                            }
                            c.status = Status::Interrupted;
                            if let Some(copy) = &mut c.copy {
                                copy.finished_at = Some(now);
                            }
                            true
                        })
                        .await?;
                    }
                    release(data, current).await?;
                }
                None => release(data, current).await?,
            }
        }

        let Some(Versioned(change, version)) = data
            .get_value::<Versioned<BlobStoreChange>>(ValueKey::from(class(id)))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(Err(Refusal::NotFound));
        };
        if !change.status.is_unresolved() || change.old_settings.is_none() {
            return Ok(Err(Refusal::Resolved));
        }
        let change = BlobStoreChange {
            status: Status::Copying,
            copy: Some(copy.clone()),
            ..change
        };
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(id), AssertValue::Hash(version));
        batch.assert_value(running_class(), AssertValue::None);
        batch.set(class(id), Json(&change).serialize()?);
        batch.set(running_class(), SerializeInfallible::serialize(&id));
        match data.write(batch.build_all()).await {
            Ok(_) => {
                remove_problems(data, id).await?;
                return Ok(Ok(change));
            }
            Err(err) if attempt < WRITE_ATTEMPTS && is_assert_failure(&err) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

/// Lets another copy run, if `id` is the one that runs now.
pub async fn release(data: &Store, id: u32) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.assert_value(running_class(), AssertValue::U32(id));
    batch.clear(running_class());
    match data.write(batch.build_all()).await {
        Ok(_) => Ok(()),
        Err(err) if is_assert_failure(&err) => Ok(()),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

/// Reads a change, changes it with `change`, and writes it back, again if
/// something else wrote it in between. `change` returns false to leave it
/// as it is. None if there's no such change.
pub async fn update<F>(data: &Store, id: u32, mut change: F) -> trc::Result<Option<BlobStoreChange>>
where
    F: FnMut(&mut BlobStoreChange) -> bool,
{
    loop {
        let Some(Versioned(mut stored, version)) = data
            .get_value::<Versioned<BlobStoreChange>>(ValueKey::from(class(id)))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };
        if !change(&mut stored) {
            return Ok(Some(stored));
        }
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(id), AssertValue::Hash(version));
        batch.set(class(id), Json(&stored).serialize()?);
        match data.write(batch.build_all()).await {
            Ok(_) => return Ok(Some(stored)),
            Err(err) if is_assert_failure(&err) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

/// Keeps problems `first..` of a change's copy (BM-6): the caller numbers
/// them and stops at [`MAX_PROBLEMS`].
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

/// The kept problems of a change's latest copy, in the order found.
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

async fn remove_problems(data: &Store, id: u32) -> trc::Result<()> {
    data.delete_range(
        ValueKey::from(problem_class(id, 0)),
        ValueKey::from(problem_class(id, u32::MAX)),
    )
    .await
    .caused_by(trc::location!())
}

/// BM-7: forgets a change, the old store's settings and its problems.
pub async fn remove(data: &Store, id: u32) -> trc::Result<()> {
    remove_problems(data, id).await?;
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

    fn fs(path: &str) -> structs::BlobStore {
        structs::BlobStore::FileSystem(structs::FileSystemStore {
            path: path.into(),
            depth: 2,
        })
    }

    #[tokio::test]
    async fn a_move_and_a_move_back() {
        let data = store::backend::ephemeral::EphemeralStore::open();
        let a = structs::BlobStore::Default;
        let b = fs("/srv/blobs");
        let (here_a, here_b) = ("the data store".to_string(), "dir".to_string());

        // First start: only where it is
        assert_eq!(
            at_start(&data, here_a.clone(), &a, 1, 10).await.unwrap(),
            Started::Same
        );
        assert_eq!(
            at_start(&data, here_a.clone(), &a, 2, 11).await.unwrap(),
            Started::Same
        );
        assert!(all(&data).await.unwrap().is_empty());

        // A to B: one change, recorded once whichever node starts first
        assert_eq!(
            at_start(&data, here_b.clone(), &b, 1, 20).await.unwrap(),
            Started::Changed(1)
        );
        assert_eq!(
            at_start(&data, here_b.clone(), &b, 2, 21).await.unwrap(),
            Started::Same
        );
        let first = get(&data, 1).await.unwrap().unwrap();
        assert_eq!(
            (first.from.as_str(), first.to.as_str()),
            ("the data store", "dir")
        );
        assert_eq!(first.old_settings, Some(a.clone()));
        assert_eq!(first.status, Status::Pending);

        // Back to A: the first change is reverted, the second is the one
        // still read through
        assert_eq!(
            at_start(&data, here_a.clone(), &a, 1, 30).await.unwrap(),
            Started::Changed(2)
        );
        let first = get(&data, 1).await.unwrap().unwrap();
        assert_eq!(first.status, Status::Reverted);
        assert_eq!(first.old_settings, None);
        let open = unresolved(&data).await.unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, 2);
        assert_eq!(open[0].old_settings, Some(b.clone()));

        // A copy: one at a time, never of a resolved change
        let copy = Copy {
            started_at: 40,
            started_by: "admin".into(),
            node_id: 1,
            blobs_per_second: 0,
            bytes_per_second: 0,
            heartbeat: 40,
            finished_at: None,
            stop_requested: false,
            progress: Progress::default(),
            problems_kept: 0,
            error: None,
        };
        assert_eq!(
            start_copy(&data, 1, copy.clone(), 40).await.unwrap(),
            Err(Refusal::Resolved)
        );
        assert_eq!(
            start_copy(&data, 9, copy.clone(), 40).await.unwrap(),
            Err(Refusal::NotFound)
        );
        let started = start_copy(&data, 2, copy.clone(), 40)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(started.status, Status::Copying);
        assert_eq!(
            start_copy(&data, 2, copy.clone(), 41).await.unwrap(),
            Err(Refusal::Running(2))
        );
        // Its node went quiet: interrupted, and another may start
        let again = start_copy(&data, 2, copy.clone(), 41 + STALE_AFTER)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again.status, Status::Copying);

        // Finished: resolved, nothing read through any more
        update(&data, 2, |c| {
            c.status = Status::Copied;
            c.old_settings = None;
            true
        })
        .await
        .unwrap();
        release(&data, 2).await.unwrap();
        assert!(unresolved(&data).await.unwrap().is_empty());
        assert_eq!(running(&data).await.unwrap(), None);

        // Where it was, again: nothing new
        assert_eq!(
            at_start(&data, here_a.clone(), &a, 1, 50).await.unwrap(),
            Started::Same
        );
        remove(&data, 2).await.unwrap();
        assert!(get(&data, 2).await.unwrap().is_none());
    }

    #[test]
    fn keys_stay_in_their_own_letter() {
        for class in [
            location_class(),
            class(1),
            problem_class(1, 0),
            running_class(),
        ] {
            let ValueClass::Any(any) = class else {
                unreachable!()
            };
            assert_eq!(any.key[0], b'W');
        }
    }

    #[test]
    fn resolved_is_copied_or_reverted() {
        for status in [
            Status::Pending,
            Status::Copying,
            Status::Incomplete,
            Status::Stopped,
            Status::Failed,
            Status::Interrupted,
        ] {
            assert!(status.is_unresolved(), "{status:?}");
        }
        assert!(!Status::Copied.is_unresolved());
        assert!(!Status::Reverted.is_unresolved());
    }

    #[test]
    fn a_quiet_copy_reads_as_interrupted() {
        let change = BlobStoreChange {
            id: 1,
            from: "the data store".into(),
            to: "the directory /srv/blobs, depth 2".into(),
            changed_at: 1_000,
            node_id: 1,
            status: Status::Copying,
            old_settings: Some(structs::BlobStore::Default),
            copy: Some(Copy {
                started_at: 1_000,
                started_by: "admin".into(),
                node_id: 1,
                blobs_per_second: 0,
                bytes_per_second: 0,
                heartbeat: 1_000,
                finished_at: None,
                stop_requested: false,
                progress: Progress::default(),
                problems_kept: 0,
                error: None,
            }),
        };
        assert_eq!(change.status_at(1_000 + STALE_AFTER), Status::Copying);
        assert_eq!(change.status_at(1_001 + STALE_AFTER), Status::Interrupted);
    }

    #[test]
    fn a_change_keeps_the_old_settings_as_json() {
        let change = BlobStoreChange {
            id: 2,
            from: "the directory /srv/blobs, depth 2".into(),
            to: "the data store".into(),
            changed_at: 5,
            node_id: 1,
            status: Status::Pending,
            old_settings: Some(fs("/srv/blobs")),
            copy: None,
        };
        let bytes = Json(&change).serialize().unwrap();
        let Json(back) = Json::<BlobStoreChange>::deserialize(&bytes).unwrap();
        assert_eq!(back, change);
    }
}
