/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Changing the blob store (docs/spec/features/blob-store-change.md): the
//! `inbuxa:BlobStoreChange` objects. A change is recorded when a node
//! starts with its blob store somewhere else than the store last said
//! (BM-2), and keeps the old store's settings so it can be read through
//! (BM-3) and copied from (BM-5). A change can also be planned before the
//! setting moves, with the new store's settings, and copied ahead
//! (docs/spec/features/blob-store-copy-ahead.md). Once resolved, its old
//! store's settings are kept so the blobs left there can be cleaned up
//! (docs/spec/features/blob-store-cleanup.md). The copy and the cleanup run
//! in `services::inbuxa_blob_move`; this module keeps what a change is.
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`), never in the
//! registry. Every key starts with `W` (where blobs are), then one byte for
//! the kind:
//!
//! - `l`: where the blob store is now, with its settings ([`Location`]);
//! - `c` + change id (u32): a change ([`BlobStoreChange`]), as JSON;
//! - `p` + change id (u32) + number (u32): one problem its latest copy
//!   found ([`Problem`]);
//! - `r`: the id of the change being copied or cleaned up now (u32), so
//!   only one runs at a time across the server (BM-5, OC-3);
//! - `n` + node id (u64): where that node's blob store is, and when it last
//!   said so ([`NodePlace`], OC-2).
//!
//! Numbers are big-endian.

use registry::schema::structs;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize, de::DeserializeOwned};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, SerializeInfallible, Store, U32_LEN,
    U64_LEN, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;

const FEATURE: u8 = b'W';
const KIND_LOCATION: u8 = b'l';
const KIND_CHANGE: u8 = b'c';
const KIND_PROBLEM: u8 = b'p';
const KIND_RUNNING: u8 = b'r';
const KIND_NODE: u8 = b'n';
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
/// OC-2: a node not heard from for this long is left out.
pub const NODE_QUIET_AFTER: u64 = 10 * 60;
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
    /// OC-4: a blob not named by its content whose copy in the new store
    /// isn't the old one's.
    Different,
}

impl ProblemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProblemKind::Missing => "missing",
            ProblemKind::Damaged => "damaged",
            ProblemKind::Unreadable => "unreadable",
            ProblemKind::Different => "different",
        }
    }
}

/// CA-1, CA-5: whether the setting has moved yet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// Planned: the new store's settings are kept, and a copy goes from the
    /// current store to it. Nothing reads through it.
    Planned,
    /// The setting moved (BM-2). Every change recorded before planning
    /// existed is one.
    #[default]
    Changed,
}

impl Stage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Stage::Planned => "planned",
            Stage::Changed => "changed",
        }
    }
}

/// CA-5: the copy ahead of a planned change, kept once the setting moved.
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct CopiedAhead {
    pub started_at: u64,
    #[serde(default)]
    pub finished_at: Option<u64>,
    pub status: Status,
    pub copied: u64,
    pub already_there: u64,
    pub bytes_copied: u64,
    pub problems: u64,
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
            // A copy compares nothing byte for byte, so never finds one
            ProblemKind::Different => self.damaged += 1,
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

/// OC-6: how a cleanup of the old store stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "lowercase")]
pub enum CleanupStatus {
    Running,
    /// Nothing kept: every blob the server holds is out of the old store.
    Done,
    /// Some blobs were kept in the old store (OC-4).
    Incomplete,
    Stopped,
    Failed,
    Interrupted,
}

impl CleanupStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CleanupStatus::Running => "running",
            CleanupStatus::Done => "done",
            CleanupStatus::Incomplete => "incomplete",
            CleanupStatus::Stopped => "stopped",
            CleanupStatus::Failed => "failed",
            CleanupStatus::Interrupted => "interrupted",
        }
    }
}

/// OC-4: how far the latest cleanup got.
#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CleanupProgress {
    /// Slices of the blob index done, of 256.
    pub slices: u32,
    pub blobs_checked: u64,
    /// Deleted from the old store, or for a preview, that would be.
    pub deleted: u64,
    pub bytes_freed: u64,
    /// Not in the old store.
    pub not_there: u64,
    pub missing: u64,
    pub damaged: u64,
    pub different: u64,
    pub unreadable: u64,
}

impl CleanupProgress {
    pub fn problems(&self) -> u64 {
        self.missing + self.damaged + self.different + self.unreadable
    }

    pub fn count(&mut self, kind: ProblemKind) {
        match kind {
            ProblemKind::Missing => self.missing += 1,
            ProblemKind::Damaged => self.damaged += 1,
            ProblemKind::Different => self.different += 1,
            ProblemKind::Unreadable => self.unreadable += 1,
        }
    }

    pub fn share(&self) -> f64 {
        self.slices.min(256) as f64 / 256.0
    }
}

/// The latest cleanup of a resolved change's old store, or a preview of
/// one (OC-3 to OC-6).
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cleanup {
    pub status: CleanupStatus,
    /// OC-5: a preview, which deletes nothing.
    #[serde(default)]
    pub dry_run: bool,
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
    pub progress: CleanupProgress,
    #[serde(default)]
    pub problems_kept: u64,
    /// OC-9: snapshots on disk taken before the change.
    #[serde(default)]
    pub snapshots_before: u64,
    #[serde(default)]
    pub error: Option<String>,
}

impl Cleanup {
    /// As it reads now: one whose node went quiet has stopped with it.
    pub fn status_at(&self, now: u64) -> CleanupStatus {
        if self.status == CleanupStatus::Running && self.heartbeat + STALE_AFTER < now {
            CleanupStatus::Interrupted
        } else {
            self.status
        }
    }
}

/// OC-2: where a node's blob store is, and when it last said so.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodePlace {
    pub location: String,
    pub at: u64,
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
    /// The old store's settings, to read it (BM-3), copy from it (BM-5) and,
    /// once resolved, clean it up (OC-1). Dropped when a cleanup is done or
    /// the change is dismissed; never shown (BM-9).
    #[serde(default)]
    pub old_settings: Option<structs::BlobStore>,
    #[serde(default)]
    pub copy: Option<Copy>,
    /// CA-1.
    #[serde(default)]
    pub stage: Stage,
    /// CA-1: a planned change's new store, to copy to (CA-2), follow deletes
    /// to (CA-4) and write to the setting (CA-7). Dropped at the switch;
    /// never shown.
    #[serde(default)]
    pub target_settings: Option<structs::BlobStore>,
    /// CA-5.
    #[serde(default)]
    pub copied_ahead: Option<CopiedAhead>,
    /// CA-7: when and by whom the setting was written.
    #[serde(default)]
    pub applied_at: Option<u64>,
    #[serde(default)]
    pub applied_by: Option<String>,
    /// OC-3 to OC-6: the latest cleanup of the old store.
    #[serde(default)]
    pub cleanup: Option<Cleanup>,
}

impl BlobStoreChange {
    /// BM-3: whether the old store is still read through. A planned change
    /// never is (CA-3).
    pub fn is_unresolved(&self) -> bool {
        self.stage == Stage::Changed && self.status.is_unresolved()
    }

    /// What a copy of it would copy from: the old store, or for a planned
    /// change the current one (CA-2).
    pub fn can_copy(&self) -> bool {
        match self.stage {
            Stage::Changed => self.is_unresolved() && self.old_settings.is_some(),
            Stage::Planned => self.target_settings.is_some(),
        }
    }

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

    /// OC-6: whether its cleanup runs, as it reads now.
    pub fn cleaning_up(&self, now: u64) -> bool {
        self.cleanup
            .as_ref()
            .is_some_and(|c| c.status_at(now) == CleanupStatus::Running)
    }

    /// BM-5, OC-3: whether a copy or a cleanup of it runs, as it reads now.
    pub fn busy(&self, now: u64) -> bool {
        self.status_at(now) == Status::Copying || self.cleaning_up(now)
    }

    /// Marks a copy or cleanup whose node went quiet as interrupted. False
    /// when there was none.
    pub fn mark_interrupted(&mut self, now: u64) -> bool {
        let mut marked = false;
        if self.status == Status::Copying && self.status_at(now) == Status::Interrupted {
            self.status = Status::Interrupted;
            if let Some(copy) = &mut self.copy {
                copy.finished_at = Some(now);
            }
            marked = true;
        }
        if let Some(cleanup) = &mut self.cleanup
            && cleanup.status == CleanupStatus::Running
            && cleanup.status_at(now) == CleanupStatus::Interrupted
        {
            cleanup.status = CleanupStatus::Interrupted;
            cleanup.finished_at = Some(now);
            marked = true;
        }
        marked
    }
}

/// The resolved changes to forget so no more than [`MAX_CHANGES`] are kept
/// once `adding` more are: oldest first, those with no old store kept for a
/// cleanup before those with one, and never one whose cleanup runs (OC-11).
fn to_forget(changes: &[BlobStoreChange], adding: usize, now: u64) -> Vec<u32> {
    let over = (changes.len() + adding).saturating_sub(MAX_CHANGES);
    let mut resolved = changes
        .iter()
        .filter(|c| c.stage == Stage::Changed && !c.status.is_unresolved() && !c.cleaning_up(now))
        .collect::<Vec<_>>();
    resolved.sort_by_key(|c| (c.old_settings.is_some(), c.id));
    resolved.into_iter().take(over).map(|c| c.id).collect()
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
    changes.retain(|c| c.is_unresolved() && c.old_settings.is_some());
    changes.reverse();
    Ok(changes)
}

/// CA-1, CA-3: the planned change, if there is one.
pub async fn planned(data: &Store) -> trc::Result<Option<BlobStoreChange>> {
    Ok(all(data)
        .await?
        .into_iter()
        .rev()
        .find(|c| c.stage == Stage::Planned && c.target_settings.is_some()))
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
                    c.is_unresolved() && c.status != Status::Copying && c.from == location
                }) {
                    let reverted = BlobStoreChange {
                        status: Status::Reverted,
                        old_settings: None,
                        ..earlier.clone()
                    };
                    batch.set(class(earlier.id), Json(&reverted).serialize()?);
                }

                // CA-5: the planned change for this move becomes the change
                let plan = changes.iter().find(|c| {
                    c.stage == Stage::Planned && c.from == last.location && c.to == location
                });
                let change = match plan {
                    Some(plan) => {
                        let stored = data
                            .get_value::<Versioned<BlobStoreChange>>(ValueKey::from(class(plan.id)))
                            .await
                            .caused_by(trc::location!())?;
                        let Some(Versioned(plan, plan_version)) = stored else {
                            continue;
                        };
                        batch.assert_value(class(plan.id), AssertValue::Hash(plan_version));
                        if running(data).await? == Some(plan.id) {
                            // Its copy ahead is cut short; its node sees the
                            // switch at its next save
                            batch.assert_value(running_class(), AssertValue::U32(plan.id));
                            batch.clear(running_class());
                        }
                        forgotten.push(plan.id);
                        switched(plan, last.settings.clone(), node_id, now)
                    }
                    None => {
                        batch.assert_value(class(id), AssertValue::None);
                        BlobStoreChange {
                            id,
                            from: last.location.clone(),
                            to: location.clone(),
                            changed_at: now,
                            node_id,
                            status: Status::Pending,
                            old_settings: Some(last.settings.clone()),
                            copy: None,
                            stage: Stage::Changed,
                            target_settings: None,
                            copied_ahead: None,
                            applied_at: None,
                            applied_by: None,
                            cleanup: None,
                        }
                    }
                };
                batch.set(class(change.id), Json(&change).serialize()?);
                started = Started::Changed(change.id);

                // The oldest resolved changes past MAX_CHANGES are forgotten
                for old in to_forget(&changes, usize::from(plan.is_none()), now) {
                    batch.clear(class(old));
                    forgotten.push(old);
                }
            }
        }
        batch.set(location_class(), Json(&here).serialize()?);

        match data.write(batch.build_all()).await {
            Ok(_) => {
                // Forgotten changes' problems, and a switched plan's from its
                // copy ahead: its count is kept in `copiedAhead` (CA-5)
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

/// CA-5: a planned change, as the change it becomes when the setting moves
/// to its store: read through from `old` until copied, its copy ahead kept.
fn switched(
    plan: BlobStoreChange,
    old: structs::BlobStore,
    node_id: u64,
    now: u64,
) -> BlobStoreChange {
    let copied_ahead = plan.copy.as_ref().map(|copy| CopiedAhead {
        started_at: copy.started_at,
        finished_at: copy.finished_at.or(Some(now)),
        status: match plan.status {
            Status::Copying => Status::Interrupted,
            status => status,
        },
        copied: copy.progress.copied,
        already_there: copy.progress.already_there,
        bytes_copied: copy.progress.bytes_copied,
        problems: copy.progress.problems(),
    });
    BlobStoreChange {
        changed_at: now,
        node_id,
        status: Status::Pending,
        old_settings: Some(old),
        copy: None,
        stage: Stage::Changed,
        target_settings: None,
        copied_ahead,
        ..plan
    }
}

/// CA-1: why a change can't be planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanRefusal {
    /// The new store is where the blob store is now.
    SamePlace,
    /// This change is planned already.
    AlreadyPlanned(u32),
    /// This change is still read through.
    Unresolved(u32),
    /// The server hasn't recorded where its blob store is yet.
    NoLocation,
}

/// CA-1: records a planned change from where the blob store is now to
/// `to`, keeping `target` to open it. The checks of the store itself (it
/// opens, a probe reads back) are the caller's.
pub async fn plan(
    data: &Store,
    to: String,
    target: structs::BlobStore,
) -> trc::Result<Result<BlobStoreChange, PlanRefusal>> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let Some(Versioned(here, version)) = data
            .get_value::<Versioned<Location>>(ValueKey::from(location_class()))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(Err(PlanRefusal::NoLocation));
        };
        if here.location == to {
            return Ok(Err(PlanRefusal::SamePlace));
        }
        let changes = all(data).await?;
        if let Some(planned) = changes.iter().find(|c| c.stage == Stage::Planned) {
            return Ok(Err(PlanRefusal::AlreadyPlanned(planned.id)));
        }
        if let Some(open) = changes.iter().rev().find(|c| c.is_unresolved()) {
            return Ok(Err(PlanRefusal::Unresolved(open.id)));
        }
        let id = changes.iter().map(|c| c.id).max().unwrap_or(0) + 1;
        let change = BlobStoreChange {
            id,
            from: here.location.clone(),
            to: to.clone(),
            changed_at: 0,
            node_id: 0,
            status: Status::Pending,
            old_settings: None,
            copy: None,
            stage: Stage::Planned,
            target_settings: Some(target.clone()),
            copied_ahead: None,
            applied_at: None,
            applied_by: None,
            cleanup: None,
        };

        let mut batch = BatchBuilder::new();
        // Planned from where the blob store is: refused if it moved meanwhile
        batch.assert_value(location_class(), AssertValue::Hash(version));
        batch.assert_value(class(id), AssertValue::None);
        batch.set(class(id), Json(&change).serialize()?);
        let mut forgotten = Vec::new();
        for old in to_forget(&changes, 1, store::write::now()) {
            batch.clear(class(old));
            forgotten.push(old);
        }
        match data.write(batch.build_all()).await {
            Ok(_) => {
                for id in forgotten {
                    remove_problems(data, id).await?;
                }
                return Ok(Ok(change));
            }
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
    /// CA-2: the blob store moved since the change was planned, so copying
    /// ahead from it would fill the planned store from the wrong place.
    Moved,
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
        if let Some(current) = busy_with(data, now).await? {
            return Ok(Err(Refusal::Running(current)));
        }

        let Some(Versioned(change, version)) = data
            .get_value::<Versioned<BlobStoreChange>>(ValueKey::from(class(id)))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(Err(Refusal::NotFound));
        };
        if !change.can_copy() {
            return Ok(Err(Refusal::Resolved));
        }
        let location = data
            .get_value::<Versioned<Location>>(ValueKey::from(location_class()))
            .await
            .caused_by(trc::location!())?;
        if change.stage == Stage::Planned
            && location
                .as_ref()
                .is_none_or(|Versioned(here, _)| here.location != change.from)
        {
            return Ok(Err(Refusal::Moved));
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

/// BM-5, OC-3: the change a copy or cleanup runs for now, if one runs. One
/// whose node went quiet is marked interrupted and lets another run.
async fn busy_with(data: &Store, now: u64) -> trc::Result<Option<u32>> {
    let Some(current) = running(data).await? else {
        return Ok(None);
    };
    match get(data, current).await? {
        Some(c) if c.busy(now) => return Ok(Some(current)),
        Some(_) => {
            update(data, current, |c| c.mark_interrupted(now)).await?;
        }
        None => {}
    }
    release(data, current).await?;
    Ok(None)
}

/// OC-3: why a cleanup can't start. The checks of the stores themselves
/// (the old one opens, the two don't overlap) are the caller's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupRefusal {
    NotFound,
    /// A copy or cleanup of this change runs now.
    Running(u32),
    /// The change isn't resolved by a copy yet.
    NotResolved,
    /// The blob store went back to the change's old store (BM-4).
    Reverted,
    /// Its old store's settings weren't kept (OC-1), or a cleanup is done.
    NoOldStore,
    /// The change's new store isn't the blob store now, or its old store is.
    NotCurrent,
    /// This planned change copies ahead to the old store.
    PlannedThere(u32),
    /// This node has its blob store at this other place.
    NodeElsewhere(u64, String),
}

/// OC-3: marks a change as being cleaned up by `cleanup` and makes it the
/// one that runs.
pub async fn start_cleanup(
    data: &Store,
    id: u32,
    cleanup: Cleanup,
    now: u64,
) -> trc::Result<Result<BlobStoreChange, CleanupRefusal>> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        if let Some(current) = busy_with(data, now).await? {
            return Ok(Err(CleanupRefusal::Running(current)));
        }
        let Some(Versioned(change, version)) = data
            .get_value::<Versioned<BlobStoreChange>>(ValueKey::from(class(id)))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(Err(CleanupRefusal::NotFound));
        };
        if let Some(refusal) = cleanup_refusal(data, &change, now).await? {
            return Ok(Err(refusal));
        }
        let change = BlobStoreChange {
            cleanup: Some(cleanup.clone()),
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

/// OC-3: what stops a change's old store being cleaned up, if anything.
pub async fn cleanup_refusal(
    data: &Store,
    change: &BlobStoreChange,
    now: u64,
) -> trc::Result<Option<CleanupRefusal>> {
    if change.stage != Stage::Changed {
        return Ok(Some(CleanupRefusal::NotResolved));
    }
    match change.status {
        Status::Copied => {}
        Status::Reverted => return Ok(Some(CleanupRefusal::Reverted)),
        _ => return Ok(Some(CleanupRefusal::NotResolved)),
    }
    if change.old_settings.is_none() {
        return Ok(Some(CleanupRefusal::NoOldStore));
    }
    let here = location(data).await?;
    if here
        .as_ref()
        .is_none_or(|here| here.location != change.to || here.location == change.from)
    {
        return Ok(Some(CleanupRefusal::NotCurrent));
    }
    if let Some(plan) = all(data)
        .await?
        .into_iter()
        .find(|c| c.stage == Stage::Planned && c.to == change.from)
    {
        return Ok(Some(CleanupRefusal::PlannedThere(plan.id)));
    }
    if let Some((node, place)) = node_places(data)
        .await?
        .into_iter()
        .find(|(_, p)| p.at + NODE_QUIET_AFTER >= now && p.location != change.to)
    {
        return Ok(Some(CleanupRefusal::NodeElsewhere(node, place.location)));
    }
    Ok(None)
}

fn node_class(node_id: u64) -> ValueClass {
    let mut key = Vec::with_capacity(2 + U64_LEN);
    key.extend_from_slice(&[FEATURE, KIND_NODE]);
    key.extend_from_slice(&node_id.to_be_bytes());
    any(key)
}

/// OC-2: notes where this node's blob store is, now.
pub async fn note_node(data: &Store, node_id: u64, location: &str, now: u64) -> trc::Result<()> {
    let place = NodePlace {
        location: location.to_string(),
        at: now,
    };
    let mut batch = BatchBuilder::new();
    batch.set(node_class(node_id), Json(&place).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// OC-2: where each node last said its blob store is, by node id.
pub async fn node_places(data: &Store) -> trc::Result<Vec<(u64, NodePlace)>> {
    let mut places = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey::from(node_class(0)),
            ValueKey::from(node_class(u64::MAX)),
        ),
        |key, value| {
            let node = key
                .get(key.len().saturating_sub(U64_LEN)..)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_be_bytes);
            if let (Some(node), Ok(Json(place))) = (node, Json::<NodePlace>::deserialize(value)) {
                places.push((node, place));
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(places)
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

    fn a_copy(at: u64) -> Copy {
        Copy {
            started_at: at,
            started_by: "admin".into(),
            node_id: 1,
            blobs_per_second: 0,
            bytes_per_second: 0,
            heartbeat: at,
            finished_at: None,
            stop_requested: false,
            progress: Progress::default(),
            problems_kept: 0,
            error: None,
        }
    }

    #[tokio::test]
    async fn a_planned_change_becomes_the_change() {
        let data = store::backend::ephemeral::EphemeralStore::open();
        let a = structs::BlobStore::Default;
        let b = fs("/srv/blobs");
        let (here_a, here_b) = ("the data store".to_string(), "dir".to_string());

        // CA-1: nothing to plan from before the server says where it is
        assert_eq!(
            plan(&data, here_b.clone(), b.clone()).await.unwrap(),
            Err(PlanRefusal::NoLocation)
        );
        at_start(&data, here_a.clone(), &a, 1, 10).await.unwrap();
        assert_eq!(
            plan(&data, here_a.clone(), a.clone()).await.unwrap(),
            Err(PlanRefusal::SamePlace)
        );
        let planned = plan(&data, here_b.clone(), b.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(planned.stage, Stage::Planned);
        assert_eq!(planned.target_settings, Some(b.clone()));
        assert_eq!(
            (planned.from.as_str(), planned.to.as_str()),
            ("the data store", "dir")
        );
        assert_eq!(
            plan(&data, "elsewhere".into(), fs("/srv/other"))
                .await
                .unwrap(),
            Err(PlanRefusal::AlreadyPlanned(planned.id))
        );

        // CA-3: not read through, so not unresolved
        assert!(!planned.is_unresolved());
        assert!(unresolved(&data).await.unwrap().is_empty());
        assert_eq!(
            super::planned(&data).await.unwrap().map(|c| c.id),
            Some(planned.id)
        );

        // CA-2: copied ahead; `copied` resolves nothing
        start_copy(&data, planned.id, a_copy(20), 20)
            .await
            .unwrap()
            .unwrap();
        update(&data, planned.id, |c| {
            c.status = Status::Copied;
            if let Some(copy) = &mut c.copy {
                copy.progress.copied = 7;
                copy.progress.bytes_copied = 700;
                copy.finished_at = Some(25);
            }
            true
        })
        .await
        .unwrap();
        release(&data, planned.id).await.unwrap();
        let ahead = get(&data, planned.id).await.unwrap().unwrap();
        assert_eq!(ahead.stage, Stage::Planned);
        assert!(ahead.target_settings.is_some());

        // CA-5: the switch makes it the change, no new one
        assert_eq!(
            at_start(&data, here_b.clone(), &b, 2, 30).await.unwrap(),
            Started::Changed(planned.id)
        );
        assert_eq!(all(&data).await.unwrap().len(), 1);
        let change = get(&data, planned.id).await.unwrap().unwrap();
        assert_eq!(change.stage, Stage::Changed);
        assert_eq!(change.status, Status::Pending);
        assert_eq!((change.changed_at, change.node_id), (30, 2));
        assert_eq!(change.old_settings, Some(a.clone()));
        assert_eq!(change.target_settings, None);
        assert_eq!(change.copy, None);
        let kept = change.copied_ahead.clone().unwrap();
        assert_eq!(
            (
                kept.status,
                kept.copied,
                kept.bytes_copied,
                kept.finished_at
            ),
            (Status::Copied, 7, 700, Some(25))
        );
        assert!(change.is_unresolved());
        assert_eq!(super::planned(&data).await.unwrap(), None);

        // CA-1: nothing more can be planned while it's read through
        assert_eq!(
            plan(&data, "elsewhere".into(), fs("/srv/other"))
                .await
                .unwrap(),
            Err(PlanRefusal::Unresolved(planned.id))
        );
    }

    #[tokio::test]
    async fn a_plan_for_somewhere_else_stays_planned() {
        let data = store::backend::ephemeral::EphemeralStore::open();
        let a = structs::BlobStore::Default;
        at_start(&data, "the data store".into(), &a, 1, 10)
            .await
            .unwrap();
        let planned = plan(&data, "dir".into(), fs("/srv/blobs"))
            .await
            .unwrap()
            .unwrap();
        start_copy(&data, planned.id, a_copy(20), 20)
            .await
            .unwrap()
            .unwrap();

        // The setting moved somewhere else: a change of its own; the plan is
        // still planned, and its copy can't start again from here (CA-2)
        let other = fs("/srv/other");
        let Started::Changed(id) = at_start(&data, "other".into(), &other, 1, 30)
            .await
            .unwrap()
        else {
            panic!("no change recorded");
        };
        assert_ne!(id, planned.id);
        assert_eq!(
            get(&data, planned.id).await.unwrap().unwrap().stage,
            Stage::Planned
        );
        update(&data, planned.id, |c| {
            c.status = Status::Stopped;
            true
        })
        .await
        .unwrap();
        release(&data, planned.id).await.unwrap();
        assert_eq!(
            start_copy(&data, planned.id, a_copy(40), 40).await.unwrap(),
            Err(Refusal::Moved)
        );
    }

    #[tokio::test]
    async fn the_switch_cuts_a_running_copy_ahead_short() {
        let data = store::backend::ephemeral::EphemeralStore::open();
        let a = structs::BlobStore::Default;
        let b = fs("/srv/blobs");
        at_start(&data, "the data store".into(), &a, 1, 10)
            .await
            .unwrap();
        let planned = plan(&data, "dir".into(), b.clone()).await.unwrap().unwrap();
        start_copy(&data, planned.id, a_copy(20), 20)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(running(&data).await.unwrap(), Some(planned.id));

        at_start(&data, "dir".into(), &b, 2, 30).await.unwrap();
        let change = get(&data, planned.id).await.unwrap().unwrap();
        assert_eq!(change.stage, Stage::Changed);
        assert_eq!(
            change.copied_ahead.map(|c| c.status),
            Some(Status::Interrupted)
        );
        // The last pass can start
        assert_eq!(running(&data).await.unwrap(), None);
        start_copy(&data, planned.id, a_copy(40), 40)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn a_change_from_before_planning_reads_as_changed() {
        let old = br#"{"id":1,"from":"a","to":"b","changedAt":5,"nodeId":1,"status":"pending","oldSettings":{"@type":"Default"}}"#;
        let Json(change) = Json::<BlobStoreChange>::deserialize(old).unwrap();
        assert_eq!(change.stage, Stage::Changed);
        assert!(change.is_unresolved());
        assert!(change.can_copy());
    }

    #[test]
    fn keys_stay_in_their_own_letter() {
        for class in [
            location_class(),
            class(1),
            problem_class(1, 0),
            running_class(),
            node_class(7),
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
            stage: Stage::Changed,
            target_settings: None,
            copied_ahead: None,
            applied_at: None,
            applied_by: None,
            cleanup: None,
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
            stage: Stage::Changed,
            target_settings: None,
            copied_ahead: None,
            applied_at: None,
            applied_by: None,
            cleanup: None,
        };
        let bytes = Json(&change).serialize().unwrap();
        let Json(back) = Json::<BlobStoreChange>::deserialize(&bytes).unwrap();
        assert_eq!(back, change);
    }

    fn a_cleanup(at: u64) -> Cleanup {
        Cleanup {
            status: CleanupStatus::Running,
            dry_run: false,
            started_at: at,
            started_by: "admin".into(),
            node_id: 1,
            blobs_per_second: 0,
            bytes_per_second: 0,
            heartbeat: at,
            finished_at: None,
            stop_requested: false,
            progress: CleanupProgress::default(),
            problems_kept: 0,
            snapshots_before: 0,
            error: None,
        }
    }

    #[tokio::test]
    async fn a_resolved_change_is_cleaned_up_once() {
        let data = store::backend::ephemeral::EphemeralStore::open();
        let a = fs("/srv/old");
        let b = structs::BlobStore::Default;
        let (here_a, here_b) = ("old".to_string(), "the data store".to_string());
        at_start(&data, here_a.clone(), &a, 1, 10).await.unwrap();
        assert_eq!(
            at_start(&data, here_b.clone(), &b, 1, 20).await.unwrap(),
            Started::Changed(1)
        );

        // OC-3: not before it's resolved
        assert_eq!(
            start_cleanup(&data, 1, a_cleanup(30), 30).await.unwrap(),
            Err(CleanupRefusal::NotResolved)
        );
        assert_eq!(
            start_cleanup(&data, 9, a_cleanup(30), 30).await.unwrap(),
            Err(CleanupRefusal::NotFound)
        );

        // OC-1: resolved, with the old store's settings kept; nothing read
        // through
        update(&data, 1, |c| {
            c.status = Status::Copied;
            true
        })
        .await
        .unwrap();
        assert!(unresolved(&data).await.unwrap().is_empty());
        assert_eq!(
            get(&data, 1).await.unwrap().unwrap().old_settings,
            Some(a.clone())
        );

        // OC-2, OC-3: a node still on the old store refuses it; one quiet
        // for long enough doesn't
        note_node(&data, 2, &here_a, 40).await.unwrap();
        note_node(&data, 1, &here_b, 40).await.unwrap();
        assert_eq!(
            start_cleanup(&data, 1, a_cleanup(40), 40).await.unwrap(),
            Err(CleanupRefusal::NodeElsewhere(2, here_a.clone()))
        );
        let later = 41 + NODE_QUIET_AFTER;
        note_node(&data, 1, &here_b, later).await.unwrap();
        assert_eq!(node_places(&data).await.unwrap().len(), 2);

        // OC-3: not while a planned change copies ahead to the old store
        plan(&data, here_a.clone(), a.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            start_cleanup(&data, 1, a_cleanup(later), later)
                .await
                .unwrap(),
            Err(CleanupRefusal::PlannedThere(2))
        );
        remove(&data, 2).await.unwrap();

        // Started: one at a time, and it can't be copied meanwhile
        let started = start_cleanup(&data, 1, a_cleanup(later), later)
            .await
            .unwrap()
            .unwrap();
        assert!(started.cleaning_up(later));
        assert_eq!(running(&data).await.unwrap(), Some(1));
        assert_eq!(
            start_cleanup(&data, 1, a_cleanup(later), later + 1)
                .await
                .unwrap(),
            Err(CleanupRefusal::Running(1))
        );

        // Its node went quiet: interrupted, and it can run again
        let quiet = later + STALE_AFTER + 1;
        let again = start_cleanup(&data, 1, a_cleanup(quiet), quiet)
            .await
            .unwrap()
            .unwrap();
        assert!(again.cleaning_up(quiet));

        // Done: the old store's settings go, and there's nothing to clean
        update(&data, 1, |c| {
            if let Some(cleanup) = &mut c.cleanup {
                cleanup.status = CleanupStatus::Done;
            }
            c.old_settings = None;
            true
        })
        .await
        .unwrap();
        release(&data, 1).await.unwrap();
        assert_eq!(
            start_cleanup(&data, 1, a_cleanup(quiet), quiet + 1)
                .await
                .unwrap(),
            Err(CleanupRefusal::NoOldStore)
        );
    }

    #[tokio::test]
    async fn not_once_the_blob_store_is_back_in_the_old_store() {
        let data = store::backend::ephemeral::EphemeralStore::open();
        let a = fs("/srv/old");
        let b = structs::BlobStore::Default;
        at_start(&data, "old".into(), &a, 1, 10).await.unwrap();
        at_start(&data, "the data store".into(), &b, 1, 20)
            .await
            .unwrap();
        update(&data, 1, |c| {
            c.status = Status::Copied;
            true
        })
        .await
        .unwrap();
        // B back to A: the copied change's old store is the blob store again
        at_start(&data, "old".into(), &a, 1, 30).await.unwrap();
        assert_eq!(
            start_cleanup(&data, 1, a_cleanup(40), 40).await.unwrap(),
            Err(CleanupRefusal::NotCurrent)
        );
    }

    #[test]
    fn forgetting_keeps_old_stores_kept_for_a_cleanup_last() {
        let change = |id: u32, kept: bool, cleanup: Option<Cleanup>| BlobStoreChange {
            id,
            from: "a".into(),
            to: "b".into(),
            changed_at: 1,
            node_id: 1,
            status: Status::Copied,
            old_settings: kept.then(|| structs::BlobStore::Default),
            copy: None,
            stage: Stage::Changed,
            target_settings: None,
            copied_ahead: None,
            applied_at: None,
            applied_by: None,
            cleanup,
        };
        let mut changes = vec![
            change(1, true, None),
            change(2, false, None),
            change(3, true, Some(a_cleanup(100))),
        ];
        changes.extend((4..=MAX_CHANGES as u32).map(|id| change(id, false, None)));
        // One more to add: the oldest without a kept store goes first
        assert_eq!(to_forget(&changes, 1, 100), [2]);
        assert_eq!(
            to_forget(&changes, 1 + MAX_CHANGES - 2, 100).last(),
            Some(&1)
        );
        // One being cleaned up is never forgotten
        assert!(!to_forget(&changes, MAX_CHANGES, 100).contains(&3));
    }

    #[test]
    fn a_change_from_before_cleanups_reads_without_one() {
        let json = br#"{"id":1,"from":"a","to":"b","changedAt":1,"nodeId":1,"status":"copied"}"#;
        let Json(change) = Json::<BlobStoreChange>::deserialize(json).unwrap();
        assert_eq!(change.cleanup, None);
        assert!(!change.busy(10));
    }
}
