/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Cleaning up the old store after a blob store change
//! (docs/spec/features/blob-store-cleanup.md). Once a change is resolved,
//! this goes through the blob index as the copy does and deletes from the
//! old store each blob it has read back from the current one and checked
//! (OC-4). A blob that fails the check stays where it is and is reported.
//! A preview does the same and deletes nothing (OC-5). It runs on the node
//! it was started on, one run at a time across the server with the copies.

use crate::{
    inbuxa_blob_move::{Holder, Pace, key_name, node_id, old_store},
    inbuxa_store_snapshot,
};
use common::{
    Server,
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY},
};
use inbuxa_features::{
    audit::{Action, Actor, Outcome, Record, Target},
    blob_move::{
        self as model, BlobStoreChange, Cleanup, CleanupProgress, CleanupRefusal, CleanupStatus,
        DEFAULT_BLOBS_PER_SECOND, DEFAULT_BYTES_PER_SECOND, MAX_PROBLEMS, Problem, ProblemKind,
    },
};
use std::time::{Duration, Instant};
use store::{BlobStore, build::blob::blob_store_places, write::now};
use types::{blob_hash::BlobHash, id::Id};

/// How often a running cleanup saves its progress, which is also its
/// heartbeat and when it sees a stop.
const SAVE_EVERY: Duration = Duration::from_secs(10);
/// OC-3: written to the current store and looked for in the old one, to
/// tell two settings that reach the same place.
const OVERLAP_PROBE_KEY: &[u8] = b"INBUXA_BLOB_STORE_OVERLAP_PROBE";

/// OC-3: why a cleanup didn't start.
pub enum NotCleaned {
    Refused(CleanupRefusal),
    /// The old store can't be opened: the reason.
    Unusable(String),
    /// Deleting from the old store would delete from the current one.
    Overlap,
}

/// OC-3, OC-5: starts a cleanup, or with `dry_run` a preview, of a change's
/// old store on this node. The confirmation (OC-8) is the caller's.
pub async fn start(
    server: &Server,
    id: u32,
    dry_run: bool,
    blobs_per_second: Option<u64>,
    bytes_per_second: Option<u64>,
    started_by: String,
) -> trc::Result<Result<(), NotCleaned>> {
    let data = server.store();
    let now = now();
    let Some(change) = model::get(data, id).await? else {
        return Ok(Err(NotCleaned::Refused(CleanupRefusal::NotFound)));
    };
    if let Some(refusal) = model::cleanup_refusal(data, &change, now).await? {
        return Ok(Err(NotCleaned::Refused(refusal)));
    }
    let old = match old_store(server, &change).await {
        Ok(old) => old,
        Err(err) => {
            return Ok(Err(NotCleaned::Unusable(format!(
                "The old blob store couldn't be opened: {err}"
            ))));
        }
    };
    let current = server.blob_store().current().clone();
    match overlaps(data, &change, &old, &current).await {
        Ok(false) => {}
        Ok(true) => return Ok(Err(NotCleaned::Overlap)),
        Err(why) => return Ok(Err(NotCleaned::Unusable(why))),
    }
    let snapshots_before = inbuxa_store_snapshot::list(server)
        .await
        .iter()
        .filter(|s| {
            s.status == inbuxa_store_snapshot::Status::Done && s.created_at < change.changed_at
        })
        .count() as u64;
    let cleanup = Cleanup {
        status: CleanupStatus::Running,
        dry_run,
        started_at: now,
        started_by,
        node_id: node_id(server),
        blobs_per_second: blobs_per_second.unwrap_or(DEFAULT_BLOBS_PER_SECOND),
        bytes_per_second: bytes_per_second.unwrap_or(DEFAULT_BYTES_PER_SECOND),
        heartbeat: now,
        finished_at: None,
        stop_requested: false,
        progress: CleanupProgress::default(),
        problems_kept: 0,
        snapshots_before,
        error: None,
    };
    let change = match model::start_cleanup(data, id, cleanup, now).await? {
        Ok(change) => change,
        Err(refusal) => return Ok(Err(NotCleaned::Refused(refusal))),
    };
    let server = server.clone();
    tokio::spawn(async move {
        run(&server, change, old, current).await;
    });
    Ok(Ok(()))
}

/// OC-4: what a `different` problem says. Two copies of the same size
/// differ in their bytes, so the sizes alone would read as a match.
fn different_detail(current: usize, old: usize) -> String {
    if current == old {
        format!("the current blob store's {current} bytes differ from the old one's")
    } else {
        format!("the current blob store has {current} bytes, the old one {old}")
    }
}

/// OC-3: whether the two stores share a place: one a sharded set with the
/// other among its members, or a probe written to the current store found
/// in the old one.
async fn overlaps(
    data: &store::Store,
    change: &BlobStoreChange,
    old: &BlobStore,
    current: &BlobStore,
) -> Result<bool, String> {
    let here = model::location(data)
        .await
        .map_err(|err| format!("Couldn't read where the blob store is: {err}"))?;
    if let (Some(old_settings), Some(here)) = (&change.old_settings, &here) {
        let old_places = blob_store_places(old_settings);
        if blob_store_places(&here.settings)
            .iter()
            .any(|place| old_places.contains(place))
        {
            return Ok(true);
        }
    }
    probe_overlap(old, current).await
}

/// OC-3: writes a probe to `current` and looks for it in `old`.
pub(crate) async fn probe_overlap(old: &BlobStore, current: &BlobStore) -> Result<bool, String> {
    let written = format!("inbuxa {}", now()).into_bytes();
    current
        .put_stored(OVERLAP_PROBE_KEY, &written)
        .await
        .map_err(|err| format!("A test blob couldn't be written to the blob store: {err}"))?;
    let seen = old.get_stored(OVERLAP_PROBE_KEY).await;
    let deleted = current.delete_blob(OVERLAP_PROBE_KEY).await;
    let seen = seen
        .map_err(|err| format!("The old blob store couldn't be read: {err}"))?
        .is_some_and(|read| read == written);
    deleted.map_err(|err| format!("A test blob couldn't be deleted from the blob store: {err}"))?;
    Ok(seen)
}

/// How a run ended before it finished.
enum Halt {
    Stopped,
    Failed(trc::Error),
}

impl From<trc::Error> for Halt {
    fn from(err: trc::Error) -> Self {
        Halt::Failed(err)
    }
}

struct Run<'x> {
    server: &'x Server,
    id: u32,
    dry_run: bool,
    old: BlobStore,
    current: BlobStore,
    progress: CleanupProgress,
    found: Vec<Problem>,
    kept: u64,
    blobs: Pace,
    bytes: Pace,
    saved: Instant,
}

impl Run<'_> {
    /// OC-4: counts a problem, logs it, and keeps the first ones. The blob
    /// stays in the old store.
    fn problem(&mut self, kind: ProblemKind, key: &[u8], holder: &Holder, detail: String) {
        self.progress.count(kind);
        let blob_id = key_name(key);
        trc::event!(
            Store(trc::StoreEvent::DataCorruption),
            Id = self.id,
            AccountId = holder.account_id,
            Collection = holder.name.clone(),
            DocumentId = holder.object_id,
            BlobId = blob_id.clone(),
            Reason = kind.as_str(),
            Details = detail.clone(),
        );
        if self.kept < MAX_PROBLEMS {
            self.kept += 1;
            self.found.push(Problem {
                kind,
                blob_id,
                holder: holder.name.clone(),
                account_id: holder.account_id,
                object_id: holder.object_id,
                detail,
            });
        }
    }

    /// Saves progress and the problems found since, now and then; a stop
    /// asked for meanwhile ends the run.
    async fn save(&mut self, force: bool) -> Result<(), Halt> {
        if !force && self.saved.elapsed() < SAVE_EVERY {
            return Ok(());
        }
        let data = self.server.store();
        let first = self.kept - self.found.len() as u64;
        model::add_problems(data, self.id, first, &self.found).await?;
        self.found.clear();
        let progress = self.progress.clone();
        let kept = self.kept;
        let saved = model::update(data, self.id, |c| {
            if let Some(cleanup) = &mut c.cleanup {
                cleanup.progress = progress.clone();
                cleanup.problems_kept = kept;
                cleanup.heartbeat = now();
            }
            true
        })
        .await?;
        self.saved = Instant::now();
        match saved {
            Some(c) if c.cleanup.as_ref().is_some_and(|c| c.stop_requested) => Err(Halt::Stopped),
            Some(_) => Ok(()),
            None => Err(Halt::Stopped),
        }
    }

    /// OC-4: one blob, deleted from the old store once the current one is
    /// checked to have it.
    async fn one(&mut self, key: &[u8], holder: Holder) -> Result<(), Halt> {
        self.blobs.take(1).await;
        self.progress.blobs_checked += 1;
        match self.old.stored_present(key).await {
            Ok(true) => {}
            Ok(false) => {
                self.progress.not_there += 1;
                return self.save(false).await;
            }
            Err(err) => {
                self.problem(
                    ProblemKind::Unreadable,
                    key,
                    &holder,
                    format!("the old blob store couldn't say: {err}"),
                );
                return self.save(false).await;
            }
        }
        let kept = match self.current.get_stored(key).await {
            Ok(Some(kept)) => kept,
            Ok(None) => {
                self.problem(
                    ProblemKind::Missing,
                    key,
                    &holder,
                    "the current blob store doesn't have it".into(),
                );
                return self.save(false).await;
            }
            Err(err) => {
                self.problem(
                    ProblemKind::Unreadable,
                    key,
                    &holder,
                    format!("the current blob store failed: {err}"),
                );
                return self.save(false).await;
            }
        };
        let size = kept.len() as u64;
        self.bytes.take(size).await;
        if holder.content_named
            && let Ok(hash) = BlobHash::try_from_hash_slice(key)
        {
            match BlobStore::content_of_stored(key, kept) {
                Ok(content) => {
                    let actual = BlobHash::generate(&content);
                    if actual != hash {
                        self.problem(
                            ProblemKind::Damaged,
                            key,
                            &holder,
                            format!(
                                "the current blob store's {} bytes hash to {}",
                                content.len(),
                                actual.to_hex()
                            ),
                        );
                        return self.save(false).await;
                    }
                }
                Err(_) => {
                    self.problem(
                        ProblemKind::Damaged,
                        key,
                        &holder,
                        "the current blob store's copy doesn't decompress".into(),
                    );
                    return self.save(false).await;
                }
            }
        } else {
            match self.old.get_stored(key).await {
                Ok(Some(old)) => {
                    self.bytes.take(old.len() as u64).await;
                    if old != kept {
                        self.problem(
                            ProblemKind::Different,
                            key,
                            &holder,
                            different_detail(kept.len(), old.len()),
                        );
                        return self.save(false).await;
                    }
                }
                Ok(None) => {
                    self.progress.not_there += 1;
                    return self.save(false).await;
                }
                Err(err) => {
                    self.problem(
                        ProblemKind::Unreadable,
                        key,
                        &holder,
                        format!("the old blob store failed: {err}"),
                    );
                    return self.save(false).await;
                }
            }
        }
        if self.dry_run {
            self.progress.deleted += 1;
            self.progress.bytes_freed += size;
            return self.save(false).await;
        }
        // Only the blob's data, from the old store itself: the blob index
        // is the data store's and stays as it is
        match self.old.delete_blob(key).await {
            Ok(_) => {
                self.progress.deleted += 1;
                self.progress.bytes_freed += size;
            }
            Err(err) => self.problem(
                ProblemKind::Unreadable,
                key,
                &holder,
                format!("the old blob store couldn't delete it: {err}"),
            ),
        }
        self.save(false).await
    }

    async fn go(&mut self) -> Result<(), Halt> {
        for slice in 0u8..=255 {
            let blobs = self.server.store().blobs_to_copy(slice).await?;
            for blob in blobs.into_iter().filter(|b| b.committed) {
                let holder = Holder::of(&blob);
                self.one(blob.hash.as_slice(), holder).await?;
            }
            self.progress.slices = slice as u32 + 1;
            self.save(false).await?;
        }
        for key in [SPAM_TRAINER_KEY, SPAM_CLASSIFIER_KEY] {
            self.one(key, Holder::fixed()).await?;
        }
        Ok(())
    }
}

/// Runs a cleanup to its end and records how it ended (OC-6, OC-12).
async fn run(server: &Server, change: BlobStoreChange, old: BlobStore, current: BlobStore) {
    let id = change.id;
    let cleanup = change.cleanup.clone();
    let dry_run = cleanup.as_ref().is_some_and(|c| c.dry_run);
    let mut run = Run {
        server,
        id,
        dry_run,
        old,
        current,
        progress: CleanupProgress::default(),
        found: Vec::new(),
        kept: 0,
        blobs: Pace::new(
            cleanup
                .as_ref()
                .map_or(DEFAULT_BLOBS_PER_SECOND, |c| c.blobs_per_second),
        ),
        bytes: Pace::new(
            cleanup
                .as_ref()
                .map_or(DEFAULT_BYTES_PER_SECOND, |c| c.bytes_per_second),
        ),
        saved: Instant::now(),
    };
    let (status, error) = match run.go().await {
        Ok(()) if run.progress.problems() == 0 => (CleanupStatus::Done, None),
        Ok(()) => (CleanupStatus::Incomplete, None),
        Err(Halt::Stopped) => (CleanupStatus::Stopped, None),
        Err(Halt::Failed(err)) => {
            let text = err
                .value_as_str(trc::Key::Details)
                .map(str::to_string)
                .unwrap_or_else(|| err.to_string());
            trc::error!(err.details("A blob store cleanup failed"));
            (CleanupStatus::Failed, Some(text))
        }
    };

    let data = server.store();
    let first = run.kept - run.found.len() as u64;
    let progress = run.progress.clone();
    let kept = run.kept;
    let mut result = model::add_problems(data, id, first, &run.found).await;
    if result.is_ok() {
        result = model::update(data, id, |c| {
            if let Some(cleanup) = &mut c.cleanup {
                cleanup.status = status;
                cleanup.progress = progress.clone();
                cleanup.problems_kept = kept;
                cleanup.finished_at = Some(now());
                cleanup.heartbeat = now();
                cleanup.error = error
                    .as_ref()
                    .map(|e| e.trim().chars().take(2_000).collect());
            }
            // OC-1, OC-6: done, so the old store's settings go
            if status == CleanupStatus::Done && !dry_run {
                c.old_settings = None;
            }
            true
        })
        .await
        .map(|_| ());
    }
    if let Err(err) = result.and(model::release(data, id).await) {
        trc::error!(err.details("Failed to save a blob store cleanup's result"));
    }

    // OC-12: each run's end, with its counts
    let p = &run.progress;
    let details = format!(
        "{} of the old blob store ({}): {}, {} blobs ({} bytes) {}, {} kept, {} not there",
        if dry_run {
            "A preview of a cleanup"
        } else {
            "A cleanup"
        },
        change.from,
        status.as_str(),
        p.deleted,
        p.bytes_freed,
        if dry_run {
            "would be deleted"
        } else {
            "deleted"
        },
        p.problems(),
        p.not_there,
    );
    server
        .audit_note(Record {
            at: now() * 1000,
            actor: Actor::system("BlobStoreCleanup"),
            via: None,
            remote_ip: None,
            action: if dry_run {
                Action::Verify
            } else {
                Action::Destroy
            },
            target: Target {
                kind: "inbuxa:BlobStoreChange".into(),
                id: Some(Id::from(id).to_string()),
                name: None,
                account_id: None,
                tenant_id: None,
            },
            changes: vec![],
            details: Some(details),
            reason: None,
            outcome: if status == CleanupStatus::Failed {
                Outcome::refused("failed", error)
            } else {
                Outcome::success()
            },
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry::schema::structs;
    use store::backend::fs::FsStore;

    #[tokio::test]
    async fn the_probe_finds_one_directory_under_two_names() {
        let dir = std::env::temp_dir().join(format!("inbuxa-overlap-{}", std::process::id()));
        let path = dir.to_string_lossy().to_string();
        let open = |path: String| async move {
            FsStore::open(structs::FileSystemStore { path, depth: 2 })
                .await
                .unwrap()
        };
        let one = open(path.clone()).await;
        let same = open(format!("{path}/.")).await;
        let other = open(format!("{path}-other")).await;
        assert!(probe_overlap(&same, &one).await.unwrap());
        assert!(!probe_overlap(&other, &one).await.unwrap());
        assert!(!one.blob_present(OVERLAP_PROBE_KEY).await.unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(format!("{path}-other"));
    }

    #[test]
    fn a_different_copy_of_the_same_size_says_the_bytes_differ() {
        assert_eq!(
            different_detail(12, 12),
            "the current blob store's 12 bytes differ from the old one's"
        );
        assert_eq!(
            different_detail(12, 10),
            "the current blob store has 12 bytes, the old one 10"
        );
    }
}
