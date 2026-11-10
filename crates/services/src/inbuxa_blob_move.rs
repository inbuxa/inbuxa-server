/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Changing the blob store (docs/spec/features/blob-store-change.md): the
//! copy behind an `inbuxa:BlobStoreChange`. It goes through the blob index
//! one slice at a time and copies each blob the current store lacks from
//! the change's old store, as the old store keeps it (BM-5). A planned
//! change is copied the other way round: from the current store to the
//! planned one (blob-store-copy-ahead spec, CA-2). It runs on the node the
//! copy was started on. Also, on every node, it keeps reading through only
//! the changes still unresolved (BM-10), deletes following to the planned
//! store, if there is one (CA-4), and notes where its blob store is
//! (blob-store-cleanup spec, OC-2). The cleanup of a resolved change's old
//! store is `inbuxa_blob_cleanup`.

use common::{
    BuildServer, Inner, Server,
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY},
};
use inbuxa_features::blob_move::{
    self as model, BlobStoreChange, CleanupStatus, Copy, DEFAULT_BLOBS_PER_SECOND,
    DEFAULT_BYTES_PER_SECOND, MAX_PROBLEMS, PlanRefusal, Problem, ProblemKind, Progress, Refusal,
    STALE_AFTER, Stage, Status,
};
use registry::schema::structs;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    BlobStore,
    build::blob::blob_store_location,
    write::{
        blob_check::{BlobHolder, LinkedBlob},
        blob_move::PlannedBlobStore,
        now,
    },
};
use types::{blob_hash::BlobHash, collection::Collection};

/// How often a running copy saves its progress, which is also its
/// heartbeat and when it sees a stop (BM-6).
const SAVE_EVERY: Duration = Duration::from_secs(10);
/// BM-10: how often a node reads which changes are still unresolved.
const REFRESH_EVERY: Duration = Duration::from_secs(60);
/// CA-1: written to a planned store, read back and deleted, to check it
/// before anything relies on it.
const PROBE_KEY: &[u8] = b"INBUXA_BLOB_STORE_PROBE";

pub(crate) fn node_id(server: &Server) -> u64 {
    server.core.network.node_id
}

/// BM-5: starts copying a change on this node. Refused while another copy
/// runs, or when the change is resolved.
pub async fn start(
    server: &Server,
    id: u32,
    blobs_per_second: Option<u64>,
    bytes_per_second: Option<u64>,
    started_by: String,
) -> trc::Result<Result<(), Refusal>> {
    let now = now();
    let copy = Copy {
        started_at: now,
        started_by,
        node_id: node_id(server),
        blobs_per_second: blobs_per_second.unwrap_or(DEFAULT_BLOBS_PER_SECOND),
        bytes_per_second: bytes_per_second.unwrap_or(DEFAULT_BYTES_PER_SECOND),
        heartbeat: now,
        finished_at: None,
        stop_requested: false,
        progress: Progress::default(),
        problems_kept: 0,
        error: None,
    };
    let change = match model::start_copy(server.store(), id, copy, now).await? {
        Ok(change) => change,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let server = server.clone();
    tokio::spawn(async move {
        run(&server, change).await;
    });
    Ok(Ok(()))
}

/// CA-1: why a change wasn't planned.
pub enum NotPlanned {
    Refused(PlanRefusal),
    /// The planned store can't be opened, or the probe failed: the reason.
    Unusable(String),
}

/// CA-1: plans a change to the store `target` names, once it opens and a
/// probe written to it reads back and deletes.
pub async fn plan(
    server: &Server,
    target: structs::BlobStore,
) -> trc::Result<Result<BlobStoreChange, NotPlanned>> {
    let to = blob_store_location(&target);
    let mut warnings = Vec::new();
    let store = match BlobStore::open(target.clone(), server.store(), &mut warnings).await {
        Ok(store) => store,
        Err(err) => {
            return Ok(Err(NotPlanned::Unusable(format!(
                "The blob store couldn't be opened: {err}"
            ))));
        }
    };
    if let Err(why) = probe(&store).await {
        return Ok(Err(NotPlanned::Unusable(why)));
    }
    match model::plan(server.store(), to, target).await? {
        Ok(change) => {
            if let Some(moving) = server.blob_store().moving() {
                moving.set_planned(Some(PlannedBlobStore {
                    change_id: change.id,
                    store,
                }));
            }
            Ok(Ok(change))
        }
        Err(refusal) => Ok(Err(NotPlanned::Refused(refusal))),
    }
}

async fn probe(store: &BlobStore) -> Result<(), String> {
    let written = format!("inbuxa {}", now()).into_bytes();
    store
        .put_stored(PROBE_KEY, &written)
        .await
        .map_err(|err| format!("A test blob couldn't be written to it: {err}"))?;
    let read = store
        .get_stored(PROBE_KEY)
        .await
        .map_err(|err| format!("A test blob written to it couldn't be read back: {err}"))?;
    if read.as_deref() != Some(&written[..]) {
        return Err("A test blob written to it didn't read back the same.".into());
    }
    store
        .delete_blob(PROBE_KEY)
        .await
        .map_err(|err| format!("A test blob written to it couldn't be deleted: {err}"))?;
    Ok(())
}

/// BM-6, OC-6: asks a running copy or cleanup to stop. Any node can: the
/// one running it sees the request at its next save. None if there's no
/// such change.
pub async fn stop(server: &Server, id: u32) -> trc::Result<Option<BlobStoreChange>> {
    model::update(server.store(), id, |c| {
        if let Some(cleanup) = &mut c.cleanup
            && cleanup.status == CleanupStatus::Running
            && !cleanup.stop_requested
        {
            cleanup.stop_requested = true;
            return true;
        }
        match &mut c.copy {
            Some(copy) if c.status == Status::Copying && !copy.stop_requested => {
                copy.stop_requested = true;
                true
            }
            _ => false,
        }
    })
    .await
}

/// BM-6: at start-up, a copy this node ran stopped with it; now and then,
/// a copy on a node that went quiet is taken to have stopped too. BM-10:
/// and every minute, only unresolved changes are read through.
pub fn spawn_blob_moves(inner: Arc<Inner>) {
    tokio::spawn(async move {
        let server = inner.build_server();
        let node = node_id(&server);
        mark_interrupted(&server, |run, _| run == node).await;
        refresh(&server).await;
        loop {
            tokio::time::sleep(REFRESH_EVERY).await;
            let server = inner.build_server();
            let cutoff = now().saturating_sub(STALE_AFTER);
            mark_interrupted(&server, |run, heartbeat| run != node && heartbeat < cutoff).await;
            refresh(&server).await;
        }
    });
}

/// BM-10: stops reading through changes resolved or dismissed anywhere.
/// CA-3, CA-4: and follows deletes to a change planned anywhere, until it's
/// switched to or dismissed.
pub async fn refresh(server: &Server) {
    let Some(moving) = server.blob_store().moving() else {
        return;
    };
    // OC-2: where this node's blob store is, for a cleanup to check
    if let Some(location) = moving.location()
        && let Err(err) = model::note_node(server.store(), node_id(server), &location, now()).await
    {
        trc::error!(err.details("Failed to note where this node's blob store is"));
    }
    match model::unresolved(server.store()).await {
        Ok(changes) => {
            let ids = changes.iter().map(|c| c.id).collect::<Vec<_>>();
            moving.retain_changes(&ids);
        }
        Err(err) => {
            trc::error!(err.details("Failed to read the blob store changes"));
        }
    }
    let plan = match model::planned(server.store()).await {
        Ok(plan) => plan,
        Err(err) => {
            trc::error!(err.details("Failed to read the planned blob store"));
            return;
        }
    };
    match plan {
        None => moving.set_planned(None),
        Some(plan) if moving.planned().is_some_and(|p| p.change_id == plan.id) => {}
        Some(plan) => {
            let settings = plan.target_settings.clone().unwrap_or_default();
            let mut warnings = Vec::new();
            match BlobStore::open(settings, server.store(), &mut warnings).await {
                Ok(store) => {
                    moving.planned_open_failed(plan.id, false);
                    moving.set_planned(Some(PlannedBlobStore {
                        change_id: plan.id,
                        store,
                    }));
                }
                Err(err) => {
                    moving.set_planned(None);
                    if !moving.planned_open_failed(plan.id, true) {
                        trc::error!(
                            trc::StoreEvent::UnexpectedError
                                .into_err()
                                .details("The planned blob store couldn't be opened")
                                .ctx(trc::Key::Id, plan.id)
                                .reason(err)
                        );
                    }
                }
            }
        }
    }
}

/// BM-6, OC-6: marks the copies and cleanups `which` picks, by their node
/// and heartbeat, as interrupted.
async fn mark_interrupted(server: &Server, which: impl Fn(u64, u64) -> bool) {
    let changes = match model::all(server.store()).await {
        Ok(changes) => changes,
        Err(err) => {
            trc::error!(err.details("Failed to read the blob store changes"));
            return;
        }
    };
    let copying = |c: &BlobStoreChange| {
        c.status == Status::Copying
            && c.copy
                .as_ref()
                .is_some_and(|copy| which(copy.node_id, copy.heartbeat))
    };
    let cleaning = |c: &BlobStoreChange| {
        c.cleanup.as_ref().is_some_and(|cleanup| {
            cleanup.status == CleanupStatus::Running && which(cleanup.node_id, cleanup.heartbeat)
        })
    };
    for change in changes.into_iter().filter(|c| copying(c) || cleaning(c)) {
        let result = model::update(server.store(), change.id, |c| {
            let mut marked = false;
            if copying(c) {
                c.status = Status::Interrupted;
                if let Some(copy) = &mut c.copy {
                    copy.finished_at = Some(now());
                }
                marked = true;
            }
            if cleaning(c)
                && let Some(cleanup) = &mut c.cleanup
            {
                cleanup.status = CleanupStatus::Interrupted;
                cleanup.finished_at = Some(now());
                marked = true;
            }
            marked
        })
        .await;
        if let Err(err) = result.and(model::release(server.store(), change.id).await) {
            trc::error!(err.details("Failed to mark an interrupted blob copy or cleanup"));
        }
    }
}

/// BM-5: keeps a rate, a second at a time.
pub(crate) struct Pace {
    per_second: u64,
    window: Instant,
    used: u64,
}

impl Pace {
    pub(crate) fn new(per_second: u64) -> Self {
        Pace {
            per_second,
            window: Instant::now(),
            used: 0,
        }
    }

    pub(crate) async fn take(&mut self, amount: u64) {
        if self.per_second == 0 {
            return;
        }
        if self.window.elapsed() >= Duration::from_secs(1) {
            self.window = Instant::now();
            self.used = 0;
        }
        self.used += amount;
        if self.used >= self.per_second {
            let rest = Duration::from_secs(1).saturating_sub(self.window.elapsed());
            tokio::time::sleep(rest).await;
            self.window = Instant::now();
            self.used = self.used.saturating_sub(self.per_second);
        }
    }
}

/// Who holds a blob, as a problem names it (BM-5).
pub(crate) struct Holder {
    pub(crate) name: String,
    pub(crate) account_id: Option<u32>,
    pub(crate) object_id: Option<u64>,
    /// Named by the hash of its content, so it can be checked.
    pub(crate) content_named: bool,
}

impl Holder {
    pub(crate) fn of(blob: &LinkedBlob) -> Holder {
        match blob.holders.first() {
            Some(BlobHolder::Document {
                account_id,
                collection,
                document_id,
            }) => Holder {
                name: match Collection::from(*collection) {
                    Collection::Email => "email".into(),
                    Collection::FileNode => "file".into(),
                    Collection::SieveScript => "sieveScript".into(),
                    Collection::CalendarEvent => "calendarEvent".into(),
                    Collection::ContactCard => "contactCard".into(),
                    _ => format!("collection{collection}"),
                },
                account_id: Some(*account_id),
                object_id: Some(*document_id as u64),
                content_named: true,
            },
            Some(BlobHolder::Queue { id }) => Holder {
                name: "queuedMessage".into(),
                account_id: None,
                object_id: Some(*id),
                content_named: true,
            },
            Some(BlobHolder::Archived { account_id, item }) => Holder {
                name: "archivedItem".into(),
                account_id: Some(*account_id),
                object_id: Some(item.id().id()),
                content_named: true,
            },
            None => Holder {
                name: "temporary".into(),
                account_id: None,
                object_id: None,
                content_named: false,
            },
        }
    }

    pub(crate) fn fixed() -> Holder {
        Holder {
            name: "fixed".into(),
            account_id: None,
            object_id: None,
            content_named: false,
        }
    }
}

struct Run<'x> {
    server: &'x Server,
    id: u32,
    /// CA-2: copying ahead, from the current store to the planned one.
    ahead: bool,
    old: BlobStore,
    target: BlobStore,
    progress: Progress,
    found: Vec<Problem>,
    kept: u64,
    blobs: Pace,
    bytes: Pace,
    saved: Instant,
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

pub(crate) fn key_name(key: &[u8]) -> String {
    match BlobHash::try_from_hash_slice(key) {
        Ok(hash) => hash.to_hex(),
        Err(_) => String::from_utf8_lossy(key).into_owned(),
    }
}

impl<'x> Run<'x> {
    /// BM-6: counts a problem, logs it, and keeps the first ones.
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
            if let Some(copy) = &mut c.copy {
                copy.progress = progress.clone();
                copy.problems_kept = kept;
                copy.heartbeat = now();
            }
            true
        })
        .await?;
        self.saved = Instant::now();
        match saved {
            Some(c) if c.copy.as_ref().is_some_and(|c| c.stop_requested) => Err(Halt::Stopped),
            // CA-5: switched to while copying ahead; the last pass is next
            Some(c) if self.ahead && c.stage != Stage::Planned => Err(Halt::Stopped),
            Some(_) => Ok(()),
            // Dismissed under it: nothing left to copy for
            None => Err(Halt::Stopped),
        }
    }

    /// What a problem calls the store copied from and the one copied to.
    fn names(&self) -> (&'static str, &'static str) {
        if self.ahead {
            ("the current blob store", "the planned blob store")
        } else {
            ("the old blob store", "the current blob store")
        }
    }

    /// BM-5: one blob, copied unless the store copied to has it.
    async fn one(&mut self, key: &[u8], holder: Holder) -> Result<(), Halt> {
        let (from, to) = self.names();
        self.blobs.take(1).await;
        self.progress.blobs_checked += 1;
        match self.target.stored_present(key).await {
            Ok(true) => {
                self.progress.already_there += 1;
                return self.save(false).await;
            }
            Ok(false) => {}
            Err(err) => {
                self.problem(
                    ProblemKind::Unreadable,
                    key,
                    &holder,
                    format!("{to} couldn't say: {err}"),
                );
                return self.save(false).await;
            }
        }
        let stored = match self.old.get_stored(key).await {
            Ok(Some(stored)) => stored,
            Ok(None) => {
                // The spam files exist only once the classifier has trained
                if holder.name != "fixed" {
                    self.problem(ProblemKind::Missing, key, &holder, String::new());
                }
                return self.save(false).await;
            }
            Err(err) => {
                self.problem(
                    ProblemKind::Unreadable,
                    key,
                    &holder,
                    format!("{from} failed: {err}"),
                );
                return self.save(false).await;
            }
        };
        let size = stored.len() as u64;
        self.bytes.take(size).await;
        if holder.content_named
            && let Ok(hash) = BlobHash::try_from_hash_slice(key)
        {
            match BlobStore::content_of_stored(key, stored.clone()) {
                Ok(content) => {
                    let actual = BlobHash::generate(&content);
                    if actual != hash {
                        self.problem(
                            ProblemKind::Damaged,
                            key,
                            &holder,
                            format!(
                                "{from}'s {} bytes hash to {}",
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
                        "it doesn't decompress".into(),
                    );
                    return self.save(false).await;
                }
            }
        }
        match self.target.put_stored(key, &stored).await {
            Ok(()) => {
                self.progress.copied += 1;
                self.progress.bytes_copied += size;
            }
            Err(err) => self.problem(
                ProblemKind::Unreadable,
                key,
                &holder,
                format!("{to} couldn't write it: {err}"),
            ),
        }
        self.save(false).await
    }

    async fn go(&mut self) -> Result<(), Halt> {
        for slice in 0u8..=255 {
            let blobs = self.server.store().blobs_to_copy(slice).await?;
            // A blob without its commit marker never finished being written
            for blob in blobs.into_iter().filter(|b| b.committed) {
                let holder = Holder::of(&blob);
                self.one(blob.hash.as_slice(), holder).await?;
            }
            self.progress.slices = slice as u32 + 1;
            self.save(false).await?;
        }
        // BM-5: the files kept under fixed names
        for key in [SPAM_TRAINER_KEY, SPAM_CLASSIFIER_KEY] {
            self.one(key, Holder::fixed()).await?;
        }
        Ok(())
    }
}

/// CA-2: the planned store: the one deletes follow to, or opened now.
async fn planned_store(server: &Server, change: &BlobStoreChange) -> Result<BlobStore, String> {
    if let Some(planned) = server
        .blob_store()
        .moving()
        .and_then(|m| m.planned())
        .filter(|p| p.change_id == change.id)
    {
        return Ok(planned.store.clone());
    }
    let Some(settings) = change.target_settings.clone() else {
        return Err("The change keeps no settings for the planned blob store".into());
    };
    let mut warnings = Vec::new();
    BlobStore::open(settings, server.store(), &mut warnings).await
}

/// What a copy reads from and writes to: the old store and the current
/// one, or for a planned change the current one and the planned one.
async fn stores(
    server: &Server,
    change: &BlobStoreChange,
) -> Result<(BlobStore, BlobStore), String> {
    let current = server.blob_store().current().clone();
    match change.stage {
        Stage::Changed => old_store(server, change)
            .await
            .map(|old| (old, current))
            .map_err(|err| format!("The old blob store couldn't be opened: {err}")),
        Stage::Planned => planned_store(server, change)
            .await
            .map(|planned| (current, planned))
            .map_err(|err| format!("The planned blob store couldn't be opened: {err}")),
    }
}

/// The change's old store: the one already read through, or opened now.
pub(crate) async fn old_store(
    server: &Server,
    change: &BlobStoreChange,
) -> Result<BlobStore, String> {
    if let Some(old) = server.blob_store().moving().and_then(|m| {
        m.old_stores()
            .iter()
            .find(|o| o.change_id == change.id)
            .map(|o| o.store.clone())
    }) {
        return Ok(old);
    }
    let Some(settings) = change.old_settings.clone() else {
        return Err("The change keeps no settings for the old blob store".into());
    };
    let mut warnings = Vec::new();
    BlobStore::open(settings, server.store(), &mut warnings).await
}

/// Runs a copy to its end and records how it ended (BM-6).
async fn run(server: &Server, change: BlobStoreChange) {
    let id = change.id;
    let ahead = change.stage == Stage::Planned;
    let (status, error, run) = match stores(server, &change).await {
        Err(err) => (Status::Failed, Some(err), None),
        Ok((old, target)) => {
            let copy = change.copy.clone().unwrap_or_else(|| Copy {
                started_at: now(),
                started_by: String::new(),
                node_id: node_id(server),
                blobs_per_second: DEFAULT_BLOBS_PER_SECOND,
                bytes_per_second: DEFAULT_BYTES_PER_SECOND,
                heartbeat: now(),
                finished_at: None,
                stop_requested: false,
                progress: Progress::default(),
                problems_kept: 0,
                error: None,
            });
            let mut run = Run {
                server,
                id,
                ahead,
                old,
                target,
                progress: Progress::default(),
                found: Vec::new(),
                kept: 0,
                blobs: Pace::new(copy.blobs_per_second),
                bytes: Pace::new(copy.bytes_per_second),
                saved: Instant::now(),
            };
            let (status, error) = match run.go().await {
                Ok(()) if run.progress.problems() == 0 => (Status::Copied, None),
                Ok(()) => (Status::Incomplete, None),
                Err(Halt::Stopped) => (Status::Stopped, None),
                Err(Halt::Failed(err)) => {
                    let text = err
                        .value_as_str(trc::Key::Details)
                        .map(str::to_string)
                        .unwrap_or_else(|| err.to_string());
                    trc::error!(err.details("A blob copy failed"));
                    (Status::Failed, Some(text))
                }
            };
            (status, error, Some(run))
        }
    };

    let data = server.store();
    let mut result = Ok(());
    let (progress, kept) = match &run {
        Some(run) => {
            let first = run.kept - run.found.len() as u64;
            result = model::add_problems(data, id, first, &run.found).await;
            (run.progress.clone(), run.kept)
        }
        None => (Progress::default(), 0),
    };
    if result.is_ok() {
        result = model::update(data, id, |c| {
            // CA-5: switched to under a copy ahead: that change is its own now
            if ahead && c.stage != Stage::Planned {
                return false;
            }
            // BM-6: resolved, and nothing is read through any more. The old
            // store's settings stay for a cleanup (blob-store-cleanup spec,
            // OC-1). A copy ahead resolves nothing (CA-2)
            c.status = status;
            if let Some(copy) = &mut c.copy {
                copy.progress = progress.clone();
                copy.problems_kept = kept;
                copy.finished_at = Some(now());
                copy.heartbeat = now();
            }
            if let Some(error) = &error {
                c.set_error(error);
            }
            true
        })
        .await
        .map(|_| ());
    }
    if let Err(err) = result.and(model::release(data, id).await) {
        trc::error!(err.details("Failed to save a blob copy's result"));
    }
    if status == Status::Copied && !ahead {
        refresh(server).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_named_by_hash_or_as_is() {
        let hash = BlobHash::generate(b"hello");
        assert_eq!(key_name(hash.as_slice()), hash.to_hex());
        assert_eq!(key_name(SPAM_TRAINER_KEY), "INBUXA_SPAM_TRAIN_DATA.lz4");
    }

    #[test]
    fn only_document_queue_and_kept_blobs_are_checked() {
        let blob = |holders| LinkedBlob {
            hash: BlobHash::generate(b"x"),
            committed: true,
            holders,
            temporary: true,
        };
        assert!(!Holder::of(&blob(vec![])).content_named);
        assert!(Holder::of(&blob(vec![BlobHolder::Queue { id: 4 }])).content_named);
        let mail = Holder::of(&blob(vec![BlobHolder::Document {
            account_id: 1,
            collection: Collection::Email.into(),
            document_id: 9,
        }]));
        assert_eq!(mail.name, "email");
        assert_eq!((mail.account_id, mail.object_id), (Some(1), Some(9)));
        assert!(!Holder::fixed().content_named);
    }
}
