/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Changing the blob store (docs/spec/features/blob-store-change.md): the
//! copy behind an `inbuxa:BlobStoreChange`. It goes through the blob index
//! one slice at a time and copies each blob the current store lacks from
//! the change's old store, as the old store keeps it (BM-5). It runs on the
//! node the copy was started on. Also, on every node, it keeps reading
//! through only the changes still unresolved (BM-10).

use common::{
    BuildServer, Inner, Server,
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY},
};
use inbuxa_features::blob_move::{
    self as model, BlobStoreChange, Copy, DEFAULT_BLOBS_PER_SECOND, DEFAULT_BYTES_PER_SECOND,
    MAX_PROBLEMS, Problem, ProblemKind, Progress, Refusal, STALE_AFTER, Status,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    BlobStore,
    write::{
        blob_check::{BlobHolder, LinkedBlob},
        now,
    },
};
use types::{blob_hash::BlobHash, collection::Collection};

/// How often a running copy saves its progress, which is also its
/// heartbeat and when it sees a stop (BM-6).
const SAVE_EVERY: Duration = Duration::from_secs(10);
/// BM-10: how often a node reads which changes are still unresolved.
const REFRESH_EVERY: Duration = Duration::from_secs(60);

fn node_id(server: &Server) -> u64 {
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

/// BM-6: asks a running copy to stop. Any node can: the one running it
/// sees the request at its next save. None if there's no such change.
pub async fn stop(server: &Server, id: u32) -> trc::Result<Option<BlobStoreChange>> {
    model::update(server.store(), id, |c| match &mut c.copy {
        Some(copy) if c.status == Status::Copying && !copy.stop_requested => {
            copy.stop_requested = true;
            true
        }
        _ => false,
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
        mark_interrupted(&server, |c| c.node_id == node).await;
        loop {
            tokio::time::sleep(REFRESH_EVERY).await;
            let server = inner.build_server();
            let cutoff = now().saturating_sub(STALE_AFTER);
            mark_interrupted(&server, |c| c.node_id != node && c.heartbeat < cutoff).await;
            refresh(&server).await;
        }
    });
}

/// BM-10: stops reading through changes resolved or dismissed anywhere.
pub async fn refresh(server: &Server) {
    let Some(moving) = server.blob_store().moving() else {
        return;
    };
    match model::unresolved(server.store()).await {
        Ok(changes) => {
            let ids = changes.iter().map(|c| c.id).collect::<Vec<_>>();
            moving.retain_changes(&ids);
        }
        Err(err) => {
            trc::error!(err.details("Failed to read the blob store changes"));
        }
    }
}

async fn mark_interrupted(server: &Server, which: impl Fn(&Copy) -> bool) {
    let changes = match model::all(server.store()).await {
        Ok(changes) => changes,
        Err(err) => {
            trc::error!(err.details("Failed to read the blob store changes"));
            return;
        }
    };
    for change in changes
        .into_iter()
        .filter(|c| c.status == Status::Copying && c.copy.as_ref().is_some_and(&which))
    {
        let result = model::update(server.store(), change.id, |c| {
            if c.status != Status::Copying || !c.copy.as_ref().is_some_and(&which) {
                return false;
            }
            c.status = Status::Interrupted;
            if let Some(copy) = &mut c.copy {
                copy.finished_at = Some(now());
            }
            true
        })
        .await;
        if let Err(err) = result.and(model::release(server.store(), change.id).await) {
            trc::error!(err.details("Failed to mark an interrupted blob copy"));
        }
    }
}

/// BM-5: keeps a rate, a second at a time.
struct Pace {
    per_second: u64,
    window: Instant,
    used: u64,
}

impl Pace {
    fn new(per_second: u64) -> Self {
        Pace {
            per_second,
            window: Instant::now(),
            used: 0,
        }
    }

    async fn take(&mut self, amount: u64) {
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
struct Holder {
    name: String,
    account_id: Option<u32>,
    object_id: Option<u64>,
    /// Named by the hash of its content, so it can be checked.
    content_named: bool,
}

impl Holder {
    fn of(blob: &LinkedBlob) -> Holder {
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

    fn fixed() -> Holder {
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

fn key_name(key: &[u8]) -> String {
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
            Some(_) => Ok(()),
            // Dismissed under it: nothing left to copy for
            None => Err(Halt::Stopped),
        }
    }

    /// BM-5: one blob, copied unless the current store has it.
    async fn one(&mut self, key: &[u8], holder: Holder) -> Result<(), Halt> {
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
                    format!("the current blob store couldn't say: {err}"),
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
                    format!("the old blob store failed: {err}"),
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
                                "the old store's {} bytes hash to {}",
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
                format!("the current blob store couldn't write it: {err}"),
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

/// The change's old store: the one already read through, or opened now.
async fn old_store(server: &Server, change: &BlobStoreChange) -> Result<BlobStore, String> {
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
    let (status, error, run) = match old_store(server, &change).await {
        Err(err) => (
            Status::Failed,
            Some(format!("The old blob store couldn't be opened: {err}")),
            None,
        ),
        Ok(old) => {
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
                old,
                target: server.blob_store().current().clone(),
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
            c.status = status;
            // BM-6: resolved, so the old store's settings go
            if status == Status::Copied {
                c.old_settings = None;
            }
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
    if status == Status::Copied {
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
