/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Checking the store's blobs (docs/spec/features/store-check.md): the run
//! behind an `inbuxa:StoreCheck`. It goes through the blob index one slice
//! at a time and asks the blob store for each blob something holds, then
//! through each account's mail metadata for the blob each message names
//! (SV-3). It reports and never repairs. It runs on the node the check was
//! started on, against the stores every node shares.

use common::{BuildServer, Inner, Server};
use email::message::metadata::MessageMetadata;
use inbuxa_features::store_check::{
    self as model, MAX_PROBLEMS, Mode, Problem, ProblemKind, Progress, Refusal, STALE_AFTER,
    Status, StoreCheck,
};
use registry::schema::prelude::ObjectType;

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    Deserialize, IterateParams, U32_LEN, ValueKey,
    registry::RegistryQuery,
    roaring::RoaringBitmap,
    write::{
        AlignedBytes, Archive,
        blob_check::{BlobHolder, LinkedBlob},
        key::DeserializeBigEndian,
        now,
    },
};
use trc::AddContext;
use types::{blob::BlobClass, blob_hash::BlobHash, collection::Collection, field::EmailField};

/// SV-7: how often a running check saves its progress, which is also its
/// heartbeat and when it sees a stop.
const SAVE_EVERY: Duration = Duration::from_secs(10);

fn node_id(server: &Server) -> u64 {
    server.core.network.node_id
}

/// SV-2: starts a check on this node. Refused while another runs.
pub async fn start(
    server: &Server,
    mode: Mode,
    blobs_per_second: Option<u64>,
    bytes_per_second: Option<u64>,
    created_by: String,
) -> trc::Result<Result<u32, Refusal>> {
    let now = now();
    let mut check = StoreCheck::new(mode, created_by, node_id(server), now);
    if let Some(limit) = blobs_per_second {
        check.blobs_per_second = limit;
    }
    if let Some(limit) = bytes_per_second {
        check.bytes_per_second = limit;
    }
    let id = match model::create(server.store(), &check, now).await? {
        Ok(id) => id,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let check = StoreCheck { id, ..check };
    let server = server.clone();
    tokio::spawn(async move {
        run(&server, check).await;
    });
    Ok(Ok(id))
}

/// SV-8: asks a running check to stop. Any node can: the one running it
/// sees the request at its next save. None if there's no such check.
pub async fn stop(server: &Server, id: u32) -> trc::Result<Option<StoreCheck>> {
    model::update(server.store(), id, |c| {
        if c.status != Status::Running || c.stop_requested {
            return false;
        }
        c.stop_requested = true;
        true
    })
    .await
}

/// SV-8: at start-up, a check this node ran stopped with it. Then, now and
/// then, a check on a node that went quiet is taken to have stopped too.
pub fn spawn_store_checks(inner: Arc<Inner>) {
    tokio::spawn(async move {
        let server = inner.build_server();
        let node = node_id(&server);
        mark_interrupted(&server, |c| c.node_id == node).await;
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let server = inner.build_server();
            let cutoff = now().saturating_sub(STALE_AFTER);
            mark_interrupted(&server, |c| c.node_id != node && c.heartbeat < cutoff).await;
        }
    });
}

async fn mark_interrupted(server: &Server, which: impl Fn(&StoreCheck) -> bool) {
    let checks = match model::all(server.store()).await {
        Ok(checks) => checks,
        Err(err) => {
            trc::error!(err.details("Failed to read the store checks"));
            return;
        }
    };
    for check in checks
        .into_iter()
        .filter(|c| c.status == Status::Running && which(c))
    {
        let result = model::update(server.store(), check.id, |c| {
            if c.status != Status::Running || !which(c) {
                return false;
            }
            c.status = Status::Interrupted;
            c.finished_at = Some(now());
            true
        })
        .await;
        if let Err(err) = result.and(model::release(server.store(), check.id).await) {
            trc::error!(err.details("Failed to mark an interrupted store check"));
        }
    }
}

/// SV-6: keeps a rate, a second at a time, so a slow stretch isn't made
/// up for with a burst.
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

/// What a blob turned out to be (SV-4).
enum Found {
    Fine,
    Problem(ProblemKind, String),
}

/// The name a problem gives an object (SV-4).
fn object_name(collection: u8) -> String {
    match Collection::from(collection) {
        Collection::Email => "email".into(),
        Collection::FileNode => "file".into(),
        Collection::SieveScript => "sieveScript".into(),
        Collection::CalendarEvent => "calendarEvent".into(),
        Collection::ContactCard => "contactCard".into(),
        _ => format!("collection{collection}"),
    }
}

struct Run<'x> {
    server: &'x Server,
    check: StoreCheck,
    progress: Progress,
    found: Vec<Problem>,
    kept: u64,
    names: HashMap<u32, String>,
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

impl<'x> Run<'x> {
    async fn account_name(&mut self, account_id: u32) -> String {
        if let Some(name) = self.names.get(&account_id) {
            return name.clone();
        }
        let name = self.server.audit_account_name(account_id).await;
        self.names.insert(account_id, name.clone());
        name
    }

    /// SV-4, SV-5: counts a problem, logs it, and keeps the first ones.
    async fn problem(
        &mut self,
        kind: ProblemKind,
        account_id: Option<u32>,
        object: String,
        object_id: u64,
        hash: &BlobHash,
        committed: bool,
        detail: String,
    ) {
        self.progress.count(kind);
        let account_name = match account_id {
            Some(id) => self.account_name(id).await,
            None => String::new(),
        };
        let blob_id = hash.to_hex();
        trc::event!(
            Store(trc::StoreEvent::DataCorruption),
            Id = self.check.id,
            AccountId = account_id,
            Collection = object.clone(),
            DocumentId = object_id,
            BlobId = blob_id.clone(),
            Reason = kind.as_str(),
            Details = detail.clone(),
        );
        if self.kept < MAX_PROBLEMS {
            self.kept += 1;
            self.found.push(Problem {
                kind,
                account_id,
                account_name,
                object,
                object_id,
                blob_id,
                committed,
                detail,
            });
        }
    }

    /// SV-7, SV-8: saves progress and the problems found since, now and
    /// then; a stop asked for meanwhile ends the run.
    async fn save(&mut self, force: bool) -> Result<(), Halt> {
        if !force && self.saved.elapsed() < SAVE_EVERY {
            return Ok(());
        }
        let data = self.server.store();
        let first = self.kept - self.found.len() as u64;
        model::add_problems(data, self.check.id, first, &self.found).await?;
        self.found.clear();
        let progress = self.progress.clone();
        let kept = self.kept;
        let saved = model::update(data, self.check.id, |c| {
            c.progress = progress.clone();
            c.problems_kept = kept;
            c.heartbeat = now();
            true
        })
        .await?;
        self.saved = Instant::now();
        match saved {
            Some(c) if c.stop_requested => Err(Halt::Stopped),
            Some(_) => Ok(()),
            // Forgotten under it: nothing left to report to
            None => Err(Halt::Stopped),
        }
    }

    /// SV-2: whether the blob is there and, in a full check, intact.
    async fn look_at(&mut self, hash: &BlobHash) -> Found {
        let store = self.server.blob_store();
        match self.check.mode {
            Mode::Quick => match store.blob_present(hash.as_slice()).await {
                Ok(true) => Found::Fine,
                Ok(false) => Found::Problem(ProblemKind::Missing, String::new()),
                Err(err) => Found::Problem(ProblemKind::Unreadable, err.to_string()),
            },
            Mode::Full => match store.get_blob(hash.as_slice(), 0..usize::MAX).await {
                Ok(Some(content)) => {
                    let size = content.len() as u64;
                    self.progress.bytes_read += size;
                    self.bytes.take(size).await;
                    let actual = BlobHash::generate(&content);
                    if &actual == hash {
                        Found::Fine
                    } else {
                        Found::Problem(
                            ProblemKind::Damaged,
                            format!("its {size} bytes hash to {}", actual.to_hex()),
                        )
                    }
                }
                Ok(None) => Found::Problem(ProblemKind::Missing, String::new()),
                Err(err)
                    if matches!(
                        err.as_ref(),
                        trc::EventType::Store(trc::StoreEvent::DecompressError)
                    ) =>
                {
                    Found::Problem(ProblemKind::Damaged, "it doesn't decompress".into())
                }
                Err(err) => Found::Problem(ProblemKind::Unreadable, err.to_string()),
            },
        }
    }

    /// SV-3, links: one slice of the blob index.
    async fn slice(&mut self, slice: u8, mail: &mut BTreeSet<u32>) -> Result<(), Halt> {
        let blobs: Vec<LinkedBlob> = self.server.store().linked_blobs(slice).await?;
        for blob in blobs {
            self.blobs.take(1).await;
            self.progress.blobs_checked += 1;
            self.progress.links_checked += blob.holders.len() as u64;
            for holder in &blob.holders {
                if let BlobHolder::Document {
                    account_id,
                    collection,
                    ..
                } = holder
                    && Collection::from(*collection) == Collection::Email
                {
                    mail.insert(*account_id);
                }
            }
            if let Found::Problem(kind, detail) = self.look_at(&blob.hash).await {
                // A shared blob is read once and reported for each holder
                for holder in &blob.holders {
                    let (account_id, object, object_id) = match holder {
                        BlobHolder::Document {
                            account_id,
                            collection,
                            document_id,
                        } => (
                            Some(*account_id),
                            object_name(*collection),
                            *document_id as u64,
                        ),
                        BlobHolder::Queue { id } => (None, "queuedMessage".to_string(), *id),
                        BlobHolder::Archived { account_id, item } => (
                            Some(*account_id),
                            "archivedItem".to_string(),
                            item.id().id(),
                        ),
                    };
                    self.problem(
                        kind,
                        account_id,
                        object,
                        object_id,
                        &blob.hash,
                        blob.committed,
                        detail.clone(),
                    )
                    .await;
                }
            }
            self.save(false).await?;
        }
        Ok(())
    }

    /// SV-3, mail metadata: each message names its blob; it must hold a
    /// link to it, or nothing keeps the blob from being purged.
    async fn mail(&mut self, account_id: u32) -> Result<(), Halt> {
        let data = self.server.store();
        let mut messages: Vec<(u32, BlobHash)> = Vec::new();
        data.iterate(
            IterateParams::new(
                ValueKey::property(account_id, Collection::Email, 0, EmailField::Metadata),
                ValueKey::property(
                    account_id,
                    Collection::Email,
                    u32::MAX,
                    EmailField::Metadata,
                ),
            ),
            |key, value| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                let archive = <Archive<AlignedBytes> as Deserialize>::deserialize(value)?;
                let metadata = archive.unarchive::<MessageMetadata>()?;
                messages.push((document_id, BlobHash::from(&metadata.blob_hash)));
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        for (document_id, hash) in messages {
            self.blobs.take(1).await;
            self.progress.messages_checked += 1;
            let linked = data
                .blob_has_access(
                    &hash,
                    BlobClass::Linked {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id,
                    },
                )
                .await?;
            if !linked {
                let committed = data.blob_exists(&hash).await?;
                let detail = match self.server.blob_store().blob_present(hash.as_slice()).await {
                    Ok(true) => "the blob is still there".to_string(),
                    Ok(false) => "the blob is gone".to_string(),
                    Err(err) => format!("the blob store couldn't say: {err}"),
                };
                self.problem(
                    ProblemKind::Unlinked,
                    Some(account_id),
                    "email".into(),
                    document_id as u64,
                    &hash,
                    committed,
                    detail,
                )
                .await;
            }
            self.save(false).await?;
        }
        Ok(())
    }

    async fn go(&mut self) -> Result<(), Halt> {
        let mut mail = BTreeSet::new();
        for slice in 0u8..=255 {
            self.slice(slice, &mut mail).await?;
            self.progress.slices = slice as u32 + 1;
            self.save(false).await?;
        }

        // Every account, and any whose mail is still linked without it
        // being in the registry any more (kept after deletion)
        let registry: RoaringBitmap = self
            .server
            .registry()
            .query::<RoaringBitmap>(RegistryQuery::new(ObjectType::Account))
            .await?;
        mail.extend(registry.iter());
        self.progress.accounts_total = mail.len() as u64;
        for account_id in mail {
            self.mail(account_id).await?;
            self.progress.accounts_done += 1;
            self.save(false).await?;
        }
        Ok(())
    }
}

/// Runs a check to its end and records how it ended (SV-8).
async fn run(server: &Server, check: StoreCheck) {
    let id = check.id;
    let mut run = Run {
        server,
        blobs: Pace::new(check.blobs_per_second),
        bytes: Pace::new(if check.mode == Mode::Full {
            check.bytes_per_second
        } else {
            0
        }),
        check,
        progress: Progress::default(),
        found: Vec::new(),
        kept: 0,
        names: HashMap::new(),
        saved: Instant::now(),
    };
    let ended = run.go().await;
    let (status, error) = match ended {
        Ok(()) => (Status::Done, None),
        Err(Halt::Stopped) => (Status::Stopped, None),
        Err(Halt::Failed(err)) => {
            let text = err
                .value_as_str(trc::Key::Details)
                .map(str::to_string)
                .unwrap_or_else(|| err.to_string());
            trc::error!(err.details("A store check failed"));
            (Status::Failed, Some(text))
        }
    };

    let data = server.store();
    let first = run.kept - run.found.len() as u64;
    let mut result = model::add_problems(data, id, first, &run.found).await;
    if result.is_ok() {
        let progress = run.progress.clone();
        let kept = run.kept;
        result = model::update(data, id, |c| {
            c.progress = progress.clone();
            c.problems_kept = kept;
            c.status = status;
            c.finished_at = Some(now());
            c.heartbeat = now();
            if let Some(error) = &error {
                c.set_error(error);
            }
            true
        })
        .await
        .map(|_| ());
    }
    if let Err(err) = result.and(model::release(data, id).await) {
        trc::error!(err.details("Failed to save a store check's result"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pace_holds_a_rate() {
        let mut pace = Pace::new(100);
        let started = Instant::now();
        for _ in 0..250 {
            pace.take(1).await;
        }
        // 250 at 100 a second: two full seconds waited, a bit of a third
        assert!(started.elapsed() >= Duration::from_millis(1_900));
        let mut free = Pace::new(0);
        let started = Instant::now();
        for _ in 0..10_000 {
            free.take(1).await;
        }
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn objects_are_named_by_collection() {
        assert_eq!(object_name(Collection::Email.into()), "email");
        assert_eq!(object_name(Collection::FileNode.into()), "file");
        assert_eq!(object_name(Collection::SieveScript.into()), "sieveScript");
        assert_eq!(object_name(Collection::Mailbox.into()), "collection1");
    }
}
