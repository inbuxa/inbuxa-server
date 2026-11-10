/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Snapshots of the store (docs/spec/features/store-snapshot.md): the run
//! behind an `inbuxa:StoreSnapshot`. It takes a RocksDB checkpoint and, for
//! a filesystem blob store, a copy of the blob files with the blob purge
//! held, into a directory under the store's own (SN-2, SN-3). The snapshots
//! on disk are the record: each one's `snapshot.json` says what it is. Only
//! the one being taken, or the last one that failed, is kept in memory.

use common::{Inner, Server};
use mail_parser::DateTime;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};
use store::write::{
    now,
    snapshot::{NotSnapshottable, SnapshotSource, copy_tree, hold_blob_purge, tree_size},
};
use types::id::Id;

/// SN-6: complete snapshots kept.
pub const KEEP: usize = 2;
const SNAPSHOTS_DIR: &str = "snapshots";
const MANIFEST: &str = "snapshot.json";
const LATEST: &str = "latest";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Running,
    Done,
    Failed,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Running => "running",
            Status::Done => "done",
            Status::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// When it was taken, in seconds: its name is that time.
    pub id: u64,
    pub name: String,
    pub status: Status,
    pub created_at: u64,
    pub created_by: String,
    pub finished_at: Option<u64>,
    pub node_id: u64,
    pub path: PathBuf,
    pub holds: Vec<String>,
    pub size: u64,
    pub blob_files: u64,
    pub error: Option<String>,
}

/// Why a snapshot isn't taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// SN-6: this one is being taken.
    Running(u64),
    /// SN-1, SN-2: these stores can't have one.
    Unsupported(String),
}

/// What `destroy` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destroyed {
    Gone,
    NotFound,
    Running,
}

/// SN-7: the one being taken, or the last one that failed, until restart.
static CURRENT: Mutex<Option<Snapshot>> = Mutex::new(None);

fn current() -> Option<Snapshot> {
    CURRENT.lock().map(|c| c.clone()).unwrap_or(None)
}

fn set_current(snapshot: Option<Snapshot>) {
    if let Ok(mut current) = CURRENT.lock() {
        *current = snapshot;
    }
}

/// The snapshots' directory, and what a snapshot would hold, or why there
/// can't be one here.
fn source(server: &Server) -> Result<(SnapshotSource, PathBuf), Refusal> {
    match server.store().snapshot_source(server.blob_store()) {
        Ok(source) => {
            let root = match &source {
                SnapshotSource::DataOnly { data_path }
                | SnapshotSource::DataAndFiles { data_path, .. } => data_path.join(SNAPSHOTS_DIR),
            };
            Ok((source, root))
        }
        Err(NotSnapshottable::DataStore(kind)) => Err(Refusal::Unsupported(format!(
            "A snapshot needs RocksDB as the data store, and this server's is {kind}. \
             Use {kind}'s own backup."
        ))),
        Err(NotSnapshottable::BlobStore(kind)) => Err(Refusal::Unsupported(format!(
            "A snapshot copies blobs kept in the data store or in a filesystem blob store, \
             and this server keeps them in {kind}."
        ))),
        // blob-store-change spec, BM-8
        Err(NotSnapshottable::BlobStoreChanging) => Err(Refusal::Unsupported(
            "The blob store changed and some blobs may still be only in the old one. \
             Copy them over or dismiss the change (inbuxa:BlobStoreChange) first."
                .to_string(),
        )),
    }
}

/// The snapshots' directory with a RocksDB data store, whether or not a
/// snapshot can be taken now. A blob store change that isn't settled
/// refuses a new one (BM-8), but the ones on disk are still listed,
/// destroyed and cleaned up (SN-7, SN-9).
fn root(server: &Server) -> Option<PathBuf> {
    server
        .store()
        .snapshot_data_path()
        .map(|path| path.join(SNAPSHOTS_DIR))
}

/// `20261109T013000Z`: a snapshot's name, the UTC time it was taken.
pub fn name_for(seconds: u64) -> String {
    let t = DateTime::from_timestamp(seconds as i64);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

fn rfc3339(seconds: u64) -> String {
    DateTime::from_timestamp(seconds as i64).to_rfc3339()
}

fn seconds_of(value: &Value) -> Option<u64> {
    DateTime::parse_rfc3339(value.as_str()?).map(|t| t.to_timestamp() as u64)
}

fn io(err: std::io::Error) -> trc::Error {
    trc::StoreEvent::FilesystemError.reason(err)
}

/// SN-1, SN-6: starts taking a snapshot on this node. Refused while one is
/// being taken, or when the stores can't have one.
pub async fn start(server: &Server, created_by: String) -> trc::Result<Result<Snapshot, Refusal>> {
    let (source, root) = match source(server) {
        Ok(found) => found,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let snapshot = {
        let Ok(mut current) = CURRENT.lock() else {
            return Err(trc::EventType::Server(trc::ServerEvent::ThreadError)
                .into_err()
                .details("The snapshot state is poisoned"));
        };
        if let Some(running) = current.as_ref().filter(|c| c.status == Status::Running) {
            return Ok(Err(Refusal::Running(running.id)));
        }
        // Names are the time to the second: a second one within the same
        // second takes the next
        let mut at = now();
        while root.join(name_for(at)).exists() {
            at += 1;
        }
        let name = name_for(at);
        let mut holds = vec!["data".to_string()];
        if matches!(source, SnapshotSource::DataAndFiles { .. }) {
            holds.push("blobs".to_string());
        }
        let snapshot = Snapshot {
            id: at,
            path: root.join(&name),
            name,
            status: Status::Running,
            created_at: at,
            created_by,
            finished_at: None,
            node_id: server.core.network.node_id,
            holds,
            size: 0,
            blob_files: 0,
            error: None,
        };
        *current = Some(snapshot.clone());
        snapshot
    };
    let server = server.clone();
    let running = snapshot.clone();
    tokio::spawn(async move {
        run(&server, source, root, running).await;
    });
    Ok(Ok(snapshot))
}

async fn run(server: &Server, source: SnapshotSource, root: PathBuf, mut snapshot: Snapshot) {
    let partial = root.join(format!(".{}.partial", snapshot.name));
    match take(server, &source, &root, &partial, &mut snapshot).await {
        // Listed from disk from now on
        Ok(()) => set_current(None),
        Err(err) => {
            let _ = tokio::fs::remove_dir_all(&partial).await;
            snapshot.status = Status::Failed;
            snapshot.finished_at = Some(now());
            snapshot.error = Some(err.to_string());
            trc::error!(err.details("Failed to take a store snapshot"));
            set_current(Some(snapshot));
        }
    }
}

async fn take(
    server: &Server,
    source: &SnapshotSource,
    root: &Path,
    partial: &Path,
    snapshot: &mut Snapshot,
) -> trc::Result<()> {
    tokio::fs::create_dir_all(root).await.map_err(io)?;
    let _ = tokio::fs::remove_dir_all(partial).await;
    tokio::fs::create_dir(partial).await.map_err(io)?;

    // SN-4: the purge is held before the checkpoint, so every blob the
    // checkpoint links to is still there when it's copied
    let hold = match source {
        SnapshotSource::DataAndFiles { .. } => Some(hold_blob_purge().await),
        SnapshotSource::DataOnly { .. } => None,
    };
    server.store().checkpoint(partial.join("data")).await?;
    let blob_path = match source {
        SnapshotSource::DataAndFiles { blob_path, .. } => {
            let copy = copy_tree(
                blob_path.clone(),
                partial.join("blobs"),
                data_path_of(source).to_path_buf(),
            )
            .await?;
            snapshot.blob_files = copy.files;
            Some(blob_path)
        }
        SnapshotSource::DataOnly { .. } => None,
    };
    drop(hold);

    snapshot.size = tree_size(partial.to_path_buf()).await?;
    snapshot.status = Status::Done;
    snapshot.finished_at = Some(now());
    let manifest = manifest(
        snapshot,
        data_path_of(source),
        blob_path.map(|p| p.as_path()),
    );
    tokio::fs::write(
        partial.join(MANIFEST),
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .await
    .map_err(io)?;

    // SN-3: whole once it has its name
    tokio::fs::rename(partial, &snapshot.path)
        .await
        .map_err(io)?;
    if let Ok(dir) = tokio::fs::File::open(root).await {
        let _ = dir.sync_all().await;
    }
    prune(root).await;
    refresh_latest(root).await;
    Ok(())
}

fn data_path_of(source: &SnapshotSource) -> &Path {
    match source {
        SnapshotSource::DataOnly { data_path } | SnapshotSource::DataAndFiles { data_path, .. } => {
            data_path
        }
    }
}

/// SN-5.
fn manifest(snapshot: &Snapshot, data_path: &Path, blob_path: Option<&Path>) -> Value {
    let mut restore = vec![
        "Stop the server.".to_string(),
        format!(
            "Move the contents of {} aside, except snapshots/, and copy this snapshot's data/ into it.",
            data_path.display()
        ),
    ];
    if let Some(blob_path) = blob_path {
        restore.push(format!(
            "Move the contents of {} aside and copy this snapshot's blobs/ into it.",
            blob_path.display()
        ));
    }
    restore.push("Start the server.".to_string());
    json!({
        "id": Id::from(snapshot.id).to_string(),
        "name": snapshot.name,
        "createdAt": rfc3339(snapshot.created_at),
        "finishedAt": snapshot.finished_at.map(rfc3339),
        "createdBy": snapshot.created_by,
        "node": snapshot.node_id.to_string(),
        "server": concat!(types::brand_server!(), " ", types::brand_version!()),
        "holds": snapshot.holds,
        "dataStore": {"type": "RocksDB", "path": data_path.to_string_lossy()},
        "blobStore": match blob_path {
            Some(path) => json!({"type": "filesystem", "path": path.to_string_lossy()}),
            None => json!({"type": "in the data store"}),
        },
        "size": snapshot.size,
        "blobFiles": snapshot.blob_files,
        "restore": restore,
    })
}

fn from_manifest(path: PathBuf, manifest: &Value) -> Option<Snapshot> {
    let id = Id::from_str(manifest.get("id")?.as_str()?).ok()?.id();
    Some(Snapshot {
        id,
        name: manifest.get("name")?.as_str()?.to_string(),
        status: Status::Done,
        created_at: seconds_of(manifest.get("createdAt")?)?,
        created_by: manifest.get("createdBy")?.as_str()?.to_string(),
        finished_at: manifest.get("finishedAt").and_then(seconds_of),
        node_id: manifest.get("node")?.as_str()?.parse().ok()?,
        path,
        holds: manifest
            .get("holds")?
            .as_array()?
            .iter()
            .filter_map(|h| h.as_str().map(|s| s.to_string()))
            .collect(),
        size: manifest.get("size")?.as_u64()?,
        blob_files: manifest.get("blobFiles")?.as_u64()?,
        error: None,
    })
}

/// The complete snapshots under `root`, oldest first. A directory without a
/// readable `snapshot.json` isn't one, and is left alone.
async fn on_disk(root: &Path) -> Vec<Snapshot> {
    let mut found = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(root).await else {
        return found;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let path = entry.path();
        let Ok(bytes) = tokio::fs::read(path.join(MANIFEST)).await else {
            continue;
        };
        if let Some(snapshot) = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|manifest| from_manifest(path, &manifest))
            .filter(|s| s.name == name)
        {
            found.push(snapshot);
        }
    }
    found.sort_by_key(|s| s.id);
    found
}

/// SN-6: the oldest beyond the latest [`KEEP`] go.
async fn prune(root: &Path) {
    let snapshots = on_disk(root).await;
    let surplus = snapshots.len().saturating_sub(KEEP);
    for old in &snapshots[..surplus] {
        if let Err(err) = tokio::fs::remove_dir_all(&old.path).await {
            trc::error!(io(err).details("Failed to remove an old store snapshot"));
        }
    }
}

/// SN-3: `latest` names the newest complete snapshot, relative to the
/// snapshots' directory so it holds wherever that's mounted.
async fn refresh_latest(root: &Path) {
    let latest = root.join(LATEST);
    match on_disk(root).await.last() {
        Some(newest) => {
            let temp = root.join(format!(".{LATEST}.tmp"));
            let _ = tokio::fs::remove_file(&temp).await;
            let linked = async {
                tokio::fs::symlink(&newest.name, &temp).await?;
                tokio::fs::rename(&temp, &latest).await
            }
            .await;
            if let Err(err) = linked {
                trc::error!(io(err).details("Failed to point snapshots/latest at a snapshot"));
            }
        }
        None => {
            let _ = tokio::fs::remove_file(&latest).await;
        }
    }
}

/// Every snapshot, newest first: those on disk, and the one being taken or
/// the last one that failed (SN-7).
pub async fn list(server: &Server) -> Vec<Snapshot> {
    let mut snapshots = match root(server) {
        Some(root) => on_disk(&root).await,
        None => Vec::new(),
    };
    if let Some(current) = current().filter(|c| !snapshots.iter().any(|s| s.id == c.id)) {
        snapshots.push(current);
    }
    snapshots.sort_by_key(|s| std::cmp::Reverse(s.id));
    snapshots
}

/// One snapshot, as [`list`] has it.
pub async fn find(server: &Server, id: u64) -> Option<Snapshot> {
    list(server).await.into_iter().find(|s| s.id == id)
}

/// SN-9: deletes a snapshot's directory. One being taken can't be.
pub async fn destroy(server: &Server, id: u64) -> trc::Result<Destroyed> {
    if let Some(current) = current().filter(|c| c.id == id) {
        if current.status == Status::Running {
            return Ok(Destroyed::Running);
        }
        set_current(None);
        return Ok(Destroyed::Gone);
    }
    let Some(root) = root(server) else {
        return Ok(Destroyed::NotFound);
    };
    let Some(snapshot) = on_disk(&root).await.into_iter().find(|s| s.id == id) else {
        return Ok(Destroyed::NotFound);
    };
    tokio::fs::remove_dir_all(&snapshot.path)
        .await
        .map_err(io)?;
    refresh_latest(&root).await;
    Ok(Destroyed::Gone)
}

/// SN-7: a snapshot being taken when the server stopped left a partial
/// directory, removed when it starts.
pub fn spawn_store_snapshots(inner: Arc<Inner>) {
    tokio::spawn(async move {
        let server = common::BuildServer::build_server(&inner);
        let Some(root) = root(&server) else {
            return;
        };
        let Ok(mut entries) = tokio::fs::read_dir(&root).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') && name.ends_with(".partial") {
                let _ = tokio::fs::remove_dir_all(entry.path()).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_the_time() {
        assert_eq!(name_for(1_794_187_800), "20261109T013000Z");
        assert_eq!(name_for(0), "19700101T000000Z");
    }

    #[test]
    fn a_manifest_reads_back() {
        let snapshot = Snapshot {
            id: 1_794_187_800,
            name: name_for(1_794_187_800),
            status: Status::Done,
            created_at: 1_794_187_800,
            created_by: "admin@example.com".into(),
            finished_at: Some(1_794_187_802),
            node_id: 3,
            path: PathBuf::from("/var/lib/inbuxa/snapshots/20261109T013000Z"),
            holds: vec!["data".into(), "blobs".into()],
            size: 4096,
            blob_files: 12,
            error: None,
        };
        let manifest = manifest(
            &snapshot,
            Path::new("/var/lib/inbuxa/"),
            Some(Path::new("/var/lib/inbuxa-blobs")),
        );
        assert_eq!(manifest["restore"].as_array().unwrap().len(), 4);
        assert_eq!(
            from_manifest(snapshot.path.clone(), &manifest).unwrap(),
            snapshot
        );
    }
}
