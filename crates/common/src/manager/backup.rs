/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::Core;
use ahash::AHashSet;
use lz4_flex::frame::FrameEncoder;
use std::{
    io::{BufWriter, Write},
    path::PathBuf,
    sync::mpsc::{self, SyncSender},
};
use store::{
    write::{AnyClass, AnyKey, ValueClass},
    *,
};
use types::blob_hash::{BLOB_HASH_LEN, BlobHash};
use utils::{UnwrapFailure, codec::leb128::Leb128_, failed};

pub(super) const MAGIC_MARKER: u8 = 123;

// inbuxa: blobs kept under a fixed name instead of a content hash. Nothing
// links to them, so the export names them outright.
const NAMED_BLOBS: &[&[u8]] = &[
    crate::manager::SPAM_CLASSIFIER_KEY,
    crate::manager::SPAM_TRAINER_KEY,
];

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub(super) enum Family {
    Data = 0,
    Blob = 2,
    Registry = 3,
    Changelog = 4,
    Queue = 5,
    Report = 6,
    Telemetry = 7,
    Tasks = 8,
    // inbuxa: SL-19: the fork's large data (store layout version 3)
    Compliance = 9,
}

type TaskHandle = (tokio::task::JoinHandle<()>, std::thread::JoinHandle<()>);

#[derive(Debug, Default, PartialEq, Eq)]
pub struct BackupParams {
    dest: PathBuf,
    families: AHashSet<Family>,
}

/// inbuxa: K-C11: where the export files go
enum Sink {
    Dir(PathBuf),
    S3(store::inbuxa_transfer::S3Transfer),
}

type Upload = tokio::task::JoinHandle<Result<u64, String>>;

/// inbuxa: K-C11: an export in S3 ends with this, written last, naming its
/// files: an export without one didn't finish.
pub const S3_EXPORT_MANIFEST: &str = "export.json";

impl Core {
    pub async fn backup(&self, mut params: BackupParams) {
        // inbuxa: K-C11: s3://bucket/prefix exports to a new folder there
        let dest_text = params.dest.to_string_lossy().to_string();
        let sink = if store::inbuxa_transfer::is_s3_url(&dest_text) {
            let transfer = store::inbuxa_transfer::S3Transfer::open(&dest_text)
                .unwrap_or_else(|err| failed(&format!("Export failed: {err}")));
            Sink::S3(transfer.join(&store::inbuxa_transfer::export_name(store::write::now())))
        } else {
            Sink::Dir(params.dest.clone())
        };
        if let Sink::S3(_) = &sink {
        } else if !params.dest.exists() {
            std::fs::create_dir_all(&params.dest).failed("Failed to create backup directory");
        } else if !params.dest.is_dir() {
            eprintln!("Backup destination {:?} is not a directory.", params.dest);
            std::process::exit(1);
        }

        let mut sync_handles = Vec::new();
        let schema_version = self
            .storage
            .data
            .get_value::<u32>(AnyKey {
                subspace: SUBSPACE_PROPERTY,
                key: vec![0u8],
            })
            .await
            .failed("Could not retrieve database schema version.")
            .failed("Could not retrieve database schema version.");

        let mut families_given = true;
        if params.families.is_empty() {
            families_given = false;
            params.families = [
                Family::Data,
                Family::Registry,
                Family::Blob,
                Family::Changelog,
                Family::Queue,
                Family::Report,
                Family::Telemetry,
                Family::Tasks,
                Family::Compliance,
            ]
            .into_iter()
            .collect();
        }

        // inbuxa: K-C11: blobs last. An export taken while the server runs
        // then holds every blob the rest of it names: a message stored
        // during the export is either in it whole or not at all. (In a set's
        // order, the blobs could go first, and the messages stored after
        // them would point at blobs the export never got.)
        let mut families = params.families.into_iter().collect::<Vec<_>>();
        families.sort_by_key(|f| (*f == Family::Blob, *f as u8));

        let mut uploads: Vec<(String, u8, Upload)> = Vec::new();
        for subspace in families.into_iter().flat_map(|f| f.subspaces()).copied() {
            let name = format!("subspace_{}", store::subspace_name(subspace));
            let (writer, upload) = match &sink {
                Sink::Dir(dir) => (Output::File(dir.join(&name)), None),
                Sink::S3(transfer) => {
                    println!("Exporting database to {}/{name}.", transfer.location());
                    let (writer, upload) = transfer.writer(&name);
                    (Output::S3(writer), Some(upload))
                }
            };
            let (async_handle, sync_handle) = if subspace == SUBSPACE_BLOBS {
                self.backup_blobs(writer, subspace, schema_version)
            } else {
                self.backup_subspace(writer, subspace, schema_version)
            };
            async_handle.await.failed("Task failed");
            sync_handles.push(sync_handle);
            if let Some(upload) = upload {
                uploads.push((name, subspace, upload));
            }
        }

        for handle in sync_handles {
            handle.join().expect("Failed to join thread");
        }

        // inbuxa: K-C11: the uploads, then the manifest that says the
        // export is whole
        if let Sink::S3(transfer) = &sink {
            let mut files = Vec::new();
            let mut bytes = 0u64;
            for (name, subspace, upload) in uploads {
                let size = upload
                    .await
                    .failed("Upload task failed")
                    .unwrap_or_else(|err| failed(&format!("Export failed: {err}")));
                bytes += size;
                files.push(serde_json::json!({"name": name, "subspace": subspace, "bytes": size}));
            }
            let manifest = serde_json::json!({
                "format": 1,
                "version": types::brand_version!(),
                "schemaVersion": schema_version,
                "createdAt": store::write::now(),
                "partial": families_given,
                "files": files,
            });
            transfer
                .put(
                    S3_EXPORT_MANIFEST,
                    &serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
                )
                .await
                .unwrap_or_else(|err| failed(&format!("Export failed: {err}")));
            println!(
                "Exported {} files, {bytes} bytes compressed, to {}.",
                manifest["files"].as_array().map_or(0, Vec::len),
                transfer.location()
            );
        }
    }

    fn backup_blobs(&self, output: Output, subspace: u8, schema_version: u32) -> TaskHandle {
        let store = self.storage.data.clone();
        let blob_store = self.storage.blob.clone();
        let (handle, writer) = spawn_writer(output, subspace, schema_version);
        (
            tokio::spawn(async move {
                let mut blobs = Vec::new();
                let mut last_hash = BlobHash::default();
                store
                    .iterate(
                        IterateParams::new(
                            AnyKey {
                                subspace: SUBSPACE_BLOB_LINK,
                                key: vec![0u8],
                            },
                            AnyKey {
                                subspace: SUBSPACE_BLOB_LINK,
                                key: vec![u8::MAX; 32],
                            },
                        )
                        .no_values(),
                        |key, _| {
                            let hash = BlobHash::try_from_hash_slice(
                                key.get(0..BLOB_HASH_LEN).ok_or_else(|| {
                                    trc::Error::corrupted_key(key, None, trc::location!())
                                })?,
                            )
                            .unwrap();

                            if last_hash != hash {
                                blobs.push(hash.clone());
                                last_hash = hash;
                            }

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");

                // inbuxa: the trained spam classifier and its trainer state are
                // blobs stored under fixed names with no blob link, so the walk
                // over links above never reaches them.
                let named = NAMED_BLOBS.iter().map(|key| key.to_vec());
                for key in blobs
                    .into_iter()
                    .map(|hash| hash.as_slice().to_vec())
                    .chain(named)
                {
                    if let Some(blob) = blob_store
                        .get_blob(&key, 0..usize::MAX)
                        .await
                        .failed("Failed to get blob")
                    {
                        writer.send((key, blob)).failed("Failed to send key");
                    }
                }
            }),
            handle,
        )
    }

    fn backup_subspace(&self, output: Output, subspace: u8, schema_version: u32) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(output, subspace, schema_version);
        (
            tokio::spawn(async move {
                if !store.is_sql() || (subspace != SUBSPACE_COUNTER && subspace != SUBSPACE_QUOTA) {
                    store
                        .iterate(
                            IterateParams::new(
                                AnyKey {
                                    subspace,
                                    key: vec![0u8],
                                },
                                AnyKey {
                                    subspace,
                                    key: vec![u8::MAX; 32],
                                },
                            )
                            .set_values(
                                ![SUBSPACE_INDEXES, SUBSPACE_REGISTRY_IDX].contains(&subspace),
                            ),
                            |key, value| {
                                writer
                                    .send((key.to_vec(), value.to_vec()))
                                    .failed("Failed to send key");

                                Ok(true)
                            },
                        )
                        .await
                        .failed("Failed to iterate over data store");
                } else {
                    let mut keys = Vec::with_capacity(128);
                    store
                        .iterate(
                            IterateParams::new(
                                AnyKey {
                                    subspace,
                                    key: vec![0u8],
                                },
                                AnyKey {
                                    subspace,
                                    key: vec![u8::MAX; 32],
                                },
                            )
                            .no_values(),
                            |key, _| {
                                keys.push(key.to_vec());

                                Ok(true)
                            },
                        )
                        .await
                        .failed("Failed to iterate over data store");

                    for key in keys {
                        let counter = store
                            .get_counter(ValueClass::Any(AnyClass {
                                subspace,
                                key: key.clone(),
                            }))
                            .await
                            .failed("Failed to get counter");
                        writer
                            .send((key.to_vec(), (counter as u64).to_le_bytes().to_vec()))
                            .failed("Failed to send key");
                    }
                }
            }),
            handle,
        )
    }
}

/// inbuxa: K-C11: one export file's destination
enum Output {
    File(PathBuf),
    S3(store::inbuxa_transfer::PartWriter),
}

/// inbuxa: K-C11: the sending end of an export file's writer. The export's
/// tasks send from the runtime's workers; when the writer is behind (an
/// upload to S3 waits on the runtime too), a plain blocking send would hold
/// the worker it needs, and with one worker (a pod limited to one CPU) the
/// export would stop there. A send that has to wait hands its worker over
/// first.
struct ExportSender(SyncSender<(Vec<u8>, Vec<u8>)>);

impl ExportSender {
    fn send(&self, item: (Vec<u8>, Vec<u8>)) -> Result<(), mpsc::SendError<(Vec<u8>, Vec<u8>)>> {
        match self.0.try_send(item) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(item)) => {
                if can_block_in_place() {
                    tokio::task::block_in_place(|| self.0.send(item))
                } else {
                    self.0.send(item)
                }
            }
            Err(mpsc::TrySendError::Disconnected(item)) => Err(mpsc::SendError(item)),
        }
    }
}

/// Whether this thread is a worker of a multi-threaded runtime, the only
/// kind `block_in_place` works on
fn can_block_in_place() -> bool {
    tokio::runtime::Handle::try_current()
        .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
}

#[allow(clippy::type_complexity)]
fn spawn_writer(
    output: Output,
    subspace: u8,
    version: u32,
) -> (std::thread::JoinHandle<()>, ExportSender) {
    let (tx, rx) = mpsc::sync_channel::<(Vec<u8>, Vec<u8>)>(10);

    let handle = std::thread::spawn(move || {
        let out: Box<dyn Write + Send> = match output {
            Output::File(path) => {
                println!("Exporting database to {}.", path.to_str().unwrap());
                Box::new(std::fs::File::create(path).failed("Failed to create backup file"))
            }
            Output::S3(writer) => Box::new(writer),
        };
        let mut file = FrameEncoder::new(BufWriter::new(out));
        file.write_all(&[MAGIC_MARKER, subspace])
            .failed("Failed to write version");
        file.write_all(&version.to_le_bytes())
            .failed("Failed to write version");

        while let Ok((key, value)) = rx.recv() {
            key.len()
                .to_leb128_writer(&mut file)
                .failed("Failed to write key value");
            file.write_all(&key).failed("Failed to write key");
            value
                .len()
                .to_leb128_writer(&mut file)
                .failed("Failed to write key value");
            if !value.is_empty() {
                file.write_all(&value).failed("Failed to write key value");
            }
        }

        let mut file = file.finish().failed("Failed to finish backup file");
        file.flush().failed("Failed to flush backup file");
    });

    (handle, ExportSender(tx))
}

impl BackupParams {
    pub fn new(dest: PathBuf) -> Self {
        let mut params = Self {
            dest,
            families: AHashSet::new(),
        };

        if let Ok(families) = std::env::var("EXPORT_TYPES") {
            params.parse_families(&families);
        }

        params
    }

    fn parse_families(&mut self, families: &str) {
        for family in families.split(',') {
            let family = family.trim();
            match Family::parse(family) {
                Ok(family) => {
                    self.families.insert(family);
                }
                Err(err) => {
                    eprintln!("Backup failed: {err}.");
                    std::process::exit(1);
                }
            }
        }
    }
}

impl Family {
    pub fn subspaces(&self) -> &'static [u8] {
        match self {
            Family::Data => &[
                SUBSPACE_ACL,
                SUBSPACE_INDEXES,
                SUBSPACE_QUOTA,
                SUBSPACE_COUNTER,
                SUBSPACE_PROPERTY,
            ],
            Family::Blob => &[SUBSPACE_BLOBS, SUBSPACE_BLOB_LINK],
            Family::Registry => &[
                SUBSPACE_REGISTRY,
                SUBSPACE_REGISTRY_IDX,
                SUBSPACE_REGISTRY_PK,
                SUBSPACE_DIRECTORY,
                // inbuxa: registry objects the upstream list left out, so an
                // export dropped them: archived items (undelete) and spam
                // training samples. Their indexes and id counters already
                // travel in this family and in `data`, so they ride along.
                SUBSPACE_DELETED_ITEMS,
                SUBSPACE_SPAM_SAMPLES,
                store::SUBSPACE_INBUXA, // inbuxa: the fork's own settings and small records (masked email, policies)
            ],
            Family::Changelog => &[SUBSPACE_LOGS],
            Family::Queue => &[SUBSPACE_QUEUE_MESSAGE, SUBSPACE_QUEUE_EVENT],
            Family::Report => &[SUBSPACE_REPORT_OUT, SUBSPACE_REPORT_IN],
            Family::Telemetry => &[SUBSPACE_TELEMETRY_SPAN, SUBSPACE_TELEMETRY_METRIC],
            Family::Tasks => &[SUBSPACE_TASK_QUEUE],
            // inbuxa: SL-19: in a family of its own, so a configuration
            // export (`registry`) can leave out the audit log and journal
            Family::Compliance => &[
                store::SUBSPACE_AUDIT,
                store::SUBSPACE_JOURNAL,
                store::SUBSPACE_HOLDS,
                store::SUBSPACE_UNDELETE,
            ],
        }
    }

    pub fn parse(family: &str) -> Result<Self, String> {
        match family {
            "data" => Ok(Family::Data),
            "registry" => Ok(Family::Registry),
            "blob" => Ok(Family::Blob),
            "changelog" => Ok(Family::Changelog),
            "queue" => Ok(Family::Queue),
            "report" => Ok(Family::Report),
            "telemetry" => Ok(Family::Telemetry),
            "tasks" => Ok(Family::Tasks),
            "compliance" => Ok(Family::Compliance),
            _ => Err(format!("Unknown family {}", family)),
        }
    }
}
