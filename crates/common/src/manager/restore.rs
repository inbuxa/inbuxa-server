/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::backup::{MAGIC_MARKER, S3_EXPORT_MANIFEST};
use crate::{Core, DATABASE_SCHEMA_VERSION};
use lz4_flex::frame::FrameDecoder;
use registry::{
    schema::{
        enums::{CompressionAlgo, TaskStoreMaintenanceType},
        structs::{Task, TaskStatus, TaskStoreMaintenance},
    },
    types::EnumImpl,
};
use std::{
    fs::File,
    io::{BufReader, ErrorKind, Read},
    path::{Path, PathBuf},
};
use store::{
    BlobStore, IterateParams, SUBSPACE_BLOBS, SUBSPACE_COUNTER, SUBSPACE_INBUXA, SUBSPACE_INDEXES,
    SUBSPACE_PROPERTY, SUBSPACE_QUOTA, SUBSPACE_REGISTRY_PK, SUBSPACE_TELEMETRY_SPAN, Store,
    U32_LEN,
    write::{
        AnyClass, AnyKey, BatchBuilder, ValueClass,
        key::{DeserializeBigEndian, is_node_id_key},
    },
};
use types::{collection::Collection, field::Field};
use utils::{UnwrapFailure, failed};

impl Core {
    /// Imports an export into an empty store and returns the subspaces it
    /// wrote. inbuxa: the caller hands them to [`Core::queue_reindex`].
    pub async fn restore(&self, src: PathBuf) -> Vec<u8> {
        // inbuxa: K-C11: an export in S3
        let src_text = src.to_string_lossy().to_string();
        if store::inbuxa_transfer::is_s3_url(&src_text) {
            return self.restore_s3(&src_text).await;
        }

        // Backup the core
        let paths = if src.is_dir() {
            let mut paths = Vec::new();
            for entry in std::fs::read_dir(&src).failed("Failed to read directory") {
                let entry = entry.failed("Failed to read entry");
                let path = entry.path();
                if path.is_file() {
                    paths.push(path);
                }
            }
            paths
        } else {
            vec![src]
        };

        let sources = paths.into_iter().map(Source::File).collect::<Vec<_>>();
        self.restore_sources(sources).await
    }

    /// inbuxa: K-C11: `s3://bucket/prefix/<name>`, or the newest finished
    /// export under `s3://bucket/prefix`. An export without its manifest
    /// didn't finish, and is refused.
    async fn restore_s3(&self, url: &str) -> Vec<u8> {
        use store::inbuxa_transfer::S3Transfer;
        let base =
            S3Transfer::open(url).unwrap_or_else(|err| failed(&format!("Import failed: {err}")));
        let (transfer, manifest) = match base.get(S3_EXPORT_MANIFEST).await {
            Ok(Some(manifest)) => (base, manifest),
            Ok(None) => {
                let names = base
                    .children_with(S3_EXPORT_MANIFEST)
                    .await
                    .unwrap_or_else(|err| failed(&format!("Import failed: {err}")));
                let Some(newest) = names.last() else {
                    failed(&format!(
                        "Import failed: no finished export at {url} or under it (an export is \
                         finished once its {S3_EXPORT_MANIFEST} is written)."
                    ));
                };
                let transfer = base.join(newest);
                println!(
                    "Importing the newest finished export, {}.",
                    transfer.location()
                );
                let manifest = transfer
                    .get(S3_EXPORT_MANIFEST)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| failed("Import failed: the export's manifest went away"));
                (transfer, manifest)
            }
            Err(err) => failed(&format!("Import failed: {err}")),
        };
        let manifest: serde_json::Value = serde_json::from_slice(&manifest)
            .unwrap_or_else(|err| failed(&format!("Import failed: {S3_EXPORT_MANIFEST}: {err}")));
        let sources = manifest["files"]
            .as_array()
            .unwrap_or_else(|| {
                failed(&format!(
                    "Import failed: {S3_EXPORT_MANIFEST} lists no files"
                ))
            })
            .iter()
            .map(|file| {
                let name = file["name"].as_str().unwrap_or_default();
                let subspace = file["subspace"].as_u64().and_then(|s| u8::try_from(s).ok());
                match (name, subspace) {
                    (name, Some(subspace))
                        if name.starts_with("subspace_") && !name.contains('/') =>
                    {
                        Source::S3 {
                            transfer: transfer.clone(),
                            name: name.to_string(),
                            subspace,
                        }
                    }
                    _ => failed(&format!(
                        "Import failed: {S3_EXPORT_MANIFEST}: a bad file entry: {file}"
                    )),
                }
            })
            .collect::<Vec<_>>();
        self.restore_sources(sources).await
    }

    async fn restore_sources(&self, paths: Vec<Source>) -> Vec<u8> {
        let mut conflicts = Vec::new();
        for path in &paths {
            let subspace = path.subspace();
            // inbuxa: K-C11: every start writes the fork's own subspace, this
            // import's too: where the blob store is (W), the permission
            // grants (P), the log files' setting (T). Its records are keyed
            // values, which an import sets over, never duplicates; a store in
            // use still has data in the other subspaces, which are checked.
            if subspace == SUBSPACE_INBUXA {
                continue;
            }
            if subspace_has_data(&self.storage.data, subspace).await {
                conflicts.push(path.describe());
            }
        }

        if !conflicts.is_empty() {
            eprintln!(
                "Cannot import: the target database already contains data in the key ranges being \
                 imported. This usually means the server was started before the import ran, which \
                 can create duplicate entries. Import into a fresh, empty database and do not \
                 start the server before importing. Conflicting dumps:"
            );
            for path in conflicts {
                eprintln!("  {path}");
            }
            std::process::exit(1);
        }

        let mut imported = paths.iter().map(Source::subspace).collect::<Vec<_>>();
        imported.sort_unstable();
        imported.dedup();

        // inbuxa: K-C11: the blobs last, into the blob store the imported
        // settings name. This process started on an empty store, whose
        // blob store is the data store; a server started on the imported
        // one reads blobs from wherever its x:BlobStore says (S3, say), so
        // blobs written to the data store would be missing there.
        let (blobs, rest): (Vec<_>, Vec<_>) = paths
            .into_iter()
            .partition(|path| path.subspace() == SUBSPACE_BLOBS);

        let mut tasks = Vec::new();
        for path in rest {
            let storage = self.storage.clone();
            let blob_store = self.storage.blob.clone();
            tasks.push(tokio::spawn(async move {
                restore_file(storage.data, blob_store, &path).await;
            }));
        }
        for task in tasks {
            task.await.failed("Failed to wait for task");
        }

        if !blobs.is_empty() {
            let blob_store = self.imported_blob_store().await;
            let mut tasks = Vec::new();
            for path in blobs {
                let storage = self.storage.clone();
                let blob_store = blob_store.clone();
                tasks.push(tokio::spawn(async move {
                    restore_file(storage.data, blob_store, &path).await;
                }));
            }
            for task in tasks {
                task.await.failed("Failed to wait for task");
            }
        }

        imported
    }

    /// inbuxa: K-C11: the blob store the store's x:BlobStore names now,
    /// after the import wrote it
    async fn imported_blob_store(&self) -> BlobStore {
        use registry::{schema::structs::BlobStore as BlobStoreSetting, types::ObjectImpl};
        let setting = self
            .storage
            .registry
            .object::<BlobStoreSetting>(BlobStoreSetting::OBJECT.singleton().id())
            .await
            .failed("Failed to read the imported blob store setting")
            .unwrap_or_default();
        if matches!(setting, BlobStoreSetting::Default) {
            println!("Importing blobs into the data store, as the export's settings say.");
            return self.storage.data.clone().into();
        }
        let mut warnings = Vec::new();
        let store = BlobStore::open(setting, &self.storage.data, &mut warnings)
            .await
            .unwrap_or_else(|err| {
                failed(&format!(
                    "Can't open the blob store the export's settings name, to import the \
                     blobs into: {err}"
                ))
            });
        for warning in warnings {
            eprintln!("Blob store: {warning}");
        }
        println!("Importing blobs into the blob store the export's settings name.");
        store
    }

    /// inbuxa: an export never carries the full-text index. It is built by
    /// and for one search backend (the SQL stores index into their own
    /// tables, the key-value stores into a subspace, external engines keep it
    /// themselves), so it would be wrong or unreadable after a move to
    /// another one. Instead, an import queues the same reindex tasks an
    /// administrator can queue by hand (`reindexAccounts` and
    /// `reindexTelemetry` store maintenance), and the server rebuilds the
    /// index for whatever search store it is configured with once it starts.
    pub async fn queue_reindex(&self, imported: &[u8]) -> Vec<TaskStoreMaintenanceType> {
        let mut queued = Vec::new();
        if imported.contains(&SUBSPACE_PROPERTY) {
            queued.push(TaskStoreMaintenanceType::ReindexAccounts);
        }
        if imported.contains(&SUBSPACE_TELEMETRY_SPAN) {
            queued.push(TaskStoreMaintenanceType::ReindexTelemetry);
        }
        if queued.is_empty() {
            return queued;
        }

        let mut batch = BatchBuilder::new();
        for maintenance_type in &queued {
            batch.schedule_task(Task::StoreMaintenance(TaskStoreMaintenance {
                maintenance_type: *maintenance_type,
                status: TaskStatus::now(),
                shard_index: None,
            }));
        }
        self.storage
            .data
            .write(batch.build_all())
            .await
            .failed("Failed to queue the reindex tasks");

        println!(
            "Queued {} to rebuild the search index; it runs when the server starts.",
            queued
                .iter()
                .map(|t| t.as_str())
                .collect::<Vec<_>>()
                .join(" and ")
        );

        queued
    }
}

async fn subspace_has_data(store: &Store, subspace: u8) -> bool {
    let mut has_data = false;
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
                if subspace == SUBSPACE_REGISTRY_PK && is_node_id_key(key) {
                    Ok(true)
                } else {
                    has_data = true;
                    Ok(false)
                }
            },
        )
        .await
        .failed("Failed to inspect target database");
    has_data
}

/// inbuxa: K-C11: one export file: on disk, or in S3
enum Source {
    File(PathBuf),
    S3 {
        transfer: store::inbuxa_transfer::S3Transfer,
        name: String,
        /// From the manifest, so the file needn't be opened to know it
        subspace: u8,
    },
}

impl Source {
    fn subspace(&self) -> u8 {
        match self {
            Source::File(path) => KeyValueReader::new(path).subspace,
            Source::S3 { subspace, .. } => *subspace,
        }
    }

    fn describe(&self) -> String {
        match self {
            Source::File(path) => path.display().to_string(),
            Source::S3 { transfer, name, .. } => format!("{}/{name}", transfer.location()),
        }
    }

    fn open(&self) -> KeyValueReader {
        match self {
            Source::File(path) => KeyValueReader::new(path),
            Source::S3 {
                transfer,
                name,
                subspace,
            } => {
                let reader =
                    KeyValueReader::from_reader(Box::new(transfer.reader(name)), &self.describe());
                if reader.subspace != *subspace {
                    failed(&format!(
                        "{} holds subspace {}, but the manifest says {subspace}",
                        self.describe(),
                        reader.subspace
                    ));
                }
                reader
            }
        }
    }
}

async fn restore_file(store: Store, blob_store: BlobStore, path: &Source) {
    println!("Importing database dump from {}.", path.describe());

    let mut reader = path.open();
    let mut batch = BatchBuilder::new();

    match reader.subspace {
        SUBSPACE_BLOBS => {
            while let Some((key, value)) = reader.next() {
                blob_store
                    .put_blob(&key, &value, CompressionAlgo::Lz4)
                    .await
                    .failed("Failed to write blob");
            }
        }
        SUBSPACE_COUNTER | SUBSPACE_QUOTA => {
            while let Some((key, value)) = reader.next() {
                let class = ValueClass::Any(AnyClass {
                    subspace: reader.subspace,
                    key,
                });
                let value = u64::from_le_bytes(
                    value
                        .try_into()
                        .expect("Failed to deserialize counter/quota"),
                ) as i64;
                // inbuxa: the SQL stores add a negative amount with an UPDATE,
                // which does nothing to a row that isn't there yet, so a
                // negative counter vanished on import. Create the row first.
                if value < 0 {
                    batch.add(class.clone(), 0);
                }
                batch.add(class, value);
                if batch.is_large_batch() {
                    store
                        .write(batch.build_all())
                        .await
                        .failed("Failed to write batch");
                    batch = BatchBuilder::new();
                }
            }
        }
        SUBSPACE_INDEXES => {
            while let Some((key, _)) = reader.next() {
                let account_id = key
                    .as_slice()
                    .deserialize_be_u32(0)
                    .failed("Failed to deserialize account ID");
                let collection = *key.get(U32_LEN).failed("Missing collection byte");
                let field = *key.get(U32_LEN + 1).failed("Missing field byte");
                let value = key
                    .get(U32_LEN + 2..key.len() - U32_LEN)
                    .failed("Missing index key")
                    .to_vec();
                let document_id = key
                    .as_slice()
                    .deserialize_be_u32(key.len() - U32_LEN)
                    .failed("Failed to deserialize document ID");

                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::from(collection))
                    .with_document(document_id)
                    .index(Field::new(field), value);

                if batch.is_large_batch() {
                    store
                        .write(batch.build_all())
                        .await
                        .failed("Failed to write batch");
                    batch = BatchBuilder::new();
                }
            }
        }
        _ => {
            while let Some((key, value)) = reader.next() {
                batch.set(
                    ValueClass::Any(AnyClass {
                        subspace: reader.subspace,
                        key,
                    }),
                    value,
                );
                if batch.is_large_batch() {
                    store
                        .write(batch.build_all())
                        .await
                        .failed("Failed to write batch");
                    batch = BatchBuilder::new();
                }
            }
        }
    }

    if !batch.is_empty() {
        store
            .write(batch.build_all())
            .await
            .failed("Failed to write batch");
    }
}

struct KeyValueReader {
    subspace: u8,
    file: FrameDecoder<BufReader<Box<dyn Read + Send>>>,
}

impl KeyValueReader {
    fn new(path: &Path) -> Self {
        Self::from_reader(
            Box::new(File::open(path).failed("Failed to open file")),
            &path.display().to_string(),
        )
    }

    // inbuxa: K-C11: any reader: a file, or a download from S3
    fn from_reader(reader: Box<dyn Read + Send>, path: &str) -> Self {
        let mut file = FrameDecoder::new(BufReader::new(reader));
        let mut buf = [0u8; 1];
        file.read_exact(&mut buf)
            .failed(&format!("Failed to read magic marker from {path:?}"));

        if buf[0] != MAGIC_MARKER {
            failed(&format!("Invalid magic marker in {path:?}"));
        }

        file.read_exact(&mut buf)
            .failed(&format!("Failed to read subspace from {path:?}"));
        let subspace = buf[0];

        let mut buf = [0u8; 4];
        file.read_exact(&mut buf)
            .failed(&format!("Failed to read version from {path:?}"));
        let version = u32::from_le_bytes(buf);

        if version != DATABASE_SCHEMA_VERSION {
            failed(&format!(
                "Invalid database schema version in {path:?}: Expected {DATABASE_SCHEMA_VERSION}, found {version}"
            ));
        }

        Self { file, subspace }
    }

    fn next(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        let size = self.read_size()?;

        let mut key = vec![0; size as usize];
        self.file
            .read_exact(&mut key)
            .failed("Failed to read bytes");
        let value = self.expect_sized_bytes();

        Some((key, value))
    }

    fn read_size(&mut self) -> Option<u32> {
        let mut result = 0;
        let mut buf = [0u8; 1];

        for shift in [0, 7, 14, 21, 28] {
            if let Err(err) = self.file.read_exact(&mut buf) {
                if err.kind() == ErrorKind::UnexpectedEof {
                    return None;
                } else {
                    failed(&format!("Failed to read file: {err:?}"));
                }
            }

            let byte = buf[0];
            if (byte & 0x80) == 0 {
                result |= (byte as u32) << shift;
                return Some(result);
            } else {
                result |= ((byte & 0x7F) as u32) << shift;
            }
        }

        failed("Invalid leb128 sequence")
    }

    fn expect_sized_bytes(&mut self) -> Vec<u8> {
        let len = self.read_size().failed("Missing leb128 value sequence") as usize;
        let mut bytes = vec![0; len];
        self.file
            .read_exact(&mut bytes)
            .failed("Failed to read bytes");
        bytes
    }
}
