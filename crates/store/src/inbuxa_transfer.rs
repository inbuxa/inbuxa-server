/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! inbuxa: K-C11: an export written to, and read back from, an S3 bucket.
//!
//! `--export s3://bucket/prefix` streams each export file into a multipart
//! upload, so nothing the size of the store lands on local disk, and
//! `--import s3://bucket/prefix/<name>` streams it back. The bucket's
//! address and keys come from the environment:
//!
//! - `INBUXA_EXPORT_S3_ENDPOINT`: an S3-compatible service (MinIO, Garage,
//!   Ceph...), addressed path-style. Without it, AWS.
//! - `INBUXA_EXPORT_S3_REGION`: `us-east-1` unless given.
//! - `INBUXA_EXPORT_S3_ACCESS_KEY_FILE`, `INBUXA_EXPORT_S3_SECRET_KEY_FILE`:
//!   files holding the keys. Without them, the usual AWS sources (the
//!   `AWS_` variables, a profile, the instance's role).
//!
//! The export and import code is sync (a writer thread per file, readers in
//! the import tasks); these bridge it to the async S3 client.

/// Whether a `--export`/`--import` value names a bucket.
pub fn is_s3_url(value: &str) -> bool {
    value.starts_with("s3://")
}

/// The name an export made now goes under: `20261119T204500Z`.
pub fn export_name(now: u64) -> String {
    let days = (now / 86_400) as i64;
    let secs = now % 86_400;
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// The size of upload part `n` (from 1): 16 MiB for the first thousand,
/// doubling every thousand after, up to 512 MiB. S3 takes at most 10,000
/// parts, so one file can be nearly 3 TiB, and only one part is held at a
/// time.
pub fn part_size(part: u32) -> usize {
    const MIB: usize = 1024 * 1024;
    let tier = (part.saturating_sub(1) / 1000).min(5);
    (16 * MIB) << tier
}

/// The most parts S3 takes in one upload.
pub const MAX_PARTS: u32 = 10_000;

#[cfg(feature = "s3")]
pub use imp::{PartReader, PartWriter, S3Transfer};

#[cfg(not(feature = "s3"))]
pub use none::{PartReader, PartWriter, S3Transfer};

#[cfg(feature = "s3")]
mod imp {
    use super::{MAX_PARTS, part_size};
    use futures::StreamExt;
    use s3::{Bucket, Region, creds::Credentials, serde_types::Part};
    use std::io::{Read, Write};
    use std::sync::mpsc as std_mpsc;
    use tokio::sync::mpsc;

    const CONTENT_TYPE: &str = "application/octet-stream";
    const RETRIES: u32 = 5;

    #[derive(Clone)]
    pub struct S3Transfer {
        bucket: Box<Bucket>,
        bucket_name: String,
        /// No leading or trailing slash; may be empty.
        prefix: String,
    }

    fn env(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    fn key_file(name: &str) -> Result<Option<String>, String> {
        match env(name) {
            Some(path) => std::fs::read_to_string(&path)
                .map(|v| Some(v.trim_end_matches(['\r', '\n']).to_string()))
                .map_err(|err| format!("{name}: can't read {path}: {err}")),
            None => Ok(None),
        }
    }

    impl S3Transfer {
        /// `s3://bucket/prefix`, with the bucket's address and keys from the
        /// environment.
        pub fn open(url: &str) -> Result<Self, String> {
            let rest = url
                .strip_prefix("s3://")
                .ok_or_else(|| format!("{url}: not an s3:// address"))?;
            let (bucket_name, prefix) = rest.split_once('/').unwrap_or((rest, ""));
            if bucket_name.is_empty() {
                return Err(format!("{url}: no bucket named"));
            }
            let region_name = env("INBUXA_EXPORT_S3_REGION").unwrap_or_else(|| "us-east-1".into());
            let endpoint = env("INBUXA_EXPORT_S3_ENDPOINT");
            let region = match &endpoint {
                Some(endpoint) => Region::Custom {
                    region: region_name,
                    endpoint: endpoint.trim_end_matches('/').to_string(),
                },
                None => region_name
                    .parse()
                    .map_err(|err| format!("INBUXA_EXPORT_S3_REGION: {err}"))?,
            };
            let access = key_file("INBUXA_EXPORT_S3_ACCESS_KEY_FILE")?;
            let secret = key_file("INBUXA_EXPORT_S3_SECRET_KEY_FILE")?;
            let credentials = match (&access, &secret) {
                (Some(access), Some(secret)) => {
                    Credentials::new(Some(access), Some(secret), None, None, None)
                }
                (None, None) => Credentials::default(),
                _ => {
                    return Err("INBUXA_EXPORT_S3_ACCESS_KEY_FILE and \
                                INBUXA_EXPORT_S3_SECRET_KEY_FILE go together"
                        .into());
                }
            }
            .map_err(|err| format!("S3 credentials: {err}"))?;
            let mut bucket = Bucket::new(bucket_name, region, credentials)
                .map_err(|err| format!("S3 bucket {bucket_name}: {err}"))?;
            if endpoint.is_some() {
                bucket = bucket.with_path_style();
            }
            Ok(S3Transfer {
                bucket,
                bucket_name: bucket_name.to_string(),
                prefix: prefix.trim_matches('/').to_string(),
            })
        }

        /// The same bucket, one level down.
        pub fn join(&self, name: &str) -> Self {
            S3Transfer {
                prefix: self.key(name),
                ..self.clone()
            }
        }

        pub fn location(&self) -> String {
            format!("s3://{}/{}", self.bucket_name, self.prefix)
        }

        fn key(&self, name: &str) -> String {
            if self.prefix.is_empty() {
                name.to_string()
            } else {
                format!("{}/{name}", self.prefix)
            }
        }

        /// A small object, whole.
        pub async fn put(&self, name: &str, data: &[u8]) -> Result<(), String> {
            let key = self.key(name);
            let mut last = String::new();
            for attempt in 0..RETRIES {
                match self.bucket.put_object(&key, data).await {
                    Ok(r) if (200..300).contains(&r.status_code()) => return Ok(()),
                    Ok(r) => {
                        last = format!(
                            "{}: {}",
                            r.status_code(),
                            String::from_utf8_lossy(r.as_slice())
                        )
                    }
                    Err(err) => last = err.to_string(),
                }
                wait(attempt).await;
            }
            Err(format!(
                "Failed to write {}: {last}",
                self.location_of(name)
            ))
        }

        /// A small object, whole; None when it isn't there.
        pub async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            let key = self.key(name);
            let mut last = String::new();
            for attempt in 0..RETRIES {
                match self.bucket.get_object(&key).await {
                    Ok(r) if (200..300).contains(&r.status_code()) => {
                        return Ok(Some(r.to_vec()));
                    }
                    Ok(r) if r.status_code() == 404 => return Ok(None),
                    Ok(r) => last = format!("{}", r.status_code()),
                    Err(s3::error::S3Error::HttpFailWithBody(404, _)) => return Ok(None),
                    Err(err) => last = err.to_string(),
                }
                wait(attempt).await;
            }
            Err(format!("Failed to read {}: {last}", self.location_of(name)))
        }

        /// The names one level down that hold `marker`: the exports under a
        /// prefix.
        pub async fn children_with(&self, marker: &str) -> Result<Vec<String>, String> {
            let prefix = if self.prefix.is_empty() {
                String::new()
            } else {
                format!("{}/", self.prefix)
            };
            let results = self
                .bucket
                .list(prefix.clone(), None)
                .await
                .map_err(|err| format!("Failed to list {}: {err}", self.location()))?;
            let mut names = results
                .iter()
                .flat_map(|r| r.contents.iter())
                .filter_map(|o| o.key.strip_prefix(&prefix))
                .filter_map(|rest| rest.strip_suffix(marker)?.strip_suffix('/'))
                .filter(|name| !name.is_empty() && !name.contains('/'))
                .map(str::to_string)
                .collect::<Vec<_>>();
            names.sort();
            Ok(names)
        }

        fn location_of(&self, name: &str) -> String {
            format!("s3://{}/{}", self.bucket_name, self.key(name))
        }

        /// A writer whose bytes go up as a multipart upload under `name`,
        /// for a thread outside the runtime; the upload runs on the
        /// runtime. Dropping the writer sends the last part; the handle
        /// ends when the upload is complete.
        pub fn writer(
            &self,
            name: &str,
        ) -> (PartWriter, tokio::task::JoinHandle<Result<u64, String>>) {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
            let this = self.clone();
            let name = name.to_string();
            let handle = tokio::spawn(async move { this.upload(&name, rx).await });
            (
                PartWriter {
                    tx: Some(tx),
                    buf: Vec::with_capacity(part_size(1)),
                    part: 1,
                },
                handle,
            )
        }

        async fn upload(&self, name: &str, mut rx: mpsc::Receiver<Vec<u8>>) -> Result<u64, String> {
            let key = self.key(name);
            let location = self.location_of(name);
            let upload_id = self
                .bucket
                .initiate_multipart_upload(&key, CONTENT_TYPE)
                .await
                .map_err(|err| format!("Failed to start uploading {location}: {err}"))?
                .upload_id;
            let mut parts: Vec<Part> = Vec::new();
            let mut total = 0u64;
            let result: Result<(), String> = async {
                while let Some(chunk) = rx.recv().await {
                    let number = parts.len() as u32 + 1;
                    if number > MAX_PARTS {
                        return Err(format!("{location}: too large for one upload"));
                    }
                    total += chunk.len() as u64;
                    parts.push(
                        self.put_part(chunk, &key, number, &upload_id, &location)
                            .await?,
                    );
                }
                Ok(())
            }
            .await;
            if let Err(err) = result {
                // Dropping rx fails the writer's next send, which stops it
                drop(rx);
                let _ = self.bucket.abort_upload(&key, &upload_id).await;
                return Err(err);
            }
            let mut last = String::new();
            for attempt in 0..RETRIES {
                match self
                    .bucket
                    .complete_multipart_upload(&key, &upload_id, parts.clone())
                    .await
                {
                    Ok(r) if (200..300).contains(&r.status_code()) => return Ok(total),
                    Ok(r) => last = format!("{}", r.status_code()),
                    Err(err) => last = err.to_string(),
                }
                wait(attempt).await;
            }
            let _ = self.bucket.abort_upload(&key, &upload_id).await;
            Err(format!("Failed to finish uploading {location}: {last}"))
        }

        async fn put_part(
            &self,
            chunk: Vec<u8>,
            key: &str,
            number: u32,
            upload_id: &str,
            location: &str,
        ) -> Result<Part, String> {
            let mut last = String::new();
            for attempt in 0..RETRIES {
                match self
                    .bucket
                    .put_multipart_chunk(chunk.clone(), key, number, upload_id, CONTENT_TYPE)
                    .await
                {
                    Ok(part) => return Ok(part),
                    Err(err) => last = err.to_string(),
                }
                wait(attempt).await;
            }
            Err(format!(
                "Failed to upload part {number} of {location}: {last}"
            ))
        }

        /// A reader of the object `name`, for code that reads synchronously
        /// on the runtime's workers: the download is a task on the runtime,
        /// and a reader that has to wait for it hands its worker over.
        pub fn reader(&self, name: &str) -> PartReader {
            let (tx, rx) = std_mpsc::sync_channel::<Result<Vec<u8>, String>>(4);
            let this = self.clone();
            let key = self.key(name);
            let location = self.location_of(name);
            tokio::spawn(async move {
                {
                    let mut stream = match this.bucket.get_object_stream(&key).await {
                        Ok(stream) if (200..300).contains(&stream.status_code) => stream,
                        Ok(stream) => {
                            let _ = send_chunk(
                                &tx,
                                Err(format!("Failed to read {location}: {}", stream.status_code)),
                            );
                            return;
                        }
                        Err(err) => {
                            let _ =
                                send_chunk(&tx, Err(format!("Failed to read {location}: {err}")));
                            return;
                        }
                    };
                    while let Some(chunk) = stream.bytes().next().await {
                        let sent = match chunk {
                            Ok(bytes) => send_chunk(&tx, Ok(bytes.to_vec())),
                            Err(err) => {
                                let _ = send_chunk(
                                    &tx,
                                    Err(format!("Failed to read {location}: {err}")),
                                );
                                return;
                            }
                        };
                        if sent.is_err() {
                            return;
                        }
                    }
                }
            });
            PartReader {
                rx,
                buf: Vec::new(),
                pos: 0,
            }
        }
    }

    /// Whether this thread is a worker of a multi-threaded runtime, where a
    /// wait can hand the worker over (`block_in_place`)
    fn on_worker() -> bool {
        tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    }

    /// A send that, when it has to wait for the reader, hands the worker over
    fn send_chunk(
        tx: &std_mpsc::SyncSender<Result<Vec<u8>, String>>,
        item: Result<Vec<u8>, String>,
    ) -> Result<(), ()> {
        match tx.try_send(item) {
            Ok(()) => Ok(()),
            Err(std_mpsc::TrySendError::Disconnected(_)) => Err(()),
            Err(std_mpsc::TrySendError::Full(item)) if on_worker() => {
                tokio::task::block_in_place(|| tx.send(item)).map_err(|_| ())
            }
            Err(std_mpsc::TrySendError::Full(item)) => tx.send(item).map_err(|_| ()),
        }
    }

    async fn wait(attempt: u32) {
        tokio::time::sleep(std::time::Duration::from_millis(250 << attempt.min(5))).await;
    }

    /// See [`S3Transfer::writer`].
    pub struct PartWriter {
        tx: Option<mpsc::Sender<Vec<u8>>>,
        buf: Vec<u8>,
        part: u32,
    }

    impl PartWriter {
        fn send(&mut self) -> std::io::Result<()> {
            let next = part_size(self.part + 1);
            let chunk = std::mem::replace(&mut self.buf, Vec::with_capacity(next));
            self.part += 1;
            match &self.tx {
                Some(tx) => tx.blocking_send(chunk).map_err(|_| {
                    std::io::Error::other("the upload stopped: its error is on the next line")
                }),
                None => Err(std::io::Error::other("the upload is finished")),
            }
        }
    }

    impl Write for PartWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            let room = part_size(self.part) - self.buf.len();
            let take = room.min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            if self.buf.len() == part_size(self.part) {
                self.send()?;
            }
            Ok(take)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Drop for PartWriter {
        fn drop(&mut self) {
            // The last part, which may be short; even an empty file is one
            // part
            if !self.buf.is_empty() || self.part == 1 {
                let _ = self.send();
            }
            self.tx = None;
        }
    }

    /// See [`S3Transfer::reader`].
    pub struct PartReader {
        rx: std_mpsc::Receiver<Result<Vec<u8>, String>>,
        buf: Vec<u8>,
        pos: usize,
    }

    impl Read for PartReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            while self.pos == self.buf.len() {
                // Readers run on the runtime's workers (the import's tasks),
                // and the download needs one to make progress: a wait hands
                // this worker over first, or a pod with one CPU's worth of
                // workers would stop here
                let next = match self.rx.try_recv() {
                    Ok(next) => Ok(next),
                    Err(std_mpsc::TryRecvError::Disconnected) => Err(std_mpsc::RecvError),
                    Err(std_mpsc::TryRecvError::Empty) => {
                        if on_worker() {
                            tokio::task::block_in_place(|| self.rx.recv())
                        } else {
                            self.rx.recv()
                        }
                    }
                };
                match next {
                    Ok(Ok(chunk)) => {
                        self.buf = chunk;
                        self.pos = 0;
                    }
                    Ok(Err(err)) => return Err(std::io::Error::other(err)),
                    // The download ended
                    Err(_) => return Ok(0),
                }
            }
            let n = out.len().min(self.buf.len() - self.pos);
            out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }
}

#[cfg(not(feature = "s3"))]
mod none {
    //! This build has no S3 client: [`S3Transfer::open`] always refuses, so
    //! nothing else here is ever reached.

    #[derive(Clone)]
    pub struct S3Transfer;
    pub struct PartWriter;
    pub struct PartReader;

    impl S3Transfer {
        pub fn open(_url: &str) -> Result<Self, String> {
            Err("this build has no S3 support (the s3 feature)".into())
        }
        pub fn join(&self, _name: &str) -> Self {
            unreachable!()
        }
        pub fn location(&self) -> String {
            unreachable!()
        }
        pub async fn put(&self, _name: &str, _data: &[u8]) -> Result<(), String> {
            unreachable!()
        }
        pub async fn get(&self, _name: &str) -> Result<Option<Vec<u8>>, String> {
            unreachable!()
        }
        pub async fn children_with(&self, _marker: &str) -> Result<Vec<String>, String> {
            unreachable!()
        }
        pub fn writer(
            &self,
            _name: &str,
        ) -> (PartWriter, tokio::task::JoinHandle<Result<u64, String>>) {
            unreachable!()
        }
        pub fn reader(&self, _name: &str) -> PartReader {
            unreachable!()
        }
    }

    impl std::io::Write for PartWriter {
        fn write(&mut self, _data: &[u8]) -> std::io::Result<usize> {
            unreachable!()
        }
        fn flush(&mut self) -> std::io::Result<()> {
            unreachable!()
        }
    }

    impl std::io::Read for PartReader {
        fn read(&mut self, _out: &mut [u8]) -> std::io::Result<usize> {
            unreachable!()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_names_sort_by_time() {
        assert_eq!(export_name(0), "19700101T000000Z");
        assert_eq!(export_name(1_795_552_496), "20261124T203456Z");
        assert_eq!(export_name(951_782_400), "20000229T000000Z");
        assert!(export_name(1_795_552_496) < export_name(1_795_552_497));
    }

    #[test]
    fn parts_grow_to_nearly_three_tebibytes() {
        assert_eq!(part_size(1), 16 << 20);
        assert_eq!(part_size(1000), 16 << 20);
        assert_eq!(part_size(1001), 32 << 20);
        assert_eq!(part_size(MAX_PARTS), 512 << 20);
        let total: u64 = (1..=MAX_PARTS).map(|n| part_size(n) as u64).sum();
        assert!(total > (29u64 << 40) / 10, "{total}");
    }

    #[test]
    fn s3_urls() {
        assert!(is_s3_url("s3://backups/inbuxa"));
        assert!(!is_s3_url("/var/backups"));
    }
}
