/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Collecting what a legal hold keeps, as a ZIP (audit-hold-lock spec,
//! LH-12). For each account the hold covers (or those asked for): its mail,
//! calendars, contacts and files, and the deleted items the hold keeps, each
//! with its SHA-256 in `manifest.csv`, and the manifest's own hash beside
//! it. The hold's date range applies as it does to what's kept (LH-3).

use common::{Server, hold::kept_member};
use email::{
    cache::MessageCacheFetch,
    message::metadata::{MESSAGE_RECEIVED_MASK, MessageMetadata},
};
use groupware::{cache::GroupwareCache, calendar::CalendarEvent, contact::ContactCard, file::FileNode};
use inbuxa_features::{
    hold::{Hold, Keeping, is_held_until},
    undelete::records,
};
use registry::schema::{prelude::ObjectType, structs::ArchivedItem};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};
use store::{
    ValueKey,
    registry::RegistryQuery,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::EmailField,
    id::Id,
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

/// The largest ZIP built in memory. A bigger collection is refused with a
/// clear error rather than taking the node down; export fewer accounts.
pub const MAX_EXPORT: u64 = 2 * 1024 * 1024 * 1024;

/// One line of `manifest.csv`.
struct Entry {
    path: String,
    account: String,
    kind: &'static str,
    folder: String,
    date: Option<i64>,
    archived: bool,
    size: usize,
    sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn csv(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// A path segment that's safe in a ZIP: no separators, no leading dots.
fn segment(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c == '/' || c == '\\' || c.is_control() { '_' } else { c })
        .collect();
    let trimmed = cleaned.trim_start_matches('.').trim();
    if trimmed.is_empty() { "_".into() } else { trimmed.chars().take(120).collect() }
}

fn date_text(at: Option<i64>) -> String {
    at.map(|at| jmap_proto::types::date::UTCDate::from_timestamp(at).to_string())
        .unwrap_or_default()
}

struct Builder {
    zip: ZipWriter<Cursor<Vec<u8>>>,
    entries: Vec<Entry>,
    written: u64,
}

impl Builder {
    fn new() -> Self {
        Builder {
            zip: ZipWriter::new(Cursor::new(Vec::new())),
            entries: Vec::new(),
            written: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        path: String,
        bytes: &[u8],
        account: &str,
        kind: &'static str,
        folder: &str,
        date: Option<i64>,
        archived: bool,
    ) -> trc::Result<()> {
        self.written += bytes.len() as u64;
        if self.written > MAX_EXPORT {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("The collection is larger than one export can hold (2 GB). Export fewer accounts at a time."));
        }
        // Unique within the ZIP, however names collide
        let mut name = path.clone();
        let mut n = 1;
        while self.entries.iter().any(|e| e.path == name) {
            n += 1;
            name = match path.rsplit_once('.') {
                Some((stem, ext)) if !stem.ends_with('/') => format!("{stem} ({n}).{ext}"),
                _ => format!("{path} ({n})"),
            };
        }
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        self.zip
            .start_file(name.as_str(), options)
            .and_then(|_| self.zip.write_all(bytes).map_err(Into::into))
            .map_err(|err| {
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("Failed to write the export")
                    .reason(err)
            })?;
        self.entries.push(Entry {
            path: name,
            account: account.to_string(),
            kind,
            folder: folder.to_string(),
            date,
            archived,
            size: bytes.len(),
            sha256: hex(&Sha256::digest(bytes)),
        });
        Ok(())
    }

    /// Closes the ZIP with its manifest and the manifest's hash. Returns the
    /// bytes and how many items went in.
    fn finish(mut self) -> trc::Result<(Vec<u8>, usize)> {
        let mut manifest = String::from("path,account,kind,folder,date,archived,size,sha256\n");
        for e in &self.entries {
            manifest.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                csv(&e.path),
                csv(&e.account),
                e.kind,
                csv(&e.folder),
                date_text(e.date),
                e.archived,
                e.size,
                e.sha256
            ));
        }
        let manifest_hash = hex(&Sha256::digest(manifest.as_bytes()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let fail = |err: zip::result::ZipError| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to write the export")
                .reason(err)
        };
        self.zip.start_file("manifest.csv", options).map_err(fail)?;
        self.zip.write_all(manifest.as_bytes()).map_err(|e| fail(e.into()))?;
        self.zip.start_file("manifest.sha256", options).map_err(fail)?;
        self.zip
            .write_all(format!("{manifest_hash}  manifest.csv\n").as_bytes())
            .map_err(|e| fail(e.into()))?;
        let items = self.entries.len();
        let bytes = self.zip.finish().map_err(fail)?.into_inner();
        Ok((bytes, items))
    }
}

/// The accounts to collect: those asked for that the hold covers, or every
/// account it covers, deleted ones it keeps included.
async fn accounts(server: &Server, hold: &Hold, asked: &[u32]) -> trc::Result<Vec<u32>> {
    let mut covered = Vec::new();
    for id in server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Account))
        .await
        .caused_by(trc::location!())?
    {
        let account_id = id.document_id();
        if let Some(member) = server.member_of(account_id).await
            && hold.scope.covers(&member)
        {
            covered.push(account_id);
        }
    }
    for (account_id, kept) in inbuxa_features::undelete::data::kept_accounts(server.store()).await? {
        if hold.scope.covers(&kept_member(account_id, &kept)) {
            covered.push(account_id);
        }
    }
    covered.sort_unstable();
    covered.dedup();
    if !asked.is_empty() {
        covered.retain(|id| asked.contains(id));
    }
    Ok(covered)
}

async fn blob(server: &Server, hash: &[u8]) -> trc::Result<Option<Vec<u8>>> {
    server.blob_store().get_blob(hash, 0..usize::MAX).await
}

/// Collects `accounts` under `hold` into a ZIP. Returns its bytes and item
/// count.
pub async fn build(server: &Server, hold: &Hold, asked: &[u32]) -> trc::Result<(Vec<u8>, usize)> {
    let keeping = Keeping::new(None, std::slice::from_ref(hold));
    let data = server.store();
    let mut out = Builder::new();

    for account_id in accounts(server, hold, asked).await? {
        let address = server.audit_account_name(account_id).await;
        let base = format!("{}/", segment(&address));
        let live = server.account(account_id).await.is_ok();

        if live {
            // Mail, by the folder it's in
            let cache = server
                .get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?;
            for message in cache.emails.items.iter() {
                let Some(metadata_) = data
                    .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                        account_id,
                        Collection::Email,
                        message.document_id,
                        EmailField::Metadata,
                    ))
                    .await?
                else {
                    continue;
                };
                let metadata = metadata_
                    .unarchive::<MessageMetadata>()
                    .caused_by(trc::location!())?;
                let received = metadata.rcvd_attach.to_native() & MESSAGE_RECEIVED_MASK;
                if !keeping.covers(Some(received)) {
                    continue;
                }
                let folder = message
                    .mailboxes
                    .first()
                    .and_then(|m| cache.mailboxes.items.iter().find(|b| b.document_id == m.mailbox_id))
                    .map(|b| b.path.clone())
                    .unwrap_or_default();
                let hash = types::blob_hash::BlobHash::from(&metadata.blob_hash);
                if let Some(bytes) = blob(server, hash.as_slice()).await? {
                    let path = format!(
                        "{base}mail/{}/{}.eml",
                        folder.split('/').map(segment).collect::<Vec<_>>().join("/"),
                        Id::from(message.document_id)
                    );
                    out.add(path, &bytes, &address, "email", &folder, Some(received as i64), false)?;
                }
            }

            // Calendars, contacts and files, by their DAV paths
            for (sync, kind) in [
                (SyncCollection::Calendar, "event"),
                (SyncCollection::AddressBook, "contact"),
                (SyncCollection::FileNode, "file"),
            ] {
                let resources = server
                    .fetch_dav_resources(account_id, account_id, sync)
                    .await
                    .caused_by(trc::location!())?;
                for path in resources.paths.iter() {
                    let Some(resource) = resources.resources.get(path.resource_idx) else {
                        continue;
                    };
                    let folder = path.path.rsplit_once('/').map(|(f, _)| f).unwrap_or_default();
                    let zip_path = |ext: Option<&str>| {
                        let mut p = format!(
                            "{base}{}/{}",
                            match kind {
                                "event" => "calendar",
                                "contact" => "contacts",
                                _ => "files",
                            },
                            path.path.split('/').map(segment).collect::<Vec<_>>().join("/")
                        );
                        if let Some(ext) = ext
                            && !p.ends_with(ext)
                        {
                            p.push_str(ext);
                        }
                        p
                    };
                    use common::DavResourceMetadata as M;
                    match &resource.data {
                        M::CalendarEvent { start, .. } => {
                            if !keeping.covers_event(Some((*start).max(0) as u64)) {
                                continue;
                            }
                            let Some(event_) = data
                                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                                    account_id,
                                    Collection::CalendarEvent,
                                    resource.document_id,
                                ))
                                .await?
                            else {
                                continue;
                            };
                            let event = event_.unarchive::<CalendarEvent>().caused_by(trc::location!())?;
                            let text = event.data.event.to_string();
                            out.add(zip_path(Some(".ics")), text.as_bytes(), &address, kind, folder, Some(*start), false)?;
                        }
                        M::ContactCard { .. } => {
                            let Some(card_) = data
                                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                                    account_id,
                                    Collection::ContactCard,
                                    resource.document_id,
                                ))
                                .await?
                            else {
                                continue;
                            };
                            let card = card_.unarchive::<ContactCard>().caused_by(trc::location!())?;
                            let mut text = String::with_capacity(256);
                            let _ = card.card.write_to(&mut text, server.core.groupware.vcard_version);
                            out.add(zip_path(Some(".vcf")), text.as_bytes(), &address, kind, folder, None, false)?;
                        }
                        M::File { size: Some(_), .. } => {
                            let Some(file_) = data
                                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                                    account_id,
                                    Collection::FileNode,
                                    resource.document_id,
                                ))
                                .await?
                            else {
                                continue;
                            };
                            let file = file_.unarchive::<FileNode>().caused_by(trc::location!())?;
                            let Some(props) = file.file.as_ref() else {
                                continue;
                            };
                            let hash = types::blob_hash::BlobHash::from(&props.blob_hash);
                            if let Some(bytes) = blob(server, hash.as_slice()).await? {
                                out.add(zip_path(None), &bytes, &address, kind, folder, None, false)?;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // What the hold keeps of what was deleted
        for (id, item) in records::of_account(data, server.registry(), account_id).await? {
            if !is_held_until(item.archived_until().timestamp().max(0) as u64) {
                continue;
            }
            let (kind, ext, date) = match &item {
                ArchivedItem::Email(e) => ("email", ".eml", Some(e.received_at.timestamp())),
                ArchivedItem::CalendarEvent(e) => ("event", ".ics", e.start_time.map(|t| t.timestamp())),
                ArchivedItem::ContactCard(_) => ("contact", ".vcf", None),
                ArchivedItem::FileNode(_) => ("file", "", None),
                ArchivedItem::SieveScript(_) => ("sieve", ".sieve", None),
            };
            // Kept by this hold, not only by another one over the same account
            let in_range = match kind {
                "event" => keeping.covers_event(date.map(|d| d.max(0) as u64)),
                _ => keeping.covers(date.map(|d| d.max(0) as u64)),
            };
            if !in_range {
                continue;
            }
            let name = match &item {
                ArchivedItem::FileNode(f) => segment(&f.name),
                ArchivedItem::SieveScript(s) => format!("{}{ext}", segment(&s.name)),
                _ => format!("{id}{ext}"),
            };
            if let Some(bytes) = blob(server, item.blob_id().hash.as_slice()).await? {
                out.add(format!("{base}archived/{kind}/{name}"), &bytes, &address, kind, "", date, true)?;
            }
        }
    }
    out.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_safe_in_a_zip() {
        assert_eq!(segment("../etc/passwd"), "_etc_passwd");
        assert_eq!(segment("  "), "_");
        assert_eq!(segment("Q3 report.pdf"), "Q3 report.pdf");
        assert_eq!(csv("a,b"), "\"a,b\"");
        assert_eq!(csv("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn a_zip_carries_its_manifest_and_its_hash() {
        let mut b = Builder::new();
        b.add("a@example.com/mail/INBOX/b.eml".into(), b"Subject: x\r\n\r\ny", "a@example.com", "email", "INBOX", Some(0), false)
            .unwrap();
        b.add("a@example.com/mail/INBOX/b.eml".into(), b"other", "a@example.com", "email", "INBOX", None, true)
            .unwrap();
        let (bytes, items) = b.finish().unwrap();
        assert_eq!(items, 2);
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut manifest = String::new();
        std::io::Read::read_to_string(&mut zip.by_name("manifest.csv").unwrap(), &mut manifest).unwrap();
        assert!(manifest.contains("a@example.com/mail/INBOX/b (2).eml"), "{manifest}");
        let mut hash = String::new();
        std::io::Read::read_to_string(&mut zip.by_name("manifest.sha256").unwrap(), &mut hash).unwrap();
        assert!(hash.starts_with(&hex(&Sha256::digest(manifest.as_bytes()))));
    }
}
