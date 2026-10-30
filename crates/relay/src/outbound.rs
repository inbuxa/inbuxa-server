/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The outbound spool (spec "Outbound", "The spool", RL-19).
//!
//! Each message is two files in `spool/out/`: `<id>.eml`, the message as
//! the downstream handed it over, moved in from its upload and fsynced
//! first; then `<id>.json`, its properties and delivery status, written
//! atomically. The `.json` is the commit point, as in the inbound spool.
//! Outbound mail isn't sealed: the relay has to read it to send it.

use crate::{
    changelog::{Changelog, Changes},
    state::{set_private, sync_dir, write_atomic},
};
use inbuxa_relay_proto::{
    time,
    types::{Address, DeliveryStatus, Envelope, Outbound, RelaySettings},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs, io,
    path::{Path, PathBuf},
};

/// Longest address, as RFC 5321 §4.5.3.1 allows for a path.
const ADDRESS_MAX: usize = 256;
const PARAMETER_NAME_MAX: usize = 64;
const PARAMETER_VALUE_MAX: usize = 500;

/// A message's stored properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub id: String,
    pub created_at: u64,
    pub blob_id: String,
    pub envelope: Envelope,
    pub size: u64,
    pub delivery_status: BTreeMap<String, DeliveryStatus>,
    pub next_attempt_at: u64,
    pub attempts: u32,
    pub expires_at: u64,
}

struct Entry {
    meta: Meta,
    created: u64,
    modseq: u64,
}

/// Why a create was refused: a JMAP `SetError` type and a description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub kind: &'static str,
    pub description: String,
}

fn refuse(kind: &'static str, description: impl Into<String>) -> Refusal {
    Refusal {
        kind,
        description: description.into(),
    }
}

pub struct Outbox {
    dir: PathBuf,
    entries: BTreeMap<String, Entry>,
    log: Changelog,
    bytes: u64,
}

pub fn new_id() -> String {
    let mut id = crate::spool::new_id();
    id.replace_range(0..1, "o");
    id
}

/// Whether `id` is one of ours: never a path.
pub fn is_valid_id(id: &str) -> bool {
    id.len() == 25 && id.starts_with('o') && id[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

impl Outbox {
    /// Opens the spool, deleting what was never committed.
    pub fn open(dir: &Path) -> io::Result<Outbox> {
        fs::create_dir_all(dir)?;
        let mut outbox = Outbox {
            dir: dir.to_path_buf(),
            entries: BTreeMap::new(),
            log: Changelog::default(),
            bytes: 0,
        };
        let mut messages = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".json") {
                if !is_valid_id(id) {
                    continue;
                }
                let meta: Meta = match fs::read(entry.path())
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                {
                    Some(meta) => meta,
                    None => {
                        eprintln!("inbuxa-relay: unreadable outbound entry {id}, skipped");
                        continue;
                    }
                };
                if !outbox.eml_path(id).exists() {
                    let _ = fs::remove_file(entry.path());
                    continue;
                }
                outbox.bytes += meta.size;
                outbox.entries.insert(
                    id.to_string(),
                    Entry {
                        meta,
                        created: 1,
                        modseq: 1,
                    },
                );
            } else if name.ends_with(".eml") || name.ends_with(".tmp") {
                messages.push((name, entry.path()));
            }
        }
        for (name, path) in messages {
            let id = name.split('.').next().unwrap_or("");
            if name.ends_with(".tmp") || !outbox.entries.contains_key(id) {
                let _ = fs::remove_file(path);
            }
        }
        Ok(outbox)
    }

    pub fn eml_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.eml"))
    }

    fn meta_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    pub fn state(&self) -> String {
        self.log.state()
    }

    pub fn count(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// RL-19: takes the uploaded message at `blob` for `envelope`. The
    /// upload is moved into the spool, so it can't be used twice. `full`
    /// is whether the spool is past its limit.
    pub fn create(
        &mut self,
        blob: &Path,
        blob_id: &str,
        envelope: Envelope,
        settings: &RelaySettings,
        full: bool,
        now: u64,
    ) -> Result<String, Refusal> {
        check_envelope(&envelope, settings)?;
        let size = fs::metadata(blob)
            .map_err(|_| refuse("invalidProperties", "blobId: no such upload"))?
            .len();
        if size == 0 {
            return Err(refuse("invalidProperties", "the message is empty"));
        }
        if size > settings.max_message_size {
            return Err(refuse(
                "tooLarge",
                format!("the message is over {} bytes", settings.max_message_size),
            ));
        }
        if full {
            return Err(refuse("overQuota", "the relay's spool is full"));
        }
        let id = new_id();
        let meta = Meta {
            id: id.clone(),
            created_at: now,
            blob_id: blob_id.to_string(),
            delivery_status: envelope
                .rcpt_to
                .iter()
                .map(|r| (r.email.clone(), DeliveryStatus::queued()))
                .collect(),
            envelope,
            size,
            next_attempt_at: now,
            attempts: 0,
            expires_at: now + u64::from(settings.outbound_expiry),
        };
        self.commit(blob, &meta)
            .map_err(|e| refuse("serverFail", format!("could not spool the message: {e}")))?;
        let modseq = self.log.bump();
        self.bytes += size;
        self.entries.insert(
            id.clone(),
            Entry {
                meta,
                created: modseq,
                modseq,
            },
        );
        Ok(id)
    }

    fn commit(&self, blob: &Path, meta: &Meta) -> io::Result<()> {
        let eml = self.eml_path(&meta.id);
        fs::File::open(blob)?.sync_all()?;
        fs::rename(blob, &eml)?;
        set_private(&eml, false)?;
        sync_dir(&self.dir)?;
        let json = serde_json::to_vec(meta).map_err(io::Error::other)?;
        if let Err(e) = write_atomic(&self.meta_path(&meta.id), &json) {
            let _ = fs::remove_file(&eml);
            return Err(e);
        }
        Ok(())
    }

    /// The JMAP object for one message.
    pub fn get(&self, id: &str) -> Option<Outbound> {
        let m = &self.entries.get(id)?.meta;
        let queued = m
            .delivery_status
            .values()
            .any(|s| s.delivered == inbuxa_relay_proto::types::Delivered::Queued);
        Some(Outbound {
            id: m.id.clone(),
            created_at: time::utc_date(m.created_at),
            blob_id: m.blob_id.clone(),
            envelope: m.envelope.clone(),
            size: m.size,
            delivery_status: m.delivery_status.clone(),
            next_attempt_at: queued.then(|| time::utc_date(m.next_attempt_at)),
            attempts: m.attempts,
            expires_at: time::utc_date(m.expires_at),
        })
    }

    /// Ids, oldest first.
    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<&Meta> = self.entries.values().map(|e| &e.meta).collect();
        ids.sort_by_key(|m| (m.created_at, m.id.clone()));
        ids.into_iter().map(|m| m.id.clone()).collect()
    }

    pub fn changes(&self, since: &str, max: usize) -> Option<Changes> {
        self.log.changes(
            since,
            max,
            self.entries.iter().map(|(id, e)| (id, e.created, e.modseq)),
        )
    }

    /// Cancels a queued message, or clears a finished one.
    pub fn destroy(&mut self, id: &str) -> bool {
        let Some(e) = self.entries.remove(id) else {
            return false;
        };
        self.bytes = self.bytes.saturating_sub(e.meta.size);
        let _ = fs::remove_file(self.meta_path(id));
        let _ = fs::remove_file(self.eml_path(id));
        let _ = sync_dir(&self.dir);
        self.log.destroyed(id);
        true
    }
}

/// RL-19: a sender at one of the relay's domains, or none; real recipients;
/// SMTP parameters that can't break the command line they go on.
pub fn check_envelope(envelope: &Envelope, settings: &RelaySettings) -> Result<(), Refusal> {
    let from = &envelope.mail_from;
    if !from.email.is_empty() {
        let domain = domain_of(&from.email)
            .ok_or_else(|| refuse("invalidProperties", "mailFrom isn't an address"))?;
        if !settings.serves(domain) {
            return Err(refuse(
                "forbiddenFrom",
                "mailFrom isn't at one of the relay's domains",
            ));
        }
    }
    check_parameters(from, "mailFrom")?;
    if envelope.rcpt_to.is_empty() {
        return Err(refuse("invalidProperties", "rcptTo needs a recipient"));
    }
    if envelope.rcpt_to.len() > settings.max_recipients as usize {
        return Err(refuse(
            "tooLarge",
            format!("at most {} recipients", settings.max_recipients),
        ));
    }
    let mut seen = HashSet::new();
    for rcpt in &envelope.rcpt_to {
        if domain_of(&rcpt.email).is_none() {
            return Err(refuse(
                "invalidProperties",
                format!("rcptTo: {} isn't an address", rcpt.email),
            ));
        }
        if !seen.insert(rcpt.email.to_lowercase()) {
            return Err(refuse(
                "invalidProperties",
                format!("rcptTo: {} is listed twice", rcpt.email),
            ));
        }
        check_parameters(rcpt, "rcptTo")?;
    }
    Ok(())
}

/// The domain of a plain address, if it is one.
fn domain_of(email: &str) -> Option<&str> {
    if email.len() > ADDRESS_MAX
        || email
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>'))
    {
        return None;
    }
    let (local, domain) = email.rsplit_once('@')?;
    let quoted = local.len() > 1 && local.starts_with('"') && local.ends_with('"');
    let domain = domain.trim_end_matches('.');
    (!local.is_empty() && !domain.is_empty() && (quoted || !local.contains('@'))).then_some(domain)
}

fn check_parameters(address: &Address, field: &str) -> Result<(), Refusal> {
    for (name, value) in address.parameters.iter().flatten() {
        let name_ok = !name.is_empty()
            && name.len() <= PARAMETER_NAME_MAX
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        let value_ok = value.as_ref().is_none_or(|v| {
            !v.is_empty()
                && v.len() <= PARAMETER_VALUE_MAX
                && !v
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || c == '=')
        });
        if !name_ok || !value_ok {
            return Err(refuse(
                "invalidProperties",
                format!("{field}: the parameter {name} isn't valid"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use inbuxa_relay_proto::types::Delivered;

    fn settings() -> RelaySettings {
        RelaySettings {
            domains: vec!["example.com".into()],
            max_recipients: 3,
            max_message_size: 100,
            ..Default::default()
        }
    }

    fn envelope(from: &str, to: &[&str]) -> Envelope {
        Envelope {
            mail_from: Address::new(from),
            rcpt_to: to.iter().map(|t| Address::new(*t)).collect(),
        }
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "inbuxa-relay-outbound-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn upload(dir: &Path, body: &[u8]) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(crate::spool::new_id());
        fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn senders_only_from_the_relays_domains() {
        let s = settings();
        assert!(check_envelope(&envelope("a@example.com", &["b@example.org"]), &s).is_ok());
        assert!(check_envelope(&envelope("a@EXAMPLE.com.", &["b@example.org"]), &s).is_ok());
        assert!(
            check_envelope(&envelope("", &["b@example.org"]), &s).is_ok(),
            "a bounce"
        );
        for from in [
            "a@example.org",
            "a@sub.example.com",
            "a@example.com@evil.org",
        ] {
            assert_eq!(
                check_envelope(&envelope(from, &["b@example.org"]), &s)
                    .unwrap_err()
                    .kind,
                if from.contains("@evil") {
                    "invalidProperties"
                } else {
                    "forbiddenFrom"
                },
                "{from}"
            );
        }
    }

    #[test]
    fn recipients_and_parameters_are_checked() {
        let s = settings();
        let bad = [
            envelope("a@example.com", &[]),
            envelope(
                "a@example.com",
                &["x@a.org", "y@a.org", "z@a.org", "w@a.org"],
            ),
            envelope("a@example.com", &["x@a.org", "X@a.org"]),
            envelope("a@example.com", &["x@a.org\r\nRCPT TO:<y@a.org>"]),
            envelope("a@example.com", &["no-at-sign"]),
            envelope("a@example.com", &["<x@a.org>"]),
        ];
        for e in &bad {
            assert!(check_envelope(e, &s).is_err(), "{e:?}");
        }
        let mut e = envelope("a@example.com", &["x@a.org"]);
        e.rcpt_to[0].parameters = Some(BTreeMap::from([("NOTIFY".into(), Some("NEVER".into()))]));
        e.mail_from.parameters = Some(BTreeMap::from([
            ("BODY".into(), Some("8BITMIME".into())),
            ("SMTPUTF8".into(), None),
        ]));
        assert!(check_envelope(&e, &s).is_ok());
        e.rcpt_to[0].parameters = Some(BTreeMap::from([(
            "NOTIFY".into(),
            Some("NEVER AUTH=x".into()),
        )]));
        assert!(check_envelope(&e, &s).is_err());
    }

    #[test]
    fn created_survives_restart_and_destroys() {
        let d = dir("restart");
        let blobs = d.join("blobs");
        let out = d.join("out");
        let s = settings();
        let mut outbox = Outbox::open(&out).unwrap();
        let s0 = outbox.state();

        let blob = upload(&blobs, b"Subject: hi\r\n\r\nhi\r\n");
        let id = outbox
            .create(
                &blob,
                "b1",
                envelope("a@example.com", &["b@example.org", "c@example.org"]),
                &s,
                false,
                100,
            )
            .unwrap();
        assert!(!blob.exists(), "the upload moved into the spool");
        assert_eq!(
            fs::read(outbox.eml_path(&id)).unwrap(),
            b"Subject: hi\r\n\r\nhi\r\n"
        );
        let got = outbox.get(&id).unwrap();
        assert_eq!(got.blob_id, "b1");
        assert_eq!(got.size, 19);
        assert_eq!(got.delivery_status.len(), 2);
        assert!(
            got.delivery_status
                .values()
                .all(|s| s.delivered == Delivered::Queued)
        );
        assert_eq!(got.next_attempt_at.as_deref(), Some(&*time::utc_date(100)));
        assert_eq!(got.expires_at, time::utc_date(100 + 3 * 86_400));
        assert_eq!(outbox.changes(&s0, 10).unwrap().created, vec![id.clone()]);

        // A crash left an uncommitted message.
        fs::write(out.join(format!("{}.eml", new_id())), b"junk").unwrap();
        let mut outbox = Outbox::open(&out).unwrap();
        assert_eq!(outbox.count(), 1);
        assert_eq!(outbox.bytes(), 19);
        assert_eq!(fs::read_dir(&out).unwrap().count(), 2);

        let s1 = outbox.state();
        assert!(outbox.destroy(&id));
        assert!(!outbox.destroy(&id));
        assert_eq!(outbox.changes(&s1, 10).unwrap().destroyed, vec![id]);
        assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn create_refusals() {
        let d = dir("refusals");
        let blobs = d.join("blobs");
        let s = settings();
        let mut outbox = Outbox::open(&d.join("out")).unwrap();
        let ok = envelope("a@example.com", &["b@example.org"]);

        let big = upload(&blobs, &[b'x'; 101]);
        let r = outbox.create(&big, "b", ok.clone(), &s, false, 0);
        assert_eq!(r.unwrap_err().kind, "tooLarge");
        assert!(big.exists(), "a refused upload stays where it was");

        let blob = upload(&blobs, b"x");
        let r = outbox.create(&blob, "b", ok.clone(), &s, true, 0);
        assert_eq!(r.unwrap_err().kind, "overQuota");
        let r = outbox.create(
            &blob,
            "b",
            envelope("a@example.org", &["b@x.org"]),
            &s,
            false,
            0,
        );
        assert_eq!(r.unwrap_err().kind, "forbiddenFrom");
        let r = outbox.create(&blobs.join("gone"), "b", ok, &s, false, 0);
        assert_eq!(r.unwrap_err().kind, "invalidProperties");
        assert_eq!(outbox.count(), 0);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn ids_are_never_paths() {
        assert!(is_valid_id(&new_id()));
        assert!(!crate::spool::is_valid_id(&new_id()));
        assert!(!is_valid_id("o../../etc/passwd"));
    }
}
