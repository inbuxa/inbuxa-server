/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The inbound spool (spec "The spool", RL-15, RL-16, RL-21).
//!
//! Each message is two files in `spool/in/`: `<id>.msg`, the sealed
//! stream, written and fsynced first; then `<id>.json`, its properties,
//! written atomically. The `.json` is the commit point: a `.msg` without
//! one is a message that was never acknowledged, and is deleted at start.
//! The index lives in memory and is rebuilt from the `.json` files.
//!
//! Leases and live verdict waiters are runtime only. After a restart every
//! message is held and unleased; the downstream deduplicates by id (RL-16).

use crate::state::{set_private, sync_dir, write_atomic};
use inbuxa_relay_proto::{
    seal::Sealer,
    time,
    types::{DoorCheck, Envelope, Inbound, InboundState, Session, Verdict},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    fs, io,
    path::{Path, PathBuf},
};
use tokio::{io::AsyncWriteExt, sync::oneshot};

/// How many destroyed ids `/changes` can still report.
const TOMBSTONES: usize = 10_000;

/// A message's stored properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub id: String,
    pub received_at: u64,
    pub envelope: Envelope,
    pub session: Session,
    pub size: u64,
    #[serde(default)]
    pub door_checks: Vec<DoorCheck>,
}

struct Lease {
    conn: u64,
    until: u64,
}

struct Entry {
    meta: Meta,
    file_len: u64,
    created: u64,
    modseq: u64,
    lease: Option<Lease>,
    /// Set while the SMTP session waits for a live verdict.
    waiter: Option<oneshot::Sender<Verdict>>,
}

impl Entry {
    fn state(&self, now: u64) -> InboundState {
        if self.lease.as_ref().is_some_and(|l| l.until > now) {
            InboundState::Claimed
        } else if self.waiter.is_some() {
            InboundState::Pending
        } else {
            InboundState::Held
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changes {
    pub old_state: String,
    pub new_state: String,
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub destroyed: Vec<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictError {
    NotFound,
    /// The message isn't waiting for a verdict.
    NotPending,
    /// The reply isn't valid for its kind.
    Invalid,
}

pub struct Spool {
    dir: PathBuf,
    entries: BTreeMap<String, Entry>,
    modseq: u64,
    tombstones: VecDeque<(u64, String)>,
    /// `/changes` can't go back past this.
    floor: u64,
    bytes: u64,
}

pub fn new_id() -> String {
    use aws_lc_rs::rand::SecureRandom;
    let mut bytes = [0u8; 12];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system random source");
    let mut id = String::with_capacity(25);
    id.push('i');
    for b in bytes {
        id.push_str(&format!("{b:02x}"));
    }
    id
}

/// Whether `id` is one of ours: never a path.
pub fn is_valid_id(id: &str) -> bool {
    id.len() == 25 && id.starts_with('i') && id[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

impl Spool {
    /// Opens the spool, deleting what was never committed.
    pub fn open(dir: &Path) -> io::Result<Spool> {
        fs::create_dir_all(dir)?;
        let mut spool = Spool {
            dir: dir.to_path_buf(),
            entries: BTreeMap::new(),
            modseq: 1,
            tombstones: VecDeque::new(),
            floor: 1,
            bytes: 0,
        };
        let mut msgs = Vec::new();
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
                        eprintln!("inbuxa-relay: unreadable spool entry {id}, skipped");
                        continue;
                    }
                };
                let file_len = fs::metadata(spool.msg_path(id)).map(|m| m.len()).ok();
                let Some(file_len) = file_len else {
                    let _ = fs::remove_file(entry.path());
                    continue;
                };
                spool.bytes += file_len;
                spool.entries.insert(
                    id.to_string(),
                    Entry {
                        meta,
                        file_len,
                        created: 1,
                        modseq: 1,
                        lease: None,
                        waiter: None,
                    },
                );
            } else if name.ends_with(".msg") || name.ends_with(".tmp") {
                msgs.push((name, entry.path()));
            }
        }
        for (name, path) in msgs {
            let id = name.split('.').next().unwrap_or("");
            if name.ends_with(".tmp") || !spool.entries.contains_key(id) {
                let _ = fs::remove_file(path);
            }
        }
        Ok(spool)
    }

    pub fn msg_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.msg"))
    }

    fn meta_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    pub fn state(&self) -> String {
        self.modseq.to_string()
    }

    pub fn count(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn contains(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }

    fn bump(&mut self) -> u64 {
        self.modseq += 1;
        self.modseq
    }

    /// Starts writing a new message in the spool directory `dir`, sealed
    /// to `sealing_key`. Needs no lock: the file is new and unlisted.
    pub async fn begin(dir: &Path, sealing_key: &[u8; 32]) -> io::Result<Incoming> {
        let id = new_id();
        let tmp = dir.join(format!("{id}.msg.tmp"));
        let (sealer, header) = Sealer::new(sealing_key, id.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .await?;
        set_private(&tmp, false)?;
        file.write_all(&header).await?;
        Ok(Incoming {
            id,
            tmp,
            file,
            sealer,
            out: Vec::with_capacity(70 * 1024),
            plaintext: 0,
            written: header.len() as u64,
        })
    }

    /// Adds a committed message. With `wait`, the message is pending and
    /// the receiver gets the downstream's verdict.
    pub fn insert(
        &mut self,
        meta: Meta,
        file_len: u64,
        wait: bool,
    ) -> Option<oneshot::Receiver<Verdict>> {
        let modseq = self.bump();
        let (tx, rx) = if wait {
            let (tx, rx) = oneshot::channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        self.bytes += file_len;
        self.entries.insert(
            meta.id.clone(),
            Entry {
                meta,
                file_len,
                created: modseq,
                modseq,
                lease: None,
                waiter: tx,
            },
        );
        rx
    }

    /// The JMAP object for one message.
    pub fn get(&self, id: &str, now: u64) -> Option<Inbound> {
        let e = self.entries.get(id)?;
        let state = e.state(now);
        Some(Inbound {
            id: e.meta.id.clone(),
            received_at: time::utc_date(e.meta.received_at),
            state,
            claimed_until: (state == InboundState::Claimed)
                .then(|| time::utc_date(e.lease.as_ref().map_or(0, |l| l.until))),
            envelope: e.meta.envelope.clone(),
            session: e.meta.session.clone(),
            size: e.meta.size,
            blob_id: e.meta.id.clone(),
            door_checks: e.meta.door_checks.clone(),
        })
    }

    /// Ids, pending first, then by arrival.
    pub fn ids(&self, now: u64) -> Vec<String> {
        let mut ids: Vec<(&Entry, bool)> = self
            .entries
            .values()
            .map(|e| (e, e.state(now) == InboundState::Pending))
            .collect();
        ids.sort_by_key(|(e, pending)| (!pending, e.meta.received_at, e.meta.id.clone()));
        ids.into_iter().map(|(e, _)| e.meta.id.clone()).collect()
    }

    pub fn changes(&self, since: &str, max: usize) -> Option<Changes> {
        let since: u64 = since.parse().ok()?;
        if since < self.floor || since > self.modseq {
            return None;
        }
        let mut created = Vec::new();
        let mut updated = Vec::new();
        for (id, e) in &self.entries {
            if e.created > since {
                created.push(id.clone());
            } else if e.modseq > since {
                updated.push(id.clone());
            }
        }
        let destroyed: Vec<String> = self
            .tombstones
            .iter()
            .filter(|(seq, _)| *seq > since)
            .map(|(_, id)| id.clone())
            .collect();
        let total = created.len() + updated.len() + destroyed.len();
        if total > max {
            // Too much at once: the client starts over with /query.
            return None;
        }
        Some(Changes {
            old_state: since.to_string(),
            new_state: self.state(),
            created,
            updated,
            destroyed,
            has_more: false,
        })
    }

    /// RL-15: leases up to `limit` unleased messages to `conn`.
    pub fn claim(&mut self, conn: u64, limit: usize, lease_secs: u64, now: u64) -> Vec<String> {
        let mut out = Vec::new();
        for id in self.ids(now) {
            if out.len() >= limit {
                break;
            }
            let e = self.entries.get(&id).expect("listed");
            if e.lease.as_ref().is_some_and(|l| l.until > now) {
                continue;
            }
            let modseq = self.bump();
            let e = self.entries.get_mut(&id).expect("listed");
            e.lease = Some(Lease {
                conn,
                until: now + lease_secs,
            });
            e.modseq = modseq;
            out.push(id);
        }
        out
    }

    /// Ends `conn`'s leases, when its link closes. True if any ended.
    pub fn release_conn(&mut self, conn: u64) -> bool {
        let ids: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.lease.as_ref().is_some_and(|l| l.conn == conn))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &ids {
            let modseq = self.bump();
            let e = self.entries.get_mut(id).expect("listed");
            e.lease = None;
            e.modseq = modseq;
        }
        !ids.is_empty()
    }

    /// Ends leases that ran out. True if any did.
    pub fn sweep_leases(&mut self, now: u64) -> bool {
        let ids: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.lease.as_ref().is_some_and(|l| l.until <= now))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &ids {
            let modseq = self.bump();
            let e = self.entries.get_mut(id).expect("listed");
            e.lease = None;
            e.modseq = modseq;
        }
        !ids.is_empty()
    }

    /// RL-12: the downstream's verdict on a pending message. A reject or
    /// tempfail removes the message: the sender keeps it.
    pub fn set_verdict(&mut self, id: &str, verdict: Verdict) -> Result<(), VerdictError> {
        if !verdict.is_valid() {
            return Err(VerdictError::Invalid);
        }
        let e = self.entries.get_mut(id).ok_or(VerdictError::NotFound)?;
        let waiter = e.waiter.take().ok_or(VerdictError::NotPending)?;
        let keep = matches!(verdict, Verdict::Accept);
        // The session may have given up a moment ago; then it holds.
        let delivered = waiter.send(verdict).is_ok();
        if keep || !delivered {
            let modseq = self.bump();
            if let Some(e) = self.entries.get_mut(id) {
                e.modseq = modseq;
            }
        } else {
            self.remove(id);
        }
        Ok(())
    }

    /// RL-13: the wait ran out, so the message is held.
    pub fn stop_waiting(&mut self, id: &str) {
        let modseq = self.bump();
        if let Some(e) = self.entries.get_mut(id)
            && e.waiter.take().is_some()
        {
            e.modseq = modseq;
        }
    }

    /// The downstream took the message: delete it. A pending message is
    /// thereby accepted.
    pub fn destroy(&mut self, id: &str) -> bool {
        if let Some(waiter) = self.entries.get_mut(id).and_then(|e| e.waiter.take()) {
            let _ = waiter.send(Verdict::Accept);
        }
        self.remove(id)
    }

    fn remove(&mut self, id: &str) -> bool {
        let Some(e) = self.entries.remove(id) else {
            return false;
        };
        self.bytes = self.bytes.saturating_sub(e.file_len);
        let _ = fs::remove_file(self.meta_path(id));
        let _ = fs::remove_file(self.msg_path(id));
        let _ = sync_dir(&self.dir);
        let modseq = self.bump();
        self.tombstones.push_back((modseq, id.to_string()));
        while self.tombstones.len() > TOMBSTONES {
            if let Some((seq, _)) = self.tombstones.pop_front() {
                self.floor = seq;
            }
        }
        true
    }

    /// Deletes held mail older than `max_age_secs`, unleased and not
    /// pending. Returns what was deleted.
    pub fn expire(&mut self, now: u64, max_age_secs: u64) -> Vec<Meta> {
        let old: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.meta.received_at + max_age_secs <= now && e.state(now) == InboundState::Held
            })
            .map(|(id, _)| id.clone())
            .collect();
        let mut out = Vec::new();
        for id in old {
            if let Some(e) = self.entries.get(&id) {
                out.push(e.meta.clone());
            }
            self.remove(&id);
        }
        out
    }

    /// Writes a message's properties into the spool directory `dir`: the
    /// commit point. Blocking (it fsyncs); needs no lock.
    pub fn commit_meta(dir: &Path, meta: &Meta) -> io::Result<()> {
        write_atomic(
            &dir.join(format!("{}.json", meta.id)),
            &serde_json::to_vec(meta).map_err(io::Error::other)?,
        )
    }
}

/// A message being received, sealed as it arrives.
pub struct Incoming {
    pub id: String,
    tmp: PathBuf,
    file: tokio::fs::File,
    sealer: Sealer,
    out: Vec<u8>,
    plaintext: u64,
    written: u64,
}

impl Incoming {
    pub fn size(&self) -> u64 {
        self.plaintext
    }

    pub async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.plaintext += data.len() as u64;
        self.sealer.update(data, &mut self.out);
        if self.out.len() >= 64 * 1024 {
            self.flush().await?;
        }
        Ok(())
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.file.write_all(&self.out).await?;
        self.written += self.out.len() as u64;
        self.out.clear();
        Ok(())
    }

    /// Seals the last chunk, fsyncs and renames the file into place.
    /// Returns its id and length; the caller commits the properties, whose
    /// write also fsyncs the directory. A failure leaves a `.tmp` that the
    /// next start deletes.
    pub async fn finish(self) -> io::Result<(String, u64)> {
        let Incoming {
            id,
            tmp,
            mut file,
            sealer,
            mut out,
            written,
            ..
        } = self;
        sealer.finish(&mut out);
        file.write_all(&out).await?;
        file.sync_all().await?;
        let dest = tmp.with_file_name(format!("{id}.msg"));
        tokio::fs::rename(&tmp, &dest).await?;
        Ok((id, written + out.len() as u64))
    }

    pub async fn abort(self) {
        drop(self.file);
        let _ = tokio::fs::remove_file(&self.tmp).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inbuxa_relay_proto::{
        seal,
        types::{Address, Reply},
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn meta(id: &str, received_at: u64) -> Meta {
        Meta {
            id: id.into(),
            received_at,
            envelope: Envelope {
                mail_from: Address::new("a@example.org"),
                rcpt_to: vec![Address::new("b@example.com")],
            },
            session: Session {
                remote_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                remote_port: 40000,
                local_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                helo: "mx.example.org".into(),
                tls: None,
                ptr: None,
            },
            size: 10,
            door_checks: vec![],
        }
    }

    fn dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("inbuxa-relay-spool-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    async fn store(
        spool: &mut Spool,
        key: &[u8; 32],
        body: &[u8],
        at: u64,
        wait: bool,
    ) -> (String, Option<oneshot::Receiver<Verdict>>) {
        let mut inc = Spool::begin(&spool.dir.clone(), key).await.unwrap();
        inc.write(body).await.unwrap();
        let (id, len) = inc.finish().await.unwrap();
        let m = Meta {
            size: body.len() as u64,
            ..meta(&id, at)
        };
        Spool::commit_meta(&spool.dir.clone(), &m).unwrap();
        let rx = spool.insert(m, len, wait);
        (id, rx)
    }

    #[tokio::test]
    async fn sealed_on_disk_and_survives_restart() {
        let d = dir("restart");
        let (secret, public) = seal::generate_keypair();
        let mut spool = Spool::open(&d).unwrap();
        let (id, _) = store(
            &mut spool,
            &public,
            b"Subject: MARKER-91\r\n\r\nhi\r\n",
            100,
            false,
        )
        .await;
        // An uncommitted file from a crash.
        fs::write(d.join(format!("{}.msg", new_id())), b"junk").unwrap();
        fs::write(d.join(format!("{}.msg.tmp", new_id())), b"junk").unwrap();

        let raw = fs::read(spool.msg_path(&id)).unwrap();
        assert!(!raw.windows(9).any(|w| w == b"MARKER-91"));
        assert_eq!(
            seal::open(&secret, id.as_bytes(), &raw).unwrap(),
            b"Subject: MARKER-91\r\n\r\nhi\r\n"
        );

        let spool = Spool::open(&d).unwrap();
        assert_eq!(spool.count(), 1);
        assert_eq!(spool.get(&id, 100).unwrap().state, InboundState::Held);
        assert_eq!(fs::read_dir(&d).unwrap().count(), 2);
        fs::remove_dir_all(d).unwrap();
    }

    #[tokio::test]
    async fn claims_leases_and_changes() {
        let d = dir("claims");
        let (_, public) = seal::generate_keypair();
        let mut spool = Spool::open(&d).unwrap();
        let s0 = spool.state();
        let (a, _) = store(&mut spool, &public, b"a", 10, false).await;
        let (b, _rx) = store(&mut spool, &public, b"b", 20, true).await;
        assert_eq!(spool.ids(30), vec![b.clone(), a.clone()], "pending first");

        let ch = spool.changes(&s0, 100).unwrap();
        assert_eq!(ch.created.len(), 2);

        let s1 = spool.state();
        assert_eq!(spool.claim(1, 1, 300, 30), vec![b.clone()]);
        assert_eq!(spool.claim(2, 5, 300, 30), vec![a.clone()]);
        assert!(spool.claim(3, 5, 300, 30).is_empty());
        assert_eq!(spool.get(&a, 30).unwrap().state, InboundState::Claimed);
        let ch = spool.changes(&s1, 100).unwrap();
        assert_eq!(ch.updated.len(), 2);

        assert!(spool.release_conn(2));
        assert_eq!(spool.claim(3, 5, 300, 30), vec![a.clone()]);
        assert!(spool.sweep_leases(400));
        assert_eq!(spool.get(&a, 400).unwrap().state, InboundState::Held);

        let s2 = spool.state();
        assert!(spool.destroy(&a));
        assert!(!spool.destroy(&a));
        assert_eq!(spool.changes(&s2, 100).unwrap().destroyed, vec![a]);
        assert!(spool.changes("0", 100).is_none());
        fs::remove_dir_all(d).unwrap();
    }

    #[tokio::test]
    async fn verdicts() {
        let d = dir("verdicts");
        let (_, public) = seal::generate_keypair();
        let mut spool = Spool::open(&d).unwrap();
        let reject = Verdict::Reject(Reply {
            code: 550,
            enhanced: "5.7.1".into(),
            text: "spam".into(),
        });

        let (a, rx) = store(&mut spool, &public, b"a", 10, true).await;
        assert_eq!(spool.set_verdict(&a, reject.clone()), Ok(()));
        assert_eq!(rx.unwrap().await.unwrap(), reject);
        assert!(!spool.contains(&a), "a rejected message leaves the spool");

        let (b, rx) = store(&mut spool, &public, b"b", 10, true).await;
        assert_eq!(spool.set_verdict(&b, Verdict::Accept), Ok(()));
        assert_eq!(rx.unwrap().await.unwrap(), Verdict::Accept);
        assert!(spool.contains(&b), "accepted mail waits for destroy");
        assert_eq!(
            spool.set_verdict(&b, Verdict::Accept),
            Err(VerdictError::NotPending)
        );

        let (c, rx) = store(&mut spool, &public, b"c", 10, true).await;
        spool.stop_waiting(&c);
        assert!(rx.unwrap().await.is_err());
        assert_eq!(spool.get(&c, 10).unwrap().state, InboundState::Held);

        let (d2, rx) = store(&mut spool, &public, b"d", 10, true).await;
        assert!(spool.destroy(&d2));
        assert_eq!(rx.unwrap().await.unwrap(), Verdict::Accept);

        let bad = Verdict::Reject(Reply {
            code: 250,
            enhanced: "2.0.0".into(),
            text: "x".into(),
        });
        assert_eq!(spool.set_verdict(&c, bad), Err(VerdictError::Invalid));
        fs::remove_dir_all(d).unwrap();
    }

    #[tokio::test]
    async fn expiry_skips_leased_and_pending() {
        let d = dir("expiry");
        let (_, public) = seal::generate_keypair();
        let mut spool = Spool::open(&d).unwrap();
        let (a, _) = store(&mut spool, &public, b"a", 0, false).await;
        let (b, _) = store(&mut spool, &public, b"b", 0, false).await;
        let (_c, _rx) = store(&mut spool, &public, b"c", 0, true).await;
        // The pending one, then one of the held two.
        assert_eq!(spool.claim(1, 2, 1000, 50).len(), 2);
        let gone = spool.expire(100, 100);
        assert_eq!(gone.len(), 1);
        assert!(gone[0].id == a || gone[0].id == b);
        assert_eq!(spool.count(), 2);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn ids_are_never_paths() {
        assert!(is_valid_id(&new_id()));
        assert!(!is_valid_id("../../etc/passwd"));
        assert!(!is_valid_id("i0123456789abcdef0123456/"));
    }
}
