/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The built-in journal (JR-5, JR-6, JR-13). Keys, after `J`:
//!
//! - `e` + node + seq: a chain link: its seq, the hash of the link before
//!   it, and the SHA-256 of its entry. One chain per node, as the audit log
//!   keeps (AU-6), but a link names its entry by hash instead of holding it,
//!   so an entry can go at the end of its own retention without breaking
//!   the chain: entries don't expire in chain order.
//! - `c` + node + seq: the entry, as JSON; its bytes are what the link's
//!   hash names.
//! - `p` + node + seq: when an entry past its retention was purged. A link
//!   whose entry is gone without this marker is a broken chain.
//! - `t` + time + node + seq: the time index, for search.
//! - `x` + expiry + node + seq: the expiry index, for purge.
//! - `h` + node: the chain's head: its hash, then its seq as the last eight
//!   bytes, which each append asserts.
//! - `f` + node: where the chain starts after purged links at its start
//!   were cleared, and the hash the first kept link names.
//!
//! The report itself is a blob, kept by a temporary link that lasts until
//! its entry is purged. Nothing here changes or removes an entry before
//! its time; nothing in JMAP can.

use super::{Direction, FEATURE, Json};
use crate::hold::HELD_UNTIL;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use sha2::{Digest, Sha256};
use std::fmt;
use store::{
    BlobStore, Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, BlobLink, BlobOp, ValueClass, assert::AssertValue},
};
use tokio::sync::Mutex;
use trc::AddContext;
use types::blob_hash::BlobHash;

const KIND_LINK: u8 = b'e';
const KIND_CONTENT: u8 = b'c';
const KIND_PURGED: u8 = b'p';
const KIND_TIME: u8 = b't';
const KIND_EXPIRY: u8 = b'x';
const KIND_HEAD: u8 = b'h';
const KIND_FLOOR: u8 = b'f';

const APPEND_ATTEMPTS: usize = 5;
/// Entries purged per batch.
const PURGE_BATCH: usize = 100;

/// Where one entry sits: its node's chain and its place in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntryId {
    pub node: u64,
    pub seq: u64,
}

impl EntryId {
    /// As one number, for JMAP ids: the node in the top 16 bits.
    pub fn to_u64(&self) -> u64 {
        (self.node << 48) | (self.seq & ((1 << 48) - 1))
    }

    pub fn from_u64(id: u64) -> Self {
        EntryId {
            node: id >> 48,
            seq: id & ((1 << 48) - 1),
        }
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.node, self.seq)
    }
}

/// One journaled message (JR-5).
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub queue_id: u64,
    /// Seconds.
    pub at: u64,
    pub direction: Direction,
    pub sender: String,
    pub authenticated: bool,
    pub recipients: Vec<String>,
    pub subject: String,
    pub message_id: String,
    /// The people here on either side, whose holds keep the entry.
    pub accounts: Vec<u32>,
    pub tenants: Vec<u32>,
    /// The journals that took it.
    pub journals: Vec<u32>,
    pub held: bool,
    /// The report's blob, hex.
    pub blob: String,
    pub size: u64,
    /// SHA-256 of the report, hex.
    pub sha256: String,
    /// Seconds.
    pub expires_at: u64,
}

impl Entry {
    pub fn blob_hash(&self) -> Option<BlobHash> {
        let bytes = unhex(&self.blob)?;
        BlobHash::try_from_hash_slice(&bytes).ok()
    }
}

#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct Link {
    seq: u64,
    prev: String,
    content: String,
}

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
struct Floor {
    seq: u64,
    prev: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Head {
    seq: u64,
    hash: String,
}

impl Head {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.hash.as_bytes().to_vec();
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes
    }
}

impl Deserialize for Head {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let split = bytes.len().checked_sub(8).ok_or_else(|| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid journal chain head")
        })?;
        Ok(Head {
            seq: u64::from_be_bytes(bytes[split..].try_into().unwrap()),
            hash: String::from_utf8_lossy(&bytes[..split]).into_owned(),
        })
    }
}

struct Raw(Vec<u8>);

impl Deserialize for Raw {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Raw(bytes.to_vec()))
    }
}

fn class(kind: u8, parts: &[u64]) -> ValueClass {
    let mut key = Vec::with_capacity(2 + parts.len() * 8);
    key.push(FEATURE);
    key.push(kind);
    for part in parts {
        key.extend_from_slice(&part.to_be_bytes());
    }
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

fn key(kind: u8, parts: &[u64]) -> ValueKey<ValueClass> {
    ValueKey::from(class(kind, parts))
}

/// Where an entry's content is kept, for tests that check tampering shows.
pub fn content_key(id: EntryId) -> ValueKey<ValueClass> {
    key(KIND_CONTENT, &[id.node, id.seq])
}

/// The numbers after the kind byte, from the key's tail.
fn parse_key(key: &[u8], kind: u8, parts: usize) -> Option<Vec<u64>> {
    let len = 2 + parts * 8;
    let tail = key.get(key.len().checked_sub(len)?..)?;
    (tail[0] == FEATURE && tail[1] == kind).then_some(())?;
    Some(
        tail[2..]
            .chunks_exact(8)
            .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
            .collect(),
    )
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    (value.len() % 2 == 0).then_some(())?;
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(value.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

async fn head(data: &Store, node: u64) -> trc::Result<Option<Head>> {
    data.get_value::<Head>(key(KIND_HEAD, &[node]))
        .await
        .caused_by(trc::location!())
}

async fn floor(data: &Store, node: u64) -> trc::Result<Floor> {
    Ok(data
        .get_value::<Json<Floor>>(key(KIND_FLOOR, &[node]))
        .await
        .caused_by(trc::location!())?
        .map(|Json(floor)| floor)
        .unwrap_or(Floor {
            seq: 1,
            prev: String::new(),
        }))
}

async fn nodes(data: &Store) -> trc::Result<Vec<u64>> {
    let mut nodes = Vec::new();
    data.iterate(
        IterateParams::new(key(KIND_HEAD, &[0]), key(KIND_HEAD, &[u64::MAX])).no_values(),
        |key, _| {
            if let Some(parts) = parse_key(key, KIND_HEAD, 1) {
                nodes.push(parts[0]);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(nodes)
}

/// Lines up this process's appends; the store's assert settles the rest.
static APPENDING: Mutex<()> = Mutex::const_new(());

/// Adds an entry to this node's chain, and links its report's blob (already
/// written) until the entry is purged. An error means nothing was written.
pub async fn append(data: &Store, node: u64, entry: &Entry) -> trc::Result<EntryId> {
    let blob = entry.blob_hash().ok_or_else(|| {
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Journal entry without a blob")
    })?;
    let content = Json(entry).serialize()?;
    let content_hash = sha256(&content);
    let _appending = APPENDING.lock().await;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let current = head(data, node).await?;
        let (seq, prev) = current
            .as_ref()
            .map_or((1, String::new()), |head| (head.seq + 1, head.hash.clone()));
        let link = Json(&Link {
            seq,
            prev,
            content: content_hash.clone(),
        })
        .serialize()?;
        let new_head = Head {
            seq,
            hash: sha256(&link),
        };

        let mut batch = BatchBuilder::new();
        batch.assert_value(
            class(KIND_HEAD, &[node]),
            current.map_or(AssertValue::None, |head| AssertValue::U64(head.seq)),
        );
        batch
            .set(class(KIND_LINK, &[node, seq]), link)
            .set(class(KIND_CONTENT, &[node, seq]), content.clone())
            .set(class(KIND_TIME, &[entry.at, node, seq]), vec![])
            .set(class(KIND_EXPIRY, &[entry.expires_at, node, seq]), vec![])
            .set(class(KIND_HEAD, &[node]), new_head.to_bytes())
            .set(
                BlobOp::Link {
                    hash: blob.clone(),
                    to: BlobLink::Temporary { until: HELD_UNTIL },
                },
                vec![],
            )
            .set(BlobOp::Commit { hash: blob.clone() }, vec![]);
        match data.write(batch.build_all()).await {
            Ok(_) => return Ok(EntryId { node, seq }),
            Err(err)
                if attempt < APPEND_ATTEMPTS
                    && matches!(
                        err.as_ref(),
                        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                    ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

/// One entry, unless it was purged.
pub async fn get(data: &Store, id: EntryId) -> trc::Result<Option<Entry>> {
    Ok(data
        .get_value::<Json<Entry>>(key(KIND_CONTENT, &[id.node, id.seq]))
        .await
        .caused_by(trc::location!())?
        .map(|Json(entry)| entry))
}

/// Entries written in `[after, before)` (seconds), newest first, up to
/// `limit`.
pub async fn list(
    data: &Store,
    after: u64,
    before: u64,
    limit: usize,
) -> trc::Result<Vec<(EntryId, Entry)>> {
    let mut ids = Vec::new();
    data.iterate(
        IterateParams::new(
            key(KIND_TIME, &[after, 0, 0]),
            key(KIND_TIME, &[before.saturating_sub(1), u64::MAX, u64::MAX]),
        )
        .descending()
        .no_values(),
        |key, _| {
            if let Some(parts) = parse_key(key, KIND_TIME, 3) {
                ids.push(EntryId {
                    node: parts[1],
                    seq: parts[2],
                });
            }
            Ok(ids.len() < limit)
        },
    )
    .await
    .caused_by(trc::location!())?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(entry) = get(data, id).await? {
            out.push((id, entry));
        }
    }
    Ok(out)
}

/// What a purge did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Purged {
    pub removed: usize,
    /// Past their time, kept for a legal hold.
    pub kept_for_hold: usize,
}

/// Removes entries past their retention (JR-13), except those `held` keeps:
/// the entry, its indexes and its blob's link go; the chain link stays,
/// with a purge marker. Then each chain's start moves past purged links.
pub async fn purge(
    data: &Store,
    now: u64,
    held: impl Fn(&Entry) -> bool + Sync + Send,
) -> trc::Result<Purged> {
    let mut due = Vec::new();
    data.iterate(
        IterateParams::new(
            key(KIND_EXPIRY, &[0, 0, 0]),
            key(KIND_EXPIRY, &[now, u64::MAX, u64::MAX]),
        )
        .ascending()
        .no_values(),
        |key, _| {
            if let Some(parts) = parse_key(key, KIND_EXPIRY, 3) {
                due.push((
                    parts[0],
                    EntryId {
                        node: parts[1],
                        seq: parts[2],
                    },
                ));
            }
            Ok(due.len() < 100_000)
        },
    )
    .await
    .caused_by(trc::location!())?;

    let mut purged = Purged::default();
    for chunk in due.chunks(PURGE_BATCH) {
        let mut batch = BatchBuilder::new();
        for (expires_at, id) in chunk {
            let parts = [id.node, id.seq];
            let Some(entry) = get(data, *id).await? else {
                // Its entry is already gone: only the index is left
                batch.clear(class(KIND_EXPIRY, &[*expires_at, id.node, id.seq]));
                continue;
            };
            if held(&entry) {
                purged.kept_for_hold += 1;
                continue;
            }
            batch
                .clear(class(KIND_CONTENT, &parts))
                .clear(class(KIND_TIME, &[entry.at, id.node, id.seq]))
                .clear(class(KIND_EXPIRY, &[*expires_at, id.node, id.seq]))
                .set(class(KIND_PURGED, &parts), now.to_be_bytes().to_vec());
            if let Some(blob) = entry.blob_hash() {
                batch.clear(BlobOp::Link {
                    hash: blob,
                    to: BlobLink::Temporary { until: HELD_UNTIL },
                });
            }
            purged.removed += 1;
        }
        if !batch.is_empty() {
            data.write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }
    }

    for node in nodes(data).await? {
        advance_floor(data, node).await?;
    }
    Ok(purged)
}

/// Clears the purged links at the start of a node's chain, recording where
/// it now starts and the hash that start names.
async fn advance_floor(data: &Store, node: u64) -> trc::Result<()> {
    let start = floor(data, node).await?;
    let mut cleared: Vec<u64> = Vec::new();
    let mut next = start.clone();
    let mut purged_seqs = Vec::new();
    data.iterate(
        IterateParams::new(
            key(KIND_PURGED, &[node, start.seq]),
            key(KIND_PURGED, &[node, u64::MAX]),
        )
        .ascending()
        .no_values(),
        |key, _| {
            if let Some(parts) = parse_key(key, KIND_PURGED, 2) {
                purged_seqs.push(parts[1]);
            }
            Ok(purged_seqs.len() < 100_000)
        },
    )
    .await
    .caused_by(trc::location!())?;
    for seq in purged_seqs {
        if seq != next.seq {
            break;
        }
        let Some(Raw(link)) = data
            .get_value::<Raw>(key(KIND_LINK, &[node, seq]))
            .await
            .caused_by(trc::location!())?
        else {
            break;
        };
        next = Floor {
            seq: seq + 1,
            prev: sha256(&link),
        };
        cleared.push(seq);
    }
    if cleared.is_empty() {
        return Ok(());
    }
    // The floor moves first: a run cut short leaves links before it, which
    // the next run clears, never a chain that looks broken
    let mut batch = BatchBuilder::new();
    batch.set(class(KIND_FLOOR, &[node]), Json(&next).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    for chunk in cleared.chunks(PURGE_BATCH) {
        let mut batch = BatchBuilder::new();
        for seq in chunk {
            batch
                .clear(class(KIND_LINK, &[node, *seq]))
                .clear(class(KIND_PURGED, &[node, *seq]));
        }
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }
    Ok(())
}

/// One node's chain, as [`verify`] found it.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainReport {
    pub node: u64,
    pub entries: u64,
    pub purged: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Rechecks every node's chain (JR-6): each link names the hash of the one
/// before it, seqs run without gaps, the head matches the last link, each
/// entry hashes to what its link names or was purged, and, with `blobs`,
/// each report is there and hashes to what its entry names.
pub async fn verify(data: &Store, blobs: Option<&BlobStore>) -> trc::Result<Vec<ChainReport>> {
    let mut reports = Vec::new();
    for node in nodes(data).await? {
        let start = floor(data, node).await?;
        let head = head(data, node).await?.unwrap_or_default();
        let mut report = ChainReport {
            node,
            entries: 0,
            purged: 0,
            first_seq: start.seq,
            last_seq: start.seq.saturating_sub(1),
            broken_at: None,
            reason: None,
        };
        let mut links = Vec::new();
        data.iterate(
            IterateParams::new(
                key(KIND_LINK, &[node, start.seq]),
                key(KIND_LINK, &[node, u64::MAX]),
            )
            .ascending(),
            |key, value| {
                if let Some(parts) = parse_key(key, KIND_LINK, 2) {
                    links.push((parts[1], value.to_vec()));
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        let mut expected_seq = start.seq;
        let mut expected_prev = start.prev.clone();
        for (seq, bytes) in links {
            let broken = |report: &mut ChainReport, reason: &str| {
                report.broken_at = Some(EntryId { node, seq }.to_string());
                report.reason = Some(reason.to_string());
            };
            let Ok(Json(link)) = Json::<Link>::deserialize(&bytes) else {
                broken(&mut report, "The link can't be read.");
                break;
            };
            if seq != expected_seq || link.seq != seq {
                report.broken_at = Some(EntryId { node, seq }.to_string());
                report.reason = Some(format!(
                    "Entry {expected_seq} is missing; the next one found is {seq}."
                ));
                break;
            }
            if link.prev != expected_prev {
                broken(
                    &mut report,
                    "The link doesn't follow from the one before it: one of them was changed.",
                );
                break;
            }
            match data
                .get_value::<Raw>(key(KIND_CONTENT, &[node, seq]))
                .await
                .caused_by(trc::location!())?
            {
                Some(Raw(content)) => {
                    if sha256(&content) != link.content {
                        broken(&mut report, "The entry was changed after it was written.");
                        break;
                    }
                    if let Some(blobs) = blobs {
                        let Ok(Json(entry)) = Json::<Entry>::deserialize(&content) else {
                            broken(&mut report, "The entry can't be read.");
                            break;
                        };
                        let report_bytes = match entry.blob_hash() {
                            Some(hash) => blobs
                                .get_blob(hash.as_slice(), 0..usize::MAX)
                                .await
                                .caused_by(trc::location!())?,
                            None => None,
                        };
                        match report_bytes {
                            Some(bytes) if sha256(&bytes) == entry.sha256 => {}
                            Some(_) => {
                                broken(&mut report, "The report doesn't match its entry.");
                                break;
                            }
                            None => {
                                broken(&mut report, "The report is missing.");
                                break;
                            }
                        }
                    }
                    report.entries += 1;
                }
                None => {
                    if data
                        .get_value::<Raw>(key(KIND_PURGED, &[node, seq]))
                        .await
                        .caused_by(trc::location!())?
                        .is_none()
                    {
                        broken(&mut report, "The entry was removed before its time.");
                        break;
                    }
                    report.purged += 1;
                }
            }
            expected_prev = sha256(&bytes);
            expected_seq = seq + 1;
            report.last_seq = seq;
        }

        if report.broken_at.is_none()
            && (head.seq != report.last_seq
                || (report.last_seq >= report.first_seq && head.hash != expected_prev))
        {
            report.broken_at = Some(
                EntryId {
                    node,
                    seq: report.last_seq,
                }
                .to_string(),
            );
            report.reason = Some(
                "The chain's recorded end doesn't match its last link: entries were removed \
                 or changed at the end."
                    .into(),
            );
        }
        reports.push(report);
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_read_back() {
        let ValueClass::Any(any) = class(KIND_EXPIRY, &[5, 3, 9]) else {
            panic!()
        };
        assert_eq!(parse_key(&any.key, KIND_EXPIRY, 3), Some(vec![5, 3, 9]));
        let mut with_subspace = vec![SUBSPACE_INBUXA];
        with_subspace.extend_from_slice(&any.key);
        assert_eq!(
            parse_key(&with_subspace, KIND_EXPIRY, 3),
            Some(vec![5, 3, 9])
        );
        assert_eq!(parse_key(&any.key, KIND_TIME, 3), None);
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&bytes)), Some(bytes.to_vec()));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn ids_read_back() {
        let id = EntryId { node: 3, seq: 77 };
        assert_eq!(EntryId::from_u64(id.to_u64()), id);
        assert_eq!(id.to_string(), "3-77");
    }
}
