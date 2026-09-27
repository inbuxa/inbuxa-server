/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The audit log's storage (AU-2, AU-3, AU-6, AU-7), in the fork's own
//! subspace (`store::SUBSPACE_INBUXA`). Every key starts with `L`, then one
//! byte for the kind:
//!
//! - `e` + node + seq: one entry of that node's chain, as JSON. An entry is
//!   an event, or the outcome of an event written before its change was
//!   tried. Each holds the SHA-256 of the entry before it on the same node.
//! - `t` + time + node + seq: the time index of events, for queries.
//! - `o` + node + seq: the seq of an event's outcome entry.
//! - `h` + node: the chain's head: that entry's hash, then its seq as the
//!   last eight bytes, which each append asserts, so two writers can never
//!   both add the same seq.
//! - `f` + node: where the chain starts after purging, and the hash the
//!   first kept entry names.
//! - `s`: the settings (`keepFor`).
//!
//! Numbers are big-endian, so keys sort in time and chain order. Each node
//! writes only its own chain, so nodes never contend for a key; nothing about
//! a chain is kept in memory, so a node restarted or rebuilt carries on
//! from what is stored.

use crate::audit::record::{Action, Outcome, Record};
use ahash::AHashMap;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use sha2::{Digest, Sha256};
use std::{fmt, net::IpAddr, str::FromStr};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use tokio::sync::Mutex;
use trc::AddContext;

const FEATURE: u8 = b'L';
const KIND_ENTRY: u8 = b'e';
const KIND_TIME: u8 = b't';
const KIND_OUTCOME: u8 = b'o';
const KIND_HEAD: u8 = b'h';
const KIND_FLOOR: u8 = b'f';
const KIND_SETTINGS: u8 = b's';

/// How long entries are kept unless set otherwise: two years (AU-7).
pub const DEFAULT_KEEP_FOR_SECS: u64 = 730 * 86_400;
/// The shortest period an administrator may set (AU-7).
pub const MIN_KEEP_FOR_SECS: u64 = 90 * 86_400;
/// Most results one query page returns.
pub const MAX_QUERY_LIMIT: usize = 500;
/// Keys cleared per purge batch.
const PURGE_BATCH: usize = 500;

/// Where one entry sits: its node's chain and its place in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntryId {
    pub node: u64,
    pub seq: u64,
}

impl EntryId {
    /// As one number, for JMAP ids: the node in the top 16 bits, the seq in
    /// the rest. Node ids are 16 bits; a chain reaches 2^48 entries never.
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

impl FromStr for EntryId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (node, seq) = s.split_once('-').ok_or(())?;
        Ok(EntryId {
            node: node.parse().map_err(|_| ())?,
            seq: seq.parse().map_err(|_| ())?,
        })
    }
}

/// What is kept for one chain entry. The hash of these exact bytes is what
/// the next entry names as `prev`.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
struct Stored {
    seq: u64,
    prev: String,
    #[serde(flatten)]
    entry: Entry,
}

#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(tag = "entry", rename_all = "camelCase")]
enum Entry {
    Event { record: Record },
    Outcome { of: u64, at: u64, outcome: Outcome },
}

impl Entry {
    fn at(&self) -> u64 {
        match self {
            Entry::Event { record } => record.at,
            Entry::Outcome { at, .. } => *at,
        }
    }
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
                .details("Invalid audit chain head")
        })?;
        Ok(Head {
            seq: u64::from_be_bytes(bytes[split..].try_into().unwrap()),
            hash: String::from_utf8_lossy(&bytes[..split]).into_owned(),
        })
    }
}

async fn head(data: &Store, node: u64) -> trc::Result<Option<Head>> {
    data.get_value::<Head>(key(KIND_HEAD, &[node]))
        .await
        .caused_by(trc::location!())
}

/// Attempts at an append that another writer beat to the same seq.
const APPEND_ATTEMPTS: usize = 5;

#[derive(Debug, Clone, Default, PartialEq, SerdeSerialize, SerdeDeserialize)]
struct Floor {
    seq: u64,
    prev: String,
}

/// The audit log's settings (`inbuxa:AuditSettings`).
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub keep_for_secs: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            keep_for_secs: DEFAULT_KEEP_FOR_SECS,
        }
    }
}

/// A value stored as JSON.
struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(&self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to serialize audit entry")
                .reason(err)
        })
    }
}

impl<T: serde::de::DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid audit entry")
                .reason(err)
        })
    }
}

/// Raw bytes, for entries whose hash is checked.
struct Raw(Vec<u8>);

impl Deserialize for Raw {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Raw(bytes.to_vec()))
    }
}

struct U64(u64);

impl Deserialize for U64 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        bytes
            .try_into()
            .map(|bytes| U64(u64::from_be_bytes(bytes)))
            .map_err(|_| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Invalid audit outcome pointer")
            })
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

/// Where an entry is kept, for tests and tools that check tampering is
/// caught.
pub fn entry_key(id: EntryId) -> ValueKey<ValueClass> {
    key(KIND_ENTRY, &[id.node, id.seq])
}

/// Where a node's chain head is kept, for the same.
pub fn head_key(node: u64) -> ValueKey<ValueClass> {
    key(KIND_HEAD, &[node])
}

/// The numbers after the kind byte, read from the key's tail: the iterator
/// may or may not hand back the subspace byte.
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

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Lines up this process's appends, so they rarely race for a head; the
/// store's assert settles any that still do.
static APPENDING: Mutex<()> = Mutex::const_new(());

/// What a node keeps in memory: which accesses it has recorded lately
/// (AU-1.6).
#[derive(Default)]
pub struct AuditLog {
    recent_access: std::sync::Mutex<AHashMap<(u32, u32, u8), u64>>,
}

/// A query over events (AU-9), newest first.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// From this time on, in ms.
    pub after: Option<u64>,
    /// Before this time, in ms.
    pub before: Option<u64>,
    pub actor_id: Option<u32>,
    pub action: Option<Action>,
    pub target_kind: Option<String>,
    pub target_id: Option<String>,
    pub account_id: Option<u32>,
    /// Records whose actor or target is in this tenant.
    pub tenant_id: Option<u32>,
    pub outcome: Option<String>,
    pub remote_ip: Option<IpAddr>,
    /// Words that must all appear in the actor's or target's name, the
    /// target kind, or the details, ignoring case.
    pub text: Option<String>,
}

impl Filter {
    pub fn matches(&self, record: &Record) -> bool {
        self.after.is_none_or(|after| record.at >= after)
            && self.before.is_none_or(|before| record.at < before)
            && self
                .actor_id
                .is_none_or(|actor| record.actor.account_id == Some(actor))
            && self.action.is_none_or(|action| record.action == action)
            && self
                .target_kind
                .as_ref()
                .is_none_or(|kind| record.target.kind.eq_ignore_ascii_case(kind))
            && self
                .target_id
                .as_ref()
                .is_none_or(|target| record.target.id.as_ref() == Some(target))
            && self.account_id.is_none_or(|account| {
                record.target.account_id == Some(account)
                    || record.actor.account_id == Some(account)
                    || (record.target.kind == "x:Account"
                        && record.target.id.as_deref()
                            == Some(types::id::Id::from(account).to_string().as_str()))
            })
            && self
                .tenant_id
                .is_none_or(|tenant| in_tenant(record, tenant))
            && self
                .outcome
                .as_ref()
                .is_none_or(|outcome| record.outcome.as_str() == outcome)
            && self.remote_ip.is_none_or(|ip| record.remote_ip == Some(ip))
            && self.text.as_ref().is_none_or(|text| {
                let haystack = format!(
                    "{} {} {} {} {}",
                    record.actor.name,
                    record.target.kind,
                    record.target.name.as_deref().unwrap_or_default(),
                    record.details.as_deref().unwrap_or_default(),
                    record.reason.as_deref().unwrap_or_default()
                )
                .to_lowercase();
                text.to_lowercase()
                    .split_whitespace()
                    .all(|word| haystack.contains(word))
            })
    }
}

/// Whether a tenant administrator may see a record: its actor or its
/// target is in the tenant (AU-9).
pub fn in_tenant(record: &Record, tenant_id: u32) -> bool {
    record.actor.tenant_id == Some(tenant_id) || record.target.tenant_id == Some(tenant_id)
}

/// One node's chain, as `verify` found it.
#[derive(Debug, Clone, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainReport {
    pub node: u64,
    pub entries: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    /// The first entry that doesn't follow from the one before it, or the
    /// head that doesn't match the last entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Events written before their change whose outcome never followed.
    pub unfinished: u64,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an event to this node's chain. An error means nothing was
    /// written, and the caller must not go ahead with the change (AU-3).
    pub async fn append(&self, data: &Store, node: u64, record: &Record) -> trc::Result<EntryId> {
        self.append_entry(
            data,
            node,
            Entry::Event {
                record: record.clone(),
            },
        )
        .await
    }

    /// Appends the outcome of an event written as pending.
    pub async fn finish(
        &self,
        data: &Store,
        node: u64,
        of: EntryId,
        at: u64,
        outcome: Outcome,
    ) -> trc::Result<EntryId> {
        self.append_entry(
            data,
            node,
            Entry::Outcome {
                of: of.seq,
                at,
                outcome,
            },
        )
        .await
    }

    async fn append_entry(&self, data: &Store, node: u64, entry: Entry) -> trc::Result<EntryId> {
        let _appending = APPENDING.lock().await;
        let at = entry.at();
        let event_of = match &entry {
            Entry::Outcome { of, .. } => Some(*of),
            Entry::Event { .. } => None,
        };
        let mut stored = Stored {
            seq: 0,
            prev: String::new(),
            entry,
        };
        let mut attempt = 0;
        loop {
            attempt += 1;
            let current = head(data, node).await?;
            let (seq, prev) = current
                .as_ref()
                .map_or((1, String::new()), |head| (head.seq + 1, head.hash.clone()));
            stored.seq = seq;
            stored.prev = prev;
            let bytes = Json(&stored).serialize()?;
            let new_head = Head {
                seq,
                hash: hash(&bytes),
            };

            let mut batch = BatchBuilder::new();
            batch.assert_value(
                class(KIND_HEAD, &[node]),
                current.map_or(AssertValue::None, |head| AssertValue::U64(head.seq)),
            );
            batch.set(class(KIND_ENTRY, &[node, seq]), bytes);
            match event_of {
                None => {
                    batch.set(class(KIND_TIME, &[at, node, seq]), vec![]);
                }
                Some(of) => {
                    batch.set(class(KIND_OUTCOME, &[node, of]), seq.to_be_bytes().to_vec());
                }
            }
            batch.set(class(KIND_HEAD, &[node]), new_head.to_bytes());
            match data.write(batch.build_all()).await {
                Ok(_) => return Ok(EntryId { node, seq }),
                Err(err)
                    if attempt < APPEND_ATTEMPTS
                        && matches!(
                            err.as_ref(),
                            trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                        ) =>
                {
                    continue;
                }
                Err(err) => return Err(err.caused_by(trc::location!())),
            }
        }
    }

    /// Whether an access of `target` by `actor` (kind 0: account, 1: blob)
    /// is the first this hour on this node, and so should be recorded
    /// (AU-1.6). Marks it recorded.
    pub fn first_access_this_hour(&self, actor: u32, target: u32, kind: u8, now_secs: u64) -> bool {
        let hour = now_secs / 3600;
        let mut recent = self.recent_access.lock().unwrap_or_else(|e| e.into_inner());
        if recent.len() > 10_000 {
            recent.retain(|_, seen| *seen == hour);
        }
        recent.insert((actor, target, kind), hour) != Some(hour)
    }

    /// Forgets which accesses were recorded, so the next is recorded again
    /// (after a write failed).
    pub fn forget_access(&self, actor: u32, target: u32, kind: u8) {
        self.recent_access
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(actor, target, kind));
    }
}

/// One event with its outcome, when that was written separately.
pub async fn get(data: &Store, id: EntryId) -> trc::Result<Option<Record>> {
    let Some(Json(stored)) = data
        .get_value::<Json<Stored>>(key(KIND_ENTRY, &[id.node, id.seq]))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    let Entry::Event { mut record } = stored.entry else {
        return Ok(None);
    };
    if record.outcome == Outcome::Pending
        && let Some(U64(outcome_seq)) = data
            .get_value::<U64>(key(KIND_OUTCOME, &[id.node, id.seq]))
            .await
            .caused_by(trc::location!())?
        && let Some(Json(Stored {
            entry: Entry::Outcome { outcome, .. },
            ..
        })) = data
            .get_value::<Json<Stored>>(key(KIND_ENTRY, &[id.node, outcome_seq]))
            .await
            .caused_by(trc::location!())?
    {
        record.outcome = outcome;
    }
    Ok(Some(record))
}

/// One event with its outcome, and the hash of its entry and the hash that
/// entry follows: what an export carries so a recipient can match it
/// against a later verification (AU-11).
pub async fn get_with_hash(
    data: &Store,
    id: EntryId,
) -> trc::Result<Option<(Record, String, String)>> {
    let Some(Raw(bytes)) = data
        .get_value::<Raw>(key(KIND_ENTRY, &[id.node, id.seq]))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    let Json(stored) = Json::<Stored>::deserialize(&bytes)?;
    if !matches!(stored.entry, Entry::Event { .. }) {
        return Ok(None);
    }
    let entry_hash = hash(&bytes);
    Ok(get(data, id)
        .await?
        .map(|record| (record, entry_hash, stored.prev)))
}

/// Every event matching `filter`, newest first, up to `max`: for exports.
pub async fn query_all(data: &Store, filter: &Filter, max: usize) -> trc::Result<Vec<EntryId>> {
    query_inner(data, filter, 0, max, false)
        .await
        .map(|(ids, _)| ids)
}

/// Events matching `filter`, newest first: the ids from `position`, at most
/// `limit` of them, and how many match in all when `count_all` is set.
pub async fn query(
    data: &Store,
    filter: &Filter,
    position: usize,
    limit: usize,
    count_all: bool,
) -> trc::Result<(Vec<EntryId>, usize)> {
    query_inner(
        data,
        filter,
        position,
        limit.min(MAX_QUERY_LIMIT),
        count_all,
    )
    .await
}

async fn query_inner(
    data: &Store,
    filter: &Filter,
    position: usize,
    limit: usize,
    count_all: bool,
) -> trc::Result<(Vec<EntryId>, usize)> {
    let from = filter.after.unwrap_or(0);
    let to = filter
        .before
        .map_or(u64::MAX, |before| before.saturating_sub(1));
    if from > to {
        return Ok((Vec::new(), 0));
    }

    // Walk the time index newest first, collecting candidates
    let mut candidates = Vec::new();
    data.iterate(
        IterateParams::new(
            key(KIND_TIME, &[from, 0, 0]),
            key(KIND_TIME, &[to, u64::MAX, u64::MAX]),
        )
        .descending()
        .no_values(),
        |key, _| {
            if let Some(parts) = parse_key(key, KIND_TIME, 3) {
                candidates.push(EntryId {
                    node: parts[1],
                    seq: parts[2],
                });
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;

    let mut ids = Vec::with_capacity(limit);
    let mut matched = 0;
    for id in candidates {
        if !count_all && ids.len() >= limit {
            break;
        }
        let Some(record) = get(data, id).await? else {
            continue;
        };
        if filter.matches(&record) {
            if matched >= position && ids.len() < limit {
                ids.push(id);
            }
            matched += 1;
        }
    }
    Ok((ids, matched))
}

pub async fn settings(data: &Store) -> trc::Result<Settings> {
    Ok(data
        .get_value::<Json<Settings>>(key(KIND_SETTINGS, &[]))
        .await
        .caused_by(trc::location!())?
        .map(|Json(settings)| settings)
        .unwrap_or_default())
}

pub async fn set_settings(data: &Store, settings: &Settings) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(class(KIND_SETTINGS, &[]), Json(settings).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// The nodes that have a chain.
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

/// Removes, from the start of every node's chain, the entries older than
/// `cutoff` (ms), stopping at the first one that is newer or that `keep`
/// holds on to (AU-7, LH-6). The chain stays verifiable: its new start and
/// the hash that start names are recorded. Returns how many were removed.
pub async fn purge(
    data: &Store,
    cutoff: u64,
    keep: impl Fn(&Record) -> bool + Sync + Send,
) -> trc::Result<usize> {
    let mut removed = 0;
    for node in nodes(data).await? {
        let start = floor(data, node).await?;
        let mut doomed: Vec<(u64, Stored)> = Vec::new();
        let mut new_floor = None;
        data.iterate(
            IterateParams::new(
                key(KIND_ENTRY, &[node, start.seq]),
                key(KIND_ENTRY, &[node, u64::MAX]),
            )
            .ascending(),
            |key, value| {
                let Some(parts) = parse_key(key, KIND_ENTRY, 2) else {
                    return Ok(true);
                };
                let Json(stored) = Json::<Stored>::deserialize(value)?;
                let held = matches!(&stored.entry, Entry::Event { record } if keep(record));
                if stored.entry.at() >= cutoff || held || doomed.len() >= 100_000 {
                    new_floor = Some(Floor {
                        seq: parts[1],
                        prev: stored.prev,
                    });
                    return Ok(false);
                }
                doomed.push((parts[1], stored));
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        if doomed.is_empty() {
            continue;
        }
        // With nothing newer, the chain continues from its head
        let new_floor = match new_floor {
            Some(floor) => floor,
            None => {
                let head = head(data, node).await?.unwrap_or_default();
                Floor {
                    seq: head.seq + 1,
                    prev: head.hash,
                }
            }
        };

        // The floor moves first: a purge cut short leaves entries before it,
        // which the next run clears, never a chain that looks broken
        let mut batch = BatchBuilder::new();
        batch.set(class(KIND_FLOOR, &[node]), Json(&new_floor).serialize()?);
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        for chunk in doomed.chunks(PURGE_BATCH / 3) {
            let mut batch = BatchBuilder::new();
            for (seq, stored) in chunk {
                batch.clear(class(KIND_ENTRY, &[node, *seq]));
                match &stored.entry {
                    Entry::Event { record } => {
                        batch
                            .clear(class(KIND_TIME, &[record.at, node, *seq]))
                            .clear(class(KIND_OUTCOME, &[node, *seq]));
                    }
                    Entry::Outcome { .. } => {}
                }
            }
            data.write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            removed += chunk.len();
        }
    }
    Ok(removed)
}

/// Rechecks every node's chain (AU-6): each entry must name the hash of the
/// one before it, seqs must run without gaps from the chain's start, and the
/// head must match the last entry.
pub async fn verify(data: &Store) -> trc::Result<Vec<ChainReport>> {
    let mut reports = Vec::new();
    for node in nodes(data).await? {
        let start = floor(data, node).await?;
        let head = head(data, node).await?.unwrap_or_default();
        let mut report = ChainReport {
            node,
            entries: 0,
            first_seq: start.seq,
            last_seq: start.seq.saturating_sub(1),
            broken_at: None,
            reason: None,
            unfinished: 0,
        };
        let mut expected_seq = start.seq;
        let mut expected_prev = start.prev.clone();
        let mut pending: ahash::AHashSet<u64> = Default::default();

        data.iterate(
            IterateParams::new(
                key(KIND_ENTRY, &[node, start.seq]),
                key(KIND_ENTRY, &[node, u64::MAX]),
            )
            .ascending(),
            |key, value| {
                let Some(parts) = parse_key(key, KIND_ENTRY, 2) else {
                    return Ok(true);
                };
                let seq = parts[1];
                let broken = |report: &mut ChainReport, reason: String| {
                    report.broken_at = Some(EntryId { node, seq }.to_string());
                    report.reason = Some(reason);
                };
                let Raw(bytes) = Raw::deserialize(value)?;
                let Ok(Json(stored)) = Json::<Stored>::deserialize(&bytes) else {
                    broken(&mut report, "The entry can't be read.".into());
                    return Ok(false);
                };
                if seq != expected_seq || stored.seq != seq {
                    broken(
                        &mut report,
                        format!("Entry {expected_seq} is missing; the next one found is {seq}."),
                    );
                    return Ok(false);
                }
                if stored.prev != expected_prev {
                    broken(
                        &mut report,
                        "The entry doesn't follow from the one before it: one of them was changed."
                            .into(),
                    );
                    return Ok(false);
                }
                match &stored.entry {
                    Entry::Event { record } if record.outcome == Outcome::Pending => {
                        pending.insert(seq);
                    }
                    Entry::Outcome { of, .. } => {
                        pending.remove(of);
                    }
                    Entry::Event { .. } => {}
                }
                expected_prev = hash(&bytes);
                expected_seq = seq + 1;
                report.entries += 1;
                report.last_seq = seq;
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        if report.broken_at.is_none() {
            if head.seq != report.last_seq || (report.entries > 0 && head.hash != expected_prev) {
                report.broken_at = Some(
                    EntryId {
                        node,
                        seq: report.last_seq,
                    }
                    .to_string(),
                );
                report.reason = Some(
                    "The chain's recorded end doesn't match its last entry: entries were \
                     removed or changed at the end."
                        .into(),
                );
            }
        }
        report.unfinished = pending.len() as u64;
        reports.push(report);
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_read_back() {
        let ValueClass::Any(any) = class(KIND_TIME, &[5, 3, 9]) else {
            panic!()
        };
        assert_eq!(parse_key(&any.key, KIND_TIME, 3), Some(vec![5, 3, 9]));
        let mut with_subspace = vec![SUBSPACE_INBUXA];
        with_subspace.extend_from_slice(&any.key);
        assert_eq!(parse_key(&with_subspace, KIND_TIME, 3), Some(vec![5, 3, 9]));
        assert_eq!(parse_key(&any.key, KIND_ENTRY, 3), None);
    }

    #[test]
    fn ids_read_back() {
        let id = EntryId { node: 2, seq: 1042 };
        assert_eq!(id.to_string(), "2-1042");
        assert_eq!("2-1042".parse::<EntryId>(), Ok(id));
        assert!("2".parse::<EntryId>().is_err());
        assert!("a-1".parse::<EntryId>().is_err());
        assert_eq!(EntryId::from_u64(id.to_u64()), id);
        let big = EntryId {
            node: 65535,
            seq: (1 << 48) - 1,
        };
        assert_eq!(EntryId::from_u64(big.to_u64()), big);
    }

    #[test]
    fn filters() {
        use crate::audit::record::{Actor, Target};
        let record = Record {
            at: 1000,
            actor: Actor::account(7, "Admin@Example.com", Some(4)),
            via: None,
            remote_ip: None,
            action: Action::Update,
            target: Target {
                kind: "x:Domain".into(),
                id: Some("d".into()),
                name: Some("example.org".into()),
                tenant_id: Some(9),
                ..Default::default()
            },
            changes: vec![],
            details: None,
            reason: None,
            outcome: Outcome::success(),
        };
        let yes = |filter: Filter| assert!(filter.matches(&record), "{filter:?}");
        let no = |filter: Filter| assert!(!filter.matches(&record), "{filter:?}");
        yes(Filter::default());
        yes(Filter {
            after: Some(1000),
            before: Some(1001),
            ..Default::default()
        });
        no(Filter {
            before: Some(1000),
            ..Default::default()
        });
        yes(Filter {
            tenant_id: Some(4),
            ..Default::default()
        });
        yes(Filter {
            tenant_id: Some(9),
            ..Default::default()
        });
        no(Filter {
            tenant_id: Some(5),
            ..Default::default()
        });
        yes(Filter {
            text: Some("admin EXAMPLE.ORG".into()),
            ..Default::default()
        });
        no(Filter {
            text: Some("admin other".into()),
            ..Default::default()
        });
        yes(Filter {
            outcome: Some("success".into()),
            action: Some(Action::Update),
            target_kind: Some("x:domain".into()),
            ..Default::default()
        });
        no(Filter {
            actor_id: Some(8),
            ..Default::default()
        });
    }

    #[test]
    fn heads_read_back() {
        let head = Head {
            seq: 77,
            hash: hash(b"x"),
        };
        let bytes = head.to_bytes();
        assert!(AssertValue::U64(77).matches(&bytes));
        assert!(!AssertValue::U64(76).matches(&bytes));
        assert_eq!(Head::deserialize(&bytes).unwrap(), head);
        assert!(Head::deserialize(b"short").is_err());
    }

    #[test]
    fn hashes_are_sha256_hex() {
        assert_eq!(
            hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
