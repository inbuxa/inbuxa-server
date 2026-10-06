/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! SQL read replicas (ST-5 to ST-15). The primary answers everything unless
//! a read is made inside a [`replica_read`] scope, opened by the call sites
//! ST-6 names, for account data only. Inside one, the first read picks a
//! replica that is healthy, within the lag limit, and has caught up with
//! every change this node knows of for the scope's accounts (ST-7);
//! otherwise the scope stays on the primary. A miss or an error on a
//! replica is answered from the primary (ST-8, ST-12).

use crate::{
    InMemoryStore, SUBSPACE_ACL, SUBSPACE_BLOB_LINK, SUBSPACE_BLOBS, SUBSPACE_COUNTER,
    SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_PROPERTY, SUBSPACE_SEARCH_INDEX, Store, ValueKey,
    write::{AssignedId, AssignedIds, ValueClass},
};
use ahash::AHashMap;
use std::{
    future::Future,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
};

/// A replica more than this far behind gets no reads (ST-11).
pub const LAG_LIMIT_MS: u64 = 5_000;
/// ... and gets them again under this (ST-11).
pub const LAG_READMIT_MS: u64 = 2_500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplicaState {
    /// Not yet checked at startup (ST-15): no reads.
    Unvalidated = 0,
    Up = 1,
    /// Failed a read or a probe (ST-12): no reads until a probe succeeds.
    Down = 2,
    /// Over the lag limit (ST-11).
    Lagging = 3,
    /// Failed a startup check (ST-15): never used.
    Excluded = 4,
    /// Its lag can't be measured (ST-11): never used.
    Unmeasurable = 5,
}

impl ReplicaState {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => ReplicaState::Up,
            2 => ReplicaState::Down,
            3 => ReplicaState::Lagging,
            4 => ReplicaState::Excluded,
            5 => ReplicaState::Unmeasurable,
            _ => ReplicaState::Unvalidated,
        }
    }
}

pub struct Replica {
    pub store: Store,
    /// `host:port database`, for logs.
    pub label: String,
    /// The connection settings, for ST-15's "is it the primary" check.
    pub location: (String, u16, String),
    state: AtomicU8,
    pub lag_ms: AtomicU64,
    /// Reads served, for observability and tests.
    pub reads: AtomicU64,
    /// Startup marker checks that timed out (ST-15).
    pub marker_misses: AtomicU8,
}

impl Replica {
    pub fn new(store: Store, host: String, port: u16, database: String) -> Self {
        Replica {
            store,
            label: format!("{host}:{port} {database}"),
            location: (host, port, database),
            state: AtomicU8::new(ReplicaState::Unvalidated as u8),
            lag_ms: AtomicU64::new(u64::MAX),
            reads: AtomicU64::new(0),
            marker_misses: AtomicU8::new(0),
        }
    }

    pub fn state(&self) -> ReplicaState {
        ReplicaState::from_u8(self.state.load(Ordering::Relaxed))
    }

    pub fn set_state(&self, state: ReplicaState) -> ReplicaState {
        ReplicaState::from_u8(self.state.swap(state as u8, Ordering::Relaxed))
    }

    fn usable(&self) -> bool {
        self.state() == ReplicaState::Up
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaKind {
    PostgreSql,
    MySql,
}

pub struct ReplicatedStore {
    pub primary: Store,
    /// The primary's connection settings, for ST-15.
    pub primary_location: (String, u16, String),
    pub replicas: Vec<Replica>,
    pub kind: ReplicaKind,
    next: AtomicUsize,
    /// The highest change id this node has written or heard of, per account
    /// (ST-7).
    marks: Mutex<AHashMap<u32, u64>>,
    /// Shared marks, when more than one node runs (ST-7, step 2).
    shared: OnceLock<InMemoryStore>,
}

/// Account data a replica may serve. Everything else (the registry,
/// in-memory values, the task queue, telemetry, the fork's own records)
/// is always read from the primary (ST-5).
pub fn is_replica_subspace(subspace: u8) -> bool {
    matches!(
        subspace,
        SUBSPACE_PROPERTY
            | SUBSPACE_INDEXES
            | SUBSPACE_LOGS
            | SUBSPACE_COUNTER
            | SUBSPACE_ACL
            | SUBSPACE_BLOB_LINK
            | SUBSPACE_BLOBS
            | SUBSPACE_SEARCH_INDEX
    )
}

/// A read scope: the accounts whose data it reads, each with any change id
/// the client presented (ST-7, step 4), and the replica it settled on.
pub struct ReadScope {
    accounts: Vec<(u32, u64)>,
    /// Change ids the client presented during the scope (ST-7, step 4).
    presented: Mutex<Vec<(u32, u64)>>,
    choice: tokio::sync::OnceCell<Option<usize>>,
    /// Set by any write made inside the scope: from then on it reads from
    /// the primary (ST-6: a read in a request that writes).
    wrote: std::sync::atomic::AtomicBool,
}

/// A state the client presented raises the mark a replica must have
/// reached before it may answer this scope (ST-7, step 4).
pub fn present_change(account_id: u32, change_id: u64) {
    let _ = READ_SCOPE.try_with(|scope| {
        scope
            .presented
            .lock()
            .unwrap()
            .push((account_id, change_id))
    });
}

/// A write happened in the current task: a read scope, if any, stops using
/// replicas.
pub fn note_scope_write() {
    let _ = READ_SCOPE.try_with(|scope| scope.wrote.store(true, Ordering::Relaxed));
}

tokio::task_local! {
    static READ_SCOPE: Arc<ReadScope>;
}

/// Runs `fut` with replica-eligible reads for `accounts`: `(account, the
/// change id the client presented, or 0)` (ST-6).
pub async fn replica_read<F: Future>(
    accounts: impl IntoIterator<Item = (u32, u64)>,
    fut: F,
) -> F::Output {
    READ_SCOPE
        .scope(
            Arc::new(ReadScope {
                accounts: accounts.into_iter().collect(),
                presented: Mutex::new(Vec::new()),
                choice: tokio::sync::OnceCell::new(),
                wrote: std::sync::atomic::AtomicBool::new(false),
            }),
            fut,
        )
        .await
}

/// Carries the current read scope, if any, into a future about to be
/// spawned as its own task (ST-6).
pub fn carry<F: Future>(fut: F) -> impl Future<Output = F::Output> {
    let scope = READ_SCOPE.try_with(|scope| scope.clone()).ok();
    async move {
        match scope {
            Some(scope) => READ_SCOPE.scope(scope, fut).await,
            None => fut.await,
        }
    }
}

#[allow(dead_code)] // used with a PostgreSQL or MySQL backend
fn change_id_key(account_id: u32) -> ValueKey<ValueClass> {
    ValueKey {
        account_id,
        collection: 0,
        document_id: 0,
        class: ValueClass::ChangeId,
    }
}

impl ReplicatedStore {
    pub fn new(
        primary: Store,
        primary_location: (String, u16, String),
        replicas: Vec<Replica>,
        kind: ReplicaKind,
    ) -> Arc<Self> {
        let store = Arc::new(ReplicatedStore {
            primary,
            primary_location,
            replicas,
            kind,
            next: AtomicUsize::new(0),
            marks: Mutex::new(AHashMap::new()),
            shared: OnceLock::new(),
        });
        super::replica_health::spawn(Arc::downgrade(&store));
        store
    }

    /// Shares high-water marks through the in-memory store, for a cluster
    /// (ST-7, step 2).
    pub fn share_marks(&self, memory: InMemoryStore) {
        let _ = self.shared.set(memory);
    }

    #[allow(dead_code)] // used with the redis feature
    fn shared_key(account_id: u32) -> Vec<u8> {
        let mut key = b"_rm".to_vec();
        key.extend_from_slice(&account_id.to_be_bytes());
        key
    }

    /// Records a change this node made or heard of (ST-7, step 1).
    pub fn note_change(&self, account_id: u32, change_id: u64) {
        let mut marks = self.marks.lock().unwrap();
        let mark = marks.entry(account_id).or_default();
        if change_id > *mark {
            *mark = change_id;
        }
    }

    /// Records the change ids a write produced, locally and, in a cluster,
    /// in the shared store before the write returns (ST-7, steps 1 and 2).
    pub async fn note_write(&self, ids: &AssignedIds) {
        let mut changes = Vec::new();
        for id in &ids.ids {
            if let AssignedId::ChangeId(change) = id {
                self.note_change(change.account_id, change.change_id);
                changes.push((change.account_id, change.change_id));
            }
        }
        #[cfg(feature = "redis")]
        if let Some(InMemoryStore::Redis(redis)) = self.shared.get() {
            for (account_id, change_id) in changes {
                let _ = redis
                    .key_set(
                        &Self::shared_key(account_id),
                        change_id.to_string().as_bytes(),
                        Some(2 * LAG_LIMIT_MS / 1000),
                    )
                    .await;
            }
        }
        #[cfg(not(feature = "redis"))]
        let _ = changes;
    }

    async fn mark(&self, account_id: u32) -> u64 {
        let local = self
            .marks
            .lock()
            .unwrap()
            .get(&account_id)
            .copied()
            .unwrap_or_default();
        #[cfg(feature = "redis")]
        let shared = match self.shared.get() {
            Some(InMemoryStore::Redis(redis)) => redis
                .key_get::<String>(&Self::shared_key(account_id))
                .await
                .ok()
                .flatten()
                .and_then(|mark| mark.parse::<u64>().ok())
                .unwrap_or_default(),
            _ => 0,
        };
        #[cfg(not(feature = "redis"))]
        let shared = 0;
        local.max(shared)
    }

    /// The replica the current scope reads from, if any (ST-7, ST-13).
    pub async fn read_target(&self, subspace: u8) -> Option<usize> {
        if !is_replica_subspace(subspace) {
            return None;
        }
        let scope = READ_SCOPE.try_with(|scope| scope.clone()).ok()?;
        if scope.wrote.load(Ordering::Relaxed) {
            return None;
        }
        *scope.choice.get_or_init(|| self.choose(&scope)).await
    }

    async fn choose(&self, scope: &ReadScope) -> Option<usize> {
        let count = self.replicas.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        'replicas: for offset in 0..count {
            let index = (start + offset) % count;
            let replica = &self.replicas[index];
            if !replica.usable() {
                continue;
            }
            let presented = scope.presented.lock().unwrap().clone();
            for (account_id, from_request) in &scope.accounts {
                let highest = presented
                    .iter()
                    .filter(|(id, _)| id == account_id)
                    .map(|(_, change_id)| *change_id)
                    .max()
                    .unwrap_or_default();
                let mark = self.mark(*account_id).await.max(*from_request).max(highest);
                if mark == 0 {
                    continue;
                }
                let seen: trc::Result<i64> = crate::sql_backend!(
                    &replica.store,
                    db => db.get_counter(change_id_key(*account_id)).await
                );
                match seen {
                    Ok(seen) if seen as u64 >= mark => {}
                    // Behind for this account: the primary answers (ST-7)
                    Ok(_) => return None,
                    Err(err) => {
                        self.failed(index, err);
                        continue 'replicas;
                    }
                }
            }
            return Some(index);
        }
        None
    }

    /// A replica read failed: it's down until a probe succeeds (ST-12).
    pub fn failed(&self, index: usize, err: trc::Error) {
        let replica = &self.replicas[index];
        if replica.set_state(ReplicaState::Down) != ReplicaState::Down {
            super::replica_health::report(
                self.kind,
                format!("Read replica {} is down: {err}", replica.label),
            );
        }
    }

    pub fn served(&self, index: usize) {
        self.replicas[index].reads.fetch_add(1, Ordering::Relaxed);
    }
}

impl Store {
    /// Records a change heard from another node (ST-7, step 1). Nothing to
    /// do without replicas.
    pub fn note_change(&self, account_id: u32, change_id: u64) {
        if let Store::Replicated(store) = self {
            store.note_change(account_id, change_id);
        }
    }

    /// Shares high-water marks through `memory`, when more than one node
    /// runs (ST-7, step 2).
    pub fn share_marks(&self, memory: &InMemoryStore) {
        if let Store::Replicated(store) = self {
            store.share_marks(memory.clone());
        }
    }
}
