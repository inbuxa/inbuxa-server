/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: the store layout runner (docs/spec/features/store-layout.md).
//! A store at an older layout version is brought up to this build's
//! `INBUXA_STORE_VERSION` at boot, one step at a time, by one node.

use common::{BuildServer, INBUXA_STORE_VERSION, INBUXA_STORE_VERSION_KEY, Inner, Server};
use registry::schema::enums::ClusterNodeStatus;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use store::{
    Deserialize, InMemoryStore, IterateParams, SUBSPACE_INBUXA, SerializeInfallible, Store,
    U64_LEN, ValueKey,
    write::{
        AnyClass, AnyKey, BatchBuilder, InMemoryClass, Operation, ValueClass, ValueOp,
        assert::AssertValue,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use trc::AddContext;

/// Where the lease of the node running the steps is kept, in `_` (SL-3).
pub const LAYOUT_LEASE_KEY: &[u8] = b"Vm";
const LEASE_SECONDS: u64 = 10 * 60;
const LEASE_RENEWAL: Duration = Duration::from_secs(60);
const WAIT_INTERVAL: Duration = Duration::from_secs(10);
const WATCH_INTERVAL: Duration = Duration::from_secs(60);
const UPDATING_DOCS: &str = "https://docs.inbuxa.org/install/updating/";

/// One step, from the version it starts at to the next.
struct Step {
    from: u32,
    /// Whether nodes on the build before it can keep running against the
    /// layout it leaves (SL-6).
    rolling_safe: bool,
    what: &'static str,
}

const STEPS: &[Step] = &[
    Step {
        from: 1,
        rolling_safe: true,
        what: "in-memory counters on SQL keep their own expiry",
    },
    Step {
        from: 2,
        // SL-18: old nodes would keep writing the moved data to `_`, and an
        // old binary can't open a RocksDB store with column families it
        // doesn't know
        rolling_safe: false,
        what: "the audit log, journal, holds and undelete notes move to subspaces of their own",
    },
];

async fn run_step(server: &Server, from: u32) -> trc::Result<u64> {
    match from {
        1 => counters_keep_expiry(server).await,
        2 => crate::fork_subspaces::fork_data_own_subspaces(server.store()).await,
        _ => unreachable!("no store layout step from version {from}"),
    }
}

/// The store's layout version, if it has a mark.
pub async fn store_version(store: &Store) -> trc::Result<Option<u32>> {
    store
        .get_value::<u32>(AnyKey {
            subspace: SUBSPACE_INBUXA,
            key: INBUXA_STORE_VERSION_KEY.to_vec(),
        })
        .await
        .caused_by(trc::location!())
}

async fn write_mark(store: &Store, version: u32) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_INBUXA,
            key: INBUXA_STORE_VERSION_KEY.to_vec(),
        }),
        version.serialize(),
    );
    store
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// Brings the store to this build's layout version (SL-1). A new install is
/// marked at it straight away; an existing store without a mark is at 1.
pub async fn upgrade_layout(
    server: &Server,
    store_version: Option<u32>,
    new_install: bool,
) -> trc::Result<()> {
    let version = store_version.unwrap_or(if new_install { INBUXA_STORE_VERSION } else { 1 });

    if version < INBUXA_STORE_VERSION {
        run_steps(server, server.registry().node_id()).await?;
    } else if store_version.is_none() {
        write_mark(server.store(), INBUXA_STORE_VERSION).await?;
    }

    // SL-7
    trc::event!(
        Server(trc::ServerEvent::Startup),
        Details = format!("Store layout version {INBUXA_STORE_VERSION}"),
    );

    Ok(())
}

/// Runs every step from the store's version up to this build's, as node
/// `node_id`, or waits for the node that runs them (SL-3).
pub async fn run_steps(server: &Server, node_id: u16) -> trc::Result<()> {
    let store = server.store();
    let mut waiting = false;

    loop {
        let version = store_version(store).await?.unwrap_or(1);
        if version >= INBUXA_STORE_VERSION {
            if waiting {
                trc::event!(
                    Server(trc::ServerEvent::Startup),
                    Details = "Another node finished upgrading the store layout",
                    Version = version,
                );
            }
            return Ok(());
        }

        if let Some(lease) = Lease::take(store, node_id).await? {
            let result = run_held(server, &lease, version).await;
            lease.release(store).await;
            return result;
        }

        if !waiting {
            trc::event!(
                Server(trc::ServerEvent::Startup),
                Details = "Waiting for another node to upgrade the store layout",
                Version = version,
            );
            waiting = true;
        }
        tokio::time::sleep(WAIT_INTERVAL).await;
    }
}

async fn run_held(server: &Server, lease: &Lease, version: u32) -> trc::Result<()> {
    let store = server.store();
    // Another node may have run a step between the read and the lease
    let mut version = store_version(store).await?.unwrap_or(version);

    while version < INBUXA_STORE_VERSION {
        let Some(step) = STEPS.iter().find(|step| step.from == version) else {
            crate::abort(&format!(
                "The data store is at layout version {version}, and this release has no step from it"
            ));
        };
        if !step.rolling_safe {
            wait_for_other_nodes(server).await?;
        }

        // SL-8
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!(
                "Upgrading the store layout from version {version} to {}: {}. This can't be rolled back without a backup taken before the upgrade, see {UPDATING_DOCS}",
                version + 1,
                step.what
            ),
            Version = version,
        );
        let started = Instant::now();
        let changed = run_step(server, version).await?;

        if lease.lost.load(Ordering::Relaxed) {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Lost the store layout lease while a step ran")
                .ctx(trc::Key::Version, version));
        }

        version += 1;
        write_mark(store, version).await?;

        // SL-7
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!("Upgraded the store layout to version {version}"),
            Version = version,
            Total = changed,
            Elapsed = started.elapsed(),
        );
    }

    Ok(())
}

/// A step that isn't rolling-safe waits until no other node shows as active
/// (SL-6). A single node never waits: only other node ids on other hosts
/// count, so this node's own earlier lease doesn't.
async fn wait_for_other_nodes(server: &Server) -> trc::Result<()> {
    let me = server.registry().node_id() as u64;
    let hostname = server.registry().local_hostname().to_string();
    let mut logged: Option<Instant> = None;

    loop {
        let others = server
            .registry()
            .cluster_node_list()
            .await
            .caused_by(trc::location!())?
            .into_iter()
            .filter(|node| {
                node.node_id != me
                    && node.hostname != hostname
                    && node.status == ClusterNodeStatus::Active
            })
            .map(|node| node.hostname)
            .collect::<Vec<_>>();
        if others.is_empty() {
            return Ok(());
        }
        if logged.is_none_or(|at| at.elapsed() >= Duration::from_secs(60)) {
            trc::event!(
                Server(trc::ServerEvent::StartupError),
                Details = "The next store layout step needs every other node stopped first",
                Hostname = others.join(", "),
            );
            logged = Some(Instant::now());
        }
        tokio::time::sleep(WAIT_INTERVAL).await;
    }
}

/// The lease on `Vm`: node id, then the time it runs out. Renewed every
/// minute while it's held.
struct Lease {
    bytes: Arc<Mutex<Vec<u8>>>,
    lost: Arc<AtomicBool>,
    renewal: tokio::task::JoinHandle<()>,
}

struct Raw(Vec<u8>);

impl Deserialize for Raw {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Raw(bytes.to_vec()))
    }
}

fn lease_class() -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: LAYOUT_LEASE_KEY.to_vec(),
    })
}

fn lease_bytes(node_id: u16) -> Vec<u8> {
    KeySerializer::new(2 + U64_LEN)
        .write(node_id)
        .write(now() + LEASE_SECONDS)
        .finalize()
}

fn is_assert_failure(err: &trc::Error) -> bool {
    matches!(
        err.as_ref(),
        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
    )
}

/// Replaces `current` (None: no lease) with `new`; false if something else
/// wrote the lease in between.
async fn swap_lease(store: &Store, current: Option<&[u8]>, new: Vec<u8>) -> trc::Result<bool> {
    let mut batch = BatchBuilder::new();
    batch.assert_value(
        lease_class(),
        current.map_or(AssertValue::None, |bytes| {
            AssertValue::Hash(store::xxhash_rust::xxh3::xxh3_64(bytes))
        }),
    );
    batch.set(lease_class(), new);
    match store.write(batch.build_all()).await {
        Ok(_) => Ok(true),
        Err(err) if is_assert_failure(&err) => Ok(false),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

impl Lease {
    /// Takes the lease if nobody holds it, it ran out, or it's this node's
    /// own (left by a run that stopped).
    async fn take(store: &Store, node_id: u16) -> trc::Result<Option<Lease>> {
        let current = store
            .get_value::<Raw>(ValueKey::from(lease_class()))
            .await
            .caused_by(trc::location!())?
            .map(|Raw(bytes)| bytes);
        if let Some(bytes) = &current {
            let holder = bytes.as_slice().deserialize_be_u16(0).unwrap_or(u16::MAX);
            let expires = bytes.as_slice().deserialize_be_u64(2).unwrap_or(0);
            if holder != node_id && expires > now() {
                return Ok(None);
            }
        }

        let new = lease_bytes(node_id);
        if !swap_lease(store, current.as_deref(), new.clone()).await? {
            return Ok(None);
        }

        let bytes = Arc::new(Mutex::new(new));
        let lost = Arc::new(AtomicBool::new(false));
        let renewal = {
            let (store, bytes, lost) = (store.clone(), bytes.clone(), lost.clone());
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(LEASE_RENEWAL).await;
                    let current = bytes.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    let new = lease_bytes(node_id);
                    match swap_lease(&store, Some(&current), new.clone()).await {
                        Ok(true) => *bytes.lock().unwrap_or_else(|e| e.into_inner()) = new,
                        Ok(false) => {
                            lost.store(true, Ordering::Relaxed);
                            trc::event!(
                                Server(trc::ServerEvent::StartupError),
                                Details = "Another node took over the store layout lease",
                            );
                            return;
                        }
                        Err(err) => {
                            trc::error!(err.details("Failed to renew the store layout lease"));
                        }
                    }
                }
            })
        };

        Ok(Some(Lease {
            bytes,
            lost,
            renewal,
        }))
    }

    async fn release(&self, store: &Store) {
        self.renewal.abort();
        let current = self.bytes.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut batch = BatchBuilder::new();
        batch.assert_value(
            lease_class(),
            AssertValue::Hash(store::xxhash_rust::xxh3::xxh3_64(&current)),
        );
        batch.clear(lease_class());
        if let Err(err) = store.write(batch.build_all()).await
            && !is_assert_failure(&err)
        {
            // It runs out on its own
            trc::error!(err.details("Failed to release the store layout lease"));
        }
    }
}

/// SL-5: a running node that finds the store marked newer than its own
/// build stops, so it can't keep writing the old layout.
pub fn spawn_mark_watch(inner: Arc<Inner>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(WATCH_INTERVAL).await;
            let server = inner.build_server();
            match store_version(server.store()).await {
                Ok(Some(version)) if version > INBUXA_STORE_VERSION => {
                    let message = format!(
                        "The data store was upgraded by a newer release (store version {version}, this release reads up to {INBUXA_STORE_VERSION}). Stopping, see {UPDATING_DOCS}"
                    );
                    trc::event!(
                        Server(trc::ServerEvent::Shutdown),
                        Details = message.clone(),
                        Version = version,
                    );
                    eprintln!("{message}");
                    // Let the log reach its collector
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    std::process::exit(1);
                }
                Ok(_) => {}
                Err(err) => {
                    trc::error!(err.details("Failed to read the store layout version"));
                }
            }
        }
    });
}

/// Step 1 → 2 (SL-11): on SQL, each counter's expiry moves from its marker
/// in `m` into its own row, and the marker goes. Other keys in `m` stay.
/// RocksDB and FoundationDB keep the marker form, so nothing changes there.
async fn counters_keep_expiry(server: &Server) -> trc::Result<u64> {
    let mut stores = Vec::new();
    let mut pending = vec![server.in_memory_store().clone()];
    while let Some(store) = pending.pop() {
        match store {
            InMemoryStore::Store(store) if store.counters_keep_expiry() => stores.push(store),
            InMemoryStore::Sharded(sharded) => pending.extend(sharded.members.iter().cloned()),
            _ => {}
        }
    }

    let mut changed = 0;
    for store in stores {
        changed += move_counter_expiry(&store).await?;
    }
    Ok(changed)
}

async fn move_counter_expiry(store: &Store) -> trc::Result<u64> {
    let from_key = ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![0u8])));
    let to_key = ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![u8::MAX; 10])));

    // A marker is a zero, then the counter's expiry (see the purge)
    let mut markers = Vec::new();
    store
        .iterate(IterateParams::new(from_key, to_key), |key, value| {
            if value.deserialize_be_u64(0).caused_by(trc::location!())? == 0 {
                markers.push((
                    key.to_vec(),
                    value
                        .deserialize_be_u64(U64_LEN)
                        .caused_by(trc::location!())?,
                ));
            }
            Ok(true)
        })
        .await
        .caused_by(trc::location!())?;

    let current_time = now();
    let changed = markers.len() as u64;
    let mut batch = BatchBuilder::new();
    for (key, expires_at) in markers {
        let counter = ValueClass::InMemory(InMemoryClass::Counter(key.clone()));
        batch.any_op(Operation::Value {
            class: counter,
            op: if expires_at > current_time {
                ValueOp::AddAndGetExpiring(0, expires_at)
            } else {
                ValueOp::Clear
            },
        });
        batch.any_op(Operation::Value {
            class: ValueClass::InMemory(InMemoryClass::Key(key)),
            op: ValueOp::Clear,
        });
        if batch.is_large_batch() {
            store
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            batch = BatchBuilder::new();
        }
    }
    if !batch.is_empty() {
        store
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(changed)
}
