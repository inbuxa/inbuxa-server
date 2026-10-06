/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Each node watches its replicas (ST-10 to ST-15): startup checks, then a
//! lag sample every second, and a probe every ten seconds while one is
//! down. Changes are logged with the backend's existing error event
//! (ST-30).

use super::replica::{
    LAG_LIMIT_MS, LAG_READMIT_MS, Replica, ReplicaKind, ReplicaState, ReplicatedStore,
};
use crate::{
    SUBSPACE_INBUXA, SerializeInfallible, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use std::{
    collections::VecDeque,
    sync::Weak,
    time::{Duration, Instant},
};

const SAMPLE_EVERY: Duration = Duration::from_secs(1);
const PROBE_EVERY: Duration = Duration::from_secs(10);
/// Startup marker checks, one a probe, before a replica is left out.
const MARKER_TRIES: u8 = 6;
/// Primary positions kept, one a second.
const SAMPLES_KEPT: usize = 120;

pub fn report(kind: ReplicaKind, message: String) {
    match kind {
        ReplicaKind::PostgreSql => {
            trc::event!(Store(trc::StoreEvent::PostgresqlError), Details = message)
        }
        ReplicaKind::MySql => trc::event!(Store(trc::StoreEvent::MysqlError), Details = message),
    }
}

/// Where the primary is replicated up to, in whatever unit the backend
/// counts (a PostgreSQL LSN, or a MySQL GTID set).
#[allow(dead_code)] // built with a PostgreSQL or MySQL backend
#[derive(Debug, Clone, PartialEq, Eq)]
enum Position {
    Lsn(u64),
    Gtid(String),
}

pub fn spawn(store: Weak<ReplicatedStore>) {
    tokio::spawn(async move {
        let mut samples: VecDeque<(Instant, Position)> = VecDeque::new();
        let mut last_probe: Vec<Option<Instant>> = Vec::new();
        loop {
            {
                let Some(store) = store.upgrade() else {
                    return;
                };
                if last_probe.len() != store.replicas.len() {
                    last_probe = vec![None; store.replicas.len()];
                }
                tick(&store, &mut samples, &mut last_probe).await;
            }
            tokio::time::sleep(SAMPLE_EVERY).await;
        }
    });
}

async fn tick(
    store: &ReplicatedStore,
    samples: &mut VecDeque<(Instant, Position)>,
    last_probe: &mut [Option<Instant>],
) {
    // The primary's position now (ST-10)
    match primary_position(store).await {
        Ok(Some(position)) => {
            if samples.back().is_none_or(|(_, last)| *last != position) {
                samples.push_back((Instant::now(), position));
            } else if let Some(last) = samples.back_mut() {
                // Unchanged: an idle primary; nothing new to wait for
                last.0 = last.0.min(Instant::now());
            }
            while samples.len() > SAMPLES_KEPT {
                samples.pop_front();
            }
        }
        Ok(None) => {}
        Err(err) => report(
            store.kind,
            format!("Failed to read the primary's replication position: {err}"),
        ),
    }

    for (index, replica) in store.replicas.iter().enumerate() {
        let state = replica.state();
        match state {
            ReplicaState::Excluded | ReplicaState::Unmeasurable => continue,
            ReplicaState::Unvalidated | ReplicaState::Down => {
                if last_probe[index].is_some_and(|at| at.elapsed() < PROBE_EVERY) {
                    continue;
                }
                last_probe[index] = Some(Instant::now());
                if state == ReplicaState::Unvalidated {
                    validate(store, index, replica).await;
                    continue;
                }
            }
            ReplicaState::Up | ReplicaState::Lagging => {}
        }

        match replica_lag(store, replica, samples).await {
            Ok(Some(lag)) => {
                replica
                    .lag_ms
                    .store(lag, std::sync::atomic::Ordering::Relaxed);
                let next = match state {
                    ReplicaState::Up if lag > LAG_LIMIT_MS => ReplicaState::Lagging,
                    ReplicaState::Lagging if lag < LAG_READMIT_MS => ReplicaState::Up,
                    ReplicaState::Down if lag < LAG_READMIT_MS => ReplicaState::Up,
                    ReplicaState::Down => ReplicaState::Lagging,
                    other => other,
                };
                if next != state {
                    replica.set_state(next);
                    report(
                        store.kind,
                        format!(
                            "Read replica {} is {} (lag {lag} ms)",
                            replica.label,
                            match next {
                                ReplicaState::Up => "up",
                                _ => "over the lag limit",
                            }
                        ),
                    );
                }
            }
            Ok(None) => {
                if replica.set_state(ReplicaState::Unmeasurable) != ReplicaState::Unmeasurable {
                    report(
                        store.kind,
                        format!(
                            "Read replica {} gets no reads: its lag can't be measured \
                             (the REPLICATION CLIENT privilege may be missing)",
                            replica.label
                        ),
                    );
                }
            }
            Err(err) if state != ReplicaState::Down => store.failed(index, err),
            Err(_) => {}
        }
    }
}

/// The startup checks (ST-15). A replica that can't be reached yet stays
/// unchecked, and is tried again at the next probe.
async fn validate(store: &ReplicatedStore, index: usize, replica: &Replica) {
    let exclude = |why: String| {
        replica.set_state(ReplicaState::Excluded);
        report(
            store.kind,
            format!("Read replica {} is left out: {why}", replica.label),
        );
    };
    if replica.location == store.primary_location {
        return exclude("it's the primary itself".to_string());
    }
    match read_only(store.kind, &replica.store).await {
        Ok(Ok(())) => {}
        Ok(Err(why)) => return exclude(why),
        Err(err) => {
            report(
                store.kind,
                format!("Read replica {} can't be checked yet: {err}", replica.label),
            );
            return;
        }
    }

    // It must be a copy of this primary: a marker written there shows up
    let marker = rand::random::<u64>() | 1;
    let class = ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: [b'S', b'r', index as u8].to_vec(),
    });
    let mut batch = BatchBuilder::new();
    batch.set(class.clone(), marker.serialize());
    if let Err(err) = store.primary.write(batch.build_all()).await {
        report(
            store.kind,
            format!("Failed to write the replica check marker: {err}"),
        );
        return;
    }
    let deadline = Instant::now() + Duration::from_millis(LAG_LIMIT_MS);
    loop {
        match replica
            .store
            .get_value::<u64>(ValueKey::from(class.clone()))
            .await
        {
            Ok(Some(seen)) if seen == marker => {
                replica.set_state(ReplicaState::Up);
                report(store.kind, format!("Read replica {} is up", replica.label));
                return;
            }
            Ok(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // A replica still catching up (after a burst of writes at
            // startup, say) gets a few more tries before it's left out
            Ok(_) => {
                let misses = replica
                    .marker_misses
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                return if misses >= MARKER_TRIES {
                    exclude("it isn't a copy of this primary".to_string())
                } else {
                    report(
                        store.kind,
                        format!(
                            "Read replica {} hasn't shown the check marker yet; trying again",
                            replica.label
                        ),
                    )
                };
            }
            Err(err) => {
                report(
                    store.kind,
                    format!("Read replica {} can't be checked yet: {err}", replica.label),
                );
                return;
            }
        }
    }
}

#[allow(unused_variables)]
async fn read_only(kind: ReplicaKind, replica: &Store) -> trc::Result<Result<(), String>> {
    match (kind, replica) {
        #[cfg(feature = "postgres")]
        (ReplicaKind::PostgreSql, Store::PostgreSQL(pg)) => {
            let conn = pg
                .conn_pool
                .get()
                .await
                .map_err(crate::backend::postgres::into_pool_error)?;
            let row = conn
                .query_one("SELECT pg_is_in_recovery()", &[])
                .await
                .map_err(crate::backend::postgres::into_error)?;
            Ok(if row.get::<_, bool>(0) {
                Ok(())
            } else {
                Err("it isn't read-only (pg_is_in_recovery() is false)".to_string())
            })
        }
        #[cfg(feature = "mysql")]
        (ReplicaKind::MySql, Store::MySQL(my)) => {
            use mysql_async::prelude::Queryable;
            let mut conn = my
                .conn_pool
                .get_conn()
                .await
                .map_err(crate::backend::mysql::into_error)?;
            let (read_only, super_read_only): (i64, i64) = conn
                .query_first("SELECT @@global.read_only, @@global.super_read_only")
                .await
                .map_err(crate::backend::mysql::into_error)?
                .unwrap_or((0, 0));
            if read_only == 0 && super_read_only == 0 {
                return Ok(Err(
                    "it isn't read-only (neither read_only nor super_read_only is on)".to_string(),
                ));
            }
            let parallel: Option<(i64, i64)> = conn
                .query_first(
                    "SELECT @@global.replica_parallel_workers, @@global.replica_preserve_commit_order",
                )
                .await
                .ok()
                .flatten();
            if let Some((workers, preserve)) = parallel
                && workers > 0
                && preserve == 0
            {
                return Ok(Err(
                    "it applies in parallel without preserving commit order".to_string(),
                ));
            }
            Ok(Ok(()))
        }
        _ => Ok(Err("the backend isn't compiled in".to_string())),
    }
}

#[cfg(feature = "postgres")]
fn parse_lsn(text: &str) -> Option<u64> {
    let (high, low) = text.split_once('/')?;
    Some((u64::from_str_radix(high, 16).ok()? << 32) | u64::from_str_radix(low, 16).ok()?)
}

#[allow(unused_variables)]
async fn primary_position(store: &ReplicatedStore) -> trc::Result<Option<Position>> {
    match &store.primary {
        #[cfg(feature = "postgres")]
        Store::PostgreSQL(pg) => {
            let conn = pg
                .conn_pool
                .get()
                .await
                .map_err(crate::backend::postgres::into_pool_error)?;
            let row = conn
                .query_one("SELECT pg_current_wal_lsn()::text", &[])
                .await
                .map_err(crate::backend::postgres::into_error)?;
            Ok(parse_lsn(row.get::<_, &str>(0)).map(Position::Lsn))
        }
        #[cfg(feature = "mysql")]
        Store::MySQL(my) => {
            use mysql_async::prelude::Queryable;
            let mut conn = my
                .conn_pool
                .get_conn()
                .await
                .map_err(crate::backend::mysql::into_error)?;
            let mode: Option<String> = conn
                .query_first("SELECT @@global.gtid_mode")
                .await
                .map_err(crate::backend::mysql::into_error)?;
            if mode.as_deref() != Some("ON") {
                return Ok(None);
            }
            let executed: Option<String> = conn
                .query_first("SELECT @@global.gtid_executed")
                .await
                .map_err(crate::backend::mysql::into_error)?;
            Ok(executed.map(Position::Gtid))
        }
        _ => Ok(None),
    }
}

/// The replica's lag in milliseconds (ST-10): the age of the oldest
/// primary position it hasn't applied yet. `None` when it can't be
/// measured.
#[allow(unused_variables)]
async fn replica_lag(
    store: &ReplicatedStore,
    replica: &Replica,
    samples: &VecDeque<(Instant, Position)>,
) -> trc::Result<Option<u64>> {
    let age = |at: Instant| at.elapsed().as_millis() as u64;
    match &replica.store {
        #[cfg(feature = "postgres")]
        Store::PostgreSQL(pg) => {
            let conn = pg
                .conn_pool
                .get()
                .await
                .map_err(crate::backend::postgres::into_pool_error)?;
            let row = conn
                .query_one("SELECT pg_last_wal_replay_lsn()::text", &[])
                .await
                .map_err(crate::backend::postgres::into_error)?;
            let Some(replayed) = row.get::<_, Option<&str>>(0).and_then(parse_lsn) else {
                return Err(trc::StoreEvent::PostgresqlError
                    .into_err()
                    .details("The replica isn't replaying"));
            };
            Ok(Some(
                samples
                    .iter()
                    .find(|(_, position)| matches!(position, Position::Lsn(lsn) if *lsn > replayed))
                    .map(|(at, _)| age(*at))
                    .unwrap_or(0),
            ))
        }
        #[cfg(feature = "mysql")]
        Store::MySQL(my) => {
            use mysql_async::prelude::Queryable;
            let mut conn = my
                .conn_pool
                .get_conn()
                .await
                .map_err(crate::backend::mysql::into_error)?;
            if samples.iter().any(|(_, p)| matches!(p, Position::Gtid(_))) {
                // With GTIDs: the oldest primary set the replica lacks
                for (at, position) in samples {
                    let Position::Gtid(set) = position else {
                        continue;
                    };
                    let applied: Option<i64> = conn
                        .exec_first(
                            "SELECT GTID_SUBSET(?, @@global.gtid_executed)",
                            (set.as_str(),),
                        )
                        .await
                        .map_err(crate::backend::mysql::into_error)?;
                    if applied != Some(1) {
                        return Ok(Some(age(*at)));
                    }
                }
                Ok(Some(0))
            } else {
                // Without: Seconds_Behind_Source, which needs REPLICATION CLIENT
                let row: Option<mysql_async::Row> =
                    match conn.query_first("SHOW REPLICA STATUS").await {
                        Ok(row) => row,
                        Err(err) => {
                            report(
                                store.kind,
                                format!(
                                    "Read replica {} won't report its status: {err}",
                                    replica.label
                                ),
                            );
                            return Ok(None);
                        }
                    };
                let Some(row) = row else {
                    return Ok(None);
                };
                let behind = ["Seconds_Behind_Source", "Seconds_Behind_Master"]
                    .into_iter()
                    .find_map(|column| row.get_opt::<mysql_async::Value, _>(column))
                    .and_then(|value| value.ok());
                match behind {
                    Some(mysql_async::Value::NULL) => Err(trc::StoreEvent::MysqlError
                        .into_err()
                        .details("Replication is stopped")),
                    Some(value) => match mysql_async::from_value_opt::<u64>(value.clone()) {
                        Ok(seconds) => Ok(Some(seconds * 1000)),
                        Err(_) => {
                            report(
                                store.kind,
                                format!(
                                    "Read replica {}: Seconds_Behind_Source isn't a number ({value:?})",
                                    replica.label
                                ),
                            );
                            Ok(None)
                        }
                    },
                    None => Ok(None),
                }
            }
        }
        _ => Ok(None),
    }
}
