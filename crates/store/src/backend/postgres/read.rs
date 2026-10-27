/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PostgresStore, into_error, is_timeout_error};
use crate::{
    Deserialize, Fetch, IterateParams, Key, Subspace, ValueKey,
    backend::{
        ValueColumn,
        postgres::{
            ITERATE_CHUNK_SIZE, MIN_ITERATE_CHUNK_SIZE, into_pool_error, pooled::PooledConn,
        },
        range_batch::{Bounds, RangeAttempt, RangeCursor, Timeout},
    },
    dispatch::store::point_keys,
    write::{AnyKey, ChunkPlan, ValueClass, backoff},
};
use futures::{TryStreamExt, pin_mut};
use std::fmt::Write;
use tokio_postgres::{Row, RowStream, types::ToSql};

pub(super) const MAX_POINT_KEYS: usize = 4096;
const DEGRADED_POINT_KEYS: usize = 512;
const MIN_POINT_KEYS: usize = 16;
const MAX_RANGES_PER_STMT: usize = 64;
const BEGIN_READ: &str = "START TRANSACTION ISOLATION LEVEL REPEATABLE READ";
const COMMIT: &str = "COMMIT";
const ROLLBACK: &str = "ROLLBACK";

impl PostgresStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let s = conn
            .prepare_cached(&self.sql.get(key.subspace()).get_value)
            .await
            .map_err(into_error)?;
        let key = key.serialize(0);
        #[cfg(stalwart_tests)]
        super::probe::record(super::probe::Statement::Read);
        conn.query_opt(&s, &[&key])
            .await
            .map_err(into_error)
            .and_then(|r| {
                if let Some(r) = r {
                    Ok(Some(U::deserialize_with_key(&key, r.get(0))?))
                } else {
                    Ok(None)
                }
            })
    }

    pub(crate) async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let s = conn
            .prepare_cached(&self.sql.get(key.subspace()).key_exists)
            .await
            .map_err(into_error)?;
        let key = key.serialize(0);
        #[cfg(stalwart_tests)]
        super::probe::record(super::probe::Statement::Read);
        conn.query_opt(&s, &[&key])
            .await
            .map_err(into_error)
            .map(|r| r.is_some())
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        debug_assert_ne!(params.fetch, Fetch::Limit(0));
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let subspace = params.begin.subspace();
        let stmts = self.sql.get(subspace);
        let column = ValueColumn::new(params.values, subspace);
        let mut from = params.begin.serialize(0);
        let mut to = params.end.serialize(0);
        let mut last_key = Vec::new();
        let mut resuming = false;
        let mut plan = ChunkPlan::new(params.fetch);
        let mut attempt = 0;

        loop {
            let limit = plan.limit(resuming);
            let (statement, bound) = match limit {
                Some(limit) if limit > 1 => (
                    stmts.iterate_limit(params.ascending, params.values),
                    Some(i64::from(limit)),
                ),
                limit => (
                    stmts.iterate(limit.is_some(), params.ascending, params.values),
                    None,
                ),
            };
            let mut skip_resumed = resuming;
            let mut progressed = false;
            let mut fetched = 0u64;
            let mut timed_out = None;

            let result = match conn.prepare_cached(statement).await {
                Ok(s) => {
                    #[cfg(stalwart_tests)]
                    super::probe::record(super::probe::Statement::Iterate);
                    match &bound {
                        Some(bound) => {
                            conn.query_raw(&s, [&from as &(dyn ToSql + Sync), &to, bound])
                                .await
                        }
                        None => conn.query_raw(&s, &[&from, &to]).await,
                    }
                }
                Err(err) => Err(err),
            };
            match result {
                Ok(rows) => {
                    pin_mut!(rows);

                    loop {
                        match rows.try_next().await {
                            Ok(Some(row)) => {
                                let key = row.try_get::<_, &[u8]>(0).map_err(into_error)?;
                                let counter;
                                let value = match column {
                                    ValueColumn::Skip => b"".as_slice(),
                                    ValueColumn::Bytes => {
                                        row.try_get::<_, &[u8]>(1).map_err(into_error)?
                                    }
                                    ValueColumn::Counter => {
                                        counter = read_counter(&row)?;
                                        counter.as_slice()
                                    }
                                };

                                fetched += 1;
                                #[cfg(stalwart_tests)]
                                super::probe::row_sent();
                                if skip_resumed {
                                    skip_resumed = false;
                                    if key == last_key.as_slice() {
                                        continue;
                                    }
                                }

                                if !cb(key, value)? || !plan.consume_row() {
                                    #[cfg(stalwart_tests)]
                                    super::probe::drain(rows.as_mut()).await;
                                    return Ok(());
                                }

                                last_key.clear();
                                last_key.extend_from_slice(key);
                                progressed = true;
                            }
                            Ok(None) => break,
                            Err(err) if is_timeout_error(&err) => {
                                timed_out = Some(err);
                                break;
                            }
                            Err(err) => return Err(into_error(err)),
                        }
                    }
                }
                Err(err) if is_timeout_error(&err) => timed_out = Some(err),
                Err(err) => return Err(into_error(err)),
            }

            if progressed {
                attempt = 0;
                match timed_out {
                    None if limit.is_some_and(|limit| fetched >= u64::from(limit)) => plan.grow(),
                    None => return Ok(()),
                    Some(_) => (),
                }
                if params.ascending {
                    from.clone_from(&last_key);
                } else {
                    to.clone_from(&last_key);
                }
                resuming = true;
            } else {
                match timed_out {
                    Some(err)
                        if !plan
                            .degrade(ITERATE_CHUNK_SIZE, MIN_ITERATE_CHUNK_SIZE, &mut attempt)
                            .await =>
                    {
                        return Err(into_error(err));
                    }
                    Some(_) => (),
                    None => return Ok(()),
                }
            }
        }
    }

    pub(crate) async fn iterate_many<T: Key>(
        &self,
        ranges: Vec<IterateParams<T>>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let Some(first) = ranges.first() else {
            return Ok(());
        };
        let subspace = first.begin.subspace();
        let column = ValueColumn::new(first.values, subspace);
        let mut conn = PooledConn::new(self.conn_pool.get().await.map_err(into_pool_error)?);

        match point_keys(&ranges) {
            Some(keys) => {
                let query = self.sql.get(subspace).iterate_points(column.is_selected());
                iterate_points(&mut conn, query, &keys, column, &mut cb).await
            }
            None => {
                let bounds = ranges
                    .iter()
                    .map(|params| (params.begin.serialize(0), params.end.serialize(0)))
                    .collect::<Vec<_>>();
                self.iterate_ranges(conn, subspace, bounds, column, &mut cb)
                    .await
            }
        }
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into();
        let subspace = key.subspace();
        let key = key.serialize(0);

        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let s = conn
            .prepare_cached(&self.sql.get(subspace).get_value)
            .await
            .map_err(into_error)?;
        #[cfg(stalwart_tests)]
        super::probe::record(super::probe::Statement::Read);
        match conn.query_opt(&s, &[&key]).await {
            Ok(Some(row)) => row.try_get(0).map_err(into_error),
            Ok(None) => Ok(0),
            Err(e) => Err(into_error(e)),
        }
    }
}

type RangeCallback<'y> =
    &'y mut (dyn for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Send + Sync);

enum Emitted {
    Done,
    Stopped,
    TimedOut {
        error: tokio_postgres::Error,
        delivered: bool,
    },
}

async fn iterate_points(
    conn: &mut PooledConn,
    query: &str,
    keys: &[Vec<u8>],
    column: ValueColumn,
    cb: RangeCallback<'_>,
) -> trc::Result<()> {
    let mut pending = keys;
    let mut last_key = Vec::new();
    let mut plan = ChunkPlan::new(Fetch::All);
    let mut attempt = 0;

    loop {
        let size = plan
            .limit(false)
            .map_or(MAX_POINT_KEYS, |size| size as usize);
        let before = pending.len();
        let error = match points_attempt(conn, query, &mut pending, size, column, &mut last_key, cb)
            .await?
        {
            None => return Ok(()),
            Some(Timeout::Begin(_)) if backoff(&mut attempt).await => continue,
            Some(Timeout::Begin(error)) => return Err(into_error(error)),
            Some(Timeout::Statement(error)) => error,
        };
        pending = keys_after(pending, &last_key);
        if pending.is_empty() {
            return Ok(());
        } else if pending.len() < before {
            attempt = 0;
        } else if !plan
            .degrade(
                DEGRADED_POINT_KEYS
                    .min(pending.len() / 2)
                    .max(MIN_POINT_KEYS),
                MIN_POINT_KEYS,
                &mut attempt,
            )
            .await
        {
            return Err(into_error(error));
        }
    }
}

async fn points_attempt(
    conn: &mut PooledConn,
    query: &str,
    pending: &mut &[Vec<u8>],
    size: usize,
    column: ValueColumn,
    last_key: &mut Vec<u8>,
    cb: RangeCallback<'_>,
) -> trc::Result<Option<Timeout<tokio_postgres::Error>>> {
    if pending.len() <= size {
        let rows = match conn.prepare_cached(query).await {
            Ok(statement) => {
                #[cfg(stalwart_tests)]
                super::probe::record(super::probe::Statement::Iterate);
                conn.query_raw(&statement, [pending as &(dyn ToSql + Sync)])
                    .await
            }
            Err(error) => Err(error),
        };
        return match emit(rows, column, false, last_key, cb).await? {
            Emitted::Done | Emitted::Stopped => Ok(None),
            Emitted::TimedOut { error, .. } => Ok(Some(Timeout::Statement(error))),
        };
    }

    if let Err(error) = begin_read(conn).await? {
        return Ok(Some(Timeout::Begin(error)));
    }
    let statement = match conn.prepare_cached(query).await {
        Ok(statement) => statement,
        Err(error) if is_timeout_error(&error) => {
            let ended = conn.batch_execute(ROLLBACK).await;
            conn.end_transaction(ended)?;
            return Ok(Some(Timeout::Statement(error)));
        }
        Err(error) => return Err(into_error(error)),
    };
    while !pending.is_empty() {
        let (chunk, rest) = pending.split_at(pending.len().min(size));
        #[cfg(stalwart_tests)]
        super::probe::record(super::probe::Statement::Iterate);
        let rows = conn
            .query_raw(&statement, [&chunk as &(dyn ToSql + Sync)])
            .await;
        match emit(rows, column, false, last_key, cb).await? {
            Emitted::Done => *pending = rest,
            Emitted::Stopped => return Ok(None),
            Emitted::TimedOut { error, .. } => {
                let ended = conn.batch_execute(ROLLBACK).await;
                conn.end_transaction(ended)?;
                return Ok(Some(Timeout::Statement(error)));
            }
        }
    }
    let ended = commit_read(conn).await;
    conn.end_transaction(ended)?;
    Ok(None)
}

impl PostgresStore {
    async fn iterate_ranges(
        &self,
        mut conn: PooledConn,
        subspace: Subspace,
        mut bounds: Vec<Bounds>,
        column: ValueColumn,
        cb: RangeCallback<'_>,
    ) -> trc::Result<()> {
        let table = subspace.name();
        let mut cursor = RangeCursor::default();
        let mut per_statement = MAX_RANGES_PER_STMT;
        let mut attempt = 0;

        loop {
            match ranges_attempt(
                &mut conn,
                table,
                &mut bounds,
                &mut cursor,
                per_statement,
                column,
                cb,
            )
            .await?
            {
                RangeAttempt::Finished => return Ok(()),
                RangeAttempt::BeginTimedOut(error) => {
                    if !backoff(&mut attempt).await {
                        return Err(error);
                    }
                }
                RangeAttempt::TimedOut { delivered: true } => attempt = 0,
                RangeAttempt::TimedOut { delivered: false } => {
                    match cursor.halve(per_statement, bounds.len()) {
                        Some(size) => per_statement = size,
                        None => {
                            drop(conn);
                            return self
                                .iterate_each(subspace, &bounds, &cursor, column, cb)
                                .await;
                        }
                    }
                }
            }
        }
    }

    async fn iterate_each(
        &self,
        subspace: Subspace,
        bounds: &[Bounds],
        cursor: &RangeCursor,
        column: ValueColumn,
        cb: RangeCallback<'_>,
    ) -> trc::Result<()> {
        let mut stopped = false;
        for (begin, end) in cursor.remaining(bounds) {
            let params = IterateParams::new(
                AnyKey {
                    subspace,
                    key: begin,
                },
                AnyKey {
                    subspace,
                    key: end.to_vec(),
                },
            )
            .set_values(column.is_selected());
            self.iterate(params, |key, value| {
                let more = cb(key, value)?;
                stopped = !more;
                Ok(more)
            })
            .await?;
            if stopped {
                break;
            }
        }
        Ok(())
    }
}

fn range_query(table: &str, values: bool, count: usize) -> String {
    debug_assert!(count > 0);
    let mut query = String::with_capacity(count * 28 + 40);
    let columns = if values { "k, v" } else { "k" };
    let _ = write!(query, "SELECT {columns} FROM {table} WHERE ");
    for i in 0..count {
        if i > 0 {
            query.push_str(" OR ");
        }
        let _ = write!(query, "(k >= ${} AND k <= ${})", i * 2 + 1, i * 2 + 2);
    }
    query.push_str(" ORDER BY k ASC");
    query
}

async fn ranges_attempt(
    conn: &mut PooledConn,
    table: &str,
    bounds: &mut [Bounds],
    cursor: &mut RangeCursor,
    size: usize,
    column: ValueColumn,
    cb: RangeCallback<'_>,
) -> trc::Result<RangeAttempt> {
    let total = bounds.len();
    if cursor.start >= total {
        return Ok(RangeAttempt::Finished);
    } else if total - cursor.start <= size {
        let chunk = bounds.get(cursor.start..).unwrap_or_default();
        let rows = async {
            let s = conn
                .prepare_cached(&range_query(table, column.is_selected(), chunk.len()))
                .await?;
            #[cfg(stalwart_tests)]
            super::probe::record(super::probe::Statement::Iterate);
            conn.query_raw(
                &s,
                chunk
                    .iter()
                    .flat_map(|(begin, end)| [begin, end])
                    .collect::<Vec<_>>(),
            )
            .await
        }
        .await;
        return Ok(
            match emit(rows, column, cursor.resumed, &mut cursor.last_key, cb).await? {
                Emitted::Done | Emitted::Stopped => RangeAttempt::Finished,
                Emitted::TimedOut { delivered, .. } => {
                    if delivered {
                        cursor.advance(bounds, total);
                    }
                    RangeAttempt::TimedOut { delivered }
                }
            },
        );
    }

    if let Err(error) = begin_read(conn).await? {
        return Ok(RangeAttempt::BeginTimedOut(into_error(error)));
    }
    while cursor.start < total {
        let end = (cursor.start + size).min(total);
        let chunk = bounds.get(cursor.start..end).unwrap_or_default();
        let rows = async {
            let s = conn
                .prepare_cached(&range_query(table, column.is_selected(), chunk.len()))
                .await?;
            #[cfg(stalwart_tests)]
            super::probe::record(super::probe::Statement::Iterate);
            conn.query_raw(
                &s,
                chunk
                    .iter()
                    .flat_map(|(begin, end)| [begin, end])
                    .collect::<Vec<_>>(),
            )
            .await
        }
        .await;
        match emit(rows, column, cursor.resumed, &mut cursor.last_key, cb).await? {
            Emitted::Done => {
                cursor.start = end;
                cursor.resumed = false;
            }
            Emitted::Stopped => return Ok(RangeAttempt::Finished),
            Emitted::TimedOut { delivered, .. } => {
                if delivered {
                    cursor.advance(bounds, end);
                }
                let ended = conn.batch_execute(ROLLBACK).await;
                conn.end_transaction(ended)?;
                return Ok(RangeAttempt::TimedOut { delivered });
            }
        }
    }
    let ended = commit_read(conn).await;
    conn.end_transaction(ended)?;
    Ok(RangeAttempt::Finished)
}

async fn commit_read(conn: &PooledConn) -> Result<(), tokio_postgres::Error> {
    #[cfg(stalwart_tests)]
    if crate::backend::sql_fault::fire() {
        return conn.batch_execute("SELECT 1/0").await;
    }
    conn.batch_execute(COMMIT).await
}

async fn begin_read(conn: &mut PooledConn) -> trc::Result<Result<(), tokio_postgres::Error>> {
    conn.transaction_started();
    match conn.batch_execute(BEGIN_READ).await {
        Ok(()) => Ok(Ok(())),
        Err(error) => {
            conn.abandon_transaction();
            if is_timeout_error(&error) {
                Ok(Err(error))
            } else {
                Err(into_error(error))
            }
        }
    }
}

async fn emit(
    rows: Result<RowStream, tokio_postgres::Error>,
    column: ValueColumn,
    resumed: bool,
    last_key: &mut Vec<u8>,
    cb: RangeCallback<'_>,
) -> trc::Result<Emitted> {
    let rows = match rows {
        Ok(rows) => rows,
        Err(error) if is_timeout_error(&error) => {
            return Ok(Emitted::TimedOut {
                error,
                delivered: false,
            });
        }
        Err(error) => return Err(into_error(error)),
    };
    pin_mut!(rows);
    let mut skip_resumed = resumed;
    let mut delivered = false;

    loop {
        match rows.try_next().await {
            Ok(Some(row)) => {
                #[cfg(stalwart_tests)]
                super::probe::row_sent();
                let key = row.try_get::<_, &[u8]>(0).map_err(into_error)?;
                let counter;
                let value = match column {
                    ValueColumn::Skip => b"".as_slice(),
                    ValueColumn::Bytes => row.try_get::<_, &[u8]>(1).map_err(into_error)?,
                    ValueColumn::Counter => {
                        counter = read_counter(&row)?;
                        counter.as_slice()
                    }
                };

                if skip_resumed {
                    skip_resumed = false;
                    if key == last_key.as_slice() {
                        continue;
                    }
                }

                if !cb(key, value)? {
                    #[cfg(stalwart_tests)]
                    super::probe::drain(rows.as_mut()).await;
                    return Ok(Emitted::Stopped);
                }

                last_key.clear();
                last_key.extend_from_slice(key);
                delivered = true;
            }
            Ok(None) => return Ok(Emitted::Done),
            Err(error) if is_timeout_error(&error) => {
                return Ok(Emitted::TimedOut { error, delivered });
            }
            Err(error) => return Err(into_error(error)),
        }
    }
}

#[inline]
fn read_counter(row: &Row) -> trc::Result<[u8; 8]> {
    row.try_get::<_, i64>(1)
        .map(i64::to_le_bytes)
        .map_err(into_error)
}

fn keys_after<'x>(keys: &'x [Vec<u8>], last_key: &[u8]) -> &'x [Vec<u8>] {
    keys.split_at(keys.partition_point(|key| key.as_slice() <= last_key))
        .1
}
