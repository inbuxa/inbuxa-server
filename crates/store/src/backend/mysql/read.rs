/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{MysqlStore, bounded, into_error, is_timeout_error, stalled};
use crate::{
    Deserialize, Fetch, IterateParams, Key, Subspace, ValueKey,
    backend::{
        ValueColumn,
        mysql::{ITERATE_CHUNK_SIZE, MIN_ITERATE_CHUNK_SIZE, pooled::PooledConn},
        range_batch::{Bounds, RangeAttempt, RangeCursor, Timeout},
    },
    dispatch::store::point_keys,
    write::{AnyKey, ChunkPlan, ValueClass, backoff},
};
use futures::TryStreamExt;
use mysql_async::{Conn, IsolationLevel, Row, Transaction, TxOpts, Value, prelude::Queryable};
use std::{fmt::Write, time::Duration};

pub(super) const POINT_BUCKETS: [usize; 4] = [16, 64, 256, MAX_POINT_KEYS];
pub(super) const MAX_POINT_KEYS: usize = 768;
const DEGRADED_POINT_KEYS: usize = 256;
const MIN_POINT_KEYS: usize = 16;
const MAX_RANGES_PER_STMT: usize = 64;

impl MysqlStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let mut conn = self.conn().await?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn
                .prep(&*self.sql.get(key.subspace()).get_value)
                .await
                .map_err(into_error)?;
            let key = key.serialize(0);
            conn.exec_first::<Vec<u8>, _, _>(&s, (&key,))
                .await
                .map_err(into_error)
                .and_then(|r| {
                    if let Some(r) = r {
                        Ok(Some(U::deserialize_owned_with_key(&key, r)?))
                    } else {
                        Ok(None)
                    }
                })
        })
        .await;
        bounded(conn, result, limit)
    }

    pub(crate) async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        let mut conn = self.conn().await?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn
                .prep(&*self.sql.get(key.subspace()).key_exists)
                .await
                .map_err(into_error)?;
            let key = key.serialize(0);
            conn.exec_first::<u8, _, _>(&s, (&key,))
                .await
                .map_err(into_error)
                .map(|r| r.is_some())
        })
        .await;
        bounded(conn, result, limit)
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        debug_assert_ne!(params.fetch, Fetch::Limit(0));
        let mut conn = PooledConn::new(self.conn().await?);
        // inbuxa: a scan may run for hours, so the query limit bounds each
        // wait for the database (preparing, the query starting, the next
        // row) rather than the scan. A wait that runs out closes the
        // connection.
        let wait = self.timeouts.query;
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
                    Some(limit),
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

            let mut stuck = false;
            {
                // None: no answer within the query limit
                let result = match tokio::time::timeout(wait, conn.prep(statement)).await {
                    Ok(Ok(s)) => match bound {
                        Some(bound) => tokio::time::timeout(
                            wait,
                            conn.exec_stream::<Row, _, _>(&s, (from.clone(), to.clone(), bound)),
                        )
                        .await
                        .ok(),
                        None => tokio::time::timeout(
                            wait,
                            conn.exec_stream::<Row, _, _>(&s, (from.clone(), to.clone())),
                        )
                        .await
                        .ok(),
                    },
                    Ok(Err(err)) => Some(Err(err)),
                    Err(_) => None,
                };
                match result {
                    Some(Ok(mut rows)) => loop {
                        let Ok(next) = tokio::time::timeout(wait, rows.try_next()).await else {
                            stuck = true;
                            break;
                        };
                        match next {
                            Ok(Some(mut row)) => {
                                let value = RowValue::take(&mut row, column)?;
                                let key = row
                                    .take_opt::<Vec<u8>, _>(0)
                                    .unwrap_or_else(|| Ok(vec![]))
                                    .map_err(into_error)?;

                                fetched += 1;
                                if skip_resumed {
                                    skip_resumed = false;
                                    if key == last_key {
                                        continue;
                                    }
                                }

                                if !cb(&key, value.as_slice())? || !plan.consume_row() {
                                    return Ok(());
                                }

                                last_key = key;
                                progressed = true;
                            }
                            Ok(None) => break,
                            Err(err) if is_timeout_error(&err) => {
                                timed_out = Some(err);
                                break;
                            }
                            Err(err) => return Err(into_error(err)),
                        }
                    },
                    Some(Err(err)) if is_timeout_error(&err) => timed_out = Some(err),
                    Some(Err(err)) => return Err(into_error(err)),
                    None => stuck = true,
                }
            }
            if stuck {
                return Err(stalled(&mut conn, wait));
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
        let mut conn = PooledConn::new(self.conn().await?);
        // inbuxa: each wait for the database is bounded, as in iterate()
        let wait = self.timeouts.query;

        match point_keys(&ranges) {
            Some(keys) => {
                iterate_points(&mut conn, subspace.name(), &keys, column, &mut cb, wait).await
            }
            None => {
                let bounds = ranges
                    .iter()
                    .map(|params| (params.begin.serialize(0), params.end.serialize(0)))
                    .collect::<Vec<_>>();
                self.iterate_ranges(conn, subspace, bounds, column, &mut cb, wait)
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
        let mut conn = self.conn().await?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn
                .prep(&*self.sql.get(subspace).get_value)
                .await
                .map_err(into_error)?;
            match conn.exec_first::<i64, _, _>(&s, (key,)).await {
                Ok(Some(num)) => Ok(num),
                Ok(None) => Ok(0),
                Err(e) => Err(into_error(e)),
            }
        })
        .await;
        bounded(conn, result, limit)
    }
}

#[derive(Clone, Copy)]
pub(super) enum PointRows {
    Keys,
    Values,
    ForUpdate,
}

impl From<bool> for PointRows {
    fn from(values: bool) -> Self {
        if values {
            PointRows::Values
        } else {
            PointRows::Keys
        }
    }
}

type RangeCallback<'y> =
    &'y mut (dyn for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Send + Sync);

enum Emitted {
    Done,
    Stopped,
    TimedOut {
        error: mysql_async::Error,
        delivered: bool,
    },
    /// inbuxa: no answer within the query limit
    Stalled,
}

/// inbuxa: how starting a read transaction went
enum Begin<'a> {
    Started(Transaction<'a>),
    TimedOut(mysql_async::Error),
    /// No answer within the query limit
    Stalled,
}

async fn iterate_points(
    conn: &mut PooledConn,
    table: &str,
    keys: &[Vec<u8>],
    column: ValueColumn,
    cb: RangeCallback<'_>,
    wait: Duration,
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
        let error = match points_attempt(
            conn,
            table,
            &mut pending,
            size,
            column,
            &mut last_key,
            cb,
            wait,
        )
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

#[allow(clippy::too_many_arguments)]
async fn points_attempt(
    conn: &mut PooledConn,
    table: &str,
    pending: &mut &[Vec<u8>],
    size: usize,
    column: ValueColumn,
    last_key: &mut Vec<u8>,
    cb: RangeCallback<'_>,
    wait: Duration,
) -> trc::Result<Option<Timeout<mysql_async::Error>>> {
    if pending.len() <= size {
        let (query, params) =
            point_statement(table, PointRows::from(column.is_selected()), pending);
        return match emit(
            &mut **conn,
            &query,
            params,
            column,
            false,
            last_key,
            cb,
            wait,
        )
        .await?
        {
            Emitted::Done | Emitted::Stopped => Ok(None),
            Emitted::TimedOut { error, .. } => Ok(Some(Timeout::Statement(error))),
            Emitted::Stalled => Err(stalled(conn, wait)),
        };
    }

    // inbuxa: None when a wait ran past the query limit
    let error = match begin_read(conn, wait).await? {
        Begin::Started(mut trx) => 'trx: {
            while !pending.is_empty() {
                let (chunk, rest) = pending.split_at(pending.len().min(size));
                let (query, params) =
                    point_statement(table, PointRows::from(column.is_selected()), chunk);
                match emit(&mut trx, &query, params, column, false, last_key, cb, wait).await? {
                    Emitted::Done => *pending = rest,
                    Emitted::Stopped => return Ok(None),
                    Emitted::TimedOut { error, .. } => {
                        let Ok(ended) = tokio::time::timeout(wait, trx.rollback()).await else {
                            break 'trx None;
                        };
                        ended.map_err(into_error)?;
                        return Ok(Some(Timeout::Statement(error)));
                    }
                    Emitted::Stalled => break 'trx None,
                }
            }
            let Ok(ended) = tokio::time::timeout(wait, trx.commit()).await else {
                break 'trx None;
            };
            ended.map_err(into_error)?;
            return Ok(None);
        }
        Begin::TimedOut(error) => Some(error),
        Begin::Stalled => None,
    };
    let Some(error) = error else {
        return Err(stalled(conn, wait));
    };
    end_failed_begin(conn, wait).await?;
    Ok(Some(Timeout::Begin(error)))
}

pub(super) fn point_statement<K: AsRef<[u8]>>(
    table: &str,
    rows: PointRows,
    keys: &[K],
) -> (String, Vec<Value>) {
    let slots = POINT_BUCKETS
        .into_iter()
        .find(|bucket| *bucket >= keys.len())
        .unwrap_or(MAX_POINT_KEYS);
    let (columns, order) = match rows {
        PointRows::Keys => ("k", " ORDER BY k"),
        PointRows::Values => ("k, v", " ORDER BY k"),
        PointRows::ForUpdate => ("k, v", " FOR UPDATE"),
    };
    let mut query = String::with_capacity(slots * 2 + table.len() + 48);
    let _ = write!(query, "SELECT {columns} FROM {table} WHERE k IN (?");
    for _ in 1..slots {
        query.push_str(",?");
    }
    query.push(')');
    query.push_str(order);

    let mut params = Vec::with_capacity(slots);
    params.extend(keys.iter().map(|key| Value::Bytes(key.as_ref().to_vec())));
    params.resize(slots, Value::NULL);
    (query, params)
}

impl MysqlStore {
    async fn iterate_ranges(
        &self,
        mut conn: PooledConn,
        subspace: Subspace,
        mut bounds: Vec<Bounds>,
        column: ValueColumn,
        cb: RangeCallback<'_>,
        wait: Duration,
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
                wait,
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
    let mut query = String::with_capacity(count * 24 + 40);
    query.push_str(if values {
        "SELECT k, v FROM "
    } else {
        "SELECT k FROM "
    });
    query.push_str(table);
    query.push_str(" WHERE ");
    for i in 0..count {
        if i > 0 {
            query.push_str(" OR ");
        }
        query.push_str("(k >= ? AND k <= ?)");
    }
    query.push_str(" ORDER BY k ASC");
    query
}

fn range_params(bounds: &[Bounds]) -> Vec<Value> {
    bounds
        .iter()
        .flat_map(|(begin, end)| [Value::Bytes(begin.clone()), Value::Bytes(end.clone())])
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn ranges_attempt(
    conn: &mut PooledConn,
    table: &str,
    bounds: &mut [Bounds],
    cursor: &mut RangeCursor,
    size: usize,
    column: ValueColumn,
    cb: RangeCallback<'_>,
    wait: Duration,
) -> trc::Result<RangeAttempt> {
    let total = bounds.len();
    if cursor.start >= total {
        return Ok(RangeAttempt::Finished);
    } else if total - cursor.start <= size {
        let chunk = bounds.get(cursor.start..).unwrap_or_default();
        return Ok(
            match emit(
                &mut **conn,
                &range_query(table, column.is_selected(), chunk.len()),
                range_params(chunk),
                column,
                cursor.resumed,
                &mut cursor.last_key,
                cb,
                wait,
            )
            .await?
            {
                Emitted::Done | Emitted::Stopped => RangeAttempt::Finished,
                Emitted::TimedOut { delivered, .. } => {
                    if delivered {
                        cursor.advance(bounds, total);
                    }
                    RangeAttempt::TimedOut { delivered }
                }
                Emitted::Stalled => return Err(stalled(conn, wait)),
            },
        );
    }

    // inbuxa: None when a wait ran past the query limit
    let error = match begin_read(conn, wait).await? {
        Begin::Started(mut trx) => 'trx: {
            while cursor.start < total {
                let end = (cursor.start + size).min(total);
                let chunk = bounds.get(cursor.start..end).unwrap_or_default();
                match emit(
                    &mut trx,
                    &range_query(table, column.is_selected(), chunk.len()),
                    range_params(chunk),
                    column,
                    cursor.resumed,
                    &mut cursor.last_key,
                    cb,
                    wait,
                )
                .await?
                {
                    Emitted::Done => {
                        cursor.start = end;
                        cursor.resumed = false;
                    }
                    Emitted::Stopped => return Ok(RangeAttempt::Finished),
                    Emitted::TimedOut { delivered, .. } => {
                        if delivered {
                            cursor.advance(bounds, end);
                        }
                        let Ok(ended) = tokio::time::timeout(wait, trx.rollback()).await else {
                            break 'trx None;
                        };
                        ended.map_err(into_error)?;
                        return Ok(RangeAttempt::TimedOut { delivered });
                    }
                    Emitted::Stalled => break 'trx None,
                }
            }
            let Ok(ended) = tokio::time::timeout(wait, trx.commit()).await else {
                break 'trx None;
            };
            ended.map_err(into_error)?;
            return Ok(RangeAttempt::Finished);
        }
        Begin::TimedOut(error) => Some(error),
        Begin::Stalled => None,
    };
    let Some(error) = error else {
        return Err(stalled(conn, wait));
    };
    end_failed_begin(conn, wait).await?;
    Ok(RangeAttempt::BeginTimedOut(into_error(error)))
}

async fn begin_read(conn: &mut Conn, wait: Duration) -> trc::Result<Begin<'_>> {
    let mut tx_opts = TxOpts::default();
    tx_opts
        .with_consistent_snapshot(true)
        .with_isolation_level(IsolationLevel::RepeatableRead);
    match tokio::time::timeout(wait, conn.start_transaction(tx_opts)).await {
        Ok(Ok(trx)) => Ok(Begin::Started(trx)),
        Ok(Err(error)) if is_timeout_error(&error) => Ok(Begin::TimedOut(error)),
        Ok(Err(error)) => Err(into_error(error)),
        Err(_) => Ok(Begin::Stalled),
    }
}

async fn end_failed_begin(conn: &mut PooledConn, wait: Duration) -> trc::Result<()> {
    match tokio::time::timeout(wait, conn.query_drop("ROLLBACK")).await {
        Ok(ended) => conn.end_transaction(ended),
        Err(_) => Err(stalled(conn, wait)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn emit<Q: Queryable>(
    q: &mut Q,
    query: &str,
    params: Vec<Value>,
    column: ValueColumn,
    resumed: bool,
    last_key: &mut Vec<u8>,
    cb: RangeCallback<'_>,
    wait: Duration,
) -> trc::Result<Emitted> {
    let s = match tokio::time::timeout(wait, q.prep(query)).await {
        Ok(Ok(s)) => s,
        Ok(Err(error)) if is_timeout_error(&error) => {
            return Ok(Emitted::TimedOut {
                error,
                delivered: false,
            });
        }
        Ok(Err(error)) => return Err(into_error(error)),
        Err(_) => return Ok(Emitted::Stalled),
    };
    let mut rows = match tokio::time::timeout(wait, q.exec_stream::<Row, _, _>(&s, params)).await {
        Ok(Ok(rows)) => rows,
        Ok(Err(error)) if is_timeout_error(&error) => {
            return Ok(Emitted::TimedOut {
                error,
                delivered: false,
            });
        }
        Ok(Err(error)) => return Err(into_error(error)),
        Err(_) => return Ok(Emitted::Stalled),
    };
    let mut skip_resumed = resumed;
    let mut delivered = false;

    loop {
        let Ok(next) = tokio::time::timeout(wait, rows.try_next()).await else {
            return Ok(Emitted::Stalled);
        };
        match next {
            Ok(Some(mut row)) => {
                let value = RowValue::take(&mut row, column)?;
                let key = row
                    .take_opt::<Vec<u8>, _>(0)
                    .unwrap_or_else(|| Ok(vec![]))
                    .map_err(into_error)?;

                if skip_resumed {
                    skip_resumed = false;
                    if key == *last_key {
                        continue;
                    }
                }

                if !cb(&key, value.as_slice())? {
                    return Ok(Emitted::Stopped);
                }

                *last_key = key;
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

enum RowValue {
    Bytes(Vec<u8>),
    Counter([u8; 8]),
}

impl RowValue {
    #[inline]
    fn take(row: &mut Row, column: ValueColumn) -> trc::Result<Self> {
        match column {
            ValueColumn::Skip => Ok(RowValue::Bytes(Vec::new())),
            ValueColumn::Bytes => row
                .take_opt::<Vec<u8>, _>(1)
                .unwrap_or_else(|| Ok(Vec::new()))
                .map(RowValue::Bytes)
                .map_err(into_error),
            ValueColumn::Counter => row
                .take_opt::<i64, _>(1)
                .unwrap_or(Ok(0))
                .map(|value| RowValue::Counter(value.to_le_bytes()))
                .map_err(into_error),
        }
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            RowValue::Bytes(bytes) => bytes,
            RowValue::Counter(bytes) => bytes,
        }
    }
}

fn keys_after<'x>(keys: &'x [Vec<u8>], last_key: &[u8]) -> &'x [Vec<u8>] {
    keys.split_at(keys.partition_point(|key| key.as_slice() <= last_key))
        .1
}
