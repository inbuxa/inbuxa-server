/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod flight;
mod reads;

use self::{
    flight::{Param, Request, StatementId, StatementKind, Transaction, dispatch},
    reads::{Pass, ReadSet, missing_read, unprefixed},
};
use super::{PostgresStore, into_error, is_timeout_error};
use crate::{
    Key, Shape, Subspace, WITH_SUBSPACE,
    backend::postgres::{
        DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE, into_pool_error, pool::PgObject, sql::SubspaceSql,
    },
    write::{
        Advance, AssignedIds, Batch, BatchCursor, ChunkedRetry, LogSet, MAX_COMMIT_ATTEMPTS,
        MAX_COMMIT_TIME, MergeResult, NewKeyAsserts, ValueOp, commit_backoff, exhausted,
    },
};
use futures::TryStreamExt;
use std::{borrow::Cow, iter, mem, ops::Range, pin::pin, time::Instant};
use tokio_postgres::error::SqlState;

const KEY_LEN_HINT: usize = 32;
const MIN_DELETE_RUN: usize = 16;
const MAX_DELETE_KEYS: usize = 1000;

#[derive(Debug)]
enum CommitError {
    Postgres(tokio_postgres::Error),
    Internal(trc::Error),
}

struct Write<'x> {
    statement: StatementId,
    target: Target,
    param: Param<'x>,
}

enum Target {
    Key(Range<usize>),
    Keys(Range<usize>),
}

impl PostgresStore {
    pub(crate) async fn write(
        &self,
        mut batch: Batch<'_>,
        assigned_ids: &mut AssignedIds,
    ) -> trc::Result<()> {
        let start = Instant::now();
        let mut retry_count = 0;
        let mut new_key_asserts = NewKeyAsserts::CheckedByInsert;
        let mark = assigned_ids.mark();

        loop {
            assigned_ids.rollback(mark);
            let mut trx = Transaction::new(
                self.conn_pool.get().await.map_err(into_pool_error)?,
                &self.sql,
            );
            let result = write_pipelined(&mut trx, &mut batch, assigned_ids, new_key_asserts).await;
            let poisoned = trx.previous_rollback_failed();
            if result.is_err() && !poisoned {
                trx.rollback();
            }
            drop(trx);

            let err = match result {
                Ok(()) => return Ok(()),
                Err(CommitError::Postgres(err)) => err,
                Err(CommitError::Internal(err)) => return Err(err),
            };

            let is_contention = poisoned
                || match err.code() {
                    Some(&SqlState::UNIQUE_VIOLATION) => {
                        new_key_asserts = NewKeyAsserts::Read;
                        false
                    }
                    Some(
                        &SqlState::T_R_SERIALIZATION_FAILURE
                        | &SqlState::T_R_DEADLOCK_DETECTED
                        | &SqlState::LOCK_NOT_AVAILABLE
                        | &SqlState::QUERY_CANCELED
                        | &SqlState::IDLE_IN_TRANSACTION_SESSION_TIMEOUT,
                    ) => true,
                    _ => return Err(into_error(err)),
                };

            if retry_count >= MAX_COMMIT_ATTEMPTS || start.elapsed() >= MAX_COMMIT_TIME {
                return Err(if is_contention {
                    exhausted(into_error(err), retry_count)
                } else {
                    trc::StoreEvent::AssertValueFailed
                        .into_err()
                        .reason("Unique violation")
                        .caused_by(trc::location!())
                });
            }

            #[cfg(stalwart_tests)]
            crate::write::record_retry(retry_count);
            tokio::time::sleep(commit_backoff(retry_count)).await;
            retry_count += 1;
        }
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;

        for subspace in Subspace::ALL
            .iter()
            .copied()
            .filter(|subspace| matches!(subspace.shape(), Shape::Counter))
        {
            purge_table(&conn, self.sql.get(subspace)).await?;
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let stmts = self.sql.get(from.subspace());
        let mut from = from.serialize(0);
        let to = to.serialize(0);

        let delete = conn
            .prepare_cached(&stmts.delete_range)
            .await
            .map_err(into_error)?;

        #[cfg(stalwart_tests)]
        super::probe::record(super::probe::Statement::AutocommitWrite);
        match conn.execute(&delete, &[&from, &to]).await {
            Ok(_) => return Ok(()),
            Err(err) if is_timeout_error(&err) => (),
            Err(err) => return Err(into_error(err)),
        }

        let mut retry = ChunkedRetry::bounded(DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE);

        let boundary = conn
            .prepare_cached(&stmts.range_boundary)
            .await
            .map_err(into_error)?;

        loop {
            let chunk_size = retry.chunk_size().unwrap_or(DELETE_CHUNK_SIZE) as i64;

            loop {
                let next = match conn.query_opt(&boundary, &[&from, &to, &chunk_size]).await {
                    Ok(next) => match next {
                        Some(row) => Some(row.try_get::<_, Vec<u8>>(0).map_err(into_error)?),
                        None => None,
                    },
                    Err(err) if is_timeout_error(&err) => {
                        if !retry.degrade().await {
                            return Err(into_error(err));
                        }
                        break;
                    }
                    Err(err) => return Err(into_error(err)),
                };

                match conn
                    .execute(&delete, &[&from, next.as_ref().unwrap_or(&to)])
                    .await
                {
                    Ok(_) => retry.progressed(),
                    Err(err) if is_timeout_error(&err) => {
                        if !retry.degrade().await {
                            return Err(into_error(err));
                        }
                        break;
                    }
                    Err(err) => return Err(into_error(err)),
                }

                match next {
                    Some(next) => from = next,
                    None => return Ok(()),
                }
            }
        }
    }
}

async fn write_pipelined(
    trx: &mut Transaction<'_>,
    batch: &mut Batch<'_>,
    ids: &mut AssignedIds,
    new_key_asserts: NewKeyAsserts,
) -> Result<(), CommitError> {
    let mut reads = ReadSet::default();
    let mut key_buf = Vec::with_capacity(KEY_LEN_HINT);
    let deferred = reads.collect(
        batch,
        ids,
        &mut key_buf,
        Pass::BeforeAllocation(new_key_asserts),
    );

    if batch.has_id_allocations() || !reads.is_empty() {
        read_flight(trx, batch, ids, &mut reads, 0).await?;

        if deferred > 0 {
            let from = reads.len();
            reads.collect(batch, ids, &mut key_buf, Pass::AfterAllocation);
            if reads.len() > from {
                read_flight(trx, batch, ids, &mut reads, from).await?;
            }
        }

        #[cfg(stalwart_tests)]
        super::probe::between_flights().await;
    }

    let mut keys = KeyBuffer {
        bytes: Vec::with_capacity(batch.ops.len() * KEY_LEN_HINT),
        deletes: Vec::new(),
    };
    let mut writes = Vec::with_capacity(batch.ops.len());
    build_writes(
        trx,
        batch,
        ids,
        &mut reads,
        &mut key_buf,
        &mut keys,
        &mut writes,
    )?;
    let deletes = keys
        .deletes
        .iter()
        .map(|key| keys.bytes.get(key.clone()).unwrap_or_default())
        .collect::<Vec<_>>();
    write_flight(
        trx,
        ids,
        Keys {
            keys: &keys.bytes,
            deletes: &deletes,
        },
        &writes,
    )
    .await
}

struct KeyBuffer {
    bytes: Vec<u8>,
    deletes: Vec<Range<usize>>,
}

#[derive(Clone, Copy)]
struct Keys<'r> {
    keys: &'r [u8],
    deletes: &'r [&'r [u8]],
}

async fn read_flight(
    trx: &mut Transaction<'_>,
    batch: &Batch<'_>,
    ids: &mut AssignedIds,
    reads: &mut ReadSet,
    from: usize,
) -> Result<(), CommitError> {
    let begin = !trx.in_transaction();
    let mut counter_keys = Vec::new();
    let mut counters = Vec::new();
    if begin {
        for allocation in batch.id_allocations() {
            let start = counter_keys.len();
            allocation.serialize_key_into(&mut counter_keys, 0);
            counters.push((allocation.increment_by(), start..counter_keys.len()));
        }
    }
    let counter = (!counters.is_empty())
        .then(|| trx.statement_id(Subspace::Counter, StatementKind::IncrementReturning));
    let plan = reads.keys.plan(from, trx);
    trx.prepare().await?;

    if begin {
        trx.begin();
    }
    let trx = &*trx;
    let requests = begin
        .then_some(Request::Begin)
        .into_iter()
        .chain(counter.into_iter().flat_map(|statement| {
            let statement = trx.statement(statement);
            counters.iter().map(|(by, key)| Request::Counter {
                statement,
                key: counter_keys.get(key.clone()).unwrap_or_default(),
                by: *by,
            })
        }))
        .chain(plan.single.iter().map(|(_, key, statement)| Request::Read {
            statement: trx.statement(*statement),
            key,
        }))
        .chain(
            plan.chunks
                .iter()
                .map(|(statement, range)| Request::ReadMany {
                    statement: trx.statement(*statement),
                    keys: plan.many_keys.get(range.clone()).unwrap_or_default(),
                }),
        );
    let mut flight = dispatch(trx.client(), requests);
    flight.send().await?;

    if begin {
        flight.next().await?.done()?;
        if counter.is_some() {
            for allocation in batch.id_allocations() {
                ids.apply(allocation, flight.next().await?.counter()?)?;
            }
        }
    }

    for (slot, ..) in &plan.single {
        reads.values.read(*slot, flight.next().await?.value()?);
    }

    for (_, range) in &plan.chunks {
        let slots = plan.many_slots.get(range.clone()).unwrap_or_default();
        let keys = plan.many_keys.get(range.clone()).unwrap_or_default();
        for slot in slots {
            reads.values.read(*slot, None);
        }

        let mut rows = pin!(flight.next().await?.stream()?);
        while let Some(row) = rows.try_next().await? {
            let slot = {
                let key: &[u8] = row.try_get(0)?;
                keys.binary_search(&key)
                    .ok()
                    .and_then(|index| slots.get(index))
                    .copied()
            }
            .ok_or_else(missing_read)?;
            reads.values.read(slot, Some(row));
        }
    }

    Ok(())
}

fn build_writes<'x>(
    trx: &mut Transaction<'_>,
    batch: &'x mut Batch<'_>,
    ids: &mut AssignedIds,
    reads: &mut ReadSet,
    key_buf: &mut Vec<u8>,
    keys: &mut KeyBuffer,
    writes: &mut Vec<Write<'x>>,
) -> Result<(), CommitError> {
    let KeyBuffer {
        bytes: keys,
        deletes,
    } = keys;
    let mut cursor = BatchCursor::new(batch);
    let mut log_scratch = Vec::new();
    let checked_by_insert = mem::take(&mut reads.checked_by_insert);
    let mut checked_by_insert = checked_by_insert.iter().copied().peekable();

    for (index, op) in batch.ops.iter_mut().enumerate() {
        match cursor.advance(op, ids) {
            Advance::Cursor => {}
            Advance::Value { class, op } => {
                cursor.value_key(class, key_buf, WITH_SUBSPACE);
                let subspace = cursor.subspace(class);
                let slot = reads.keys.find(subspace, key_buf);

                match op {
                    ValueOp::Set(value) => {
                        let value = value.resolve(ids)?;
                        if matches!(subspace.shape(), Shape::Presence) {
                            let statement =
                                trx.statement_id(subspace, StatementKind::InsertPresence);
                            push_write(writes, keys, statement, key_buf, Param::Key);
                        } else {
                            let kind = match slot {
                                Some(slot) if reads.values.is_asserted(slot) => {
                                    if reads.values.exists(slot) {
                                        StatementKind::Update
                                    } else {
                                        StatementKind::Insert
                                    }
                                }
                                _ => StatementKind::Upsert,
                            };
                            let statement = trx.statement_id(subspace, kind);
                            let write =
                                push_write(writes, keys, statement, key_buf, Param::Value(value));
                            if let Some(slot) = slot {
                                reads.values.written(slot, write);
                            }
                        }
                    }
                    ValueOp::MergeFnc(merge) => {
                        let slot = slot.ok_or_else(missing_read)?;
                        let exists = reads.values.exists(slot);
                        let merged = (merge.0)(ids, reads.values.value(slot, writes)?)?;

                        match merged {
                            MergeResult::Update(value) => {
                                let kind = if exists {
                                    StatementKind::Update
                                } else {
                                    StatementKind::Insert
                                };
                                let statement = trx.statement_id(subspace, kind);
                                let write = push_write(
                                    writes,
                                    keys,
                                    statement,
                                    key_buf,
                                    Param::Value(Cow::Owned(value)),
                                );
                                reads.values.written(slot, write);
                            }
                            MergeResult::Delete if exists => {
                                push_delete(trx, writes, keys, deletes, subspace, key_buf);
                                reads.values.cleared(slot);
                            }
                            MergeResult::Delete | MergeResult::Skip => {}
                        }
                    }
                    ValueOp::AtomicAdd(by) => {
                        let (kind, param) = if *by >= 0 {
                            (StatementKind::Increment, Param::Add(*by))
                        } else {
                            (StatementKind::Decrement, Param::Subtract(*by))
                        };
                        let statement = trx.statement_id(subspace, kind);
                        push_write(writes, keys, statement, key_buf, param);
                    }
                    ValueOp::AddAndGet(by) => {
                        let statement =
                            trx.statement_id(subspace, StatementKind::IncrementReturning);
                        push_write(writes, keys, statement, key_buf, Param::AddAndGet(*by));
                    }
                    ValueOp::Clear => {
                        push_delete(trx, writes, keys, deletes, subspace, key_buf);
                        if let Some(slot) = slot {
                            reads.values.cleared(slot);
                        }
                    }
                }
            }
            Advance::Index { field, key, set } => {
                cursor.index_key(field, key, key_buf, WITH_SUBSPACE);
                if set {
                    let statement =
                        trx.statement_id(Subspace::Indexes, StatementKind::InsertPresence);
                    push_write(writes, keys, statement, key_buf, Param::Key);
                } else {
                    push_delete(trx, writes, keys, deletes, Subspace::Indexes, key_buf);
                }
            }
            Advance::Log { collection, set } => {
                cursor.log_key(collection, ids, key_buf, WITH_SUBSPACE);
                let value = match set {
                    LogSet::Bytes(bytes) => Cow::Borrowed(bytes.as_slice()),
                    LogSet::Pending(changes) => {
                        let mut value = Vec::new();
                        changes.serialize_into(
                            collection.is_prefixed(),
                            ids,
                            &mut log_scratch,
                            &mut value,
                        );
                        Cow::Owned(value)
                    }
                };
                let slot = reads.keys.find(Subspace::Logs, key_buf);
                let statement = trx.statement_id(Subspace::Logs, StatementKind::Upsert);
                let write = push_write(writes, keys, statement, key_buf, Param::Value(value));
                if let Some(slot) = slot {
                    reads.values.written(slot, write);
                }
            }
            Advance::ClearRange { subspace, from, to } => {
                reads.clear_range(subspace, from, to);
                let statement = trx.statement_id(subspace, StatementKind::DeleteRange);
                let start = keys.len();
                keys.extend_from_slice(from);
                writes.push(Write {
                    statement,
                    target: Target::Key(start..keys.len()),
                    param: Param::Until(Cow::Borrowed(to)),
                });
            }
            Advance::Assert {
                class,
                assert_value,
            } => {
                cursor.value_key(class, key_buf, WITH_SUBSPACE);
                let subspace = cursor.subspace(class);
                let checked = checked_by_insert.next_if_eq(&index).is_some();
                let slot = match reads.keys.find(subspace, key_buf) {
                    Some(slot) => slot,
                    None if checked => reads.assume_absent(subspace, key_buf),
                    None => return Err(missing_read()),
                };
                let matches = match reads.values.value(slot, writes)? {
                    Some(value) => assert_value.matches(value),
                    None => assert_value.is_none(),
                };
                if !matches {
                    return Err(trc::StoreEvent::AssertValueFailed
                        .into_err()
                        .caused_by(trc::location!())
                        .into());
                }
                reads.values.asserted(slot);
            }
        }
    }

    if !batch.bounds.is_empty() {
        let statement = trx.statement_id(Subspace::Counter, StatementKind::IncrementBounded);
        for bound in batch.bounds {
            let start = keys.len();
            bound.serialize_key_into(keys, 0);
            writes.push(Write {
                statement,
                target: Target::Key(start..keys.len()),
                param: Param::Bounded(*bound),
            });
        }
    }

    Ok(())
}

async fn write_flight(
    trx: &mut Transaction<'_>,
    ids: &mut AssignedIds,
    keys: Keys<'_>,
    writes: &[Write<'_>],
) -> Result<(), CommitError> {
    trx.prepare().await?;

    let begin = !trx.in_transaction();
    if begin {
        match writes {
            [] => return Ok(()),
            [write] => return write_autocommit(trx, ids, keys, write).await,
            _ => trx.begin(),
        }
    }

    let requests = begin
        .then_some(Request::Begin)
        .into_iter()
        .chain(writes.iter().map(|write| write.request(trx, keys)))
        .chain(iter::once(Request::Commit));
    let mut flight = dispatch(trx.client(), requests);
    flight.send().await?;
    let result = async {
        if begin {
            flight.next().await?.done()?;
        }
        for write in writes {
            let response = flight.next().await.map_err(|err| write.map_error(err))?;
            if let Param::AddAndGet(_) = write.param {
                ids.push_counter_id(response.counter()?);
            } else if let Param::Bounded(_) = write.param {
                response.counter()?;
            } else {
                let rows = response.rows()?;
                debug_assert!(
                    rows > 0 || trx.statement_kind(write.statement) != StatementKind::Update,
                    "update of a key read for update affected no rows"
                );
            }
        }
        flight.next().await?.done()
    }
    .await;
    drop(flight);
    trx.commit_sent();

    result
}

async fn write_autocommit(
    trx: &Transaction<'_>,
    ids: &mut AssignedIds,
    keys: Keys<'_>,
    write: &Write<'_>,
) -> Result<(), CommitError> {
    #[cfg(stalwart_tests)]
    {
        super::probe::record_flight();
        super::probe::record(super::probe::Statement::AutocommitWrite);
    }

    let response = write
        .request(trx, keys)
        .send(trx.client())
        .await
        .map_err(|err| write.map_error(err.into()))?;
    if let Param::AddAndGet(_) = write.param {
        ids.push_counter_id(response.counter()?);
    } else if let Param::Bounded(_) = write.param {
        response.counter()?;
    } else {
        response.rows()?;
    }
    Ok(())
}

fn push_write<'x>(
    writes: &mut Vec<Write<'x>>,
    keys: &mut Vec<u8>,
    statement: StatementId,
    key: &[u8],
    param: Param<'x>,
) -> usize {
    let start = keys.len();
    keys.extend_from_slice(unprefixed(key));
    writes.push(Write {
        statement,
        target: Target::Key(start..keys.len()),
        param,
    });
    writes.len() - 1
}

fn push_delete(
    trx: &mut Transaction<'_>,
    writes: &mut Vec<Write<'_>>,
    keys: &mut Vec<u8>,
    deletes: &mut Vec<Range<usize>>,
    subspace: Subspace,
    key: &[u8],
) {
    let start = keys.len();
    keys.extend_from_slice(unprefixed(key));
    let key = start..keys.len();

    if let Some(Write {
        statement,
        target: Target::Keys(run),
        ..
    }) = writes.last_mut()
        && run.len() < MAX_DELETE_KEYS
        && trx.is_statement(*statement, subspace, StatementKind::DeleteMany)
    {
        deletes.push(key);
        run.end = deletes.len();
        return;
    }

    let delete = trx.statement_id(subspace, StatementKind::Delete);
    writes.push(Write {
        statement: delete,
        target: Target::Key(key),
        param: Param::Key,
    });

    let run = writes
        .iter()
        .rev()
        .take(MIN_DELETE_RUN)
        .take_while(|write| write.statement == delete && matches!(write.target, Target::Key(_)))
        .count();
    if run == MIN_DELETE_RUN {
        let from = deletes.len();
        deletes.extend(
            writes
                .drain(writes.len() - MIN_DELETE_RUN..)
                .filter_map(|write| match write.target {
                    Target::Key(key) => Some(key),
                    Target::Keys(_) => None,
                }),
        );
        writes.push(Write {
            statement: trx.statement_id(subspace, StatementKind::DeleteMany),
            target: Target::Keys(from..deletes.len()),
            param: Param::Key,
        });
    }
}

impl<'x> Write<'x> {
    #[inline]
    fn request<'r>(&'r self, trx: &'r Transaction<'_>, keys: Keys<'r>) -> Request<'r> {
        let statement = trx.statement(self.statement);
        match &self.target {
            Target::Key(key) => Request::Write {
                statement,
                key: keys.keys.get(key.clone()).unwrap_or_default(),
                param: &self.param,
            },
            Target::Keys(run) => Request::WriteMany {
                statement,
                keys: keys.deletes.get(run.clone()).unwrap_or_default(),
            },
        }
    }

    #[inline]
    fn value(&self) -> Option<&[u8]> {
        self.param.value()
    }

    fn map_error(&self, err: CommitError) -> CommitError {
        match (&self.param, err) {
            (Param::Bounded(bound), CommitError::Postgres(err))
                if err.code() == Some(&SqlState::NOT_NULL_VIOLATION) =>
            {
                CommitError::Internal(bound.exceeded())
            }
            (_, err) => err,
        }
    }
}

async fn purge_table(conn: &PgObject, stmts: &SubspaceSql) -> trc::Result<()> {
    let s = conn
        .prepare_cached(&stmts.purge_zero)
        .await
        .map_err(into_error)?;

    match conn.execute(&s, &[]).await {
        Ok(_) => return Ok(()),
        Err(err) if is_timeout_error(&err) => (),
        Err(err) => return Err(into_error(err)),
    }

    let purge = conn
        .prepare_cached(&stmts.purge_zero_range)
        .await
        .map_err(into_error)?;
    let purge_last = conn
        .prepare_cached(&stmts.purge_zero_from)
        .await
        .map_err(into_error)?;
    let boundary = conn
        .prepare_cached(&stmts.purge_boundary)
        .await
        .map_err(into_error)?;
    let mut retry = ChunkedRetry::bounded(DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE);
    let mut from = Vec::new();

    loop {
        let chunk_size = retry.chunk_size().unwrap_or(DELETE_CHUNK_SIZE) as i64;

        loop {
            let next = match conn.query_opt(&boundary, &[&from, &chunk_size]).await {
                Ok(next) => match next {
                    Some(row) => Some(row.try_get::<_, Vec<u8>>(0).map_err(into_error)?),
                    None => None,
                },
                Err(err) if is_timeout_error(&err) => {
                    if !retry.degrade().await {
                        return Err(into_error(err));
                    }
                    break;
                }
                Err(err) => return Err(into_error(err)),
            };

            let result = match &next {
                Some(next) => conn.execute(&purge, &[&from, next]).await,
                None => conn.execute(&purge_last, &[&from]).await,
            };

            match result {
                Ok(_) => retry.progressed(),
                Err(err) if is_timeout_error(&err) => {
                    if !retry.degrade().await {
                        return Err(into_error(err));
                    }
                    break;
                }
                Err(err) => return Err(into_error(err)),
            }

            match next {
                Some(next) => from = next,
                None => return Ok(()),
            }
        }
    }
}

impl From<trc::Error> for CommitError {
    fn from(err: trc::Error) -> Self {
        CommitError::Internal(err)
    }
}

impl From<tokio_postgres::Error> for CommitError {
    fn from(err: tokio_postgres::Error) -> Self {
        CommitError::Postgres(err)
    }
}
