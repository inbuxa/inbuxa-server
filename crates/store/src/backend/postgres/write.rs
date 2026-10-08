/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{PostgresStore, bounded, into_error, is_timeout_error};
use crate::{
    IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER, SUBSPACE_QUOTA,
    SUBSPACE_REGISTRY_IDX,
    backend::postgres::{DELETE_CHUNK_SIZE, MIN_DELETE_CHUNK_SIZE, into_pool_error},
    write::{
        AssignedIds, Batch, MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME, MergeResult, Operation,
        ValueClass, ValueOp,
    },
};
use ahash::AHashMap;
use deadpool_postgres::{Object, Transaction};
use futures::{StreamExt, future::BoxFuture, stream::FuturesOrdered};
use rand::RngExt;
use std::{
    borrow::Cow,
    future::poll_fn,
    task::Poll,
    time::{Duration, Instant},
};
use tokio_postgres::{IsolationLevel, Statement, error::SqlState, types::ToSql};

#[derive(Debug)]
enum CommitError {
    Postgres(tokio_postgres::Error),
    Internal(trc::Error),
    //Retry,
}

// INBUXA: on a single node every statement is a microsecond away, so upstream
// awaits each one before building the next. On a cluster each await is a
// network round trip, and a batch of a few hundred operations held the
// account's change-id row locked for all of them. Statements that need no
// answer are now sent as soon as they are built and their replies are read
// later, in order; the server still runs them in the order sent. Anything
// that needs a reply to continue (asserts, merges, AddAndGet) drains the
// queue first, so the first error reported is the real one and not
// "current transaction is aborted".
struct Pipeline<'b, 'a> {
    trx: &'b Transaction<'a>,
    queue: FuturesOrdered<BoxFuture<'b, Result<(), CommitError>>>,
}

// Owned (or batch-borrowed) statement parameters, so a queued statement can
// outlive the loop iteration that built it.
enum Params<'b> {
    Key(Vec<u8>),
    KeyValue(Vec<u8>, Cow<'b, [u8]>),
    KeyInt(Vec<u8>, i64),
    IntKey(i64, Vec<u8>),
}

impl Params<'_> {
    fn as_sql(&self) -> Vec<&(dyn ToSql + Sync)> {
        match self {
            Params::Key(k) => vec![k],
            Params::KeyValue(k, v) => vec![k, v],
            Params::KeyInt(k, i) => vec![k, i],
            Params::IntKey(i, k) => vec![i, k],
        }
    }
}

impl<'b, 'a> Pipeline<'b, 'a> {
    fn new(trx: &'b Transaction<'a>) -> Self {
        Pipeline {
            trx,
            queue: FuturesOrdered::new(),
        }
    }

    // Queues a statement. With `require_row` the statement must touch a row
    // (an UPDATE after a successful assert), otherwise the assert failed.
    async fn execute(
        &mut self,
        statement: Statement,
        params: Params<'b>,
        require_row: bool,
    ) -> Result<(), CommitError> {
        let trx = self.trx;
        self.queue.push_back(Box::pin(async move {
            let rows = trx.execute(&statement, &params.as_sql()).await?;
            if require_row && rows == 0 {
                Err(trc::StoreEvent::AssertValueFailed
                    .into_err()
                    .caused_by(trc::location!())
                    .into())
            } else {
                Ok(())
            }
        }));

        // Poll once so the statement goes out now, in operation order; the
        // reply is read at the next flush.
        poll_fn(|cx| match self.queue.poll_next_unpin(cx) {
            Poll::Ready(Some(result)) => Poll::Ready(result),
            Poll::Ready(None) | Poll::Pending => Poll::Ready(Ok(())),
        })
        .await
    }

    async fn flush(&mut self) -> Result<(), CommitError> {
        while let Some(result) = self.queue.next().await {
            result?;
        }
        Ok(())
    }
}

impl PostgresStore {
    pub(crate) async fn write(&self, mut batch: Batch<'_>) -> trc::Result<AssignedIds> {
        let mut conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let start = Instant::now();
            let mut retry_count = 0;

            loop {
                match self.write_trx(&mut conn, &mut batch).await {
                    Ok(result) => {
                        return Ok(result);
                    }
                    Err(err) => {
                        match err {
                            CommitError::Postgres(err) => match err.code() {
                                Some(
                                    &SqlState::T_R_SERIALIZATION_FAILURE
                                    | &SqlState::T_R_DEADLOCK_DETECTED,
                                ) if retry_count < MAX_COMMIT_ATTEMPTS
                                    && start.elapsed() < MAX_COMMIT_TIME => {}
                                Some(&SqlState::UNIQUE_VIOLATION) => {
                                    return Err(trc::StoreEvent::AssertValueFailed
                                        .into_err()
                                        .reason("Unique violation")
                                        .caused_by(trc::location!()));
                                }
                                _ => return Err(into_error(err)),
                            },
                            CommitError::Internal(err) => return Err(err),
                            /*CommitError::Retry => {
                                if retry_count > MAX_COMMIT_ATTEMPTS
                                    || start.elapsed() > MAX_COMMIT_TIME
                                {
                                    return Err(trc::StoreEvent::AssertValueFailed
                                        .into_err()
                                        .caused_by(trc::location!()));
                                }
                            }*/
                        }

                        let backoff = rand::rng().random_range(50..=300);
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                        retry_count += 1;
                    }
                }
            }
        })
        .await;
        bounded(conn, result, limit)
    }

    async fn write_trx(
        &self,
        conn: &mut Object,
        batch: &mut Batch<'_>,
    ) -> Result<AssignedIds, CommitError> {
        let mut account_id = u32::MAX;
        let mut collection = u8::MAX;
        let mut document_id = u32::MAX;
        let mut change_id = 0u64;
        let mut asserted_values = AHashMap::new();
        let trx = conn
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        let mut result = AssignedIds::default();
        let has_changes = !batch.changes.is_empty();

        if has_changes {
            // INBUXA: one round trip for every account in the batch, not one each.
            let s = trx
                .prepare_cached(concat!(
                    "INSERT INTO n (k, v) VALUES ($1, 1) ",
                    "ON CONFLICT(k) DO UPDATE SET v = n.v + 1 RETURNING v"
                ))
                .await?;
            let mut queries = FuturesOrdered::new();
            for &account_id in batch.changes.keys() {
                let key = ValueClass::ChangeId.serialize(account_id, 0, 0, 0);
                let s = s.clone();
                let trx = &trx;
                queries.push_back(async move {
                    trx.query_one(&s, &[&key])
                        .await
                        .and_then(|row| row.try_get::<_, i64>(0))
                        .map(|change_id| (account_id, change_id as u64))
                });
            }
            while let Some(next) = queries.next().await {
                let (account_id, change_id) = next?;
                result.push_change_id(account_id, change_id);
            }
        }

        let mut pipeline = Pipeline::new(&trx);

        for op in batch.ops.iter() {
            match op {
                Operation::AccountId {
                    account_id: account_id_,
                } => {
                    account_id = *account_id_;
                    if has_changes {
                        change_id = result.set_current_change_id(account_id)?;
                    }
                }
                Operation::Collection {
                    collection: collection_,
                } => {
                    collection = u8::from(*collection_);
                }
                Operation::DocumentId {
                    document_id: document_id_,
                } => {
                    document_id = *document_id_;
                }
                Operation::Value { class, op } => {
                    let key = class.serialize(account_id, collection, document_id, 0);
                    let subspace = class.subspace(collection);
                    let table = char::from(subspace);

                    match op {
                        ValueOp::Set(value) => {
                            if subspace != SUBSPACE_REGISTRY_IDX {
                                let s = if let Some(exists) = asserted_values.get(&key) {
                                    if *exists {
                                        trx.prepare_cached(&format!(
                                            "UPDATE {} SET v = $2 WHERE k = $1",
                                            table
                                        ))
                                        .await?
                                    } else {
                                        trx.prepare_cached(&format!(
                                            "INSERT INTO {} (k, v) VALUES ($1, $2)",
                                            table
                                        ))
                                        .await?
                                    }
                                } else {
                                    trx.prepare_cached(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES ($1, $2) ",
                                            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v"
                                        ),
                                        table
                                    ))
                                    .await?
                                };

                                pipeline
                                    .execute(s, Params::KeyValue(key, Cow::Borrowed(value)), true)
                                    .await?;
                            } else {
                                let s = trx
                                    .prepare_cached(
                                        "INSERT INTO b (k) VALUES ($1) ON CONFLICT (k) DO NOTHING",
                                    )
                                    .await?;
                                pipeline.execute(s, Params::Key(key), false).await?;
                            }
                        }
                        ValueOp::SetFnc(set_op) => {
                            let value = (set_op.fnc)(&set_op.params, &result)?;

                            let s = if let Some(exists) = asserted_values.get(&key) {
                                if *exists {
                                    trx.prepare_cached(&format!(
                                        "UPDATE {} SET v = $2 WHERE k = $1",
                                        table
                                    ))
                                    .await?
                                } else {
                                    trx.prepare_cached(&format!(
                                        "INSERT INTO {} (k, v) VALUES ($1, $2)",
                                        table
                                    ))
                                    .await?
                                }
                            } else {
                                trx.prepare_cached(&format!(
                                    concat!(
                                        "INSERT INTO {} (k, v) VALUES ($1, $2) ",
                                        "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v"
                                    ),
                                    table
                                ))
                                .await?
                            };

                            pipeline
                                .execute(s, Params::KeyValue(key, Cow::Owned(value)), true)
                                .await?;
                        }
                        ValueOp::MergeFnc(merge_op) => {
                            pipeline.flush().await?;
                            let s = trx
                                .prepare_cached(&format!(
                                    "SELECT v FROM {} WHERE k = $1 FOR UPDATE",
                                    table
                                ))
                                .await?;
                            let (exists, merge_result) = trx
                                .query_opt(&s, &[&key])
                                .await?
                                .map(|row| {
                                    row.try_get::<_, &[u8]>(0)
                                        .map_err(CommitError::from)
                                        .and_then(|v| {
                                            (merge_op.fnc)(&merge_op.params, &result, Some(v))
                                                .map(|v| (true, v))
                                                .map_err(CommitError::from)
                                        })
                                })
                                .unwrap_or_else(|| {
                                    (merge_op.fnc)(&merge_op.params, &result, None)
                                        .map(|v| (false, v))
                                        .map_err(CommitError::from)
                                })?;

                            match merge_result {
                                MergeResult::Update(value) => {
                                    let s = if exists {
                                        trx.prepare_cached(&format!(
                                            "UPDATE {} SET v = $2 WHERE k = $1",
                                            table
                                        ))
                                        .await?
                                    } else {
                                        trx.prepare_cached(&format!(
                                            "INSERT INTO {} (k, v) VALUES ($1, $2)",
                                            table
                                        ))
                                        .await?
                                    };

                                    pipeline
                                        .execute(s, Params::KeyValue(key, Cow::Owned(value)), false)
                                        .await?;
                                }
                                MergeResult::Delete if exists => {
                                    let s = trx
                                        .prepare_cached(&format!(
                                            "DELETE FROM {} WHERE k = $1",
                                            table
                                        ))
                                        .await?;

                                    // Update asserted value
                                    if let Some(exists) = asserted_values.get_mut(&key) {
                                        *exists = false;
                                    }

                                    pipeline.execute(s, Params::Key(key), false).await?;
                                }
                                _ => (),
                            }
                        }
                        ValueOp::AtomicAdd(by) => {
                            if *by >= 0 {
                                let s = trx
                                    .prepare_cached(&format!(
                                        concat!(
                                            "INSERT INTO {} (k, v) VALUES ($1, $2) ",
                                            "ON CONFLICT(k) DO UPDATE SET v = {}.v + EXCLUDED.v"
                                        ),
                                        table, table
                                    ))
                                    .await?;
                                pipeline.execute(s, Params::KeyInt(key, *by), false).await?;
                            } else {
                                let s = trx
                                    .prepare_cached(&format!(
                                        "UPDATE {table} SET v = v + $1 WHERE k = $2"
                                    ))
                                    .await?;
                                pipeline.execute(s, Params::IntKey(*by, key), false).await?;
                            }
                        }
                        ValueOp::AddAndGet(by) => {
                            pipeline.flush().await?;
                            let s = trx
                                .prepare_cached(&format!(
                                    concat!(
                                    "INSERT INTO {} (k, v) VALUES ($1, $2) ",
                                    "ON CONFLICT(k) DO UPDATE SET v = {}.v + EXCLUDED.v RETURNING v"
                                ),
                                    table, table
                                ))
                                .await?;
                            result.push_counter_id(
                                trx.query_one(&s, &[&key, by])
                                    .await
                                    .and_then(|row| row.try_get::<_, i64>(0))?,
                            );
                        }
                        ValueOp::Clear => {
                            let s = trx
                                .prepare_cached(&format!("DELETE FROM {} WHERE k = $1", table))
                                .await?;

                            // Update asserted value
                            if let Some(exists) = asserted_values.get_mut(&key) {
                                *exists = false;
                            }

                            pipeline.execute(s, Params::Key(key), false).await?;
                        }
                    }
                }
                Operation::Index { field, key, set } => {
                    let key = IndexKey {
                        account_id,
                        collection,
                        document_id,
                        field: *field,
                        key,
                    }
                    .serialize(0);

                    let s = if *set {
                        trx.prepare_cached(
                            "INSERT INTO i (k) VALUES ($1) ON CONFLICT (k) DO NOTHING",
                        )
                        .await?
                    } else {
                        trx.prepare_cached("DELETE FROM i WHERE k = $1").await?
                    };
                    pipeline.execute(s, Params::Key(key), false).await?;
                }
                Operation::Log { collection, set } => {
                    let key = LogKey {
                        account_id,
                        collection: u8::from(*collection),
                        change_id,
                    }
                    .serialize(0);

                    let s = trx
                        .prepare_cached(concat!(
                            "INSERT INTO l (k, v) VALUES ($1, $2) ",
                            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v"
                        ))
                        .await?;

                    pipeline
                        .execute(s, Params::KeyValue(key, Cow::Borrowed(set)), false)
                        .await?;
                }
                Operation::AssertValue {
                    class,
                    assert_value,
                } => {
                    pipeline.flush().await?;
                    let key = class.serialize(account_id, collection, document_id, 0);
                    let table = char::from(class.subspace(collection));

                    let s = trx
                        .prepare_cached(&format!("SELECT v FROM {} WHERE k = $1 FOR UPDATE", table))
                        .await?;
                    let (exists, matches) = trx
                        .query_opt(&s, &[&key])
                        .await?
                        .map(|row| {
                            row.try_get::<_, &[u8]>(0)
                                .map_or((true, false), |v| (true, assert_value.matches(v)))
                        })
                        .unwrap_or_else(|| (false, assert_value.is_none()));
                    if !matches {
                        return Err(trc::StoreEvent::AssertValueFailed
                            .into_err()
                            .caused_by(trc::location!())
                            .into());
                    }
                    asserted_values.insert(key, exists);
                }
            }
        }

        pipeline.flush().await?;
        drop(pipeline);

        trx.commit().await.map(|_| result).map_err(Into::into)
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let limit = self.timeouts.maintenance;
        let result = tokio::time::timeout(limit, async {
            for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER, SUBSPACE_IN_MEMORY_COUNTER] {
                purge_table(&conn, char::from(subspace)).await?;
            }

            Ok(())
        })
        .await;
        bounded(conn, result, limit)
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let limit = self.timeouts.maintenance;
        let result = tokio::time::timeout(limit, async {
            let table = char::from(from.subspace());
            let mut from = from.serialize(0);
            let to = to.serialize(0);

            let delete = conn
                .prepare_cached(&format!("DELETE FROM {table} WHERE k >= $1 AND k < $2"))
                .await
                .map_err(into_error)?;

            match conn.execute(&delete, &[&from, &to]).await {
                Ok(_) => return Ok(()),
                Err(err) if is_timeout_error(&err) => (),
                Err(err) => return Err(into_error(err)),
            }

            let mut chunk_size = DELETE_CHUNK_SIZE;

            loop {
                let boundary = conn
                    .prepare_cached(&format!(
                        "SELECT k FROM {table} WHERE k >= $1 AND k < $2 ORDER BY k ASC LIMIT 1 OFFSET {chunk_size}"
                    ))
                    .await
                    .map_err(into_error)?;

                loop {
                    let next = match conn.query_opt(&boundary, &[&from, &to]).await {
                        Ok(next) => match next {
                            Some(row) => Some(row.try_get::<_, Vec<u8>>(0).map_err(into_error)?),
                            None => None,
                        },
                        Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                            chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
                            break;
                        }
                        Err(err) => return Err(into_error(err)),
                    };

                    match conn
                        .execute(&delete, &[&from, next.as_ref().unwrap_or(&to)])
                        .await
                    {
                        Ok(_) => (),
                        Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                            chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
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
        })
        .await;
        bounded(conn, result, limit)
    }
}

async fn purge_table(conn: &Object, table: char) -> trc::Result<()> {
    let s = conn
        .prepare_cached(&format!("DELETE FROM {table} WHERE v = 0"))
        .await
        .map_err(into_error)?;

    match conn.execute(&s, &[]).await {
        Ok(_) => return Ok(()),
        Err(err) if is_timeout_error(&err) => (),
        Err(err) => return Err(into_error(err)),
    }

    let purge = conn
        .prepare_cached(&format!(
            "DELETE FROM {table} WHERE v = 0 AND k >= $1 AND k < $2"
        ))
        .await
        .map_err(into_error)?;
    let purge_last = conn
        .prepare_cached(&format!("DELETE FROM {table} WHERE v = 0 AND k >= $1"))
        .await
        .map_err(into_error)?;
    let mut chunk_size = DELETE_CHUNK_SIZE;
    let mut from = Vec::new();

    loop {
        let boundary = conn
            .prepare_cached(&format!(
                "SELECT k FROM {table} WHERE k >= $1 ORDER BY k ASC LIMIT 1 OFFSET {chunk_size}"
            ))
            .await
            .map_err(into_error)?;

        loop {
            let next = match conn.query_opt(&boundary, &[&from]).await {
                Ok(next) => match next {
                    Some(row) => Some(row.try_get::<_, Vec<u8>>(0).map_err(into_error)?),
                    None => None,
                },
                Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                    chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
                    break;
                }
                Err(err) => return Err(into_error(err)),
            };

            let result = match &next {
                Some(next) => conn.execute(&purge, &[&from, next]).await,
                None => conn.execute(&purge_last, &[&from]).await,
            };

            match result {
                Ok(_) => (),
                Err(err) if is_timeout_error(&err) && chunk_size > MIN_DELETE_CHUNK_SIZE => {
                    chunk_size = (chunk_size / 2).max(MIN_DELETE_CHUNK_SIZE);
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
