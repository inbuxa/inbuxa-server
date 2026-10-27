/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::CommitError;
use crate::{
    Subspace,
    backend::postgres::{
        pool::{PgObject, RollbackOutcome},
        pooled::PooledConn,
        sql::SqlStatements,
    },
    write::CounterBound,
};
use deadpool_postgres::ClientWrapper;
use futures::future::{MaybeDone, maybe_done, poll_fn};
use std::{borrow::Cow, future::Future, pin::Pin, task::Poll, vec::IntoIter};
use tokio_postgres::{Client, Row, RowStream, Statement};

const BEGIN: &str = "BEGIN ISOLATION LEVEL READ COMMITTED";
const COMMIT: &str = "COMMIT";

pub(super) struct Flight<F: Future> {
    pending: IntoIter<Pin<Box<MaybeDone<F>>>>,
    #[cfg(stalwart_tests)]
    probes: Vec<crate::backend::postgres::probe::Statement>,
}

pub(super) struct Transaction<'s> {
    conn: PooledConn,
    in_transaction: bool,
    sql: &'s SqlStatements,
    statements: Vec<(Subspace, StatementKind)>,
    prepared: Vec<Statement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StatementKind {
    Insert,
    Update,
    Upsert,
    InsertPresence,
    Delete,
    DeleteMany,
    DeleteRange,
    Increment,
    Decrement,
    IncrementReturning,
    IncrementBounded,
    ReadForUpdate,
    ReadManyForUpdate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StatementId(usize);

pub(super) enum Param<'x> {
    Key,
    Value(Cow<'x, [u8]>),
    Add(i64),
    Subtract(i64),
    AddAndGet(i64),
    Bounded(CounterBound),
    Until(Cow<'x, [u8]>),
}

pub(super) enum Request<'r> {
    Begin,
    Commit,
    Counter {
        statement: &'r Statement,
        key: &'r [u8],
        by: i64,
    },
    Read {
        statement: &'r Statement,
        key: &'r [u8],
    },
    ReadMany {
        statement: &'r Statement,
        keys: &'r [&'r [u8]],
    },
    Write {
        statement: &'r Statement,
        key: &'r [u8],
        param: &'r Param<'r>,
    },
    WriteMany {
        statement: &'r Statement,
        keys: &'r [&'r [u8]],
    },
}

pub(super) enum Response {
    Done,
    Rows(u64),
    Counter(i64),
    Value(Option<Row>),
    Stream(RowStream),
}

impl<'s> Transaction<'s> {
    pub(super) fn new(object: PgObject, sql: &'s SqlStatements) -> Self {
        Transaction {
            conn: PooledConn::new(object),
            in_transaction: false,
            sql,
            statements: Vec::new(),
            prepared: Vec::new(),
        }
    }

    #[inline]
    pub(super) fn client(&self) -> &Client {
        &self.conn
    }

    #[inline]
    pub(super) fn in_transaction(&self) -> bool {
        self.in_transaction
    }

    pub(super) fn statement_id(&mut self, subspace: Subspace, kind: StatementKind) -> StatementId {
        let entry = (subspace, kind);
        StatementId(
            match self.statements.iter().position(|item| *item == entry) {
                Some(id) => id,
                None => {
                    self.statements.push(entry);
                    self.statements.len() - 1
                }
            },
        )
    }

    #[inline]
    pub(super) fn statement(&self, id: StatementId) -> &Statement {
        &self.prepared[id.0]
    }

    #[inline]
    pub(super) fn is_statement(
        &self,
        id: StatementId,
        subspace: Subspace,
        kind: StatementKind,
    ) -> bool {
        self.statements.get(id.0) == Some(&(subspace, kind))
    }

    #[inline]
    pub(super) fn statement_kind(&self, id: StatementId) -> StatementKind {
        self.statements[id.0].1
    }

    pub(super) async fn prepare(&mut self) -> Result<(), CommitError> {
        if self.prepared.len() < self.statements.len() {
            Box::pin(self.prepare_missing()).await?;
        }
        Ok(())
    }

    async fn prepare_missing(&mut self) -> Result<(), CommitError> {
        let client: &ClientWrapper = &self.conn;
        for &(subspace, kind) in self
            .statements
            .get(self.prepared.len()..)
            .unwrap_or_default()
        {
            self.prepared
                .push(client.prepare_cached(kind.text(self.sql, subspace)).await?);
        }
        Ok(())
    }

    #[inline]
    pub(super) fn begin(&mut self) {
        self.in_transaction = true;
        self.conn.set_detach(true);
    }

    #[inline]
    pub(super) fn commit_sent(&mut self) {
        self.in_transaction = false;
        self.conn.set_detach(false);
    }

    pub(super) fn rollback(&mut self) {
        if self.in_transaction {
            self.in_transaction = false;
            if self.conn.defer_rollback() {
                self.conn.set_detach(false);
            }
        }
    }

    pub(super) fn previous_rollback_failed(&mut self) -> bool {
        let failed = matches!(self.conn.rollback_outcome(), RollbackOutcome::Failed);
        if failed {
            #[cfg(stalwart_tests)]
            crate::backend::sql_fault::record_detection(
                crate::backend::sql_fault::Detection::Retry,
            );
            self.conn.set_detach(true);
        }
        failed
    }
}

impl StatementKind {
    fn text(self, sql: &SqlStatements, subspace: Subspace) -> &str {
        let stmts = sql.get(subspace);
        match self {
            StatementKind::Insert => &stmts.insert_value,
            StatementKind::Update => &stmts.update_value,
            StatementKind::Upsert => &stmts.upsert_value,
            StatementKind::InsertPresence => &stmts.insert_presence,
            StatementKind::Delete => &stmts.delete_key,
            StatementKind::DeleteMany => &stmts.delete_keys,
            StatementKind::DeleteRange => &stmts.delete_range,
            StatementKind::Increment => &stmts.increment,
            StatementKind::Decrement => &stmts.decrement,
            StatementKind::IncrementReturning => &stmts.increment_returning,
            StatementKind::IncrementBounded => &stmts.increment_bounded,
            StatementKind::ReadForUpdate => &stmts.get_value_for_update,
            StatementKind::ReadManyForUpdate => &stmts.get_values_for_update,
        }
    }
}

impl Param<'_> {
    #[inline]
    pub(super) fn value(&self) -> Option<&[u8]> {
        match self {
            Param::Value(value) => Some(value),
            _ => None,
        }
    }
}

impl<'r> Request<'r> {
    pub(super) async fn send(self, client: &'r Client) -> Result<Response, tokio_postgres::Error> {
        match self {
            Request::Begin => client.batch_execute(BEGIN).await.map(|_| Response::Done),
            Request::Commit => client.batch_execute(COMMIT).await.map(|_| Response::Done),
            Request::Counter { statement, key, by } => client
                .query_one(statement, &[&key, &by])
                .await?
                .try_get(0)
                .map(Response::Counter),
            Request::Read { statement, key } => client
                .query_opt(statement, &[&key])
                .await
                .map(Response::Value),
            Request::ReadMany { statement, keys } => client
                .query_raw(statement, [keys])
                .await
                .map(Response::Stream),
            Request::Write {
                statement,
                key,
                param,
            } => match param {
                Param::Key => client.execute(statement, &[&key]).await.map(Response::Rows),
                Param::Value(value) => client
                    .execute(statement, &[&key, &value.as_ref()])
                    .await
                    .map(Response::Rows),
                Param::Add(by) => client
                    .execute(statement, &[&key, by])
                    .await
                    .map(Response::Rows),
                Param::Subtract(by) => client
                    .execute(statement, &[by, &key])
                    .await
                    .map(Response::Rows),
                Param::AddAndGet(by) => client
                    .query_one(statement, &[&key, by])
                    .await?
                    .try_get(0)
                    .map(Response::Counter),
                Param::Bounded(bound) => client
                    .query_one(statement, &[&key, &bound.by, &bound.max])
                    .await?
                    .try_get(0)
                    .map(Response::Counter),
                Param::Until(to) => client
                    .execute(statement, &[&key, &to.as_ref()])
                    .await
                    .map(Response::Rows),
            },
            Request::WriteMany { statement, keys } => client
                .execute(statement, &[&keys])
                .await
                .map(Response::Rows),
        }
    }
}

impl Response {
    pub(super) fn done(self) -> Result<(), CommitError> {
        match self {
            Response::Done => Ok(()),
            _ => Err(unexpected_response()),
        }
    }

    pub(super) fn rows(self) -> Result<u64, CommitError> {
        match self {
            Response::Rows(rows) => Ok(rows),
            _ => Err(unexpected_response()),
        }
    }

    pub(super) fn counter(self) -> Result<i64, CommitError> {
        match self {
            Response::Counter(value) => Ok(value),
            _ => Err(unexpected_response()),
        }
    }

    pub(super) fn value(self) -> Result<Option<Row>, CommitError> {
        match self {
            Response::Value(row) => Ok(row),
            _ => Err(unexpected_response()),
        }
    }

    pub(super) fn stream(self) -> Result<RowStream, CommitError> {
        match self {
            Response::Stream(stream) => Ok(stream),
            _ => Err(unexpected_response()),
        }
    }
}

pub(super) fn dispatch<'r>(
    client: &'r Client,
    requests: impl Iterator<Item = Request<'r>>,
) -> Flight<impl Future<Output = Result<Response, tokio_postgres::Error>> + 'r> {
    #[cfg(stalwart_tests)]
    let mut probes = Vec::with_capacity(requests.size_hint().0);
    let pending = requests
        .map(|request| {
            #[cfg(stalwart_tests)]
            probes.push(request.probe());
            Box::pin(maybe_done(request.send(client)))
        })
        .collect::<Vec<_>>()
        .into_iter();

    Flight {
        pending,
        #[cfg(stalwart_tests)]
        probes,
    }
}

impl<F> Flight<F>
where
    F: Future<Output = Result<Response, tokio_postgres::Error>>,
{
    pub(super) async fn send(&mut self) -> Result<(), CommitError> {
        #[cfg(stalwart_tests)]
        crate::backend::postgres::probe::record_flight();
        #[cfg(stalwart_tests)]
        let mut probes = self.probes.iter();

        let pending = self.pending.as_mut_slice();
        let failed = poll_fn(|cx| {
            for future in pending.iter_mut() {
                if future.as_mut().poll(cx).is_ready()
                    && let Some(Err(_)) = future.as_mut().output_mut()
                {
                    return Poll::Ready(future.as_mut().take_output());
                }
                #[cfg(stalwart_tests)]
                if let Some(statement) = probes.next() {
                    crate::backend::postgres::probe::record(*statement);
                }
            }
            Poll::Ready(None)
        })
        .await;

        match failed {
            Some(Err(err)) => Err(err.into()),
            _ => Ok(()),
        }
    }

    pub(super) async fn next(&mut self) -> Result<Response, CommitError> {
        let mut future = self.pending.next().ok_or_else(unexpected_response)?;
        future.as_mut().await;
        future
            .as_mut()
            .take_output()
            .ok_or_else(unexpected_response)?
            .map_err(CommitError::from)
    }
}

#[cold]
fn unexpected_response() -> CommitError {
    CommitError::Internal(
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Unexpected pipelined response")
            .caused_by(trc::location!()),
    )
}

