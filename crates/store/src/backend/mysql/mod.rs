/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::backend::query_timeout::QueryTimeouts;
use crate::{
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, FileSearchField, SearchField,
        TracingSearchField,
    },
    write::SearchIndex,
};
use mysql_async::Pool;
use std::{fmt::Display, time::Duration};

pub mod blob;
pub mod lookup;
pub mod main;
pub mod read;
pub mod search;
pub mod write;

pub struct MysqlStore {
    pub(crate) conn_pool: Pool,
    /// inbuxa: client-side query limits (see backend::query_timeout)
    pub(crate) timeouts: QueryTimeouts,
}

/// inbuxa: how long a request waits for a pooled connection (including
/// opening one). mysql_async's pool has no wait timeout, so upstream waited
/// forever when the server stopped answering.
pub(crate) const POOL_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// inbuxa: idle time before TCP keepalive probes start.
pub(crate) const POOL_KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

impl MysqlStore {
    /// inbuxa: a pooled connection, or an error once POOL_WAIT_TIMEOUT has
    /// passed without one.
    pub(crate) async fn conn(&self) -> trc::Result<mysql_async::Conn> {
        pool_conn(&self.conn_pool, POOL_WAIT_TIMEOUT).await
    }
}

pub(crate) async fn pool_conn(
    pool: &Pool,
    wait: std::time::Duration,
) -> trc::Result<mysql_async::Conn> {
    match tokio::time::timeout(wait, pool.get_conn()).await {
        Ok(result) => result.map_err(into_error),
        Err(_) => Err(trc::StoreEvent::MysqlError
            .reason("Timed out waiting for a database connection")
            .details(format!("No connection within {} s", wait.as_secs()))),
    }
}

/// inbuxa: the error for an operation that ran past its time limit.
pub(crate) fn query_timeout_error(limit: Duration) -> trc::Error {
    trc::StoreEvent::MysqlError
        .reason("Query timed out")
        .details(format!(
            "No answer from the database within {} s",
            limit.as_secs()
        ))
}

/// inbuxa: ends an operation run on `conn` under `limit`. When it ran out,
/// the connection is closed rather than returned to the pool: a query may
/// still be in flight on it, or a transaction open. Conn::disconnect marks
/// the connection closed before it sends anything, so even when the server
/// doesn't answer and the attempt is dropped, the pool discards it instead
/// of waiting to clean it up.
pub(crate) fn bounded<T>(
    conn: mysql_async::Conn,
    result: Result<trc::Result<T>, tokio::time::error::Elapsed>,
    limit: Duration,
) -> trc::Result<T> {
    match result {
        Ok(result) => result,
        Err(_) => {
            discard(conn);
            Err(query_timeout_error(limit))
        }
    }
}

/// inbuxa: closes a connection whose state is unknown (see bounded).
pub(crate) fn discard(conn: mysql_async::Conn) {
    tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(1), conn.disconnect()).await;
    });
}

#[inline(always)]
pub(crate) fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::MysqlError.reason(err)
}

const ER_LOCK_WAIT_TIMEOUT: u16 = 1205;
const ER_STATEMENT_TIMEOUT: u16 = 1969;
const ER_QUERY_TIMEOUT: u16 = 3024;

pub(crate) const DELETE_CHUNK_SIZE: usize = 1000;
pub(crate) const MIN_DELETE_CHUNK_SIZE: usize = 10;

#[inline(always)]
pub(crate) fn is_timeout_error(err: &mysql_async::Error) -> bool {
    matches!(err, mysql_async::Error::Server(err)
        if matches!(
            err.code,
            ER_LOCK_WAIT_TIMEOUT | ER_STATEMENT_TIMEOUT | ER_QUERY_TIMEOUT
        )
    )
}

impl SearchIndex {
    pub fn mysql_table(&self) -> &'static str {
        match self {
            SearchIndex::Email => "s_email",
            SearchIndex::Calendar => "s_cal",
            SearchIndex::Contacts => "s_card",
            SearchIndex::File => "s_file",
            SearchIndex::Tracing => "s_trace",
            SearchIndex::InMemory => "",
        }
    }
}

trait MysqlSearchField {
    fn column(&self) -> &'static str;
    fn column_type(&self) -> &'static str;
}

impl MysqlSearchField for EmailSearchField {
    fn column(&self) -> &'static str {
        match self {
            EmailSearchField::From => "fadr",
            EmailSearchField::To => "tadr",
            EmailSearchField::Cc => "cc",
            EmailSearchField::Bcc => "bcc",
            EmailSearchField::Subject => "subj",
            EmailSearchField::Body => "body",
            EmailSearchField::Attachment => "atta",
            EmailSearchField::ReceivedAt => "rcvd",
            EmailSearchField::SentAt => "sent",
            EmailSearchField::Size => "size",
            EmailSearchField::HasAttachment => "hatt",
            EmailSearchField::Headers => "hdrs",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            EmailSearchField::ReceivedAt | EmailSearchField::SentAt => "BIGINT",
            EmailSearchField::Size => "INT",
            EmailSearchField::HasAttachment => "BOOLEAN",
            EmailSearchField::Headers => "JSON",
            EmailSearchField::From => "TEXT",
            EmailSearchField::To => "TEXT",
            EmailSearchField::Cc => "TEXT",
            EmailSearchField::Bcc => "TEXT",
            EmailSearchField::Subject => "TEXT",
            EmailSearchField::Body => "MEDIUMTEXT",
            EmailSearchField::Attachment => "MEDIUMTEXT",
        }
    }
}

impl MysqlSearchField for CalendarSearchField {
    fn column(&self) -> &'static str {
        match self {
            CalendarSearchField::Title => "titl",
            CalendarSearchField::Description => "dscd",
            CalendarSearchField::Location => "locn",
            CalendarSearchField::Owner => "ownr",
            CalendarSearchField::Attendee => "atnd",
            CalendarSearchField::Start => "strt",
            CalendarSearchField::Uid => "uid",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            CalendarSearchField::Start => "BIGINT NOT NULL",
            _ => "TEXT",
        }
    }
}

impl MysqlSearchField for ContactSearchField {
    fn column(&self) -> &'static str {
        match self {
            ContactSearchField::Member => "mmbr",
            ContactSearchField::Name => "name",
            ContactSearchField::Nickname => "nick",
            ContactSearchField::Organization => "orgn",
            ContactSearchField::Email => "eml",
            ContactSearchField::Phone => "phon",
            ContactSearchField::OnlineService => "olsv",
            ContactSearchField::Address => "addr",
            ContactSearchField::Note => "note",
            ContactSearchField::Kind => "kind",
            ContactSearchField::Uid => "uid",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            ContactSearchField::Kind | ContactSearchField::Uid => "TEXT",
            _ => "TEXT",
        }
    }
}

impl MysqlSearchField for FileSearchField {
    fn column(&self) -> &'static str {
        match self {
            FileSearchField::Name => "name",
            FileSearchField::Content => "body",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            FileSearchField::Name => "TEXT",
            FileSearchField::Content => "MEDIUMTEXT",
        }
    }
}
impl MysqlSearchField for TracingSearchField {
    fn column(&self) -> &'static str {
        match self {
            TracingSearchField::QueueId => "qid",
            TracingSearchField::EventType => "etyp",
            TracingSearchField::Keywords => "kwds",
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            TracingSearchField::EventType => "BIGINT",
            TracingSearchField::QueueId => "BIGINT",
            TracingSearchField::Keywords => "TEXT",
        }
    }
}

impl MysqlSearchField for SearchField {
    fn column(&self) -> &'static str {
        match self {
            SearchField::AccountId => "accid",
            SearchField::DocumentId => "docid",
            SearchField::Id => "id",
            SearchField::Email(field) => field.column(),
            SearchField::Calendar(field) => field.column(),
            SearchField::Contact(field) => field.column(),
            SearchField::File(field) => field.column(),
            SearchField::Tracing(field) => field.column(),
        }
    }

    fn column_type(&self) -> &'static str {
        match self {
            SearchField::AccountId => "INT NOT NULL",
            SearchField::DocumentId => "INT NOT NULL",
            SearchField::Id => "BIGINT NOT NULL",
            SearchField::Email(field) => field.column_type(),
            SearchField::Calendar(field) => field.column_type(),
            SearchField::Contact(field) => field.column_type(),
            SearchField::File(field) => field.column_type(),
            SearchField::Tracing(field) => field.column_type(),
        }
    }
}
