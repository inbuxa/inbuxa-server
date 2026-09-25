/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Client-side limits on SQL queries.
//!
//! The pool timeouts bound getting a connection, not using one. A database
//! that stops answering while the TCP connection stays up (a paused
//! container, a hung server whose kernel still acknowledges keepalives)
//! left a query on a checked-out connection waiting for as long as it took.
//! A server-side statement_timeout can't help there: the server that would
//! enforce it is the one not answering. So each operation on a PostgreSQL
//! or MySQL connection runs under a time limit here, and a connection whose
//! operation ran out is closed rather than put back in the pool, since its
//! protocol state is unknown.
//!
//! Two limits:
//! - `query`, two minutes, for request-path work: reads, writes, blob
//!   transfers, search queries and document indexing. Those take
//!   milliseconds; two minutes leaves room for a large blob over a slow
//!   link and still ends a hang.
//! - `maintenance`, thirty minutes, for work that legitimately runs long in
//!   one statement: range deletes (account removal, purges), unindexing,
//!   and creating tables and indexes at startup.
//!
//! Iterating over a range (exports, reindexing, maintenance scans) can run
//! for hours, so there the `query` limit applies to each wait for the next
//! row instead of the whole scan.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryTimeouts {
    pub query: Duration,
    pub maintenance: Duration,
}

impl QueryTimeouts {
    pub const QUERY: Duration = Duration::from_secs(120);
    pub const MAINTENANCE: Duration = Duration::from_secs(30 * 60);
}

impl Default for QueryTimeouts {
    fn default() -> Self {
        Self {
            query: Self::QUERY,
            maintenance: Self::MAINTENANCE,
        }
    }
}

#[cfg(feature = "test_mode")]
impl crate::Store {
    /// Sets the query limits of a SQL store that was just built (tests only:
    /// the limits aren't configurable).
    pub fn with_query_timeouts(self, timeouts: QueryTimeouts) -> Self {
        match self {
            #[cfg(feature = "postgres")]
            crate::Store::PostgreSQL(mut store) => {
                std::sync::Arc::get_mut(&mut store)
                    .expect("store already shared")
                    .timeouts = timeouts;
                crate::Store::PostgreSQL(store)
            }
            #[cfg(feature = "mysql")]
            crate::Store::MySQL(mut store) => {
                std::sync::Arc::get_mut(&mut store)
                    .expect("store already shared")
                    .timeouts = timeouts;
                crate::Store::MySQL(store)
            }
            store => store,
        }
    }
}
