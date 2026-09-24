/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{PostgresStore, bounded, into_error, is_timeout_error, query_timeout_error};
use crate::{
    Deserialize, IterateParams, Key, ValueKey, backend::postgres::into_pool_error,
    write::ValueClass,
};
use futures::{TryStreamExt, pin_mut};

impl PostgresStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn
                .prepare_cached(&format!(
                    "SELECT v FROM {} WHERE k = $1",
                    char::from(key.subspace())
                ))
                .await
                .map_err(into_error)?;
            let key = key.serialize(0);
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
        })
        .await;
        bounded(conn, result, limit)
    }

    pub(crate) async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn
                .prepare_cached(&format!(
                    "SELECT 1 FROM {} WHERE k = $1",
                    char::from(key.subspace())
                ))
                .await
                .map_err(into_error)?;
            let key = key.serialize(0);
            conn.query_opt(&s, &[&key])
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
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let table = char::from(params.begin.subspace());
        let begin = params.begin.serialize(0);
        let end = params.end.serialize(0);
        let keys = if params.values { "k, v" } else { "k" };

        // inbuxa: a scan may run for hours, so the query limit bounds each
        // wait for the database (preparing, the query starting, the next
        // row) rather than the scan. A wait that runs out closes the
        // connection.
        let limit = self.timeouts.query;
        let query = match (params.first, params.ascending) {
            (true, true) => {
                format!(
                    "SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k ASC LIMIT 1"
                )
            }
            (true, false) => {
                format!(
                    "SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k DESC LIMIT 1"
                )
            }
            (false, true) => {
                format!("SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k ASC")
            }
            (false, false) => {
                format!("SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k DESC")
            }
        };
        let s = match tokio::time::timeout(limit, conn.prepare_cached(&query)).await {
            Ok(s) => s.map_err(into_error)?,
            Err(_) => {
                drop(deadpool_postgres::Object::take(conn));
                return Err(query_timeout_error(limit));
            }
        };
        let mut from = begin;
        let mut to = end;
        let mut resume_key: Option<Vec<u8>> = None;

        let mut stalled = false;

        loop {
            let mut last_key = None;
            let mut timed_out = false;

            {
                let rows =
                    match tokio::time::timeout(limit, conn.query_raw(&s, &[&from, &to])).await {
                        Ok(rows) => rows.map_err(into_error)?,
                        // Leaves the scan loop for the timeout below
                        Err(_) => break,
                    };

                pin_mut!(rows);

                loop {
                    let next = match tokio::time::timeout(limit, rows.try_next()).await {
                        Ok(next) => next,
                        Err(_) => {
                            stalled = true;
                            break;
                        }
                    };
                    match next {
                        Ok(Some(row)) => {
                            let key = row.try_get::<_, &[u8]>(0).map_err(into_error)?;
                            let value = if params.values {
                                row.try_get::<_, &[u8]>(1).map_err(into_error)?
                            } else {
                                b"".as_slice()
                            };

                            if resume_key.take().is_some_and(|resumed| resumed == key) {
                                continue;
                            }

                            if !cb(key, value)? {
                                return Ok(());
                            }

                            last_key = Some(key.to_vec());
                        }
                        Ok(None) => break,
                        Err(err) => {
                            if params.first || last_key.is_none() || !is_timeout_error(&err) {
                                return Err(into_error(err));
                            }
                            timed_out = true;
                            break;
                        }
                    }
                }
            }

            if stalled {
                break;
            }

            match last_key {
                Some(last_key) if timed_out => {
                    if params.ascending {
                        from.clone_from(&last_key);
                    } else {
                        to.clone_from(&last_key);
                    }
                    resume_key = Some(last_key);
                }
                _ => return Ok(()),
            }
        }

        drop(deadpool_postgres::Object::take(conn));
        Err(query_timeout_error(limit))
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into();
        let table = char::from(key.subspace());
        let key = key.serialize(0);

        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn
                .prepare_cached(&format!("SELECT v FROM {table} WHERE k = $1"))
                .await
                .map_err(into_error)?;
            match conn.query_opt(&s, &[&key]).await {
                Ok(Some(row)) => row.try_get(0).map_err(into_error),
                Ok(None) => Ok(0),
                Err(e) => Err(into_error(e)),
            }
        })
        .await;
        bounded(conn, result, limit)
    }
}
