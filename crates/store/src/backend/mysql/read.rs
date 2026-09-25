/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{MysqlStore, bounded, discard, into_error, is_timeout_error, query_timeout_error};
use crate::{Deserialize, IterateParams, Key, ValueKey, write::ValueClass};
use futures::TryStreamExt;
use mysql_async::{Row, prelude::Queryable};

impl MysqlStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let mut conn = self.conn().await?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn
                .prep(format!(
                    "SELECT v FROM {} WHERE k = ?",
                    char::from(key.subspace())
                ))
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
                .prep(format!(
                    "SELECT 1 FROM {} WHERE k = ?",
                    char::from(key.subspace())
                ))
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
        let mut conn = self.conn().await?;
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
                format!("SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k ASC LIMIT 1")
            }
            (true, false) => {
                format!(
                    "SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k DESC LIMIT 1"
                )
            }
            (false, true) => {
                format!("SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k ASC")
            }
            (false, false) => {
                format!("SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k DESC")
            }
        };
        let s = match tokio::time::timeout(limit, conn.prep(&query)).await {
            Ok(s) => s.map_err(into_error)?,
            Err(_) => {
                discard(conn);
                return Err(query_timeout_error(limit));
            }
        };
        let mut from = begin;
        let mut stalled = false;
        let mut to = end;
        let mut resume_key = None;

        loop {
            let mut last_key = None;
            let mut timed_out = false;

            {
                let mut rows = match tokio::time::timeout(
                    limit,
                    conn.exec_stream::<Row, _, _>(&s, (from.clone(), to.clone())),
                )
                .await
                {
                    Ok(rows) => rows.map_err(into_error)?,
                    // Leaves the scan loop for the timeout below
                    Err(_) => break,
                };

                loop {
                    let next = match tokio::time::timeout(limit, rows.try_next()).await {
                        Ok(next) => next,
                        Err(_) => {
                            stalled = true;
                            break;
                        }
                    };
                    match next {
                        Ok(Some(mut row)) => {
                            let value = if params.values {
                                row.take_opt::<Vec<u8>, _>(1)
                                    .unwrap_or_else(|| Ok(vec![]))
                                    .map_err(into_error)?
                            } else {
                                vec![]
                            };
                            let key = row
                                .take_opt::<Vec<u8>, _>(0)
                                .unwrap_or_else(|| Ok(vec![]))
                                .map_err(into_error)?;

                            if resume_key.take().is_some_and(|resumed| resumed == key) {
                                continue;
                            }

                            if !cb(&key, &value)? {
                                return Ok(());
                            }

                            last_key = Some(key);
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

        discard(conn);
        Err(query_timeout_error(limit))
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into();
        let table = char::from(key.subspace());
        let key = key.serialize(0);
        let mut conn = self.conn().await?;
        let limit = self.timeouts.query;
        let result = tokio::time::timeout(limit, async {
            let s = conn
                .prep(format!("SELECT v FROM {table} WHERE k = ?"))
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
