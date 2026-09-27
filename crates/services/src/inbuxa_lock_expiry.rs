/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Ends a locked account's delegations at their `until` (AL-5), rather than
//! at the next daily sweep. Each node sleeps until the soonest `until`, wakes
//! early when a lock is written here, and checks at least hourly for locks
//! written on other nodes. One node re-applies each lock; the others find it
//! claimed.

use common::{BuildServer, Inner, KV_LOCK_TASK, Server};
use inbuxa_features::lock;
use std::{sync::Arc, time::Duration};
use store::write::now;

/// The longest the timer sleeps, so an `until` set on another node is seen.
const CEILING: u64 = 3600;

pub fn spawn_lock_expiry(inner: Arc<Inner>) {
    tokio::spawn(async move {
        // Since boot: anything that ended while the server was down
        let mut checked = 0;
        loop {
            let server = inner.build_server();
            let now = now();
            let wait = match lock::all(server.store()).await {
                Ok(locks) => {
                    for account_id in lock::ended_between(&locks, checked, now).collect::<Vec<_>>()
                    {
                        end_delegations(&server, account_id).await;
                    }
                    checked = now;
                    lock::next_until(&locks, now)
                        .map_or(CEILING, |until| (until - now).min(CEILING))
                }
                Err(err) => {
                    trc::error!(err.details("Failed to read account locks for their end dates"));
                    60
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(wait.max(1))) => {}
                _ = lock::UNTIL_CHANGED.notified() => {}
            }
        }
    });
}

async fn end_delegations(server: &Server, account_id: u32) {
    let key = [b"lock-until:".as_slice(), &account_id.to_be_bytes()].concat();
    match server
        .in_memory_store()
        .try_lock(KV_LOCK_TASK, &key, 60)
        .await
    {
        Ok(true) => {
            if let Err(err) = email::inbuxa_lock::reconcile(server, account_id).await {
                trc::error!(
                    err.account_id(account_id)
                        .details("Failed to end a delegation at its date")
                );
            }
        }
        Ok(false) => {}
        Err(err) => {
            trc::error!(err.details("Failed to claim a delegation's end"));
        }
    }
}
