/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! One mailbox create or rename at a time per account. A create or rename
//! checks the new name against the account's mailboxes and saves later, so
//! without it two sessions creating the same name at the same moment could
//! both pass the check and leave two mailboxes with one name. The lock lives
//! in the in-memory store, so it holds across a cluster. A write takes it
//! before it reads the account's mailboxes and keeps it until it has saved;
//! the lock is released when the guard is dropped, and one left behind by a
//! node that stopped expires on its own. A write holds at most one account's
//! lock, so two can't wait on each other.

use crate::{KV_LOCK_TASK, Server};
use std::time::Duration;

/// How long a lock outlives a write that never releases it.
const LOCK_SECONDS: u64 = 30;
/// How long to wait for another write to the same account, in all.
const WAIT_TRIES: u32 = 100;
const WAIT_STEP: Duration = Duration::from_millis(50);

/// What a write that couldn't get the lock is told.
pub const BUSY: &str = "Another change to this account's folders is being saved. Try again.";

fn key(account_id: u32) -> Vec<u8> {
    [b"mailbox-names:".as_slice(), &account_id.to_be_bytes()].concat()
}

/// Held while an account's mailbox names are checked and saved.
pub struct MailboxNamesLock {
    server: Server,
    account_id: u32,
}

impl Server {
    /// Takes the account's mailbox-name lock, waiting up to five seconds for
    /// a write that holds it. `None` when it's still held.
    pub async fn lock_mailbox_names(
        &self,
        account_id: u32,
    ) -> trc::Result<Option<MailboxNamesLock>> {
        let key = key(account_id);
        for _ in 0..WAIT_TRIES {
            if self
                .in_memory_store()
                .try_lock(KV_LOCK_TASK, &key, LOCK_SECONDS)
                .await?
            {
                return Ok(Some(MailboxNamesLock {
                    server: self.clone(),
                    account_id,
                }));
            }
            tokio::time::sleep(WAIT_STEP).await;
        }
        Ok(None)
    }
}

impl Drop for MailboxNamesLock {
    fn drop(&mut self) {
        // A failure, or no runtime to release it on, only leaves it to expire
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let server = self.server.clone();
        let account_id = self.account_id;
        runtime.spawn(async move {
            if let Err(err) = server
                .in_memory_store()
                .remove_lock(KV_LOCK_TASK, &key(account_id))
                .await
            {
                trc::error!(
                    err.details("Failed to release an account's mailbox-name lock")
                        .ctx(trc::Key::AccountId, account_id)
                );
            }
        });
    }
}
