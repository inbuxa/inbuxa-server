/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    ItemDelta, MailboxRow, MailboxRowsMemo, MessagesCache, NO_ID, RefreshState, SharedMailboxRows,
    UidNextMemo,
};
use std::{borrow::Cow, ptr, sync::Arc};
use tokio::sync::OnceCell;

pub const MAX_ITEM_DELTAS: usize = 8;
pub const MAX_DELTA_IDS: usize = 4096;
pub const MIN_SHARED_ROWS: usize = 16_384;
pub const MAX_SHARED_MAILBOXES: usize = 4;
pub const SHARED_ROWS_WEIGHT_DIVISOR: u64 = 4;

impl RefreshState {
    pub fn advance(&self, delta: ItemDelta) -> RefreshState {
        let mut total = delta.document_ids.len();
        let mut from_change_id = delta.from_change_id;
        let mut kept = 0;
        for older in self.deltas.iter().rev().take(MAX_ITEM_DELTAS - 1) {
            total += older.document_ids.len();
            if older.to_change_id != from_change_id || total > MAX_DELTA_IDS {
                break;
            }
            from_change_id = older.from_change_id;
            kept += 1;
        }

        let carried = self
            .deltas
            .get(self.deltas.len() - kept..)
            .unwrap_or_default();
        let mut deltas = Vec::with_capacity(carried.len() + 1);
        deltas.extend_from_slice(carried);
        deltas.push(delta);

        RefreshState {
            deltas: deltas.into_boxed_slice(),
            uid_next: UidNextMemo::default(),
            mailbox_rows: Arc::default(),
        }
    }

    pub fn with_new_uid_next(&self) -> RefreshState {
        RefreshState {
            deltas: self.deltas.clone(),
            uid_next: UidNextMemo::default(),
            mailbox_rows: self.mailbox_rows.clone(),
        }
    }

    pub fn changed_items(&self, from_change_id: u64, to_change_id: u64) -> Option<Cow<'_, [u32]>> {
        let start = self
            .deltas
            .iter()
            .position(|delta| delta.from_change_id == from_change_id)?;
        let chain = self.deltas.get(start..)?;
        let mut next_change_id = from_change_id;
        for delta in chain {
            if delta.from_change_id != next_change_id {
                return None;
            }
            next_change_id = delta.to_change_id;
        }
        if next_change_id != to_change_id {
            return None;
        }

        match chain {
            [delta] => Some(Cow::Borrowed(&delta.document_ids)),
            _ => {
                let mut ids = Vec::with_capacity(
                    chain
                        .iter()
                        .map(|delta| delta.document_ids.len())
                        .sum::<usize>(),
                );
                for delta in chain {
                    ids.extend_from_slice(&delta.document_ids);
                }
                ids.sort_unstable();
                ids.dedup();
                Some(Cow::Owned(ids))
            }
        }
    }
}

impl ItemDelta {
    pub fn new(from_change_id: u64, to_change_id: u64, document_ids: &[u32]) -> Option<Self> {
        (document_ids.len() <= MAX_DELTA_IDS).then(|| ItemDelta {
            from_change_id,
            to_change_id,
            document_ids: Arc::from(document_ids),
        })
    }
}

impl UidNextMemo {
    pub async fn get_or_read<F, Fut>(&self, mailbox_id: u32, read: F) -> trc::Result<u32>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = trc::Result<u32>>,
    {
        let cell = {
            let mut values = self.values.lock();
            let index = values.partition_point(|(id, _)| *id < mailbox_id);
            match values.get(index) {
                Some((id, cell)) if *id == mailbox_id => Arc::clone(cell),
                _ => {
                    let cell = Arc::new(OnceCell::new());
                    values.insert(index, (mailbox_id, Arc::clone(&cell)));
                    cell
                }
            }
        };
        cell.get_or_try_init(read).await.copied()
    }
}

impl MailboxRow {
    #[inline(always)]
    pub fn is_live(&self) -> bool {
        self.id != NO_ID
    }

    pub fn bytes_of(rows: usize) -> u64 {
        (rows * size_of::<MailboxRow>()) as u64
    }
}

impl MailboxRowsMemo {
    pub fn get_or_build(
        &self,
        emails: &Arc<MessagesCache>,
        mailbox_id: u32,
        build: impl FnOnce() -> Vec<MailboxRow>,
    ) -> Arc<Vec<MailboxRow>> {
        let shared = self
            .entries
            .lock()
            .iter()
            .find(|entry| entry.mailbox_id == mailbox_id && entry.is_of(emails))
            .map(|entry| entry.rows.clone());
        if let Some(rows) = shared {
            return rows;
        }

        let mut rows = build();
        if rows.len() < MIN_SHARED_ROWS {
            return Arc::new(rows);
        }

        let mut entries = self.entries.lock();
        entries.retain(|entry| entry.is_of(emails));
        if let Some(entry) = entries.iter().find(|entry| entry.mailbox_id == mailbox_id) {
            return entry.rows.clone();
        }
        let is_full = entries.len() >= MAX_SHARED_MAILBOXES;
        let kept = entries
            .iter()
            .skip(usize::from(is_full))
            .map(SharedMailboxRows::bytes)
            .sum::<u64>();
        if kept + MailboxRow::bytes_of(rows.len()) > emails.size / SHARED_ROWS_WEIGHT_DIVISOR {
            return Arc::new(rows);
        }
        if is_full {
            entries.remove(0);
        }
        rows.shrink_to_fit();
        let rows = Arc::new(rows);
        entries.push(SharedMailboxRows {
            mailbox_id,
            emails: Arc::downgrade(emails),
            rows: rows.clone(),
        });
        rows
    }
}

impl SharedMailboxRows {
    fn bytes(&self) -> u64 {
        MailboxRow::bytes_of(self.rows.len())
    }

    #[inline(always)]
    fn is_of(&self, emails: &Arc<MessagesCache>) -> bool {
        ptr::eq(self.emails.as_ptr(), Arc::as_ptr(emails))
    }
}

