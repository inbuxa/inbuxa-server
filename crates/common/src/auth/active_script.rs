/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::{AtomicU64, Ordering};

const VALUE_MASK: u64 = u32::MAX as u64;
const GENERATION: u64 = 1 << u32::BITS;
const UNKNOWN: u32 = u32::MAX;
const INACTIVE: u32 = u32::MAX - 1;

#[derive(Debug)]
pub struct ActiveScriptSlot(AtomicU64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedActiveScript {
    Known(Option<u32>),
    Unknown(ActiveScriptTicket),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveScriptTicket(u64);

impl ActiveScriptSlot {
    pub fn get(&self) -> CachedActiveScript {
        let state = self.0.load(Ordering::Relaxed);
        match (state & VALUE_MASK) as u32 {
            UNKNOWN => CachedActiveScript::Unknown(ActiveScriptTicket(state)),
            INACTIVE => CachedActiveScript::Known(None),
            document_id => CachedActiveScript::Known(Some(document_id)),
        }
    }

    pub fn fill(&self, ticket: ActiveScriptTicket, document_id: Option<u32>) {
        let value = match document_id {
            None => INACTIVE,
            Some(document_id) if document_id < INACTIVE => document_id,
            Some(_) => return,
        };
        let _ = self.0.compare_exchange(
            ticket.0,
            (ticket.0 & !VALUE_MASK) | u64::from(value),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    pub fn invalidate(&self) {
        self.0
            .update(Ordering::Relaxed, Ordering::Relaxed, |state| {
                (state & !VALUE_MASK).wrapping_add(GENERATION) | u64::from(UNKNOWN)
            });
    }
}

impl Default for ActiveScriptSlot {
    fn default() -> Self {
        ActiveScriptSlot(AtomicU64::new(u64::from(UNKNOWN)))
    }
}

impl Clone for ActiveScriptSlot {
    fn clone(&self) -> Self {
        ActiveScriptSlot::default()
    }
}

