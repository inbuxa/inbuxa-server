/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    LocalStore,
    entry::{Entry, Liveness},
};
use std::sync::atomic::Ordering;

const SWEEP_INTERVAL: u64 = 30;

impl LocalStore {
    pub(super) fn reserve(&self, now: u64) -> trc::Result<()> {
        self.sweep_if_due(now);
        while self
            .state
            .len
            .try_update(Ordering::AcqRel, Ordering::Acquire, |len| {
                (len < self.max_entries).then_some(len + 1)
            })
            .is_err()
        {
            if !self.make_room(now) {
                return Err(trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("In-memory store is full"));
            }
        }
        Ok(())
    }

    #[inline]
    pub(super) fn release(&self) {
        self.state.len.fetch_sub(1, Ordering::AcqRel);
    }

    #[inline]
    pub(super) fn kill(&self, entry: &Entry) {
        if entry.mark_dead() {
            self.release();
        }
    }

    pub(super) fn kill_expired(&self, entry: &Entry, now: u64) -> bool {
        match entry.mark_dead_if_expired(now) {
            Liveness::Live => false,
            Liveness::Expired => {
                self.release();
                true
            }
            Liveness::Dead => true,
        }
    }

    pub(super) fn sweep(&self, now: u64) {
        self.entries
            .pin()
            .retain(|_, entry| !self.kill_expired(entry, now));
    }

    fn sweep_if_due(&self, now: u64) {
        let next_sweep = self.state.next_sweep.load(Ordering::Relaxed);
        if now >= next_sweep
            && self
                .state
                .next_sweep
                .compare_exchange(
                    next_sweep,
                    now.saturating_add(SWEEP_INTERVAL),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            self.sweep(now);
        }
    }

    #[cold]
    #[inline(never)]
    fn make_room(&self, now: u64) -> bool {
        let _eviction = self.eviction.lock();
        if self.len() < self.max_entries {
            return true;
        }

        let entries = self.entries.pin();
        let mut expired = false;
        let mut scores = Vec::with_capacity(self.len());
        entries.retain(|_, entry| {
            if self.kill_expired(entry, now) {
                expired = true;
                false
            } else {
                scores.extend(entry.eviction_score());
                true
            }
        });

        let target = self.max_entries - self.eviction_batch;
        let len = self.len();
        if len > target && !scores.is_empty() {
            let excess = len - target;
            let (threshold, ties_evicted, ties_total) = if excess < scores.len() {
                let (below, threshold, above) = scores.select_nth_unstable(excess - 1);
                let threshold = *threshold;
                let below_ties = below.iter().filter(|score| **score == threshold).count();
                let above_ties = above.iter().filter(|score| **score == threshold).count();
                (
                    threshold,
                    excess - (below.len() - below_ties),
                    below_ties + above_ties + 1,
                )
            } else {
                (u64::MAX, 0, 1)
            };

            let mut ties_stride = 0;
            entries.retain(|_, entry| {
                let evict = self.kill_expired(entry, now)
                    || match entry.eviction_score() {
                        Some(score) if score < threshold => true,
                        Some(score) if score == threshold => {
                            ties_stride += ties_evicted;
                            if ties_stride >= ties_total {
                                ties_stride -= ties_total;
                                true
                            } else {
                                false
                            }
                        }
                        _ => false,
                    };
                if evict {
                    self.kill(entry);
                }
                !evict
            });
        }

        expired || !scores.is_empty() || self.len() < self.max_entries
    }
}
