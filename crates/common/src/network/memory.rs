/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

pub const MEMORY_STEP: u64 = 1024 * 1024;
pub const MEMORY_RETRY_AFTER: u64 = 5;
const RESERVATION_GRANULE: u64 = 64 * 1024;
const CLASS_FLOOR_SHARE: u64 = 4;
const SOFT_LIMIT_PERCENT: u64 = 75;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryClass {
    SmtpInbound,
    Read,
}

#[derive(Debug, Default, Clone)]
#[repr(transparent)]
pub struct MemoryBudget(Arc<[ClassCounter; 2]>);

#[derive(Debug, Default)]
#[repr(align(128))]
struct ClassCounter(AtomicU64);

#[derive(Debug)]
pub struct MemoryReservation {
    budget: MemoryBudget,
    class: MemoryClass,
    limit: u64,
    reserved: u64,
}

#[derive(Debug)]
pub struct ReservationScope<'x> {
    reservation: &'x mut MemoryReservation,
    start: u64,
    committed: bool,
}

impl MemoryClass {
    fn index(self) -> usize {
        match self {
            MemoryClass::SmtpInbound => 0,
            MemoryClass::Read => 1,
        }
    }

    fn other(self) -> Self {
        match self {
            MemoryClass::SmtpInbound => MemoryClass::Read,
            MemoryClass::Read => MemoryClass::SmtpInbound,
        }
    }
}

impl MemoryBudget {
    pub fn reservation(&self, class: MemoryClass, limit: u64) -> MemoryReservation {
        MemoryReservation {
            budget: self.clone(),
            class,
            limit,
            reserved: 0,
        }
    }

    pub fn is_accepting(&self, class: MemoryClass, limit: u64) -> bool {
        self.used(class)
            < class_capacity(limit, self.used(class.other())) / 100 * SOFT_LIMIT_PERCENT
    }

    pub fn used(&self, class: MemoryClass) -> u64 {
        self.counter(class).load(Ordering::SeqCst)
    }

    fn counter(&self, class: MemoryClass) -> &AtomicU64 {
        &self.0[class.index()].0
    }
}

impl MemoryReservation {
    pub fn reserve_to(&mut self, bytes: u64) -> bool {
        if bytes <= self.reserved {
            return true;
        }

        let delta = (bytes - self.reserved).next_multiple_of(RESERVATION_GRANULE);
        let counter = self.budget.counter(self.class);
        let previous = counter.fetch_add(delta, Ordering::SeqCst);
        let other = self.budget.used(self.class.other());
        if previous.saturating_add(delta) <= class_capacity(self.limit, other)
            || previous == self.reserved
        {
            self.reserved += delta;
            true
        } else {
            counter.fetch_sub(delta, Ordering::SeqCst);
            false
        }
    }

    pub fn try_reserve_to(&mut self, bytes: u64) -> trc::Result<()> {
        if self.reserve_to(bytes) {
            Ok(())
        } else {
            Err(self.budget_error(bytes))
        }
    }

    pub fn try_reserve_within_limit(&mut self, bytes: u64) -> trc::Result<()> {
        if bytes <= self.limit && self.reserve_to(bytes) {
            Ok(())
        } else {
            Err(self.budget_error(bytes))
        }
    }

    #[cold]
    fn budget_error(&self, bytes: u64) -> trc::Error {
        trc::LimitEvent::MemoryBudget
            .into_err()
            .ctx(trc::Key::Size, bytes)
            .ctx(trc::Key::Limit, self.limit)
    }

    pub fn scope(&mut self) -> ReservationScope<'_> {
        ReservationScope {
            start: self.reserved,
            reservation: self,
            committed: false,
        }
    }

    pub fn shrink_to(&mut self, bytes: u64) {
        let keep = bytes.next_multiple_of(RESERVATION_GRANULE);
        if keep < self.reserved {
            self.budget
                .counter(self.class)
                .fetch_sub(self.reserved - keep, Ordering::SeqCst);
            self.reserved = keep;
        }
    }

    pub fn reserved(&self) -> u64 {
        self.reserved
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

impl ReservationScope<'_> {
    pub fn try_reserve_extra(&mut self, extra: u64) -> trc::Result<()> {
        self.reservation
            .try_reserve_within_limit(self.start.saturating_add(extra))
    }

    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for ReservationScope<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.reservation.shrink_to(self.start);
        }
    }
}

impl Drop for MemoryReservation {
    fn drop(&mut self) {
        if self.reserved > 0 {
            self.budget
                .counter(self.class)
                .fetch_sub(self.reserved, Ordering::SeqCst);
        }
    }
}

fn class_capacity(limit: u64, other_used: u64) -> u64 {
    let floor = limit / CLASS_FLOOR_SHARE;
    limit.saturating_sub(other_used.max(floor)).max(floor)
}

