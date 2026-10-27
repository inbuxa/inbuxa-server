/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ThrottleKey;
use registry::schema::structs::Rate;
use std::{
    hash::Hasher,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
};
use store::dispatch::lookup::RateWindow;

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct ConcurrencyLimiter(Arc<ConcurrencyLimiterInner>);

#[derive(Debug, Default)]
pub struct ConcurrencyLimiterInner {
    max_concurrent: u64,
    concurrent: AtomicU64,
}

#[derive(Debug, Default)]
pub struct AccountLimits {
    concurrency: [AccountConcurrency; AccountLimit::COUNT],
    rates: [RateCounter; AccountRate::COUNT],
    enabled: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountLimit {
    HttpRequests = 0,
    ImapRequests = 1,
    Uploads = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountRate {
    Http = 0,
    Imap = 1,
}

#[derive(Debug, Default)]
struct AccountConcurrency {
    max_concurrent: u32,
    concurrent: AtomicU32,
}

pub struct InFlight(InFlightSlot);

enum InFlightSlot {
    Limiter(Arc<ConcurrencyLimiterInner>),
    Account(Arc<AccountLimits>, AccountLimit),
    Untracked,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        match &self.0 {
            InFlightSlot::Limiter(limiter) => {
                limiter.concurrent.fetch_sub(1, Ordering::Relaxed);
            }
            InFlightSlot::Account(limits, limit) => {
                limits.concurrency[*limit as usize]
                    .concurrent
                    .fetch_sub(1, Ordering::Relaxed);
            }
            InFlightSlot::Untracked => {}
        }
    }
}

impl AccountConcurrency {
    fn new(max_concurrent: u64) -> Self {
        AccountConcurrency {
            max_concurrent: u32::try_from(max_concurrent).unwrap_or(u32::MAX),
            concurrent: AtomicU32::new(0),
        }
    }

    #[inline]
    fn try_acquire(&self) -> bool {
        if self.concurrent.load(Ordering::Relaxed) < self.max_concurrent {
            self.concurrent.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: u64) -> Self {
        ConcurrencyLimiter(Arc::new(ConcurrencyLimiterInner {
            max_concurrent,
            concurrent: AtomicU64::new(0),
        }))
    }

    pub fn is_allowed(&self) -> LimiterResult {
        if self.0.concurrent.load(Ordering::Relaxed) < self.0.max_concurrent {
            // Return in-flight request
            self.0.concurrent.fetch_add(1, Ordering::Relaxed);
            LimiterResult::Allowed(InFlight(InFlightSlot::Limiter(self.0.clone())))
        } else {
            LimiterResult::Forbidden
        }
    }

    pub fn check_is_allowed(&self) -> bool {
        self.0.concurrent.load(Ordering::Relaxed) < self.0.max_concurrent
    }

    pub fn is_active(&self) -> bool {
        self.0.concurrent.load(Ordering::Relaxed) > 0
    }

    pub fn max_concurrent(&self) -> u64 {
        self.0.max_concurrent
    }
}

impl AccountLimit {
    const COUNT: usize = 3;
}

impl AccountRate {
    const COUNT: usize = 2;
}

impl AccountLimits {
    pub fn new(
        concurrency: [Option<u64>; AccountLimit::COUNT],
        rates: [bool; AccountRate::COUNT],
    ) -> Option<Arc<Self>> {
        let mut limits = AccountLimits::default();
        for (bit, (max_concurrent, limiter)) in concurrency
            .into_iter()
            .zip(&mut limits.concurrency)
            .enumerate()
        {
            if let Some(max_concurrent) = max_concurrent {
                *limiter = AccountConcurrency::new(max_concurrent);
                limits.enabled |= 1 << bit;
            }
        }
        for (bit, enabled) in rates.into_iter().enumerate() {
            if enabled {
                limits.enabled |= 1 << (AccountLimit::COUNT + bit);
            }
        }
        (limits.enabled != 0).then(|| Arc::new(limits))
    }

    #[inline]
    fn has_limit(&self, limit: AccountLimit) -> bool {
        self.enabled & (1 << limit as u8) != 0
    }

    pub fn is_allowed(self: &Arc<Self>, limit: AccountLimit) -> LimiterResult {
        if !self.has_limit(limit) {
            LimiterResult::Disabled
        } else if self.concurrency[limit as usize].try_acquire() {
            LimiterResult::Allowed(InFlight(InFlightSlot::Account(self.clone(), limit)))
        } else {
            LimiterResult::Forbidden
        }
    }

    pub fn max_concurrent(&self, limit: AccountLimit) -> u64 {
        if self.has_limit(limit) {
            u64::from(self.concurrency[limit as usize].max_concurrent)
        } else {
            0
        }
    }

    #[inline]
    pub fn rate_counter(&self, rate: AccountRate) -> Option<&RateCounter> {
        (self.enabled & (1 << (AccountLimit::COUNT + rate as usize)) != 0)
            .then(|| &self.rates[rate as usize])
    }
}

impl InFlight {
    pub fn num_concurrent(&self) -> u64 {
        match &self.0 {
            InFlightSlot::Limiter(limiter) => limiter.concurrent.load(Ordering::Relaxed),
            InFlightSlot::Account(limits, limit) => u64::from(
                limits.concurrency[*limit as usize]
                    .concurrent
                    .load(Ordering::Relaxed),
            ),
            InFlightSlot::Untracked => 0,
        }
    }
}

pub enum LimiterResult {
    Allowed(InFlight),
    Forbidden,
    Disabled,
}

impl From<LimiterResult> for Option<InFlight> {
    fn from(result: LimiterResult) -> Self {
        match result {
            LimiterResult::Allowed(in_flight) => Some(in_flight),
            LimiterResult::Forbidden => None,
            LimiterResult::Disabled => Some(InFlight(InFlightSlot::Untracked)),
        }
    }
}

#[derive(Debug, Default)]
#[repr(transparent)]
pub struct RateCounter(AtomicU64);

#[derive(Debug)]
pub enum RateHit<'x> {
    Allowed,
    Exceeded { reset_in: u64 },
    Flush(RateFlush<'x>),
}

#[derive(Debug)]
pub struct RateFlush<'x> {
    counter: &'x RateCounter,
    window: RateWindow,
    delta: u32,
    owner: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateState {
    window: u32,
    total: u32,
    learned: bool,
    in_flight: bool,
    pending: u32,
}

const RATE_PENDING_BITS: u32 = 5;
const RATE_PENDING_MASK: u64 = (1 << RATE_PENDING_BITS) - 1;
const RATE_IN_FLIGHT: u64 = 1 << RATE_PENDING_BITS;
const RATE_LEARNED: u64 = 1 << (RATE_PENDING_BITS + 1);
const RATE_TOTAL_SHIFT: u32 = RATE_PENDING_BITS + 2;
const RATE_TOTAL_MAX: u32 = (1 << (u32::BITS - RATE_TOTAL_SHIFT)) - 1;
const RATE_BATCH_DIVISOR: u64 = 64;
const RATE_MAX_BATCH: u64 = 32;

const _: () = assert!(RATE_MAX_BATCH - 1 <= RATE_PENDING_MASK);

impl RateCounter {
    fn batch_size(rate: &Rate) -> u32 {
        if rate.count <= u64::from(RATE_TOTAL_MAX) {
            (rate.count / RATE_BATCH_DIVISOR).clamp(1, RATE_MAX_BATCH) as u32
        } else {
            1
        }
    }

    pub fn hit(&self, rate: &Rate, now: u64) -> RateHit<'_> {
        let window = RateWindow::new(rate, now);
        let batch = Self::batch_size(rate);
        if batch == 1 {
            return self.flush(window, 1, false);
        }

        let index = window.index as u32;
        let mut current = self.0.load(Ordering::Relaxed);
        loop {
            let state = RateState::from(current);
            let (next, flush) = if state.window == index {
                if u64::from(state.total) + u64::from(state.pending) >= rate.count {
                    return RateHit::Exceeded {
                        reset_in: window.expires_in,
                    };
                }
                let pending = state.pending + 1;
                if !state.learned || (pending == batch && state.in_flight) {
                    (
                        RateState {
                            total: state.total.saturating_add(1).min(RATE_TOTAL_MAX),
                            ..state
                        },
                        Some((1, false)),
                    )
                } else if pending < batch {
                    (RateState { pending, ..state }, None)
                } else {
                    (
                        RateState {
                            total: state.total.saturating_add(pending).min(RATE_TOTAL_MAX),
                            in_flight: true,
                            pending: 0,
                            ..state
                        },
                        Some((pending, true)),
                    )
                }
            } else if state.window == index.wrapping_add(1) {
                return self.flush(window, 1, false);
            } else {
                (
                    RateState {
                        window: index,
                        total: 1,
                        learned: false,
                        in_flight: true,
                        pending: 0,
                    },
                    Some((1, true)),
                )
            };

            match self.0.compare_exchange_weak(
                current,
                next.into(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return match flush {
                        Some((delta, owner)) => self.flush(window, delta, owner),
                        None => RateHit::Allowed,
                    };
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn flush(&self, window: RateWindow, delta: u32, owner: bool) -> RateHit<'_> {
        RateHit::Flush(RateFlush {
            counter: self,
            window,
            delta,
            owner,
        })
    }

    fn update(&self, window: RateWindow, known: u32, release: bool) {
        let index = window.index as u32;
        let _ = self
            .0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let state = RateState::from(current);
                let next = RateState {
                    total: state.total.max(known),
                    learned: state.learned || known > 0,
                    in_flight: state.in_flight && !release,
                    ..state
                };
                (state.window == index && next != state).then(|| next.into())
            });
    }
}

impl RateFlush<'_> {
    pub fn window(&self) -> RateWindow {
        self.window
    }

    pub fn delta(&self) -> u32 {
        self.delta
    }

    pub fn settle(mut self, rate: &Rate, total: u64) -> Option<u64> {
        let known = u32::try_from(total).unwrap_or(u32::MAX).min(RATE_TOTAL_MAX);
        self.counter
            .update(self.window, known, std::mem::take(&mut self.owner));
        (total > rate.count).then_some(self.window.expires_in)
    }
}

impl Drop for RateFlush<'_> {
    fn drop(&mut self) {
        if self.owner {
            self.counter.update(self.window, 0, true);
        }
    }
}

impl From<u64> for RateState {
    fn from(value: u64) -> Self {
        RateState {
            window: (value >> u32::BITS) as u32,
            total: ((value >> RATE_TOTAL_SHIFT) as u32) & RATE_TOTAL_MAX,
            learned: value & RATE_LEARNED != 0,
            in_flight: value & RATE_IN_FLIGHT != 0,
            pending: (value & RATE_PENDING_MASK) as u32,
        }
    }
}

impl From<RateState> for u64 {
    fn from(state: RateState) -> Self {
        let mut value = (u64::from(state.window) << u32::BITS)
            | (u64::from(state.total) << RATE_TOTAL_SHIFT)
            | u64::from(state.pending);
        if state.learned {
            value |= RATE_LEARNED;
        }
        if state.in_flight {
            value |= RATE_IN_FLIGHT;
        }
        value
    }
}

impl PartialEq for ThrottleKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl std::hash::Hash for ThrottleKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl AsRef<[u8]> for ThrottleKey {
    fn as_ref(&self) -> &[u8] {
        &self.hash
    }
}

impl ThrottleKey {
    pub fn quota_key(&self) -> u128 {
        u128::from_be_bytes(self.hash[..std::mem::size_of::<u128>()].try_into().unwrap())
    }
}

