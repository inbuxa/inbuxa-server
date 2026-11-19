/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::sync::atomic::{AtomicU64, Ordering};

use crate::MetricType;

pub struct AtomicGauge {
    id: MetricType,
    value: AtomicU64,
}

impl AtomicGauge {
    pub const fn new(id: MetricType) -> Self {
        Self {
            id,
            value: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    // inbuxa: K-C10: never below zero. A process can take off what another
    // added (a message queued on one node, delivered on another), and a
    // wrapped u64 read as 18446744073709552000 messages in the queue.
    #[inline(always)]
    pub fn decrement(&self) {
        self.subtract(1);
    }

    #[inline(always)]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn add(&self, value: u64) {
        self.value.fetch_add(value, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn subtract(&self, value: u64) {
        let _ = self
            .value
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(value))
            });
    }

    pub fn id(&self) -> MetricType {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::AtomicGauge;
    use crate::MetricType;

    #[test]
    fn gauge_stops_at_zero() {
        let gauge = AtomicGauge::new(MetricType::QueueCount);
        gauge.increment();
        gauge.decrement();
        gauge.decrement();
        assert_eq!(gauge.get(), 0);
        gauge.add(3);
        gauge.subtract(5);
        assert_eq!(gauge.get(), 0);
    }
}
