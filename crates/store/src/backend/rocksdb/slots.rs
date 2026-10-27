/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::into_error;
use crate::{backend::deserialize_i64_le, write::key::CounterKind};
use rocksdb::{DBAccess, DBRawIteratorWithThreadMode, ReadOptions};
use std::sync::atomic::{AtomicBool, Ordering};

const SLOT_KEY_LEN: usize = 18;
const MAX_COUNTER_SLOTS: usize = u8::MAX as usize + 1;
const QUEUE_QUOTA_END: u8 = CounterKind::QueueQuotaSize.byte() + 1;

pub(crate) struct CounterSlots(Box<[AtomicBool]>);

pub(crate) struct CounterSlot<'x> {
    slots: &'x CounterSlots,
    index: usize,
}

pub(crate) struct SlotSum {
    pub(crate) total: i64,
    pub(crate) own: i64,
}

impl CounterSlots {
    pub(crate) fn new(writers: usize) -> Self {
        CounterSlots(
            (0..writers.clamp(1, MAX_COUNTER_SLOTS))
                .map(|_| AtomicBool::new(false))
                .collect(),
        )
    }

    pub(crate) fn acquire(&self) -> Option<CounterSlot<'_>> {
        self.0
            .iter()
            .position(|slot| {
                slot.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            })
            .map(|index| CounterSlot { slots: self, index })
    }
}

impl CounterSlot<'_> {
    #[inline]
    pub(crate) fn byte(&self) -> u8 {
        u8::try_from(self.index).unwrap_or(u8::MAX)
    }
}

impl Drop for CounterSlot<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slots.0.get(self.index) {
            slot.store(false, Ordering::Release);
        }
    }
}

pub(crate) fn queue_quota_read_options() -> ReadOptions {
    let mut options = ReadOptions::default();
    options.set_iterate_upper_bound(vec![QUEUE_QUOTA_END]);
    options
}

pub(crate) fn sum_slots<D: DBAccess>(
    iter: &mut DBRawIteratorWithThreadMode<'_, D>,
    key: &[u8],
    own_slot: u8,
) -> trc::Result<SlotSum> {
    iter.seek(key);
    let mut sum = SlotSum { total: 0, own: 0 };
    while let (Some(slot_key), Some(value)) = (iter.key(), iter.value()) {
        let Some(suffix) = slot_key.strip_prefix(key) else {
            break;
        };
        let value = deserialize_i64_le(slot_key, value)?;
        sum.total = sum.total.saturating_add(value);
        if suffix == [own_slot] {
            sum.own = value;
        }
        iter.next();
    }
    iter.status().map_err(into_error)?;
    Ok(sum)
}

#[derive(Default)]
pub(crate) struct SlotGroups(Vec<SlotGroup>);

struct SlotGroup {
    base: Box<[u8]>,
    total: i64,
    keys: Vec<Box<[u8]>>,
}

impl SlotGroups {
    pub(crate) fn add(&mut self, key: Box<[u8]>, value: i64) {
        let Some((_, base)) = key.split_last() else {
            return;
        };
        if key.len() != SLOT_KEY_LEN
            || !matches!(
                key.first().copied(),
                Some(kind) if kind == CounterKind::QueueQuotaCount.byte()
                    || kind == CounterKind::QueueQuotaSize.byte()
            )
        {
            return;
        }
        match self.0.last_mut() {
            Some(group) if *group.base == *base => {
                group.total = group.total.saturating_add(value);
                group.keys.push(key);
            }
            _ => self.0.push(SlotGroup {
                base: base.into(),
                total: value,
                keys: vec![key],
            }),
        }
    }

    pub(crate) fn zero_sum(&self) -> impl Iterator<Item = &[Box<[u8]>]> {
        self.0
            .iter()
            .filter(|group| group.total == 0)
            .map(|group| group.keys.as_slice())
    }
}
