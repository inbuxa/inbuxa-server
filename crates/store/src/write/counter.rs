/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Operation, QueueClass, ValueClass, ValueOp, key::CounterKind};
use crate::{Subspace, U16_LEN, U32_LEN};
use ahash::AHashMap;
use registry::{schema::enums::StorageQuota, types::EnumImpl};
use std::mem;
use utils::hash128::Hash128;

const LINEAR_LOOKUP_MAX: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountCounter {
    Quota,
    ObjectCount(StorageQuota),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueueCounter {
    Count(Hash128),
    Size(Hash128),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterBound {
    pub(crate) key: CounterKey,
    pub(crate) by: i64,
    pub(crate) max: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CounterKey {
    Account {
        account_id: u32,
        counter: AccountCounter,
    },
    Queue(QueueCounter),
}

#[derive(Debug)]
struct PendingCounter {
    key: CounterKey,
    delta: i64,
    max: Option<i64>,
    reset: bool,
}

#[derive(Debug, Default)]
pub(super) struct PendingCounters {
    counters: Vec<PendingCounter>,
    index: Option<AHashMap<CounterKey, usize>>,
}

impl CounterKey {
    #[inline]
    pub(super) fn new(class: &ValueClass, account_id: Option<u32>) -> Option<Self> {
        let counter = match class {
            ValueClass::Quota => AccountCounter::Quota,
            ValueClass::ObjectCount(object) => AccountCounter::ObjectCount(*object),
            ValueClass::Queue(QueueClass::QuotaCount(key)) => {
                return Some(CounterKey::Queue(QueueCounter::Count(*key)));
            }
            ValueClass::Queue(QueueClass::QuotaSize(key)) => {
                return Some(CounterKey::Queue(QueueCounter::Size(*key)));
            }
            _ => return None,
        };
        Some(CounterKey::account(account_id, counter))
    }

    #[inline]
    pub(super) fn account(account_id: Option<u32>, counter: AccountCounter) -> Self {
        CounterKey::Account {
            account_id: account_id.unwrap_or(u32::MAX),
            counter,
        }
    }

    fn class_and_account(self) -> (ValueClass, u32) {
        match self {
            CounterKey::Account {
                account_id,
                counter,
            } => (counter.into(), account_id),
            CounterKey::Queue(counter) => (counter.into(), 0),
        }
    }

    fn class(self) -> ValueClass {
        self.class_and_account().0
    }

    fn sort_key(self) -> (u8, u32, u8, Hash128) {
        match self {
            CounterKey::Account {
                account_id,
                counter: AccountCounter::Quota,
            } => (CounterKind::Quota.byte(), account_id, 0, Hash128::default()),
            CounterKey::Account {
                account_id,
                counter: AccountCounter::ObjectCount(object),
            } => (
                CounterKind::ObjectCount.byte(),
                account_id,
                object as u8,
                Hash128::default(),
            ),
            CounterKey::Queue(QueueCounter::Count(key)) => {
                (CounterKind::QueueQuotaCount.byte(), 0, 0, key)
            }
            CounterKey::Queue(QueueCounter::Size(key)) => {
                (CounterKind::QueueQuotaSize.byte(), 0, 0, key)
            }
        }
    }
}

impl PendingCounters {
    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    pub(super) fn add(&mut self, key: CounterKey, by: i64) -> bool {
        let counter = self.entry(key);
        let was_idle = counter.delta == 0;
        counter.delta = counter.delta.saturating_add(by);
        was_idle
    }

    pub(super) fn limit(&mut self, key: CounterKey, max: i64) {
        let counter = self.entry(key);
        counter.max = Some(counter.max.map_or(max, |current| current.min(max)));
    }

    pub(super) fn reset(&mut self, key: CounterKey) -> bool {
        let counter = self.entry(key);
        counter.delta = 0;
        counter.max = None;
        !mem::replace(&mut counter.reset, true)
    }

    pub(super) fn settle(&mut self, key: CounterKey) -> (bool, i64) {
        match self
            .position(key)
            .and_then(|pos| self.counters.get_mut(pos))
        {
            Some(counter) => {
                counter.max = None;
                (mem::take(&mut counter.reset), mem::take(&mut counter.delta))
            }
            None => (false, 0),
        }
    }

    pub(super) fn clear_range(&mut self, subspace: Subspace, from: &[u8], to: &[u8]) {
        let range = from..to;
        let mut key = Vec::with_capacity(U32_LEN + U16_LEN);
        for counter in &mut self.counters {
            let (class, account_id) = counter.key.class_and_account();
            if class.subspace(0) == subspace {
                key.clear();
                class.serialize_into(&mut key, account_id, 0, 0, 0);
                if range.contains(&key.as_slice()) {
                    counter.delta = 0;
                    counter.max = None;
                }
            }
        }
    }

    pub(super) fn flush(
        &mut self,
        mut account_id: Option<u32>,
        ops: &mut Vec<Operation>,
        bounds: &mut Vec<CounterBound>,
    ) {
        self.counters
            .sort_unstable_by_key(|counter| counter.key.sort_key());
        for pending in &mut self.counters {
            let delta = mem::take(&mut pending.delta);
            let reset = mem::take(&mut pending.reset);
            match (pending.key, pending.max) {
                _ if delta == 0 && !reset => {}
                (key @ (CounterKey::Account { .. } | CounterKey::Queue(_)), Some(max))
                    if delta > 0 && !reset =>
                {
                    bounds.push(CounterBound {
                        key,
                        by: delta,
                        max,
                    })
                }
                (key, _) => {
                    if let CounterKey::Account {
                        account_id: counter_account_id,
                        ..
                    } = key
                        && account_id != Some(counter_account_id)
                    {
                        ops.push(Operation::AccountId {
                            account_id: counter_account_id,
                        });
                        account_id = Some(counter_account_id);
                    }
                    if reset {
                        ops.push(Operation::Value {
                            class: key.class(),
                            op: ValueOp::Clear,
                        });
                    }
                    if delta != 0 {
                        ops.push(Operation::Value {
                            class: key.class(),
                            op: ValueOp::AtomicAdd(delta),
                        });
                    }
                }
            }
        }
        self.counters.retain(|counter| counter.max.is_some());
        self.index = (self.counters.len() > LINEAR_LOOKUP_MAX).then(|| self.build_index());
    }

    fn position(&self, key: CounterKey) -> Option<usize> {
        match &self.index {
            Some(index) => index.get(&key).copied(),
            None => self.counters.iter().rposition(|counter| counter.key == key),
        }
    }

    fn entry(&mut self, key: CounterKey) -> &mut PendingCounter {
        if let Some(pos) = self.position(key) {
            return &mut self.counters[pos];
        }

        let pos = self.counters.len();
        self.counters.push(PendingCounter {
            key,
            delta: 0,
            max: None,
            reset: false,
        });
        match &mut self.index {
            Some(index) => {
                index.insert(key, pos);
            }
            None if self.counters.len() > LINEAR_LOOKUP_MAX => {
                self.index = Some(self.build_index());
            }
            None => {}
        }
        &mut self.counters[pos]
    }

    fn build_index(&self) -> AHashMap<CounterKey, usize> {
        self.counters
            .iter()
            .enumerate()
            .map(|(pos, counter)| (counter.key, pos))
            .collect()
    }
}

impl CounterBound {
    #[inline]
    pub fn serialize_key_into(&self, buf: &mut Vec<u8>, flags: u32) {
        let (class, account_id) = self.key.class_and_account();
        class.serialize_into(buf, account_id, 0, 0, flags)
    }

    #[inline]
    pub fn verify(&self, value: i64) -> trc::Result<()> {
        if value <= self.max {
            Ok(())
        } else {
            Err(self.exceeded_at(value))
        }
    }

    #[cold]
    #[inline(never)]
    fn exceeded_at(&self, value: i64) -> trc::Error {
        self.exceeded().ctx(
            trc::Key::Used,
            u64::try_from(value.saturating_sub(self.by)).unwrap_or_default(),
        )
    }

    #[cfg(any(feature = "foundation", feature = "rocks"))]
    #[inline]
    pub(crate) fn allows_overshoot(&self) -> bool {
        matches!(self.key, CounterKey::Queue(_))
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn exceeded(&self) -> trc::Error {
        let err = trc::LimitEvent::Quota
            .into_err()
            .ctx(trc::Key::Limit, u64::try_from(self.max).unwrap_or_default())
            .ctx(trc::Key::Size, u64::try_from(self.by).unwrap_or_default());
        match self.key {
            CounterKey::Account {
                account_id,
                counter: AccountCounter::Quota,
            } => err.account_id(account_id),
            CounterKey::Account {
                account_id,
                counter: AccountCounter::ObjectCount(object),
            } => err
                .account_id(account_id)
                .ctx(trc::Key::ObjectType, object.as_str()),
            _ => err,
        }
    }
}

impl ValueClass {
    #[cfg(feature = "rocks")]
    #[inline]
    pub(crate) fn is_queue_quota(&self) -> bool {
        matches!(
            self,
            ValueClass::Queue(QueueClass::QuotaCount(_) | QueueClass::QuotaSize(_))
        )
    }
}

impl From<QueueCounter> for ValueClass {
    #[inline]
    fn from(counter: QueueCounter) -> Self {
        ValueClass::Queue(match counter {
            QueueCounter::Count(key) => QueueClass::QuotaCount(key),
            QueueCounter::Size(key) => QueueClass::QuotaSize(key),
        })
    }
}

impl From<AccountCounter> for ValueClass {
    #[inline]
    fn from(counter: AccountCounter) -> Self {
        match counter {
            AccountCounter::Quota => ValueClass::Quota,
            AccountCounter::ObjectCount(object) => ValueClass::ObjectCount(object),
        }
    }
}

