/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Deserialize;
use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
};

const INLINE_KEY_LEN: usize = 46;
const EXPIRY_MASK: u64 = (1 << 62) - 1;
const COUNTER_RANK: u64 = 0;
const VALUE_RANK: u64 = 1 << 62;

pub(super) const NEVER: u64 = u64::MAX;
const DEAD: u64 = 0;
const MIN_EXPIRY: u64 = DEAD + 1;

pub(super) enum EntryKey {
    Inline {
        len: u8,
        bytes: [u8; INLINE_KEY_LEN],
    },
    Heap(Box<[u8]>),
}

pub(super) struct Entry {
    expires: AtomicU64,
    payload: Payload,
}

enum Payload {
    Value(Box<[u8]>),
    Counter(AtomicI64),
    Lock,
    Lease(u64),
}

pub(super) enum Liveness {
    Live,
    Expired,
    Dead,
}

const _: () = assert!(size_of::<EntryKey>() == 48);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Entry>() == 32);

impl EntryKey {
    #[inline]
    pub(super) fn as_bytes(&self) -> &[u8] {
        match self {
            EntryKey::Inline { len, bytes } => bytes.get(..usize::from(*len)).unwrap_or_default(),
            EntryKey::Heap(bytes) => bytes,
        }
    }
}

impl From<&[u8]> for EntryKey {
    fn from(key: &[u8]) -> Self {
        let mut bytes = [0u8; INLINE_KEY_LEN];
        match (bytes.get_mut(..key.len()), u8::try_from(key.len())) {
            (Some(inline), Ok(len)) => {
                inline.copy_from_slice(key);
                EntryKey::Inline { len, bytes }
            }
            _ => EntryKey::Heap(key.into()),
        }
    }
}

impl From<Vec<u8>> for EntryKey {
    fn from(key: Vec<u8>) -> Self {
        if key.len() <= INLINE_KEY_LEN {
            EntryKey::from(key.as_slice())
        } else {
            EntryKey::Heap(key.into_boxed_slice())
        }
    }
}

impl Borrow<[u8]> for EntryKey {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Hash for EntryKey {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state)
    }
}

impl PartialEq for EntryKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for EntryKey {}

impl Entry {
    #[inline]
    pub(super) fn expiry_at(now: u64, ttl: u64) -> u64 {
        now.saturating_add(ttl).max(MIN_EXPIRY)
    }

    pub(super) fn value(value: Vec<u8>, expires: u64) -> Self {
        Entry {
            expires: AtomicU64::new(expires),
            payload: Payload::Value(value.into_boxed_slice()),
        }
    }

    pub(super) fn counter(value: i64, expires: u64) -> Self {
        Entry {
            expires: AtomicU64::new(expires),
            payload: Payload::Counter(AtomicI64::new(value)),
        }
    }

    pub(super) fn lock(expires: u64) -> Self {
        Entry {
            expires: AtomicU64::new(expires),
            payload: Payload::Lock,
        }
    }

    pub(super) fn lease(token: u64, expires: u64) -> Self {
        Entry {
            expires: AtomicU64::new(expires),
            payload: Payload::Lease(token),
        }
    }

    #[inline]
    pub(super) fn is_lease(&self, token: u64) -> bool {
        matches!(self.payload, Payload::Lease(owner) if owner == token)
    }

    pub(super) fn extend_lease(&self, token: u64, expires: u64) -> bool {
        if !self.is_lease(token) {
            return false;
        }
        let mut current = self.expires();
        loop {
            if current == DEAD {
                return false;
            }
            match self.expires.compare_exchange_weak(
                current,
                expires,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    #[inline]
    pub(super) fn expires(&self) -> u64 {
        self.expires.load(Ordering::Acquire)
    }

    #[inline]
    pub(super) fn is_live(&self, now: u64) -> bool {
        self.expires() > now
    }

    #[inline]
    pub(super) fn is_counter(&self) -> bool {
        matches!(self.payload, Payload::Counter(_))
    }

    pub(super) fn deserialize<T: Deserialize>(&self) -> trc::Result<Option<T>> {
        match &self.payload {
            Payload::Value(value) => T::deserialize(value).map(Some),
            Payload::Lock => T::deserialize(&[]).map(Some),
            Payload::Lease(token) => T::deserialize(&token.to_be_bytes()).map(Some),
            Payload::Counter(_) => Ok(None),
        }
    }

    #[cfg(all(test, stalwart_tests))]
    pub(super) fn counter_value(&self) -> i64 {
        match &self.payload {
            Payload::Counter(counter) => counter.load(Ordering::Relaxed),
            Payload::Value(_) | Payload::Lock | Payload::Lease(_) => 0,
        }
    }

    #[inline]
    pub(super) fn increment(&self, delta: i64, expires: Option<u64>, now: u64) -> Option<i64> {
        let Payload::Counter(counter) = &self.payload else {
            return None;
        };
        let mut current = self.expires();
        loop {
            if current <= now {
                return None;
            }
            match expires {
                Some(expires) if expires != current => {
                    match self.expires.compare_exchange_weak(
                        current,
                        expires,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break,
                        Err(actual) => current = actual,
                    }
                }
                _ => break,
            }
        }
        Some(
            counter
                .fetch_add(delta, Ordering::Relaxed)
                .wrapping_add(delta),
        )
    }

    pub(super) fn eviction_score(&self) -> Option<u64> {
        let rank = match self.payload {
            Payload::Counter(_) => COUNTER_RANK,
            Payload::Value(_) => VALUE_RANK,
            Payload::Lock | Payload::Lease(_) => return None,
        };
        Some(rank | self.expires().min(EXPIRY_MASK))
    }

    #[inline]
    pub(super) fn mark_dead(&self) -> bool {
        self.expires.swap(DEAD, Ordering::AcqRel) != DEAD
    }

    pub(super) fn mark_dead_if_expired(&self, now: u64) -> Liveness {
        let mut current = self.expires();
        loop {
            if current == DEAD {
                return Liveness::Dead;
            } else if current > now {
                return Liveness::Live;
            }
            match self.expires.compare_exchange_weak(
                current,
                DEAD,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Liveness::Expired,
                Err(actual) => current = actual,
            }
        }
    }
}
