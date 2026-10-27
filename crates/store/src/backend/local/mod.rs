/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod entry;
mod maintenance;

use self::entry::{Entry, EntryKey, NEVER};
use crate::Deserialize;
use ahash::RandomState;
use papaya::{Compute, HashMap, Operation, ResizeMode};
use parking_lot::Mutex;
use std::{
    fmt,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

pub struct LocalStore {
    entries: HashMap<EntryKey, Entry, RandomState>,
    state: SharedState,
    max_entries: usize,
    eviction_batch: usize,
    eviction: Mutex<()>,
}

#[repr(align(128))]
struct SharedState {
    len: AtomicUsize,
    next_sweep: AtomicU64,
}

impl LocalStore {
    pub const DEFAULT_MAX_ENTRIES: usize = 1 << 20;
    const EVICTION_DIVISOR: usize = 16;

    pub fn new(max_entries: usize) -> Self {
        let max_entries = max_entries.max(1);
        LocalStore {
            entries: HashMap::builder()
                .hasher(RandomState::new())
                .resize_mode(ResizeMode::Blocking)
                .build(),
            state: SharedState {
                len: AtomicUsize::new(0),
                next_sweep: AtomicU64::new(0),
            },
            max_entries,
            eviction_batch: (max_entries / Self::EVICTION_DIVISOR).max(1),
            eviction: Mutex::new(()),
        }
    }

    pub fn key_set(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        expires: Option<u64>,
        now: u64,
    ) -> trc::Result<()> {
        let expires = expires.map_or(NEVER, |ttl| Entry::expiry_at(now, ttl));
        self.reserve(now)?;
        if let Some(previous) = self
            .entries
            .pin()
            .insert(EntryKey::from(key), Entry::value(value, expires))
        {
            self.kill(previous);
        }
        Ok(())
    }

    pub fn key_incr(
        &self,
        key: Vec<u8>,
        delta: i64,
        expires: Option<u64>,
        now: u64,
    ) -> trc::Result<i64> {
        let expires = expires.map(|ttl| Entry::expiry_at(now, ttl));
        let entries = self.entries.pin();
        loop {
            if let Some(value) = entries
                .get(key.as_slice())
                .and_then(|entry| entry.increment(delta, expires, now))
            {
                return Ok(value);
            }

            self.reserve(now)?;
            match entries.compute(EntryKey::from(key.as_slice()), |current| match current {
                Some((_, entry)) if !self.kill_expired(entry, now) && entry.is_counter() => {
                    Operation::Abort(())
                }
                _ => Operation::Insert(Entry::counter(delta, expires.unwrap_or(NEVER))),
            }) {
                Compute::Inserted(..) => return Ok(delta),
                Compute::Updated {
                    old: (_, previous), ..
                } => {
                    self.kill(previous);
                    return Ok(delta);
                }
                Compute::Aborted(_) | Compute::Removed(..) => self.release(),
            }
        }
    }

    pub fn key_get<T: Deserialize>(&self, key: &[u8], now: u64) -> trc::Result<Option<T>> {
        match self.entries.pin().get(key) {
            Some(entry) if entry.is_live(now) => entry.deserialize(),
            _ => Ok(None),
        }
    }

    pub fn key_exists(&self, key: &[u8], now: u64) -> bool {
        self.entries
            .pin()
            .get(key)
            .is_some_and(|entry| entry.is_live(now))
    }

    pub fn key_delete(&self, key: &[u8], now: u64) -> bool {
        match self.entries.pin().remove(key) {
            Some(previous) => {
                let is_live = previous.is_live(now);
                self.kill(previous);
                is_live
            }
            None => false,
        }
    }

    pub fn key_delete_prefix(&self, prefix: &[u8]) {
        if !prefix.is_empty() {
            self.entries.pin().retain(|key, entry| {
                if key.as_bytes().starts_with(prefix) {
                    self.kill(entry);
                    false
                } else {
                    true
                }
            });
        }
    }

    pub fn try_lock(&self, key: Vec<u8>, duration: u64, now: u64) -> trc::Result<bool> {
        self.try_insert(key, duration, now, Entry::lock)
    }

    pub fn renew_lock(&self, key: Vec<u8>, duration: u64, now: u64) -> trc::Result<()> {
        self.reserve(now)?;
        if let Some(previous) = self.entries.pin().insert(
            EntryKey::from(key),
            Entry::lock(Entry::expiry_at(now, duration)),
        ) {
            self.kill(previous);
        }
        Ok(())
    }

    pub fn try_lease(
        &self,
        key: Vec<u8>,
        token: u64,
        duration: u64,
        now: u64,
    ) -> trc::Result<bool> {
        self.try_insert(key, duration, now, |expires| Entry::lease(token, expires))
    }

    fn try_insert(
        &self,
        key: Vec<u8>,
        duration: u64,
        now: u64,
        entry: impl Fn(u64) -> Entry,
    ) -> trc::Result<bool> {
        let entries = self.entries.pin();
        if entries
            .get(key.as_slice())
            .is_some_and(|entry| entry.is_live(now))
        {
            return Ok(false);
        }

        self.reserve(now)?;
        let expires = Entry::expiry_at(now, duration);
        match entries.compute(EntryKey::from(key), |current| match current {
            Some((_, entry)) if !self.kill_expired(entry, now) => Operation::Abort(()),
            _ => Operation::Insert(entry(expires)),
        }) {
            Compute::Inserted(..) => Ok(true),
            Compute::Updated {
                old: (_, previous), ..
            } => {
                self.kill(previous);
                Ok(true)
            }
            Compute::Aborted(_) | Compute::Removed(..) => {
                self.release();
                Ok(false)
            }
        }
    }

    pub fn renew_lease(&self, key: &[u8], token: u64, duration: u64, now: u64) -> bool {
        self.entries.pin().get(key).is_some_and(|entry| {
            entry.is_live(now) && entry.extend_lease(token, Entry::expiry_at(now, duration))
        })
    }

    pub fn release_lease(&self, key: Vec<u8>, token: u64) -> bool {
        match self
            .entries
            .pin()
            .compute(EntryKey::from(key), |current| match current {
                Some((_, entry)) if entry.is_lease(token) => Operation::Remove,
                _ => Operation::Abort(()),
            }) {
            Compute::Removed(_, previous) => {
                self.kill(previous);
                true
            }
            Compute::Inserted(..) | Compute::Updated { .. } | Compute::Aborted(_) => false,
        }
    }

    pub fn len(&self) -> usize {
        self.state.len.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for LocalStore {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX_ENTRIES)
    }
}

impl fmt::Debug for LocalStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalStore")
            .field("len", &self.len())
            .field("max_entries", &self.max_entries)
            .finish()
    }
}
