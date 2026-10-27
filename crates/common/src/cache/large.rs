/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Caches, GroupwareResources, MessageStoreCache,
    cache::swap::{evict::SwapEviction, writer::SwapChanges, writer::SwapTarget},
};
use ahash::AHashMap;
use parking_lot::Mutex;
use std::{
    hash::Hash,
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use trc::CacheEvent;
use types::collection::SyncCollection;
use utils::cache::{Cache, CacheGuard, CacheItemWeight};

pub type MessageCacheGuard<'x> = CacheGuard<'x, u32, Arc<MessageStoreCache>, SwapEviction>;
pub type ResourceCache = Cache<u32, Arc<GroupwareResources>, SwapEviction>;
pub type ResourceCacheGuard<'x> = CacheGuard<'x, u32, Arc<GroupwareResources>, SwapEviction>;

const SWEEPS_PER_TTL: u64 = 16;

pub type LargeMessageCaches = LargeCaches<u32, MessageStoreCache>;
pub type LargeResourceCaches = LargeCaches<SwapTarget, GroupwareResources>;

pub struct LargeCaches<K, T> {
    slots: Mutex<LargeSlots<K, T>>,
    occupied: AtomicUsize,
    budget: u64,
    expiry: Option<IdleExpiry>,
}

struct IdleExpiry {
    epoch: Instant,
    ttl: u64,
    interval: u64,
    next_sweep: AtomicU64,
}

struct IdleSweep {
    now: u64,
    ttl: u64,
}

struct LargeSlots<K, T> {
    accounts: AHashMap<K, LargeSlot<T>>,
    pinned_bytes: u64,
    tick: u64,
    swept_tick: u64,
}

struct LargeSlot<T> {
    pinned: Option<Arc<T>>,
    shared: Weak<T>,
    last_use: u64,
    seen_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Residency {
    Pinned,
    Shared,
}

pub struct Publication<K, T> {
    pub residency: Residency,
    pub unpinned: Vec<(K, Arc<T>)>,
    _replaced: Option<Arc<T>>,
}

impl<K, T> Default for LargeSlots<K, T> {
    fn default() -> Self {
        LargeSlots {
            accounts: AHashMap::new(),
            pinned_bytes: 0,
            tick: 0,
            swept_tick: 0,
        }
    }
}

impl<T> LargeSlot<T> {
    fn is_live(&self) -> bool {
        self.pinned.is_some() || self.shared.strong_count() > 0
    }
}

impl<K: Copy, T: CacheItemWeight> LargeSlots<K, T> {
    fn sweep(&mut self, idle: Option<IdleSweep>, unpinned: &mut Vec<(K, Arc<T>)>) {
        let LargeSlots {
            accounts,
            pinned_bytes,
            tick,
            swept_tick,
        } = self;
        let Some(IdleSweep { now, ttl }) = idle else {
            accounts.retain(|_, slot| slot.is_live());
            return;
        };

        accounts.retain(|account_id, slot| {
            if slot.last_use > *swept_tick {
                slot.seen_at = now;
            } else if now.saturating_sub(slot.seen_at) > ttl
                && let Some(cache) = slot.pinned.take()
            {
                *pinned_bytes = pinned_bytes.saturating_sub(cache.weight());
                unpinned.push((*account_id, cache));
            }
            slot.is_live()
        });
        *swept_tick = *tick;
    }
}

impl IdleExpiry {
    fn new(ttl: Duration) -> Option<Self> {
        (!ttl.is_zero()).then(|| {
            let ttl = ttl.as_secs().max(1);
            IdleExpiry {
                epoch: Instant::now(),
                ttl,
                interval: (ttl / SWEEPS_PER_TTL).max(1),
                next_sweep: AtomicU64::new(0),
            }
        })
    }

    fn now(&self) -> u64 {
        self.epoch.elapsed().as_secs()
    }

    fn is_due(&self, now: u64) -> bool {
        let due = self.next_sweep.load(Ordering::Relaxed);
        now >= due
            && self
                .next_sweep
                .compare_exchange(
                    due,
                    now + self.interval,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
    }
}

impl<K: Copy + Eq + Hash, T: CacheItemWeight> LargeCaches<K, T> {
    pub fn new(budget: u64, idle_ttl: Duration) -> Self {
        LargeCaches {
            slots: Mutex::new(LargeSlots::default()),
            occupied: AtomicUsize::new(0),
            budget,
            expiry: IdleExpiry::new(idle_ttl),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.occupied.load(Ordering::Relaxed) == 0
    }

    pub fn lookup(&self, account_id: K) -> Option<Arc<T>> {
        if self.is_empty() {
            return None;
        }

        let mut slots = self.slots.lock();
        let LargeSlots { accounts, tick, .. } = &mut *slots;
        let slot = accounts.get_mut(&account_id)?;
        if let Some(pinned) = &slot.pinned {
            *tick += 1;
            slot.last_use = *tick;
            return Some(pinned.clone());
        }

        let shared = slot.shared.upgrade();
        if shared.is_none() {
            accounts.remove(&account_id);
            self.occupied.store(accounts.len(), Ordering::Relaxed);
        }
        shared
    }

    pub fn peek(&self, account_id: K) -> Option<Arc<T>> {
        if self.is_empty() {
            return None;
        }

        let slots = self.slots.lock();
        let slot = slots.accounts.get(&account_id)?;
        slot.pinned.clone().or_else(|| slot.shared.upgrade())
    }

    pub fn contains(&self, account_id: K) -> bool {
        !self.is_empty()
            && self
                .slots
                .lock()
                .accounts
                .get(&account_id)
                .is_some_and(LargeSlot::is_live)
    }

    pub fn publish(&self, account_id: K, cache: &Arc<T>) -> Publication<K, T> {
        self.publish_at(
            account_id,
            cache,
            self.expiry.as_ref().map_or(0, IdleExpiry::now),
        )
    }

    pub fn expire_idle(&self) -> Vec<(K, Arc<T>)> {
        match &self.expiry {
            Some(expiry) if !self.is_empty() => self.expire_idle_at(expiry.now()),
            _ => Vec::new(),
        }
    }

    fn expire_idle_at(&self, now: u64) -> Vec<(K, Arc<T>)> {
        let mut unpinned = Vec::new();
        if let Some(expiry) = &self.expiry
            && expiry.is_due(now)
        {
            let mut slots = self.slots.lock();
            slots.sweep(
                Some(IdleSweep {
                    now,
                    ttl: expiry.ttl,
                }),
                &mut unpinned,
            );
            self.occupied.store(slots.accounts.len(), Ordering::Relaxed);
        }
        unpinned
    }

    fn publish_at(&self, account_id: K, cache: &Arc<T>, now: u64) -> Publication<K, T> {
        let size = cache.weight();
        let pinnable = self.budget > 0 && size <= self.budget;
        let mut unpinned = Vec::new();

        let mut slots = self.slots.lock();
        let LargeSlots {
            accounts,
            pinned_bytes,
            tick,
            ..
        } = &mut *slots;
        *tick += 1;
        let last_use = *tick;

        let replaced = match accounts.get_mut(&account_id) {
            Some(slot) => {
                slot.shared = Arc::downgrade(cache);
                slot.last_use = last_use;
                slot.pinned.take()
            }
            None => {
                accounts.insert(
                    account_id,
                    LargeSlot {
                        pinned: None,
                        shared: Arc::downgrade(cache),
                        last_use,
                        seen_at: now,
                    },
                );
                None
            }
        };
        if let Some(replaced) = &replaced {
            *pinned_bytes = pinned_bytes.saturating_sub(replaced.weight());
        }
        slots.sweep(
            self.expiry.as_ref().map(|expiry| IdleSweep {
                now,
                ttl: expiry.ttl,
            }),
            &mut unpinned,
        );

        let LargeSlots {
            accounts,
            pinned_bytes,
            ..
        } = &mut *slots;
        let residency = if pinnable {
            while *pinned_bytes + size > self.budget {
                let Some(victim) = accounts
                    .iter_mut()
                    .filter(|(id, slot)| **id != account_id && slot.pinned.is_some())
                    .min_by_key(|(_, slot)| slot.last_use)
                    .and_then(|(id, slot)| slot.pinned.take().map(|cache| (*id, cache)))
                else {
                    break;
                };
                *pinned_bytes = pinned_bytes.saturating_sub(victim.1.weight());
                unpinned.push(victim);
            }

            if let Some(slot) = accounts.get_mut(&account_id) {
                slot.pinned = Some(cache.clone());
                *pinned_bytes += size;
            }
            Residency::Pinned
        } else {
            Residency::Shared
        };

        self.occupied.store(accounts.len(), Ordering::Relaxed);
        drop(slots);

        Publication {
            residency,
            unpinned,
            _replaced: replaced,
        }
    }

    pub fn remove(&self, account_id: K) -> Option<Arc<T>> {
        if self.is_empty() {
            return None;
        }

        let mut slots = self.slots.lock();
        let LargeSlots {
            accounts,
            pinned_bytes,
            ..
        } = &mut *slots;
        let pinned = accounts.remove(&account_id)?.pinned;
        self.occupied.store(accounts.len(), Ordering::Relaxed);
        if let Some(pinned) = &pinned {
            *pinned_bytes = pinned_bytes.saturating_sub(pinned.weight());
        }
        pinned
    }

    pub fn resident_bytes(&self) -> u64 {
        if self.is_empty() {
            return 0;
        }

        let slots = self.slots.lock();
        let shared = slots
            .accounts
            .values()
            .filter(|slot| slot.pinned.is_none())
            .filter_map(|slot| slot.shared.upgrade())
            .collect::<Vec<_>>();
        let pinned_bytes = slots.pinned_bytes;
        drop(slots);
        shared.iter().fold(pinned_bytes, |total, cache| {
            total.saturating_add(cache.weight())
        })
    }

    pub fn clear(&self) {
        let mut slots = self.slots.lock();
        let cleared = std::mem::take(&mut *slots);
        self.occupied.store(0, Ordering::Relaxed);
        drop(slots);
        drop(cleared);
    }
}

impl Caches {
    pub fn messages_weight(&self) -> u64 {
        self.messages.weight()
    }

    pub fn messages_large_weight(&self) -> u64 {
        self.messages_large.resident_bytes()
    }

    pub fn other_weight(&self) -> u64 {
        let total = self.access_tokens.weight()
            + self.http_auth.weight()
            + self.files.weight()
            + self.contacts.weight()
            + self.events.weight()
            + self.scheduling.weight()
            + self.metadata_viewers.weight()
            + self.emails.weight()
            + self.emails_negative.weight()
            + self.domain_names.weight()
            + self.domain_names_negative.weight()
            + self.domains.weight()
            + self.accounts.weight()
            + self.roles.weight()
            + self.lists.weight()
            + self.dkim_signers.weight()
            + self.dns_txt.weight()
            + self.dns_mx.weight()
            + self.dns_ptr.weight()
            + self.dns_ipv4.weight()
            + self.dns_ipv6.weight()
            + self.dns_tlsa.weight()
            + self.dns_mta_sts.weight()
            + self.spam_lookup.weight()
            + self.directory_recipients.weight()
            + self.resources_large.resident_bytes();


        total
    }

    #[inline]
    pub fn resident_messages(&self, account_id: u32) -> Option<Arc<MessageStoreCache>> {
        match self.messages.get(&account_id) {
            Some(cache) => Some(cache),
            None => self.messages_large.lookup(account_id),
        }
    }

    pub fn peek_messages(&self, account_id: u32) -> Option<Arc<MessageStoreCache>> {
        match self.messages.peek(&account_id) {
            Some(cache) => Some(cache),
            None => self.messages_large.peek(account_id),
        }
    }

    pub fn has_messages(&self, account_id: u32) -> bool {
        self.messages.inner().contains_key(&account_id) || self.messages_large.contains(account_id)
    }

    pub fn admits_messages(&self, account_id: u32, cache: &Arc<MessageStoreCache>) -> bool {
        if !self.messages.is_oversized(&account_id, cache) {
            return true;
        }

        trc::event!(
            Cache(CacheEvent::EntryTooLarge),
            AccountId = account_id,
            Collection = SyncCollection::Email.as_str(),
            Size = cache.size,
            Limit = self.messages.admission_limit(),
        );
        false
    }

    pub fn publish_messages(
        &self,
        account_id: u32,
        cache: &Arc<MessageStoreCache>,
        changes: Option<SwapChanges>,
    ) {
        if self.admits_messages(account_id, cache) {
            self.messages.update(account_id, cache.clone());
            if !self.messages_large.is_empty() {
                drop(self.messages_large.remove(account_id));
                self.expire_large_messages();
            }
            if let Some(changes) = changes {
                self.swap
                    .notify_changed(account_id, SyncCollection::Email, changes);
            }
        } else {
            self.publish_large_messages(account_id, cache, changes);
        }
    }

    pub fn publish_loaded_messages(
        &self,
        guard: MessageCacheGuard<'_>,
        account_id: u32,
        cache: &Arc<MessageStoreCache>,
        changes: Option<SwapChanges>,
    ) {
        if self.admits_messages(account_id, cache) {
            let _ = guard.insert(cache.clone());
            self.expire_large_messages();
            if let Some(changes) = changes {
                self.swap
                    .notify_changed(account_id, SyncCollection::Email, changes);
            }
        } else {
            self.publish_large_messages(account_id, cache, changes);
            drop(guard);
        }
    }

    pub fn remove_messages(&self, account_id: u32) {
        let resident = self.messages.remove(&account_id);
        let large = self.messages_large.remove(account_id);
        drop((resident, large));
    }

    pub fn clear_messages(&self) {
        self.messages.clear();
        self.messages_large.clear();
    }

    fn expire_large_messages(&self) {
        for (account_id, cache) in self.messages_large.expire_idle() {
            self.swap.notify_evicted_messages(account_id, cache);
        }
    }

    fn publish_large_messages(
        &self,
        account_id: u32,
        cache: &Arc<MessageStoreCache>,
        changes: Option<SwapChanges>,
    ) {
        if self.messages.inner().contains_key(&account_id) {
            drop(self.messages.remove(&account_id));
        }

        let publication = self.messages_large.publish(account_id, cache);
        for (unpinned_id, unpinned) in publication.unpinned {
            self.swap.notify_evicted_messages(unpinned_id, unpinned);
        }

        if let Some(changes) = changes {
            match publication.residency {
                Residency::Pinned => {
                    self.swap
                        .notify_changed(account_id, SyncCollection::Email, changes)
                }
                Residency::Shared => self
                    .swap
                    .notify_refresh_messages(account_id, changes, cache),
            }
        }
    }
}

impl Caches {
    pub fn resources(&self, collection: SyncCollection) -> Option<&ResourceCache> {
        match collection {
            SyncCollection::Calendar => Some(&self.events),
            SyncCollection::AddressBook => Some(&self.contacts),
            SyncCollection::FileNode => Some(&self.files),
            SyncCollection::CalendarEventNotification => Some(&self.scheduling),
            _ => None,
        }
    }

    #[inline]
    pub fn resident_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> Option<Arc<GroupwareResources>> {
        match self.resources(collection)?.get(&account_id) {
            Some(cache) => Some(cache),
            None => self
                .resources_large
                .lookup(SwapTarget::new(account_id, collection)),
        }
    }

    pub fn peek_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> Option<Arc<GroupwareResources>> {
        match self.resources(collection)?.peek(&account_id) {
            Some(cache) => Some(cache),
            None => self
                .resources_large
                .peek(SwapTarget::new(account_id, collection)),
        }
    }

    pub fn has_resources(&self, account_id: u32, collection: SyncCollection) -> bool {
        self.resources(collection).is_some_and(|resources| {
            resources.inner().contains_key(&account_id)
                || self
                    .resources_large
                    .contains(SwapTarget::new(account_id, collection))
        })
    }

    pub fn publish_resources(
        &self,
        account_id: u32,
        collection: SyncCollection,
        cache: &Arc<GroupwareResources>,
        changes: Option<SwapChanges>,
    ) {
        let Some(resources) = self.resources(collection) else {
            return;
        };
        if admits_resources(resources, account_id, collection, cache) {
            resources.update(account_id, cache.clone());
            if !self.resources_large.is_empty() {
                drop(
                    self.resources_large
                        .remove(SwapTarget::new(account_id, collection)),
                );
                self.expire_large_resources();
            }
            if let Some(changes) = changes {
                self.swap.notify_changed(account_id, collection, changes);
            }
        } else {
            self.publish_large_resources(resources, account_id, collection, cache, changes);
        }
    }

    pub fn publish_loaded_resources(
        &self,
        guard: ResourceCacheGuard<'_>,
        account_id: u32,
        collection: SyncCollection,
        cache: &Arc<GroupwareResources>,
        changes: Option<SwapChanges>,
    ) {
        let Some(resources) = self.resources(collection) else {
            return;
        };
        if admits_resources(resources, account_id, collection, cache) {
            let _ = guard.insert(cache.clone());
            self.expire_large_resources();
            if let Some(changes) = changes {
                self.swap.notify_changed(account_id, collection, changes);
            }
        } else {
            self.publish_large_resources(resources, account_id, collection, cache, changes);
            drop(guard);
        }
    }

    pub fn remove_resources(&self, account_id: u32) {
        for collection in [
            SyncCollection::Calendar,
            SyncCollection::AddressBook,
            SyncCollection::FileNode,
            SyncCollection::CalendarEventNotification,
        ] {
            let resident = self
                .resources(collection)
                .and_then(|resources| resources.remove(&account_id));
            let large = self
                .resources_large
                .remove(SwapTarget::new(account_id, collection));
            drop((resident, large));
        }
    }

    pub fn clear_resources(&self) {
        self.files.clear();
        self.contacts.clear();
        self.events.clear();
        self.scheduling.clear();
        self.resources_large.clear();
    }

    fn expire_large_resources(&self) {
        for (target, cache) in self.resources_large.expire_idle() {
            self.swap.notify_evicted_resources(target, cache);
        }
    }

    fn publish_large_resources(
        &self,
        resources: &ResourceCache,
        account_id: u32,
        collection: SyncCollection,
        cache: &Arc<GroupwareResources>,
        changes: Option<SwapChanges>,
    ) {
        if resources.inner().contains_key(&account_id) {
            drop(resources.remove(&account_id));
        }

        let publication = self
            .resources_large
            .publish(SwapTarget::new(account_id, collection), cache);
        for (target, unpinned) in publication.unpinned {
            self.swap.notify_evicted_resources(target, unpinned);
        }

        if let Some(changes) = changes {
            match publication.residency {
                Residency::Pinned => self.swap.notify_changed(account_id, collection, changes),
                Residency::Shared => self
                    .swap
                    .notify_refresh_resources(account_id, collection, changes, cache),
            }
        }
    }
}

fn admits_resources(
    resources: &ResourceCache,
    account_id: u32,
    collection: SyncCollection,
    cache: &Arc<GroupwareResources>,
) -> bool {
    if !resources.is_oversized(&account_id, cache) {
        return true;
    }

    trc::event!(
        Cache(CacheEvent::EntryTooLarge),
        AccountId = account_id,
        Collection = collection.as_str(),
        Size = cache.size,
        Limit = resources.admission_limit(),
    );
    false
}

