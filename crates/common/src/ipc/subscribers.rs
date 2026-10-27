/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{CalendarAlert, PushNotification, ViewerStateChange};
use ahash::AHashMap;
use futures::task::AtomicWaker;
use parking_lot::{Mutex, RwLock};
use std::{
    collections::VecDeque,
    future::poll_fn,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
};
use tokio::runtime::Handle;
use trc::ServerEvent;
use types::type_state::{DataType, StateChange};
use utils::map::bitmap::Bitmap;

const SHARDS: usize = 256;
const _: () = assert!(SHARDS.is_power_of_two());
const MAX_PENDING_ALERTS: usize = 64;
const MAX_RELAYED_ALERTS: usize = 1024;
const MAX_TRACKED_CHANGES: usize = 64;
const RECLAIM_SLACK: u32 = 2;
const OFFLOAD_THRESHOLD: u32 = 256;
const RELAY_CHUNK: usize = 256;

pub struct PushSubscribers {
    shards: Box<[Shard]>,
    is_closed: AtomicBool,
    offload_threshold: u32,
}

#[derive(Default)]
#[repr(align(128))]
struct Shard(RwLock<AHashMap<u32, AccountSubscribers>>);

type Slots = Arc<[OnceLock<Slot>]>;

struct Slot {
    mailbox: Arc<Mailbox>,
    types: u64,
}

#[derive(Default)]
struct AccountSubscribers {
    slots: Slots,
    relay: Option<Arc<Relay>>,
    len: u32,
    live: u32,
    is_push: bool,
}

#[derive(Default)]
struct Relay {
    queue: Mutex<RelayQueue>,
}

#[derive(Default)]
struct RelayQueue {
    filtered: Changes,
    unfiltered: Changes,
    alerts: VecDeque<CalendarAlert>,
    is_running: bool,
}

pub struct PushReceiver {
    mailbox: Arc<Mailbox>,
    subscribers: Arc<PushSubscribers>,
    account_ids: Box<[u32]>,
}

struct Mailbox {
    // inbuxa: SCIM-52: the account whose session subscribed
    owner: u32,
    types: AtomicU64,
    is_retired: AtomicBool,
    pending: Mutex<Pending>,
    waker: AtomicWaker,
}

#[derive(Default)]
struct Pending {
    changes: Changes,
    alerts: VecDeque<CalendarAlert>,
    is_closed: bool,
}

#[derive(Default)]
struct Changes {
    entries: Vec<Change>,
    has_pending: bool,
}

#[derive(Debug, Clone, Copy)]
struct Change {
    viewer_id: Option<u32>,
    account_id: u32,
    types: u64,
    pending: u64,
    change_id: u64,
}

enum Taken {
    Some,
    Empty,
    Closed,
}

enum Route {
    Inline(Slots, usize),
    Relay(Arc<Relay>, Handle),
}

impl PushSubscribers {
    pub fn with_offload_threshold(offload_threshold: u32) -> Self {
        PushSubscribers {
            shards: (0..SHARDS).map(|_| Shard::default()).collect(),
            is_closed: AtomicBool::new(false),
            offload_threshold,
        }
    }

    fn shard(&self, account_id: u32) -> &RwLock<AHashMap<u32, AccountSubscribers>> {
        &self.shards[account_id as usize & (SHARDS - 1)].0
    }

    pub fn subscribe(
        self: &Arc<Self>,
        account_ids: impl IntoIterator<Item = u32>,
        types: Bitmap<DataType>,
    ) -> PushReceiver {
        let account_ids = account_ids.into_iter().collect::<Box<[u32]>>();
        let mailbox = Arc::new(Mailbox {
            owner: account_ids.first().copied().unwrap_or(u32::MAX),
            types: AtomicU64::new(*types),
            is_retired: AtomicBool::new(false),
            pending: Mutex::default(),
            waker: AtomicWaker::new(),
        });
        if self.is_closed.load(Ordering::SeqCst) {
            mailbox.retire();
            return PushReceiver {
                mailbox,
                subscribers: self.clone(),
                account_ids: Box::default(),
            };
        }
        for &account_id in &account_ids {
            let mut accounts = self.shard(account_id).write();
            let retired = accounts.entry(account_id).or_default().add(
                &mailbox,
                *types,
                self.offload_threshold,
            );
            drop(accounts);
            drop(retired);
        }
        if self.is_closed.load(Ordering::SeqCst) {
            mailbox.close();
        }
        PushReceiver {
            mailbox,
            subscribers: self.clone(),
            account_ids,
        }
    }

    fn unsubscribe(&self, account_ids: &[u32]) {
        for &account_id in account_ids {
            let mut accounts = self.shard(account_id).write();
            let Some(account) = accounts.get_mut(&account_id) else {
                continue;
            };
            account.live -= 1;
            let retired = if account.live == 0 && !account.is_push {
                accounts.remove(&account_id).map(|account| account.slots)
            } else {
                account.reclaim()
            };
            drop(accounts);
            drop(retired);
        }
    }

    pub fn dispatch(self: &Arc<Self>, notification: &PushNotification) -> bool {
        let account_id = notification.recipient();
        let (route, is_push) = {
            let accounts = self.shard(account_id).read();
            let Some(account) = accounts.get(&account_id) else {
                return false;
            };
            let relay = account.relay.as_ref().filter(|relay| {
                account.live > self.offload_threshold || relay.queue.lock().is_running
            });
            let route = match relay.and_then(|relay| Some((relay, Handle::try_current().ok()?))) {
                Some((relay, handle)) => Route::Relay(relay.clone(), handle),
                None => Route::Inline(account.slots.clone(), account.len as usize),
            };
            (route, account.is_push)
        };
        match route {
            Route::Inline(slots, len) => deliver(&slots[..len], notification),
            Route::Relay(relay, handle) => {
                if relay.queue.lock().push(notification) {
                    handle.spawn(self.clone().relay(account_id, relay));
                }
            }
        }
        is_push
    }

    async fn relay(self: Arc<Self>, account_id: u32, relay: Arc<Relay>) {
        let mut batch = RelayQueue::default();
        loop {
            {
                let mut queue = relay.queue.lock();
                if queue.is_empty() {
                    queue.is_running = false;
                    return;
                }
                queue.swap(&mut batch);
            }
            let snapshot = {
                let accounts = self.shard(account_id).read();
                accounts
                    .get(&account_id)
                    .filter(|account| {
                        account
                            .relay
                            .as_ref()
                            .is_some_and(|current| Arc::ptr_eq(current, &relay))
                    })
                    .map(|account| (account.slots.clone(), account.len as usize))
            };
            if let Some((slots, len)) = snapshot {
                for chunk in slots[..len].chunks(RELAY_CHUNK) {
                    batch.deliver(chunk);
                    tokio::task::yield_now().await;
                }
            }
            batch.clear();
        }
    }

    pub fn register_push(&self, activate: &[u32], expired: &[u32]) {
        for &account_id in activate {
            self.shard(account_id)
                .write()
                .entry(account_id)
                .or_default()
                .is_push = true;
        }
        for &account_id in expired {
            let mut accounts = self.shard(account_id).write();
            let retired = match accounts.get_mut(&account_id) {
                Some(account) if account.live == 0 => accounts.remove(&account_id),
                Some(account) => {
                    account.is_push = false;
                    None
                }
                None => None,
            };
            drop(accounts);
            drop(retired);
        }
    }

    /// inbuxa: SCIM-52: closes the subscriptions the account's own sessions
    /// hold on this node, which ends those sessions. The owner subscribes
    /// under its own id first, so its entry holds every one of them.
    pub fn revoke(&self, account_id: u32) {
        if let Some(account) = self.shard(account_id).read().get(&account_id) {
            for slot in account.slots() {
                if slot.mailbox.owner == account_id {
                    slot.mailbox.close();
                }
            }
        }
    }

    pub fn close_all(&self) {
        self.is_closed.store(true, Ordering::SeqCst);
        for shard in self.shards.iter() {
            for account in shard.0.read().values() {
                for slot in account.slots() {
                    slot.mailbox.close();
                }
            }
        }
    }
}

fn deliver(slots: &[OnceLock<Slot>], notification: &PushNotification) {
    match notification {
        PushNotification::StateChange(change) => deliver_change(slots, None, change, true),
        PushNotification::ViewerStateChange(ViewerStateChange { viewer_id, change }) => {
            deliver_change(slots, Some(*viewer_id), change, true)
        }
        PushNotification::EmailPush(push) => {
            deliver_change(slots, None, &push.to_state_change(), false)
        }
        PushNotification::CalendarAlert(alert) => deliver_alert(slots, alert),
    }
}

fn deliver_change(
    slots: &[OnceLock<Slot>],
    viewer_id: Option<u32>,
    change: &StateChange,
    is_filtered: bool,
) {
    let types = *change.types;
    for slot in slots.iter().filter_map(OnceLock::get) {
        if slot.types & types != 0 {
            slot.mailbox.deliver_change(viewer_id, change, is_filtered);
        }
    }
}

fn deliver_alert(slots: &[OnceLock<Slot>], alert: &CalendarAlert) {
    let filter = *Bitmap::from_iter([DataType::CalendarAlert]);
    for slot in slots.iter().filter_map(OnceLock::get) {
        if slot.types & filter != 0 {
            slot.mailbox.deliver_alert(alert);
        }
    }
}

impl RelayQueue {
    fn is_empty(&self) -> bool {
        !self.filtered.has_pending && !self.unfiltered.has_pending && self.alerts.is_empty()
    }

    fn push(&mut self, notification: &PushNotification) -> bool {
        match notification {
            PushNotification::StateChange(change) => {
                self.filtered.merge(None, change);
            }
            PushNotification::ViewerStateChange(ViewerStateChange { viewer_id, change }) => {
                self.filtered.merge(Some(*viewer_id), change);
            }
            PushNotification::EmailPush(push) => {
                self.unfiltered.merge(None, &push.to_state_change());
            }
            PushNotification::CalendarAlert(alert) => {
                if self.alerts.len() == MAX_RELAYED_ALERTS {
                    self.alerts.pop_front();
                    trc::event!(
                        Server(ServerEvent::ThreadError),
                        Details = "Dropped the oldest calendar alert of a busy account.",
                        CausedBy = trc::location!()
                    );
                }
                self.alerts.push_back(alert.clone());
            }
        }
        !std::mem::replace(&mut self.is_running, true)
    }

    fn swap(&mut self, batch: &mut RelayQueue) {
        std::mem::swap(&mut self.filtered, &mut batch.filtered);
        std::mem::swap(&mut self.unfiltered, &mut batch.unfiltered);
        std::mem::swap(&mut self.alerts, &mut batch.alerts);
    }

    fn deliver(&self, slots: &[OnceLock<Slot>]) {
        for (changes, is_filtered) in [(&self.filtered, true), (&self.unfiltered, false)] {
            for (viewer_id, change) in changes.pending() {
                deliver_change(slots, viewer_id, &change, is_filtered);
            }
        }
        for alert in &self.alerts {
            deliver_alert(slots, alert);
        }
    }

    fn clear(&mut self) {
        self.filtered.clear();
        self.unfiltered.clear();
        self.alerts.clear();
    }
}

impl AccountSubscribers {
    fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.slots[..self.len as usize]
            .iter()
            .filter_map(OnceLock::get)
    }

    fn add(&mut self, mailbox: &Arc<Mailbox>, types: u64, offload_threshold: u32) -> Option<Slots> {
        let retired = (self.len as usize == self.slots.len()).then(|| self.compact(1));
        let _ = self.slots[self.len as usize].set(Slot {
            mailbox: mailbox.clone(),
            types,
        });
        self.len += 1;
        self.live += 1;
        if self.live > offload_threshold && self.relay.is_none() {
            self.relay = Some(Arc::default());
        }
        retired
    }

    fn reclaim(&mut self) -> Option<Slots> {
        (self.len > 2 * self.live + RECLAIM_SLACK).then(|| self.compact(0))
    }

    fn compact(&mut self, reserve: usize) -> Slots {
        let mut slots = Vec::with_capacity(2 * self.live as usize + reserve);
        let mut len = 0u32;
        slots.extend(
            self.slots()
                .filter(|slot| !slot.mailbox.is_retired.load(Ordering::Relaxed))
                .map(|slot| {
                    len += 1;
                    OnceLock::from(Slot {
                        mailbox: slot.mailbox.clone(),
                        types: slot.types,
                    })
                }),
        );
        self.len = len;
        slots.resize_with(2 * slots.len() + reserve, OnceLock::new);
        std::mem::replace(&mut self.slots, slots.into())
    }
}

impl PushReceiver {
    pub async fn recv(&mut self, notifications: &mut Vec<PushNotification>) -> bool {
        poll_fn(|cx| match self.mailbox.take(notifications) {
            Taken::Some => Poll::Ready(true),
            Taken::Closed => Poll::Ready(false),
            Taken::Empty => {
                self.mailbox.waker.register(cx.waker());
                match self.mailbox.take(notifications) {
                    Taken::Some => Poll::Ready(true),
                    Taken::Closed => Poll::Ready(false),
                    Taken::Empty => Poll::Pending,
                }
            }
        })
        .await
    }
}

impl Drop for PushReceiver {
    fn drop(&mut self) {
        self.mailbox.retire();
        self.subscribers.unsubscribe(&self.account_ids);
    }
}

impl Mailbox {
    fn deliver_change(&self, viewer_id: Option<u32>, change: &StateChange, is_filtered: bool) {
        let mut pending = self.pending.lock();
        let types = self.types.load(Ordering::Relaxed);
        if types == 0 {
            return;
        }
        let was_empty = pending.is_empty();
        let types = if is_filtered {
            types & *change.types
        } else {
            *change.types
        };
        pending
            .changes
            .merge_types(viewer_id, change.account_id, types, change.change_id);
        let wake = was_empty && !pending.is_empty();
        drop(pending);
        if wake {
            self.waker.wake();
        }
    }

    fn deliver_alert(&self, alert: &CalendarAlert) {
        let alert = alert.clone();
        let mut pending = self.pending.lock();
        if self.types.load(Ordering::Relaxed) == 0 {
            return;
        }
        let was_empty = pending.is_empty();
        if pending.alerts.len() == MAX_PENDING_ALERTS {
            pending.alerts.pop_front();
            trc::event!(
                Server(ServerEvent::ThreadError),
                Details = "Dropped the oldest calendar alert of a slow subscriber.",
                CausedBy = trc::location!()
            );
        }
        pending.alerts.push_back(alert);
        drop(pending);
        if was_empty {
            self.waker.wake();
        }
    }

    fn take(&self, notifications: &mut Vec<PushNotification>) -> Taken {
        let mut pending = self.pending.lock();
        if pending.is_empty() {
            return if pending.is_closed {
                Taken::Closed
            } else {
                Taken::Empty
            };
        }
        notifications.extend(pending.changes.pending().map(
            |(viewer_id, change)| match viewer_id {
                Some(viewer_id) => {
                    PushNotification::ViewerStateChange(ViewerStateChange { viewer_id, change })
                }
                None => PushNotification::StateChange(change),
            },
        ));
        pending.changes.mark_taken();
        notifications.extend(
            pending
                .alerts
                .drain(..)
                .map(PushNotification::CalendarAlert),
        );
        Taken::Some
    }

    fn retire(&self) {
        self.types.store(0, Ordering::Relaxed);
        self.is_retired.store(true, Ordering::Relaxed);
        self.pending.lock().is_closed = true;
    }

    fn close(&self) {
        self.retire();
        self.waker.wake();
    }
}

impl Pending {
    fn is_empty(&self) -> bool {
        !self.changes.has_pending && self.alerts.is_empty()
    }
}

impl Changes {
    fn merge(&mut self, viewer_id: Option<u32>, change: &StateChange) -> bool {
        self.merge_types(
            viewer_id,
            change.account_id,
            *change.types,
            change.change_id,
        )
    }

    fn merge_types(
        &mut self,
        viewer_id: Option<u32>,
        account_id: u32,
        mut types: u64,
        change_id: u64,
    ) -> bool {
        if types == 0 {
            return false;
        }
        let same_key =
            |entry: &Change| entry.viewer_id == viewer_id && entry.account_id == account_id;
        for entry in self.entries.iter_mut().filter(|entry| same_key(entry)) {
            let overlap = entry.types & types;
            if overlap != 0 {
                if entry.change_id >= change_id {
                    types &= !overlap;
                } else {
                    entry.types &= !overlap;
                    entry.pending &= !overlap;
                }
            }
        }
        self.entries.retain(|entry| entry.types != 0);
        if types == 0 {
            return false;
        }
        match self
            .entries
            .iter_mut()
            .find(|entry| same_key(entry) && entry.change_id == change_id)
        {
            Some(entry) => {
                entry.types |= types;
                entry.pending |= types;
            }
            None => self.entries.push(Change {
                viewer_id,
                account_id,
                types,
                pending: types,
                change_id,
            }),
        }
        self.has_pending = true;
        if self.entries.len() > MAX_TRACKED_CHANGES {
            self.forget_taken();
        }
        true
    }

    fn pending(&self) -> impl Iterator<Item = (Option<u32>, StateChange)> + '_ {
        self.entries
            .iter()
            .filter(|entry| entry.pending != 0)
            .map(|entry| {
                (
                    entry.viewer_id,
                    StateChange {
                        account_id: entry.account_id,
                        change_id: entry.change_id,
                        types: Bitmap::from(entry.pending),
                    },
                )
            })
    }

    fn mark_taken(&mut self) {
        for entry in &mut self.entries {
            entry.pending = 0;
        }
        self.has_pending = false;
    }

    #[cold]
    fn forget_taken(&mut self) {
        let mut excess = self.entries.len() - MAX_TRACKED_CHANGES / 2;
        self.entries.retain(|entry| {
            if excess > 0 && entry.pending == 0 {
                excess -= 1;
                false
            } else {
                true
            }
        });
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.has_pending = false;
    }
}

impl Default for PushSubscribers {
    fn default() -> Self {
        Self::with_offload_threshold(OFFLOAD_THRESHOLD)
    }
}

