/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    SwapHandoff,
    writer::{Snapshot, SwapTarget},
};
use crate::{GroupwareResources, MessageStoreCache};
use quick_cache::Lifecycle;
use std::sync::Arc;
use types::collection::SyncCollection;

pub trait SwapCached {
    fn into_snapshot(cache: Arc<Self>) -> Snapshot;
}

impl SwapCached for MessageStoreCache {
    fn into_snapshot(cache: Arc<Self>) -> Snapshot {
        Snapshot::Messages(cache)
    }
}

impl SwapCached for GroupwareResources {
    fn into_snapshot(cache: Arc<Self>) -> Snapshot {
        Snapshot::Resources(cache)
    }
}

#[derive(Clone)]
pub struct SwapEviction {
    handoff: Option<Arc<SwapHandoff>>,
    collection: SyncCollection,
}

pub struct EvictionState<T: SwapCached> {
    released: [Option<Arc<T>>; 2],
    evicted: Vec<(u32, Arc<T>)>,
    handoff: Option<(Arc<SwapHandoff>, SyncCollection)>,
}

impl SwapEviction {
    pub(super) fn new(handoff: Option<Arc<SwapHandoff>>, collection: SyncCollection) -> Self {
        SwapEviction {
            handoff,
            collection,
        }
    }
}

impl<T: SwapCached> Default for EvictionState<T> {
    fn default() -> Self {
        EvictionState {
            released: [None, None],
            evicted: Vec::new(),
            handoff: None,
        }
    }
}

impl<T: SwapCached> Drop for EvictionState<T> {
    fn drop(&mut self) {
        if let Some((handoff, collection)) = self.handoff.take() {
            for (account_id, cache) in self.evicted.drain(..) {
                handoff.evicted(
                    SwapTarget::new(account_id, collection),
                    T::into_snapshot(cache),
                );
            }
        }
    }
}

impl<T: SwapCached> Lifecycle<u32, Arc<T>> for SwapEviction {
    type RequestState = EvictionState<T>;

    fn before_evict(&self, state: &mut Self::RequestState, key: &u32, val: &mut Arc<T>) {
        if let Some(handoff) = &self.handoff {
            if state.handoff.is_none() {
                state.handoff = Some((handoff.clone(), self.collection));
            }
            state.evicted.push((*key, val.clone()));
        }
    }

    fn on_evict(&self, state: &mut Self::RequestState, _: u32, val: Arc<T>) {
        if let Some(slot) = state.released.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(val);
        }
    }
}

