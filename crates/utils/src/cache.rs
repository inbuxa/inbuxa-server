/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use arcstr::ArcStr;
use compact_str::CompactString;
use mail_auth::{DnssecStatus, Mx, Negative, RecordSet, ResolverCache, TxtRecord};
use quick_cache::{
    Equivalent, Lifecycle, Options, OptionsBuilder, Weighter,
    sync::{DefaultLifecycle, PlaceholderGuard},
};
use std::{
    borrow::Borrow,
    hash::{BuildHasher, Hash},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

const HOT_ALLOCATION: f64 = 0.97;
const SPILL_FRACTION: u64 = 8;

pub const ENTRY_SLOT_SIZE: u64 = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryCharge {
    Payload,
    PayloadAndSlot,
}

pub struct Cache<
    K: Eq + Hash + CacheItemWeight,
    V: Clone + CacheItemWeight,
    L: Lifecycle<K, V> + Clone = DefaultLifecycle<K, V>,
    S: BuildHasher + Clone = ahash::RandomState,
> {
    inner: quick_cache::sync::Cache<K, V, CacheItemWeighter, S, L>,
    weighter: CacheItemWeighter,
    admission_limit: u64,
    name: &'static str,
}

pub struct SpillCache<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> {
    main: Cache<K, V>,
    spill: Cache<K, V>,
}

pub struct SpillGuard<'a, K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> {
    guard: CacheGuard<'a, K, V, DefaultLifecycle<K, V>>,
    key: K,
    cache: &'a SpillCache<K, V>,
}

pub type CacheGuard<'a, K, V, L, S = ahash::RandomState> =
    PlaceholderGuard<'a, K, V, CacheItemWeighter, S, L>;

pub struct CacheWithTtl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> {
    inner: quick_cache::sync::Cache<K, TtlEntry<V>, CacheItemWeighter, ahash::RandomState>,
    clock: TtlClock,
}

pub type TtlPlaceholder<'a, K, V> = PlaceholderGuard<
    'a,
    K,
    TtlEntry<V>,
    CacheItemWeighter,
    ahash::RandomState,
    DefaultLifecycle<K, TtlEntry<V>>,
>;

pub struct TtlGuard<'a, K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> {
    guard: TtlPlaceholder<'a, K, V>,
    clock: &'a TtlClock,
}

#[derive(Clone)]
pub struct TtlEntry<V: Clone + CacheItemWeight> {
    value: V,
    expires: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct TtlClock(Instant);

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> Cache<K, V> {
    pub fn new(weight: u64, estimated_weight: u64) -> Self {
        Self::new_with_charge(weight, estimated_weight, EntryCharge::PayloadAndSlot)
    }

    pub fn new_with_charge(weight: u64, estimated_weight: u64, charge: EntryCharge) -> Self {
        let weighter = CacheItemWeighter::from(charge);
        Self::build(
            cache_options(weighter.items(weight, estimated_weight), weight, None),
            DefaultLifecycle::default(),
            weighter,
        )
    }

    pub fn new_estimated(estimated_items_capacity: usize, weight_capacity: u64) -> Self {
        Self::build(
            cache_options(estimated_items_capacity, weight_capacity, None),
            DefaultLifecycle::default(),
            EntryCharge::PayloadAndSlot.into(),
        )
    }

    pub fn new_single_shard(weight: u64, estimated_weight: u64) -> Self {
        Self::new_single_shard_with(weight, estimated_weight, DefaultLifecycle::default())
    }
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight, S: BuildHasher + Clone + Default>
    Cache<K, V, DefaultLifecycle<K, V>, S>
{
    pub fn new_with_hasher(weight: u64, estimated_weight: u64) -> Self {
        let weighter = CacheItemWeighter::from(EntryCharge::PayloadAndSlot);
        Self::build(
            cache_options(weighter.items(weight, estimated_weight), weight, None),
            DefaultLifecycle::default(),
            weighter,
        )
    }
}

impl<
    K: Eq + Hash + CacheItemWeight,
    V: Clone + CacheItemWeight,
    L: Lifecycle<K, V> + Clone,
    S: BuildHasher + Clone + Default,
> Cache<K, V, L, S>
{
    pub fn new_single_shard_with(weight: u64, estimated_weight: u64, lifecycle: L) -> Self {
        let weighter = CacheItemWeighter::from(EntryCharge::Payload);
        Self::build(
            cache_options(weighter.items(weight, estimated_weight), weight, Some(1)),
            lifecycle,
            weighter,
        )
    }

    pub fn with_name(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }

    fn build(options: Options, lifecycle: L, weighter: CacheItemWeighter) -> Self {
        let inner =
            quick_cache::sync::Cache::with_options(options, weighter, S::default(), lifecycle);
        let shard_capacity = inner.shard_capacity();
        let admission_limit = ((shard_capacity as f64 * HOT_ALLOCATION) as u64)
            .clamp(shard_capacity.min(1), shard_capacity);

        Self {
            inner,
            weighter,
            admission_limit,
            name: "",
        }
    }

    #[inline(always)]
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.inner.get(key)
    }

    #[inline(always)]
    pub fn peek<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.inner.peek(key)
    }

    #[inline(always)]
    pub fn get_value_or_guard_async<'a, Q>(
        &'a self,
        key: &Q,
    ) -> impl Future<Output = Result<V, CacheGuard<'a, K, V, L, S>>>
    where
        Q: Hash + Equivalent<K> + ToOwned<Owned = K> + ?Sized,
    {
        self.inner.get_value_or_guard_async(key)
    }

    #[inline(always)]
    pub fn insert(&self, key: K, value: V) {
        if self.reject_oversized(&key, &value) {
            return;
        }
        self.inner.insert(key, value);
    }

    #[inline(always)]
    pub fn update(&self, key: K, value: V) {
        if self.reject_oversized(&key, &value) {
            return;
        }
        if let Err((key, value)) = self.inner.replace(key, value, true) {
            self.inner.insert(key, value);
        }
    }

    #[inline(always)]
    fn reject_oversized(&self, key: &K, value: &V) -> bool {
        let weight = self.weighter.charge(key, value);
        if weight <= self.admission_limit {
            return false;
        }

        trc::event!(
            Cache(trc::CacheEvent::EntryTooLarge),
            Name = self.name,
            Size = weight,
            Limit = self.admission_limit,
        );
        true
    }

    #[inline(always)]
    pub fn is_oversized(&self, key: &K, value: &V) -> bool {
        self.weighter.charge(key, value) > self.admission_limit
    }

    #[inline(always)]
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.inner.remove(key).map(|(_, v)| v)
    }

    #[inline(always)]
    pub fn clear(&self) {
        self.inner.clear();
    }

    #[inline(always)]
    pub fn inner(&self) -> &quick_cache::sync::Cache<K, V, CacheItemWeighter, S, L> {
        &self.inner
    }

    #[inline(always)]
    pub fn weight_capacity(&self) -> u64 {
        self.inner.capacity()
    }

    #[inline(always)]
    pub fn weight(&self) -> u64 {
        self.inner.weight()
    }

    #[inline(always)]
    pub fn admission_limit(&self) -> u64 {
        self.admission_limit
    }
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> CacheWithTtl<K, V> {
    pub fn new(weight: u64, estimated_weight: u64) -> Self {
        Self::new_estimated(
            CacheItemWeighter::from(EntryCharge::PayloadAndSlot).items(weight, estimated_weight),
            weight,
        )
    }

    #[inline(always)]
    pub fn weight(&self) -> u64 {
        self.inner.weight()
    }

    pub fn new_estimated(estimated_items_capacity: usize, weight_capacity: u64) -> Self {
        Self {
            inner: quick_cache::sync::Cache::with_options(
                cache_options(estimated_items_capacity, weight_capacity, None),
                CacheItemWeighter::from(EntryCharge::PayloadAndSlot),
                ahash::RandomState::default(),
                DefaultLifecycle::default(),
            ),
            clock: TtlClock::new(),
        }
    }

    #[inline(always)]
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.inner.get(key).and_then(|v| {
            if self.clock.is_live(v.expires) {
                Some(v.value)
            } else {
                self.inner
                    .remove_if(key, |entry| !self.clock.is_live(entry.expires));
                None
            }
        })
    }

    #[inline(always)]
    pub async fn get_value_or_guard_async<'a, Q>(&'a self, key: &Q) -> Result<V, TtlGuard<'a, K, V>>
    where
        Q: Hash + Equivalent<K> + ToOwned<Owned = K> + ?Sized,
    {
        let result = match self.inner.get_value_or_guard_async(key).await {
            Ok(value) if self.clock.is_live(value.expires) => return Ok(value.value),
            Ok(_) => {
                self.inner
                    .remove_if(key, |entry| !self.clock.is_live(entry.expires));
                self.inner.get_value_or_guard_async(key).await
            }
            Err(guard) => Err(guard),
        };
        result.map(|v| v.value).map_err(|guard| TtlGuard {
            guard,
            clock: &self.clock,
        })
    }

    #[inline(always)]
    pub fn insert(&self, key: K, value: V, expires: Duration) {
        self.inner
            .insert(key, TtlEntry::new(value, self.clock.expires_in(expires)));
    }

    #[inline(always)]
    pub fn insert_with_expiry(&self, key: K, value: V, expires: Instant) {
        self.inner
            .insert(key, TtlEntry::new(value, self.clock.expires_at(expires)));
    }

    #[inline(always)]
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.inner.remove(key).map(|(_, v)| v.value)
    }

    #[inline(always)]
    pub fn retain(&self, f: impl Fn(&K) -> bool) {
        self.inner.retain(|key, _| f(key));
    }

    #[inline(always)]
    pub fn clear(&self) {
        self.inner.clear();
    }
}

impl<'a, K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> TtlGuard<'a, K, V> {
    pub fn insert(self, value: V, expires: Duration) {
        let _ = self
            .guard
            .insert(TtlEntry::new(value, self.clock.expires_in(expires)));
    }

    pub fn insert_with_expiry(self, value: V, expires: Instant) {
        let _ = self
            .guard
            .insert(TtlEntry::new(value, self.clock.expires_at(expires)));
    }
}

impl TtlClock {
    pub fn new() -> Self {
        TtlClock(Instant::now())
    }

    #[inline(always)]
    pub fn now(&self) -> u32 {
        clamp_secs(self.0.elapsed().as_secs())
    }

    #[inline(always)]
    pub fn is_live(&self, expires: u32) -> bool {
        expires > self.now()
    }

    #[inline(always)]
    pub fn expires_in(&self, ttl: Duration) -> u32 {
        if !ttl.is_zero() {
            ceil_secs(self.0.elapsed().saturating_add(ttl))
        } else {
            0
        }
    }

    #[inline(always)]
    pub fn expires_at(&self, expires: Instant) -> u32 {
        if expires > Instant::now() {
            ceil_secs(expires.saturating_duration_since(self.0))
        } else {
            0
        }
    }
}

impl Default for TtlClock {
    fn default() -> Self {
        TtlClock::new()
    }
}

#[inline(always)]
fn ceil_secs(elapsed: Duration) -> u32 {
    clamp_secs(elapsed.as_secs() + u64::from(elapsed.subsec_nanos() > 0))
}

#[inline(always)]
fn clamp_secs(secs: u64) -> u32 {
    u32::try_from(secs).unwrap_or(u32::MAX)
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> SpillCache<K, V> {
    pub fn new(weight: u64, estimated_weight: u64) -> Self {
        let weighter = CacheItemWeighter::from(EntryCharge::PayloadAndSlot);
        let spill_weight = weight / SPILL_FRACTION;
        let main_weight = weight - spill_weight;
        SpillCache {
            main: Cache::build(
                cache_options(
                    weighter.items(main_weight, estimated_weight),
                    main_weight,
                    None,
                ),
                DefaultLifecycle::default(),
                weighter,
            ),
            spill: Cache::build(
                cache_options(
                    weighter.items(spill_weight, estimated_weight),
                    spill_weight,
                    Some(1),
                ),
                DefaultLifecycle::default(),
                weighter,
            ),
        }
    }

    pub fn with_name(self, name: &'static str) -> Self {
        SpillCache {
            main: self.main.with_name(name),
            spill: self.spill.with_name(name),
        }
    }

    #[inline(always)]
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.main.get(key).or_else(|| self.spill.get(key))
    }

    pub async fn get_value_or_guard_async<'a, Q>(
        &'a self,
        key: &Q,
    ) -> Result<V, SpillGuard<'a, K, V>>
    where
        Q: Hash + Equivalent<K> + ToOwned<Owned = K> + ?Sized,
    {
        if let Some(value) = self.get(key) {
            return Ok(value);
        }
        match self.main.get_value_or_guard_async(key).await {
            Ok(value) => Ok(value),
            Err(guard) => match self.spill.get(key) {
                Some(value) => Ok(value),
                None => Err(SpillGuard {
                    guard,
                    key: key.to_owned(),
                    cache: self,
                }),
            },
        }
    }

    pub fn update(&self, key: K, value: V) {
        if self.main.is_oversized(&key, &value) {
            self.main.remove(&key);
            self.spill.update(key, value);
        } else {
            self.spill.remove(&key);
            self.main.update(key, value);
        }
    }

    pub fn remove<Q>(&self, key: &Q)
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.main.remove(key);
        self.spill.remove(key);
    }

    pub fn clear(&self) {
        self.main.clear();
        self.spill.clear();
    }

    pub fn weight(&self) -> u64 {
        self.main.weight() + self.spill.weight()
    }
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> SpillGuard<'_, K, V> {
    pub fn insert(self, value: V) {
        if self.cache.main.is_oversized(&self.key, &value) {
            self.cache.spill.insert(self.key, value);
            drop(self.guard);
        } else {
            let _ = self.guard.insert(value);
        }
    }
}

const MIN_ENTRIES_PER_SHARD: usize = 256;

fn cache_options(
    estimated_items_capacity: usize,
    weight_capacity: u64,
    shards: Option<usize>,
) -> Options {
    let estimated_items_capacity = estimated_items_capacity.max(1);
    let mut builder = OptionsBuilder::new();
    builder
        .estimated_items_capacity(estimated_items_capacity)
        .weight_capacity(weight_capacity);
    builder.shards(match shards {
        Some(shards) => shards.max(1),
        None => {
            let capped = default_shards().min(estimated_items_capacity / MIN_ENTRIES_PER_SHARD);
            if capped <= 1 {
                1
            } else {
                1 << (usize::BITS - 1 - capped.leading_zeros())
            }
        }
    });
    builder.build().unwrap()
}

fn default_shards() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        * 4
}

#[derive(Debug, Clone, Copy)]
pub struct CacheItemWeighter {
    entry_overhead: u64,
}

impl CacheItemWeighter {
    #[inline(always)]
    fn charge<K: CacheItemWeight, V: CacheItemWeight>(&self, key: &K, val: &V) -> u64 {
        key.weight() + val.weight() + self.entry_overhead
    }

    fn items(&self, weight: u64, estimated_weight: u64) -> usize {
        (weight / (estimated_weight + self.entry_overhead).max(1)) as usize
    }
}

impl From<EntryCharge> for CacheItemWeighter {
    fn from(charge: EntryCharge) -> Self {
        CacheItemWeighter {
            entry_overhead: match charge {
                EntryCharge::Payload => 0,
                EntryCharge::PayloadAndSlot => ENTRY_SLOT_SIZE,
            },
        }
    }
}

impl<K: CacheItemWeight, V: CacheItemWeight> Weighter<K, V> for CacheItemWeighter {
    fn weight(&self, key: &K, val: &V) -> u64 {
        self.charge(key, val)
    }
}

pub trait CacheItemWeight {
    fn weight(&self) -> u64;
}

impl<T: Clone + CacheItemWeight> CacheItemWeight for TtlEntry<T> {
    fn weight(&self) -> u64 {
        self.value.weight() + std::mem::size_of::<u32>() as u64
    }
}

impl<T: Clone + CacheItemWeight> CacheItemWeight for Option<T> {
    fn weight(&self) -> u64 {
        match self {
            Some(v) => v.weight(),
            None => std::mem::size_of::<usize>() as u64,
        }
    }
}

impl<T: CacheItemWeight> CacheItemWeight for Arc<T> {
    fn weight(&self) -> u64 {
        self.as_ref().weight()
    }
}

impl CacheItemWeight for u64 {
    fn weight(&self) -> u64 {
        std::mem::size_of::<u64>() as u64
    }
}

impl CacheItemWeight for String {
    fn weight(&self) -> u64 {
        self.len() as u64 + std::mem::size_of::<String>() as u64
    }
}

impl CacheItemWeight for Box<str> {
    fn weight(&self) -> u64 {
        self.len() as u64 + std::mem::size_of::<Box<str>>() as u64
    }
}

impl<T: CacheItemWeight> CacheItemWeight for Box<[T]> {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Box<[T]>>() as u64 + self.iter().map(|item| item.weight()).sum::<u64>()
    }
}

impl<T: CacheItemWeight> CacheItemWeight for Arc<[T]> {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Arc<[T]>>() as u64 + self.iter().map(|item| item.weight()).sum::<u64>()
    }
}

impl<T: CacheItemWeight> CacheItemWeight for RecordSet<T> {
    fn weight(&self) -> u64 {
        self.records.weight() + std::mem::size_of::<DnssecStatus>() as u64
    }
}

impl<T: CacheItemWeight> CacheItemWeight for Result<RecordSet<T>, Negative> {
    fn weight(&self) -> u64 {
        match self {
            Ok(records) => records.weight(),
            Err(_) => std::mem::size_of::<Negative>() as u64,
        }
    }
}

impl CacheItemWeight for u32 {
    fn weight(&self) -> u64 {
        std::mem::size_of::<u32>() as u64
    }
}

impl CacheItemWeight for IpAddr {
    fn weight(&self) -> u64 {
        std::mem::size_of::<IpAddr>() as u64
    }
}

impl CacheItemWeight for Ipv4Addr {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Ipv4Addr>() as u64
    }
}

impl CacheItemWeight for Ipv6Addr {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Ipv6Addr>() as u64
    }
}

impl CacheItemWeight for Mx {
    fn weight(&self) -> u64 {
        self.exchanges
            .iter()
            .map(|e| e.len() as u64 + std::mem::size_of::<Box<str>>() as u64)
            .sum::<u64>()
            + std::mem::size_of::<Mx>() as u64
    }
}

impl CacheItemWeight for TxtRecord {
    fn weight(&self) -> u64 {
        (std::mem::size_of::<TxtRecord>() + self.heap_size()) as u64
    }
}

impl CacheItemWeight for bool {
    fn weight(&self) -> u64 {
        std::mem::size_of::<bool>() as u64
    }
}

impl CacheItemWeight for CompactString {
    fn weight(&self) -> u64 {
        let heap = if self.is_heap_allocated() {
            self.capacity() as u64
        } else {
            0
        };
        heap + std::mem::size_of::<CompactString>() as u64
    }
}

impl CacheItemWeight for ArcStr {
    fn weight(&self) -> u64 {
        self.len() as u64 + std::mem::size_of::<ArcStr>() as u64
    }
}

impl CacheItemWeight for () {
    fn weight(&self) -> u64 {
        0
    }
}

impl<T: Clone + CacheItemWeight> TtlEntry<T> {
    fn new(value: T, expires: u32) -> Self {
        Self { value, expires }
    }
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> ResolverCache<K, V>
    for CacheWithTtl<K, V>
{
    fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        CacheWithTtl::get(self, key)
    }

    fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        CacheWithTtl::remove(self, key)
    }

    fn insert(&self, key: K, value: V, expires: Instant) {
        CacheWithTtl::insert_with_expiry(self, key, value, expires);
    }
}


