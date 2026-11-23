/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use arcstr::ArcStr;
use mail_auth::{DnssecStatus, MX, RecordSet, ResolverCache, Txt};
use quick_cache::{
    Equivalent, Options, OptionsBuilder, Weighter,
    sync::{DefaultLifecycle, PlaceholderGuard},
};
use std::{
    borrow::Borrow,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

pub struct Cache<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight>(
    quick_cache::sync::Cache<K, V, CacheItemWeighter, ahash::RandomState>,
);

pub struct CacheWithTtl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight>(
    quick_cache::sync::Cache<K, TtlEntry<V>, CacheItemWeighter, ahash::RandomState>,
);

#[derive(Clone)]
pub struct TtlEntry<V: Clone + CacheItemWeight> {
    value: V,
    expires: Instant,
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> Cache<K, V> {
    pub fn new(weight: u64, estimated_weight: u64) -> Self {
        Self::new_estimated(weight as usize / estimated_weight as usize, weight)
    }

    pub fn new_estimated(estimated_items_capacity: usize, weight_capacity: u64) -> Self {
        Self(quick_cache::sync::Cache::with_options(
            cache_options(estimated_items_capacity, weight_capacity, None),
            CacheItemWeighter,
            ahash::RandomState::default(),
            DefaultLifecycle::default(),
        ))
    }

    pub fn new_single_shard(weight: u64, estimated_weight: u64) -> Self {
        Self(quick_cache::sync::Cache::with_options(
            cache_options(weight as usize / estimated_weight as usize, weight, Some(1)),
            CacheItemWeighter,
            ahash::RandomState::default(),
            DefaultLifecycle::default(),
        ))
    }

    #[inline(always)]
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.get(key)
    }

    #[inline(always)]
    pub fn peek<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.peek(key)
    }

    #[inline(always)]
    pub async fn get_value_or_guard_async<'a, Q>(
        &'a self,
        key: &Q,
    ) -> Result<
        V,
        PlaceholderGuard<'a, K, V, CacheItemWeighter, ahash::RandomState, DefaultLifecycle<K, V>>,
    >
    where
        Q: Hash + Equivalent<K> + ToOwned<Owned = K> + ?Sized,
    {
        self.0.get_value_or_guard_async(key).await
    }

    #[inline(always)]
    pub fn insert(&self, key: K, value: V) {
        self.0.insert(key, value);
    }

    #[inline(always)]
    pub fn update(&self, key: K, value: V) {
        if let Err((key, value)) = self.0.replace(key, value, true) {
            self.0.insert(key, value);
        }
    }

    #[inline(always)]
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.remove(key).map(|(_, v)| v)
    }

    #[inline(always)]
    pub fn clear(&self) {
        self.0.clear();
    }

    #[inline(always)]
    pub fn inner(&self) -> &quick_cache::sync::Cache<K, V, CacheItemWeighter, ahash::RandomState> {
        &self.0
    }

    #[inline(always)]
    pub fn weight_capacity(&self) -> u64 {
        self.0.capacity()
    }
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> CacheWithTtl<K, V> {
    pub fn new(weight: u64, estimated_weight: u64) -> Self {
        Self::new_estimated(weight as usize / estimated_weight as usize, weight)
    }

    pub fn new_estimated(estimated_items_capacity: usize, weight_capacity: u64) -> Self {
        Self(quick_cache::sync::Cache::with_options(
            cache_options(estimated_items_capacity, weight_capacity, None),
            CacheItemWeighter,
            ahash::RandomState::default(),
            DefaultLifecycle::default(),
        ))
    }

    #[inline(always)]
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.get(key).and_then(|v| {
            if v.expires > Instant::now() {
                Some(v.value)
            } else {
                self.0.remove(key);
                None
            }
        })
    }

    #[inline(always)]
    pub async fn get_value_or_guard_async<'a, Q>(
        &'a self,
        key: &Q,
    ) -> Result<
        V,
        PlaceholderGuard<
            'a,
            K,
            TtlEntry<V>,
            CacheItemWeighter,
            ahash::RandomState,
            DefaultLifecycle<K, TtlEntry<V>>,
        >,
    >
    where
        Q: Hash + Equivalent<K> + ToOwned<Owned = K> + ?Sized,
    {
        match self.0.get_value_or_guard_async(key).await {
            Ok(value) => {
                if value.expires > Instant::now() {
                    Ok(value.value)
                } else {
                    self.0.remove(key);
                    self.0.get_value_or_guard_async(key).await.map(|v| v.value)
                }
            }
            Err(err) => Err(err),
        }
    }

    #[inline(always)]
    pub fn insert(&self, key: K, value: V, expires: Duration) {
        self.0.insert(key, TtlEntry::new(value, expires));
    }

    #[inline(always)]
    pub fn insert_with_expiry(&self, key: K, value: V, expires: Instant) {
        self.0.insert(key, TtlEntry::with_expiry(value, expires));
    }

    #[inline(always)]
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.remove(key).map(|(_, v)| v.value)
    }

    #[inline(always)]
    pub fn retain(&self, f: impl Fn(&K) -> bool) {
        self.0.retain(|key, _| f(key));
    }

    #[inline(always)]
    pub fn clear(&self) {
        self.0.clear();
    }
}

fn cache_options(
    estimated_items_capacity: usize,
    weight_capacity: u64,
    shards: Option<usize>,
) -> Options {
    let mut builder = OptionsBuilder::new();
    builder
        .estimated_items_capacity(estimated_items_capacity.max(1))
        .weight_capacity(weight_capacity);
    if let Some(shards) = shards {
        builder.shards(shards.max(1));
    }
    builder.build().unwrap()
}

#[derive(Clone)]
pub struct CacheItemWeighter;

impl<K: CacheItemWeight, V: CacheItemWeight> Weighter<K, V> for CacheItemWeighter {
    fn weight(&self, key: &K, val: &V) -> u64 {
        key.weight() + val.weight()
    }
}

pub trait CacheItemWeight {
    fn weight(&self) -> u64;
}

impl<T: Clone + CacheItemWeight> CacheItemWeight for TtlEntry<T> {
    fn weight(&self) -> u64 {
        self.value.weight() + std::mem::size_of::<Instant>() as u64
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

// inbuxa: the outbound TLS types moved to their own crate (RL-30), so
// their weights live here, with the trait.
impl CacheItemWeight for inbuxa_outbound_tls::Tlsa {
    fn weight(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| {
                (entry.data.len() + std::mem::size_of::<inbuxa_outbound_tls::TlsaEntry>()) as u64
            })
            .sum::<u64>()
            + std::mem::size_of::<inbuxa_outbound_tls::Tlsa>() as u64
    }
}

impl CacheItemWeight for inbuxa_outbound_tls::Policy {
    fn weight(&self) -> u64 {
        (std::mem::size_of::<inbuxa_outbound_tls::Policy>()
            + self
                .mx
                .iter()
                .map(|mx| match mx {
                    inbuxa_outbound_tls::MxPattern::Equals(t) => t.len(),
                    inbuxa_outbound_tls::MxPattern::StartsWith(t) => t.len(),
                })
                .sum::<usize>()) as u64
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
        self.rrset.weight() + std::mem::size_of::<DnssecStatus>() as u64
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

impl CacheItemWeight for MX {
    fn weight(&self) -> u64 {
        self.exchanges
            .iter()
            .map(|e| e.len() as u64 + std::mem::size_of::<Box<str>>() as u64)
            .sum::<u64>()
            + std::mem::size_of::<MX>() as u64
    }
}

impl CacheItemWeight for Txt {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Txt>() as u64
    }
}

impl CacheItemWeight for bool {
    fn weight(&self) -> u64 {
        std::mem::size_of::<bool>() as u64
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
    pub fn new(value: T, expires: Duration) -> Self {
        Self {
            value,
            expires: Instant::now() + expires,
        }
    }

    pub fn with_expiry(value: T, expires: Instant) -> Self {
        Self { value, expires }
    }
}

/// inbuxa: whether a resolver answer may be stored in a DNS cache. The resolver keys
/// its caches by name only, so one TXT entry answers every record type asked for at
/// that name (SPF, DKIM key, DMARC, MTA-STS, TLS-RPT...).
pub trait ResolverCacheValue {
    fn is_cacheable(&self) -> bool {
        true
    }
}

impl<T> ResolverCacheValue for RecordSet<T> {}

impl ResolverCacheValue for Txt {
    // A TXT answer is stored only when its records parsed as a record type that keeps
    // to its own names (v=spf1, v=DMARC1, a DKIM key...). A parse failure doesn't say
    // which type was asked for, and an SPF explanation parses from any text. Anyone
    // can make the server look up any name as SPF or as an explanation (include:,
    // redirect=, exp=), so caching those would hide another domain's DMARC policy or
    // DKIM key from the lookups that follow until the TTL ran out. They are looked
    // up again each time instead, like names that have no TXT record.
    fn is_cacheable(&self) -> bool {
        !matches!(self, Txt::Error(_) | Txt::SpfMacro(_))
    }
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight + ResolverCacheValue>
    ResolverCache<K, V> for CacheWithTtl<K, V>
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
        if value.is_cacheable() {
            self.0.insert(key, TtlEntry::with_expiry(value, expires));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_auth::{
        DnsError, Error,
        common::{parse::TxtRecordParser, resolver::UnwrapTxtRecord, verify::DomainKey},
        dmarc::{Dmarc, Policy},
        spf::{Macro, Spf},
    };

    // What the resolver does with a DNS answer for `name` when type T was asked for:
    // parse every record as T and store the first match, or the last error, under the name.
    fn resolve_as<T: TxtRecordParser + Into<Txt>>(
        cache: &CacheWithTtl<Box<str>, Txt>,
        name: &str,
        records: &[&[u8]],
    ) {
        let mut result = Err(Error::Dns(DnsError::InvalidRecordType));
        for record in records {
            result = T::parse(record);
            if result.is_ok() {
                break;
            }
        }
        ResolverCache::insert(
            cache,
            name.into(),
            result.into(),
            Instant::now() + Duration::from_secs(3600),
        );
    }

    // What the resolver does before asking DNS: a cache hit is the answer for type T.
    fn cached_as<T: UnwrapTxtRecord>(
        cache: &CacheWithTtl<Box<str>, Txt>,
        name: &str,
    ) -> Option<mail_auth::Result<Arc<T>>> {
        ResolverCache::get(cache, name).map(T::unwrap_txt)
    }

    #[test]
    fn txt_answer_for_one_record_type_is_not_served_to_another() {
        let cache = CacheWithTtl::<Box<str>, Txt>::new(1024 * 1024, 512);

        // A sender's SPF record says include:_dmarc.victim.example, so that name is
        // looked up as SPF first. The DMARC check for victim.example must still see
        // its p=reject policy, not the SPF lookup's "not an SPF record".
        let dmarc_name = "_dmarc.victim.example.";
        let dmarc_record: &[u8] = b"v=DMARC1; p=reject";
        resolve_as::<Spf>(&cache, dmarc_name, &[dmarc_record]);
        assert!(
            cached_as::<Dmarc>(&cache, dmarc_name).is_none(),
            "an SPF lookup of {dmarc_name} answered the DMARC lookup from the cache"
        );
        // The same through exp=, which looks the name up as an explanation string.
        resolve_as::<Macro>(&cache, dmarc_name, &[dmarc_record]);
        assert!(
            cached_as::<Dmarc>(&cache, dmarc_name).is_none(),
            "an SPF exp= lookup of {dmarc_name} answered the DMARC lookup from the cache"
        );
        // The DMARC lookup resolves the name itself, and its answer is cached.
        resolve_as::<Dmarc>(&cache, dmarc_name, &[dmarc_record]);
        let dmarc = cached_as::<Dmarc>(&cache, dmarc_name)
            .expect("the DMARC record is cached")
            .expect("the DMARC record parses");
        assert_eq!(dmarc.p, Policy::Reject);

        // The same for a DKIM key name (RFC 8463 test key).
        let key_name = "brisbane._domainkey.victim.example.";
        let key_record: &[u8] =
            b"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        resolve_as::<Spf>(&cache, key_name, &[key_record]);
        assert!(
            cached_as::<DomainKey>(&cache, key_name).is_none(),
            "an SPF lookup of {key_name} answered the DKIM key lookup from the cache"
        );
        resolve_as::<DomainKey>(&cache, key_name, &[key_record]);
        assert!(
            matches!(cached_as::<DomainKey>(&cache, key_name), Some(Ok(_))),
            "the DKIM key is cached"
        );

        // A name that holds no record of the type asked for isn't cached either, so a
        // later lookup of another type resolves it.
        let spf_name = "victim.example.";
        resolve_as::<Spf>(&cache, spf_name, &[b"google-site-verification=abc"]);
        assert!(ResolverCache::get(&cache, spf_name).is_none());
        // A valid SPF record is cached as before.
        resolve_as::<Spf>(&cache, spf_name, &[b"v=spf1 ip4:192.0.2.1 -all"]);
        assert!(matches!(cached_as::<Spf>(&cache, spf_name), Some(Ok(_))));
    }

    #[test]
    fn single_shard_retains_large_entry() {
        let capacity = 10_000_000u64;
        let cache = Cache::<u32, String>::new_single_shard(capacity, 1000);
        assert_eq!(cache.inner().num_shards(), 1);

        let value = "x".repeat(9_000_000);
        cache.insert(0, value.clone());
        assert_eq!(cache.get(&0), Some(value));
    }

    #[test]
    fn sharded_cache_drops_entry_larger_than_a_shard() {
        let capacity = 10_000_000u64;
        let cache = Cache::<u32, String>::new_estimated(10_000, capacity);

        let value = "x".repeat((capacity / 2) as usize);
        cache.insert(0, value);

        if cache.inner().num_shards() > 1 {
            assert_eq!(cache.get(&0), None);
        }
    }
}
