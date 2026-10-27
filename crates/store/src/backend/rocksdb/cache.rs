/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use rocksdb::{Cache, LruCacheOptions};
use utils::memory::available_memory;

const MIN_CACHE_SHARD: usize = 8 * 1024 * 1024;
const MAX_CACHE_SHARD_BITS: u32 = 6;
const MIN_DEFAULT_CACHE_SIZE: u64 = 256 * 1024 * 1024;
const MAX_DEFAULT_CACHE_SIZE: u64 = 8 * 1024 * 1024 * 1024;
const DEFAULT_CACHE_MEMORY_SHARE: u64 = 8;
const MAX_FLOOR_MEMORY_SHARE: u64 = 4;

pub(super) fn block_cache(cache_size: Option<u64>) -> Cache {
    let capacity =
        usize::try_from(cache_size.unwrap_or_else(default_cache_size)).unwrap_or(usize::MAX);
    let mut opts = LruCacheOptions::default();
    opts.set_capacity(capacity);
    opts.set_num_shard_bits(shard_bits(capacity));
    Cache::new_lru_cache_opts(&opts)
}

fn shard_bits(capacity: usize) -> i32 {
    (capacity / MIN_CACHE_SHARD)
        .max(1)
        .ilog2()
        .min(MAX_CACHE_SHARD_BITS) as i32
}

fn default_cache_size() -> u64 {
    cache_size_for(available_memory())
}

fn cache_size_for(memory: Option<u64>) -> u64 {
    memory.map_or(MIN_DEFAULT_CACHE_SIZE, |memory| {
        (memory / DEFAULT_CACHE_MEMORY_SHARE).clamp(
            MIN_DEFAULT_CACHE_SIZE.min(memory / MAX_FLOOR_MEMORY_SHARE),
            MAX_DEFAULT_CACHE_SIZE,
        )
    })
}

