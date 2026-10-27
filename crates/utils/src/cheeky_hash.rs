/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use nohash_hasher::IsEnabled;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
};

// A hash that can cheekily store small inputs directly without hashing them.
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive,
)]
#[repr(transparent)]
pub struct CheekyHash([u8; HASH_SIZE + 1]);

const HASH_SIZE: usize = std::mem::size_of::<u128>();

pub type CheekyHashSet = HashSet<CheekyHash, nohash_hasher::BuildNoHashHasher<CheekyHash>>;
pub type CheekyHashMap<V> = HashMap<CheekyHash, V, nohash_hasher::BuildNoHashHasher<CheekyHash>>;
pub type CheekyBTreeMap<V> = BTreeMap<CheekyHash, V>;

impl CheekyHash {
    pub const HASH_SIZE: usize = HASH_SIZE;
    pub const EMPTY: CheekyHash = CheekyHash([0u8; HASH_SIZE + 1]);
    pub const FULL: CheekyHash = CheekyHash([u8::MAX; HASH_SIZE + 1]);

    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        let mut hash = [0u8; HASH_SIZE + 1];

        hash[HASH_SIZE] = bytes.len().min(u8::MAX as usize) as u8;

        if bytes.len() <= HASH_SIZE {
            hash[..bytes.len()].copy_from_slice(bytes);
        } else {
            let h1 = xxhash_rust::xxh3::xxh3_128(bytes).to_be_bytes();
            hash[..HASH_SIZE].copy_from_slice(&h1);
        }

        CheekyHash(hash)
    }

    #[inline(always)]
    pub fn as_key(&self) -> &[u8] {
        &self.0[..(self.0[HASH_SIZE] as usize).min(HASH_SIZE)]
    }

    #[inline(always)]
    pub fn key_len(&self) -> usize {
        (self.0[HASH_SIZE] as usize).min(HASH_SIZE)
    }

    #[inline(always)]
    pub fn as_payload(&self) -> &[u8] {
        &self.0[..HASH_SIZE]
    }

    pub fn from_key_bytes(key: &[u8], len: u8) -> Option<Self> {
        if key.len() == (len as usize).min(HASH_SIZE) {
            let mut hash = [0u8; HASH_SIZE + 1];
            hash[..key.len()].copy_from_slice(key);
            hash[HASH_SIZE] = len;
            Some(CheekyHash(hash))
        } else {
            None
        }
    }

    #[inline(always)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0[HASH_SIZE] as usize
    }

    #[inline(always)]
    fn as_u128(&self) -> u128 {
        u128::from_be_bytes(self.as_payload().try_into().unwrap())
    }
}

impl std::fmt::Display for CheekyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:032x}", self.as_u128())
    }
}

impl Hash for CheekyHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let len = self.0[HASH_SIZE] as usize;
        if len <= HASH_SIZE {
            state.write_u64(xxhash_rust::xxh3::xxh3_64(&self.0[..len]));
        } else {
            state.write_u64(u64::from_be_bytes(
                self.0[..std::mem::size_of::<u64>()].try_into().unwrap(),
            ));
        }
    }
}

impl IsEnabled for CheekyHash {}

impl Debug for CheekyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.0[HASH_SIZE] as usize;
        let payload = self.as_payload();
        let payload_str = if len <= HASH_SIZE {
            std::str::from_utf8(&payload[..len]).unwrap_or("<non-utf8>")
        } else {
            "<hashed data>"
        };

        f.debug_struct("CheekyHash")
            .field("length", &len)
            .field("bytes", &payload_str)
            .finish()
    }
}

