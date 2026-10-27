/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::{AHashMap, RandomState};
use std::{borrow::Borrow, hash::Hash, vec::IntoIter};

pub(crate) const INDEX_THRESHOLD: usize = 16;

#[derive(Debug)]
pub(crate) struct OrderedMap<K, V> {
    entries: Vec<(K, V)>,
    index: Option<Box<HashIndex>>,
}

#[derive(Debug)]
struct HashIndex {
    state: RandomState,
    positions: AHashMap<u64, usize>,
}

impl<K, V> Default for OrderedMap<K, V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            index: None,
        }
    }
}

impl<K: Hash + Eq, V> OrderedMap<K, V> {
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(key, value)| (key, value))
    }

    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.position(key).is_some()
    }

    pub(crate) fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let position = self.position(key)?;
        self.entries.get_mut(position).map(|(_, value)| value)
    }

    pub(crate) fn push(&mut self, key: K, value: V) {
        if let Some(index) = &mut self.index {
            index.insert(&key, self.entries.len());
        }
        self.entries.push((key, value));
        if self.index.is_none() {
            self.index = HashIndex::build(&self.entries);
        }
    }

    pub(crate) fn insert(&mut self, key: K, value: V) {
        match self.get_mut(&key) {
            Some(existing) => *existing = value,
            None => self.push(key, value),
        }
    }

    pub(crate) fn insert_if_absent(&mut self, key: K, value: V) {
        if !self.contains_key(&key) {
            self.push(key, value);
        }
    }

    pub(crate) fn upsert(
        &mut self,
        key: K,
        value: impl FnOnce() -> V,
        update: impl FnOnce(&mut V),
    ) {
        match self.get_mut(&key) {
            Some(existing) => update(existing),
            None => {
                let mut value = value();
                update(&mut value);
                self.push(key, value);
            }
        }
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        let len = self.entries.len();
        self.entries.retain_mut(|(key, value)| keep(key, value));
        if self.entries.len() != len {
            self.index = HashIndex::build(&self.entries);
        }
    }

    fn position<Q>(&self, key: &Q) -> Option<usize>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let Some(index) = &self.index else {
            return self.scan(key);
        };
        let position = index.get(key)?;
        match self.entries.get(position) {
            Some((item, _)) if item.borrow() == key => Some(position),
            _ => self.scan(key),
        }
    }

    fn scan<Q>(&self, key: &Q) -> Option<usize>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.entries
            .iter()
            .position(|(item, _)| item.borrow() == key)
    }
}

impl<K, V> IntoIterator for OrderedMap<K, V> {
    type Item = (K, V);
    type IntoIter = IntoIter<(K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl HashIndex {
    #[inline]
    fn build<K: Hash, V>(entries: &[(K, V)]) -> Option<Box<Self>> {
        (entries.len() > INDEX_THRESHOLD).then(|| Self::index(entries))
    }

    #[cold]
    #[inline(never)]
    fn index<K: Hash, V>(entries: &[(K, V)]) -> Box<Self> {
        let mut index = Box::new(HashIndex {
            state: RandomState::new(),
            positions: AHashMap::with_capacity(entries.len()),
        });
        for (position, (key, _)) in entries.iter().enumerate() {
            index.insert(key, position);
        }
        index
    }

    fn insert<Q: Hash + ?Sized>(&mut self, key: &Q, position: usize) {
        self.positions
            .entry(self.state.hash_one(key))
            .or_insert(position);
    }

    fn get<Q: Hash + ?Sized>(&self, key: &Q) -> Option<usize> {
        self.positions.get(&self.state.hash_one(key)).copied()
    }
}

