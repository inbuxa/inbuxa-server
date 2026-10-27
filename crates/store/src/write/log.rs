/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    U16_LEN, U64_LEN,
    write::{AssignedIds, PendingId},
};
use ahash::{AHashSet, RandomState};
use indexmap::IndexSet;
use types::collection::{SyncCollection, VanishedCollection};
use utils::{codec::leb128::Leb128Writer, map::vec_map::VecMap};

pub const CONTAINER_INSERTS: usize = 0;
pub const CONTAINER_UPDATES: usize = 1;
pub const CONTAINER_PROPERTY_CHANGES: usize = 2;
pub const CONTAINER_DELETES: usize = 3;
pub const ITEM_INSERTS: usize = 4;
pub const ITEM_UPDATES: usize = 5;
pub const ITEM_DELETES: usize = 6;
pub const CONTAINER_METADATA: usize = 7;
pub const ITEM_METADATA: usize = 8;
pub const CHANGE_LISTS: usize = 9;

pub(crate) const PRESENCE_EXTENDED: u8 = 0x80;
pub(crate) const BASE_LISTS: usize = CONTAINER_METADATA;
pub(crate) const CONTAINER_LISTS: u16 = (1 << CONTAINER_INSERTS)
    | (1 << CONTAINER_UPDATES)
    | (1 << CONTAINER_PROPERTY_CHANGES)
    | (1 << CONTAINER_DELETES)
    | (1 << CONTAINER_METADATA);
pub(crate) const ITEM_LISTS: u16 =
    (1 << ITEM_INSERTS) | (1 << ITEM_UPDATES) | (1 << ITEM_DELETES) | (1 << ITEM_METADATA);

const _: () = assert!(CHANGE_LISTS == ITEM_METADATA + 1);
const _: () = assert!(BASE_LISTS == ITEM_DELETES + 1);
const _: () = assert!(BASE_LISTS < u8::BITS as usize);
const _: () = assert!(CHANGE_LISTS - BASE_LISTS < u8::BITS as usize);
const _: () = assert!(CONTAINER_LISTS & ITEM_LISTS == 0);
const _: () = assert!((CONTAINER_LISTS | ITEM_LISTS).count_ones() as usize == CHANGE_LISTS);

const CHANGE_SET_THRESHOLD: usize = 256;
const CHANGE_SET_SCAN_LIMIT: usize = 32;

const CONTAINER_BYTES_HINT: usize = 2;
const ITEM_BYTES_HINT: usize = 2;
const PREFIXED_ITEM_BYTES_HINT: usize = 3;
const VANISHED_ID_BYTES_HINT: usize = 2;

#[derive(Debug)]
pub enum ChangeSet<T> {
    Small(Vec<T>),
    Large(AHashSet<T>),
}

pub const PENDING_ID_MARKER: u64 = (u32::MAX as u64) << 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PendingChange {
    pub prefix: Option<PendingId>,
    pub id: PendingId,
}

#[inline(always)]
pub const fn is_pending_id(id: u64) -> bool {
    id & PENDING_ID_MARKER == PENDING_ID_MARKER
}

impl<T> Default for ChangeSet<T> {
    fn default() -> Self {
        ChangeSet::Small(Vec::new())
    }
}

pub enum ChangeSetIter<'x, T> {
    Small(std::slice::Iter<'x, T>),
    Large(std::collections::hash_set::Iter<'x, T>),
}

impl<'x, T> Iterator for ChangeSetIter<'x, T> {
    type Item = &'x T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ChangeSetIter::Small(items) => items.next(),
            ChangeSetIter::Large(items) => items.next(),
        }
    }
}

impl<T> ChangeSet<T> {
    pub fn iter(&self) -> ChangeSetIter<'_, T> {
        match self {
            ChangeSet::Small(items) => ChangeSetIter::Small(items.iter()),
            ChangeSet::Large(items) => ChangeSetIter::Large(items.iter()),
        }
    }
}

impl<'x, T> IntoIterator for &'x ChangeSet<T> {
    type Item = &'x T;
    type IntoIter = ChangeSetIter<'x, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: Copy + Eq + std::hash::Hash + Into<u64>> ChangeSet<T> {
    pub fn insert(&mut self, value: T) -> bool {
        match self {
            ChangeSet::Small(items) => {
                if items.contains(&value) {
                    return false;
                }
                items.push(value);
                if items.len() > CHANGE_SET_THRESHOLD {
                    *self = ChangeSet::Large(items.iter().copied().collect());
                }
                true
            }
            ChangeSet::Large(items) => items.insert(value),
        }
    }

    pub fn remove(&mut self, value: &T) -> bool {
        if let ChangeSet::Small(items) = self
            && items.len() > CHANGE_SET_SCAN_LIMIT
        {
            *self = ChangeSet::Large(items.iter().copied().collect());
        }

        match self {
            ChangeSet::Small(items) => {
                if let Some(pos) = items.iter().position(|item| item == value) {
                    items.swap_remove(pos);
                    true
                } else {
                    false
                }
            }
            ChangeSet::Large(items) => items.remove(value),
        }
    }

    pub fn contains(&self, value: &T) -> bool {
        match self {
            ChangeSet::Small(items) => items.contains(value),
            ChangeSet::Large(items) => items.contains(value),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            ChangeSet::Small(items) => items.len(),
            ChangeSet::Large(items) => items.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            ChangeSet::Small(items) => items.is_empty(),
            ChangeSet::Large(items) => items.is_empty(),
        }
    }

    fn collect_unsorted(&self, out: &mut Vec<u64>) {
        out.clear();
        match self {
            ChangeSet::Small(items) => out.extend(items.iter().map(|item| (*item).into())),
            ChangeSet::Large(items) => out.extend(items.iter().map(|item| (*item).into())),
        }
    }

    fn collect_sorted(&self, out: &mut Vec<u64>) {
        self.collect_unsorted(out);
        out.sort_unstable();
    }
}

#[inline(always)]
pub fn zigzag_encode(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

#[inline(always)]
pub fn zigzag_decode(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

#[inline(always)]
fn write_ids(buf: &mut Vec<u8>, ids: &[u64]) {
    let mut prev = 0u64;
    for id in ids {
        buf.push_leb128(*id - prev);
        prev = *id;
    }
}

#[inline(always)]
fn write_prefixed_ids(buf: &mut Vec<u8>, ids: &[u64]) {
    let mut prev_prefix = 0i64;
    let mut prev_document_id = 0i64;
    for id in ids {
        let prefix = (*id >> 32) as i64;
        let document_id = (*id & u32::MAX as u64) as i64;
        buf.push_leb128((prefix - prev_prefix) as u64);
        buf.push_leb128(zigzag_encode(document_id - prev_document_id));
        prev_prefix = prefix;
        prev_document_id = document_id;
    }
}

#[derive(Default, Debug)]
pub(crate) struct ChangeLogBuilder {
    pub changes: VecMap<SyncCollection, Changes>,
    pub vanished: VecMap<VanishedCollection, VanishedItems>,
    pub private: VecMap<PrivateLog, Changes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PrivateLog {
    pub collection: SyncCollection,
    pub viewer: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum VanishedItem {
    Name(String),
    Id(u64),
}

#[derive(Default, Debug)]
pub(crate) struct VanishedItems(Vec<VanishedItem>);

#[derive(Default, Debug)]
pub struct Changes {
    pub item_inserts: ChangeSet<u64>,
    pub item_updates: ChangeSet<u64>,
    pub item_deletes: ChangeSet<u64>,

    pub container_inserts: ChangeSet<u64>,
    pub container_updates: ChangeSet<u64>,
    pub container_deletes: ChangeSet<u64>,
    pub container_property_changes: ChangeSet<u64>,

    pub metadata: Option<Box<MetadataChanges>>,

    pending: IndexSet<PendingChange, RandomState>,
}

#[derive(Default, Debug)]
pub struct MetadataChanges {
    pub containers: ChangeSet<u64>,
    pub items: ChangeSet<u64>,
}

impl MetadataChanges {
    #[cold]
    fn bytes_hint(&self, item_bytes_hint: usize) -> usize {
        1 + CHANGE_LISTS - BASE_LISTS
            + (self.containers.len() * CONTAINER_BYTES_HINT)
            + (self.items.len() * item_bytes_hint)
    }
}

impl Changes {
    fn build_id(&mut self, prefix: Option<PendingId>, document_id: PendingId) -> u64 {
        match (prefix, document_id) {
            (None, PendingId::Assigned(document_id)) => document_id as u64,
            (Some(PendingId::Assigned(prefix)), PendingId::Assigned(document_id)) => {
                debug_assert_ne!(prefix, u32::MAX, "prefix collides with the pending marker");
                ((prefix as u64) << 32) | document_id as u64
            }
            _ => {
                let change = PendingChange {
                    prefix,
                    id: document_id,
                };
                PENDING_ID_MARKER | self.pending.insert_full(change).0 as u64
            }
        }
    }

    fn resolve_id(&self, id: u64, ids: &AssignedIds) -> u64 {
        if !is_pending_id(id) {
            return id;
        }

        let Some(change) = self
            .pending
            .get_index((id & u32::MAX as u64) as usize)
            .copied()
        else {
            debug_assert!(false, "pending change is out of range");
            return id;
        };
        let document_id = change.id.resolve(ids) as u64;

        match change.prefix {
            Some(prefix) => ((prefix.resolve(ids) as u64) << 32) | document_id,
            None => document_id,
        }
    }

    #[inline(always)]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    #[inline(always)]
    fn supersede_container_metadata(&mut self, id: u64) {
        if let Some(metadata) = &mut self.metadata {
            metadata.containers.remove(&id);
        }
    }

    #[inline(always)]
    fn supersede_item_metadata(&mut self, id: u64) {
        if let Some(metadata) = &mut self.metadata {
            metadata.items.remove(&id);
        }
    }
}

impl ChangeLogBuilder {
    pub fn log_container_insert(&mut self, collection: SyncCollection, document_id: PendingId) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(None, document_id);
        changes.supersede_container_metadata(id);
        if changes.container_deletes.remove(&id) {
            changes.container_updates.insert(id);
        } else {
            changes.container_inserts.insert(id);
        }
    }

    pub fn log_item_insert(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
        document_id: PendingId,
    ) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(prefix, document_id);
        changes.supersede_item_metadata(id);
        if changes.item_deletes.remove(&id) {
            changes.item_updates.insert(id);
        } else {
            changes.item_inserts.insert(id);
        }
    }

    pub fn log_container_update(&mut self, collection: SyncCollection, document_id: PendingId) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(None, document_id);
        changes.supersede_container_metadata(id);
        changes.container_updates.insert(id);
    }

    pub fn log_container_property_update(
        &mut self,
        collection: SyncCollection,
        document_id: PendingId,
    ) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(None, document_id);
        changes.container_property_changes.insert(id);
    }

    pub fn log_item_update(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
        document_id: PendingId,
    ) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(prefix, document_id);
        changes.supersede_item_metadata(id);
        changes.item_updates.insert(id);
    }

    pub fn log_container_delete(&mut self, collection: SyncCollection, document_id: PendingId) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(None, document_id);
        changes.container_updates.remove(&id);
        changes.container_property_changes.remove(&id);
        changes.supersede_container_metadata(id);
        changes.container_deletes.insert(id);
    }

    pub fn log_item_delete(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
        document_id: PendingId,
    ) {
        let changes = self.changes.get_mut_or_insert(collection);
        let id = changes.build_id(prefix, document_id);
        changes.item_updates.remove(&id);
        changes.supersede_item_metadata(id);
        changes.item_deletes.insert(id);
    }

    pub fn log_container_metadata(&mut self, collection: SyncCollection, document_id: PendingId) {
        self.changes
            .get_mut_or_insert(collection)
            .container_metadata_change(document_id);
    }

    pub fn log_item_metadata(
        &mut self,
        collection: SyncCollection,
        prefix: Option<PendingId>,
        document_id: PendingId,
    ) {
        self.changes
            .get_mut_or_insert(collection)
            .item_metadata_change(prefix, document_id);
    }

    pub fn log_private_container_metadata(
        &mut self,
        collection: SyncCollection,
        viewer: u32,
        document_id: PendingId,
    ) {
        self.private
            .get_mut_or_insert(PrivateLog { collection, viewer })
            .container_metadata_change(document_id);
    }

    pub fn log_private_item_metadata(
        &mut self,
        collection: SyncCollection,
        viewer: u32,
        prefix: Option<PendingId>,
        document_id: PendingId,
    ) {
        self.private
            .get_mut_or_insert(PrivateLog { collection, viewer })
            .item_metadata_change(prefix, document_id);
    }

    pub fn log_vanished_item(
        &mut self,
        collection: VanishedCollection,
        item: impl Into<VanishedItem>,
    ) {
        self.vanished
            .get_mut_or_insert(collection)
            .0
            .push(item.into());
    }
}

impl Changes {
    fn container_metadata_change(&mut self, document_id: PendingId) {
        let id = self.build_id(None, document_id);
        if !self.container_inserts.contains(&id)
            && !self.container_updates.contains(&id)
            && !self.container_deletes.contains(&id)
        {
            self.metadata.get_or_insert_default().containers.insert(id);
        }
    }

    fn item_metadata_change(&mut self, prefix: Option<PendingId>, document_id: PendingId) {
        let id = self.build_id(prefix, document_id);
        if !self.item_inserts.contains(&id)
            && !self.item_updates.contains(&id)
            && !self.item_deletes.contains(&id)
        {
            self.metadata.get_or_insert_default().items.insert(id);
        }
    }

    pub fn has_container_changes(&self) -> bool {
        !self.container_inserts.is_empty()
            || !self.container_updates.is_empty()
            || !self.container_property_changes.is_empty()
            || !self.container_deletes.is_empty()
            || self
                .metadata
                .as_ref()
                .is_some_and(|metadata| !metadata.containers.is_empty())
    }

    pub fn has_item_changes(&self) -> bool {
        !self.item_inserts.is_empty()
            || !self.item_updates.is_empty()
            || !self.item_deletes.is_empty()
            || self
                .metadata
                .as_ref()
                .is_some_and(|metadata| !metadata.items.is_empty())
    }
}

impl Changes {
    pub fn serialize(&self, is_prefixed: bool, scratch: &mut Vec<u64>) -> Option<Vec<u8>> {
        if self.has_pending() {
            return None;
        }
        let mut buf = Vec::new();
        self.write_into(is_prefixed, None, scratch, &mut buf);
        Some(buf)
    }

    pub fn serialize_into(
        &self,
        is_prefixed: bool,
        ids: &AssignedIds,
        scratch: &mut Vec<u64>,
        buf: &mut Vec<u8>,
    ) {
        let pending = self.has_pending().then_some(ids);
        self.write_into(is_prefixed, pending, scratch, buf);
    }

    fn write_into(
        &self,
        is_prefixed: bool,
        ids: Option<&AssignedIds>,
        scratch: &mut Vec<u64>,
        buf: &mut Vec<u8>,
    ) {
        let container_lists = [
            (CONTAINER_INSERTS, &self.container_inserts),
            (CONTAINER_UPDATES, &self.container_updates),
            (CONTAINER_PROPERTY_CHANGES, &self.container_property_changes),
            (CONTAINER_DELETES, &self.container_deletes),
        ];
        let item_lists = [
            (ITEM_INSERTS, &self.item_inserts),
            (ITEM_UPDATES, &self.item_updates),
            (ITEM_DELETES, &self.item_deletes),
        ];

        let mut presence = 0u8;
        for (slot, list) in container_lists.iter() {
            if !list.is_empty() {
                presence |= 1 << slot;
            }
        }
        for (slot, list) in item_lists.iter() {
            if !list.is_empty() {
                presence |= 1 << slot;
            }
        }

        let containers = self.container_inserts.len()
            + self.container_updates.len()
            + self.container_property_changes.len()
            + self.container_deletes.len();
        let items = self.item_inserts.len() + self.item_updates.len() + self.item_deletes.len();
        let item_bytes_hint = if is_prefixed {
            PREFIXED_ITEM_BYTES_HINT
        } else {
            ITEM_BYTES_HINT
        };

        let mut capacity =
            1 + BASE_LISTS + (containers * CONTAINER_BYTES_HINT) + (items * item_bytes_hint);
        if let Some(metadata) = &self.metadata {
            capacity += metadata.bytes_hint(item_bytes_hint);
        }

        buf.clear();
        buf.reserve(capacity);
        buf.push(presence);

        for (slot, list) in container_lists.iter() {
            if presence & (1 << slot) != 0 {
                buf.push_leb128(list.len());
            }
        }
        for (slot, list) in item_lists.iter() {
            if presence & (1 << slot) != 0 {
                buf.push_leb128(list.len());
            }
        }

        for (slot, list) in container_lists.iter() {
            if presence & (1 << slot) == 0 {
                continue;
            }
            self.collect(list, scratch, ids);
            write_ids(buf, scratch);
        }

        for (slot, list) in item_lists.iter() {
            if presence & (1 << slot) == 0 {
                continue;
            }
            self.collect(list, scratch, ids);
            if is_prefixed {
                write_prefixed_ids(buf, scratch);
            } else {
                write_ids(buf, scratch);
            }
        }

        if let Some(metadata) = &self.metadata {
            self.serialize_metadata(metadata, is_prefixed, ids, scratch, buf);
        }
    }

    #[cold]
    fn serialize_metadata(
        &self,
        metadata: &MetadataChanges,
        is_prefixed: bool,
        ids: Option<&AssignedIds>,
        scratch: &mut Vec<u64>,
        buf: &mut Vec<u8>,
    ) {
        let lists = [
            (CONTAINER_METADATA, &metadata.containers),
            (ITEM_METADATA, &metadata.items),
        ];
        let mut extended = 0u8;
        for (slot, list) in lists.iter() {
            if !list.is_empty() {
                extended |= 1 << (slot - BASE_LISTS);
            }
        }
        if extended == 0 {
            return;
        }
        if let Some(presence) = buf.first_mut() {
            *presence |= PRESENCE_EXTENDED;
        }
        buf.push(extended);

        for (_, list) in lists.iter().filter(|(_, list)| !list.is_empty()) {
            buf.push_leb128(list.len());
        }
        for (slot, list) in lists.iter().filter(|(_, list)| !list.is_empty()) {
            self.collect(list, scratch, ids);
            if is_prefixed && *slot == ITEM_METADATA {
                write_prefixed_ids(buf, scratch);
            } else {
                write_ids(buf, scratch);
            }
        }
    }

    fn collect(&self, list: &ChangeSet<u64>, scratch: &mut Vec<u64>, ids: Option<&AssignedIds>) {
        let Some(ids) = ids else {
            list.collect_sorted(scratch);
            return;
        };

        list.collect_unsorted(scratch);
        for id in scratch.iter_mut() {
            *id = self.resolve_id(*id, ids);
        }
        scratch.sort_unstable();
    }
}

impl From<String> for VanishedItem {
    fn from(value: String) -> Self {
        VanishedItem::Name(value)
    }
}

impl From<(u32, u32)> for VanishedItem {
    fn from(value: (u32, u32)) -> Self {
        VanishedItem::Id((value.0 as u64) << 32 | value.1 as u64)
    }
}

impl VanishedItem {
    pub fn serialized_size(&self) -> usize {
        match self {
            VanishedItem::Name(name) => name.len() + U16_LEN,
            VanishedItem::Id(_) => U16_LEN,
        }
    }
}

fn shared_prefix_len(prev: &str, name: &str) -> usize {
    let prev = prev.as_bytes();
    let bytes = name.as_bytes();
    let max_len = prev.len().min(bytes.len());
    let mut len = 0;

    while len + U64_LEN <= max_len {
        let a = u64::from_le_bytes(prev[len..len + U64_LEN].try_into().unwrap());
        let b = u64::from_le_bytes(bytes[len..len + U64_LEN].try_into().unwrap());
        if a != b {
            len += (a ^ b).trailing_zeros() as usize / 8;
            break;
        }
        len += U64_LEN;
    }
    while len < max_len && prev[len] == bytes[len] {
        len += 1;
    }
    while len > 0 && !name.is_char_boundary(len) {
        len -= 1;
    }

    len
}

impl VanishedItems {
    pub fn serialize(&self, is_named: bool, scratch: &mut Vec<u64>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(if is_named {
            self.0.iter().map(|item| item.serialized_size()).sum()
        } else {
            self.0.len() * VANISHED_ID_BYTES_HINT + U64_LEN
        });

        if is_named {
            let mut prev: Option<&str> = None;

            for item in &self.0 {
                match item {
                    VanishedItem::Name(name) => {
                        if let Some(prev) = prev {
                            let shared = shared_prefix_len(prev, name);
                            buf.push_leb128(shared);
                            buf.push_leb128(name.len() - shared);
                            buf.extend_from_slice(&name.as_bytes()[shared..]);
                        } else {
                            buf.push_leb128(name.len());
                            buf.extend_from_slice(name.as_bytes());
                        }
                        prev = Some(name);
                    }
                    VanishedItem::Id(_) => {
                        debug_assert!(false, "id logged for a name-based vanished collection");
                    }
                }
            }

            return buf;
        }

        scratch.clear();
        scratch.extend(self.0.iter().filter_map(|item| match item {
            VanishedItem::Id(id) => Some(*id),
            VanishedItem::Name(_) => {
                debug_assert!(false, "name logged for an id-based vanished collection");
                None
            }
        }));
        scratch.sort_unstable();
        scratch.dedup();

        let mut pos = 0;
        let mut prev_group = 0u64;
        while pos < scratch.len() {
            let group = scratch[pos] >> 32;
            let mut end = pos;
            while end < scratch.len() && scratch[end] >> 32 == group {
                end += 1;
            }

            buf.push_leb128(group - prev_group);
            buf.push_leb128(end - pos);

            let mut prev_id = 0u64;
            for id in &scratch[pos..end] {
                let id = *id & u32::MAX as u64;
                buf.push_leb128(id - prev_id);
                prev_id = id;
            }

            prev_group = group;
            pos = end;
        }

        buf
    }
}

