/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    ArenaRef, CachedName, DAV_CHUNK, DavName, GroupwareResource, GroupwareResourceMetadata,
    GroupwareResourceRef, NO_ID, ResourceChunk, ResourceStore, TinyCalendarPreferences,
};
use ahash::AHashMap;
use std::{
    borrow::Cow,
    ops::Range,
    sync::{Arc, OnceLock},
};
use types::acl::AclGrant;
use xxhash_rust::xxh3::xxh3_64;

const UID_SLOT_MASK: u64 = u32::MAX as u64;

#[inline(always)]
fn uid_key(cached_uid: &[u8]) -> u64 {
    xxh3_64(cached_uid) & !UID_SLOT_MASK
}

impl ResourceChunk {
    #[inline(always)]
    pub fn str_at(&self, r: ArenaRef) -> &str {
        std::str::from_utf8(self.bytes_at(r)).unwrap_or_default()
    }

    #[inline(always)]
    pub fn bytes_at(&self, r: ArenaRef) -> &[u8] {
        &self.bytes[r.range()]
    }

    #[inline(always)]
    pub fn names_at(&self, r: ArenaRef) -> &[CachedName] {
        &self.names[r.range()]
    }

    #[inline(always)]
    pub fn acls_at(&self, r: ArenaRef) -> &[AclGrant] {
        &self.acls[r.range()]
    }

    #[inline(always)]
    pub fn prefs_at(&self, r: ArenaRef) -> &[TinyCalendarPreferences] {
        &self.prefs[r.range()]
    }

    #[inline(always)]
    pub fn principals_at(&self, r: ArenaRef) -> &[u32] {
        &self.principals[r.range()]
    }

    fn build_uid_index(records: &[GroupwareResource], bytes: &[u8]) -> Box<[u64]> {
        let mut index = Vec::new();
        for (slot, record) in records.iter().enumerate() {
            if let Some(uid) = record.uid_ref().and_then(|uid| bytes.get(uid.range())) {
                if index.is_empty() {
                    index.reserve_exact(records.len() - slot);
                }
                index.push(uid_key(uid) | slot as u64);
            }
        }
        index.sort_unstable();
        index.into_boxed_slice()
    }

    fn with_uid_key(&self, key: u64) -> impl Iterator<Item = GroupwareResourceRef<'_>> {
        let uid_index = self
            .uid_index
            .get_or_init(|| Self::build_uid_index(&self.records, &self.bytes));
        let start = uid_index.partition_point(|entry| *entry < key);
        uid_index
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take_while(move |entry| *entry & !UID_SLOT_MASK == key)
            .filter_map(move |entry| {
                self.records
                    .get((*entry & UID_SLOT_MASK) as usize)
                    .map(|resource| GroupwareResourceRef {
                        chunk: self,
                        resource,
                    })
            })
    }

    fn uid_index_size(&self) -> u64 {
        if self
            .records
            .first()
            .is_some_and(|record| record.uid_ref().is_some())
        {
            (self.records.len() * std::mem::size_of::<u64>()) as u64
        } else {
            0
        }
    }

    pub fn heap_size(&self) -> u64 {
        (self.records.len() * std::mem::size_of::<GroupwareResource>()
            + self.bytes.len()
            + self.names.len() * std::mem::size_of::<CachedName>()
            + self.acls.len() * std::mem::size_of::<AclGrant>()
            + self.prefs.len() * std::mem::size_of::<TinyCalendarPreferences>()
            + self.principals.len() * std::mem::size_of::<u32>()
            + std::mem::size_of::<ResourceChunk>()) as u64
    }
}

#[derive(Default)]
pub struct ResourceChunkBuilder {
    pub records: Vec<GroupwareResource>,
    pub bytes: Vec<u8>,
    pub names: Vec<CachedName>,
    pub acls: Vec<AclGrant>,
    pub prefs: Vec<TinyCalendarPreferences>,
    pub principals: Vec<u32>,
    principal_runs: AHashMap<Box<[u32]>, ArenaRef>,
}

impl ResourceChunkBuilder {
    pub fn with_capacity(n: usize) -> Self {
        Self {
            records: Vec::with_capacity(n),
            bytes: Vec::with_capacity(n * 48),
            names: Vec::with_capacity(n),
            acls: Vec::with_capacity(8),
            prefs: Vec::with_capacity(8),
            principals: Vec::new(),
            principal_runs: AHashMap::new(),
        }
    }

    pub fn push_str(&mut self, s: &str) -> ArenaRef {
        self.push_arena_bytes(s.as_bytes())
    }

    fn push_arena_bytes(&mut self, bytes: &[u8]) -> ArenaRef {
        let off = self.bytes.len() as u32;
        self.bytes.extend_from_slice(bytes);
        ArenaRef {
            off,
            len: bytes.len() as u32,
        }
    }

    pub fn push_uid(&mut self, uid: &str, names: ArenaRef) -> ArenaRef {
        self.push_uid_bytes(uid.as_bytes(), names)
    }

    fn push_uid_bytes(&mut self, uid: &[u8], names: ArenaRef) -> ArenaRef {
        for name in self.names.get(names.range()).unwrap_or_default() {
            if self
                .bytes
                .get(name.name.range())
                .is_some_and(|bytes| bytes.starts_with(uid))
            {
                return ArenaRef {
                    off: name.name.off,
                    len: uid.len() as u32,
                };
            }
        }
        self.push_arena_bytes(uid)
    }

    pub fn push_acls(&mut self, acls: &[AclGrant]) -> ArenaRef {
        let off = self.acls.len() as u32;
        self.acls.extend_from_slice(acls);
        ArenaRef {
            off,
            len: acls.len() as u32,
        }
    }

    pub fn push_prefs(&mut self, prefs: &[TinyCalendarPreferences]) -> ArenaRef {
        let off = self.prefs.len() as u32;
        self.prefs.extend_from_slice(prefs);
        ArenaRef {
            off,
            len: prefs.len() as u32,
        }
    }

    pub fn push_principals(&mut self, principals: impl IntoIterator<Item = u32>) -> ArenaRef {
        let off = self.principals.len();
        self.principals.extend(principals);
        if self.principals.len() == off {
            return ArenaRef::default();
        }

        if let Some(interned) = self.principal_runs.get(&self.principals[off..]).copied() {
            self.principals.truncate(off);
            return interned;
        }

        let arena = ArenaRef {
            off: off as u32,
            len: (self.principals.len() - off) as u32,
        };
        self.principal_runs
            .insert(Box::from(&self.principals[off..]), arena);
        arena
    }

    pub fn push_names(&mut self, names: &[DavName]) -> ArenaRef {
        let off = self.names.len() as u32;
        for name in names {
            let name_ref = self.push_str(&name.name);
            self.names.push(CachedName {
                name: name_ref,
                parent_id: name.parent_id,
            });
        }
        ArenaRef {
            off,
            len: names.len() as u32,
        }
    }

    pub fn push_from(&mut self, src: &GroupwareResourceRef<'_>) {
        let data = match &src.resource.data {
            GroupwareResourceMetadata::File {
                name,
                size,
                parent_id,
                acls,
                etag,
                modified,
                created_delta,
                flags,
            } => GroupwareResourceMetadata::File {
                name: self.push_file_bytes(src.chunk, *name, *flags),
                size: *size,
                parent_id: *parent_id,
                acls: self.push_acls(src.chunk.acls_at(*acls)),
                etag: *etag,
                modified: *modified,
                created_delta: *created_delta,
                flags: *flags,
            },
            GroupwareResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                etag,
                metadata,
            } => GroupwareResourceMetadata::Calendar {
                name: self.push_arena_bytes(src.chunk.bytes_at(*name)),
                acls: self.push_acls(src.chunk.acls_at(*acls)),
                preferences: self.push_prefs(src.chunk.prefs_at(*preferences)),
                etag: *etag,
                metadata: *metadata,
            },
            GroupwareResourceMetadata::AddressBook {
                name,
                acls,
                etag,
                metadata,
            } => GroupwareResourceMetadata::AddressBook {
                name: self.push_arena_bytes(src.chunk.bytes_at(*name)),
                acls: self.push_acls(src.chunk.acls_at(*acls)),
                etag: *etag,
                metadata: *metadata,
            },
            GroupwareResourceMetadata::CalendarEvent {
                names,
                start,
                duration,
                created_at,
                modified_at,
                uid,
                etag,
                flags,
            } => {
                let names = self.push_cached_names(src.chunk, *names);
                GroupwareResourceMetadata::CalendarEvent {
                    names,
                    start: *start,
                    duration: *duration,
                    created_at: *created_at,
                    modified_at: *modified_at,
                    uid: self.push_uid_bytes(src.chunk.bytes_at(*uid), names),
                    etag: *etag,
                    flags: *flags,
                }
            }
            GroupwareResourceMetadata::ContactCard {
                names,
                created_at,
                modified_at,
                uid,
                etag,
                flags,
            } => {
                let names = self.push_cached_names(src.chunk, *names);
                GroupwareResourceMetadata::ContactCard {
                    names,
                    created_at: *created_at,
                    modified_at: *modified_at,
                    uid: self.push_uid_bytes(src.chunk.bytes_at(*uid), names),
                    etag: *etag,
                    flags: *flags,
                }
            }
            GroupwareResourceMetadata::CalendarEventNotification {
                names,
                created_at,
                event_id,
                etag,
                changed_by,
                principals,
                calendar_ids_len,
                flags,
            } => GroupwareResourceMetadata::CalendarEventNotification {
                names: self.push_cached_names(src.chunk, *names),
                created_at: *created_at,
                event_id: *event_id,
                etag: *etag,
                changed_by: *changed_by,
                principals: self
                    .push_principals(src.chunk.principals_at(*principals).iter().copied()),
                calendar_ids_len: *calendar_ids_len,
                flags: *flags,
            },
        };
        self.records.push(GroupwareResource {
            document_id: src.resource.document_id,
            data,
        });
    }

    fn push_cached_names(&mut self, chunk: &ResourceChunk, names: ArenaRef) -> ArenaRef {
        let off = self.names.len() as u32;
        for name in chunk.names_at(names) {
            let name_ref = self.push_arena_bytes(chunk.bytes_at(name.name));
            self.names.push(CachedName {
                name: name_ref,
                parent_id: name.parent_id,
            });
        }
        ArenaRef {
            off,
            len: names.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn finish(self) -> ResourceChunk {
        let min_id = self.records.first().map(|r| r.document_id).unwrap_or(NO_ID);
        let max_id = self.records.last().map(|r| r.document_id).unwrap_or(0);
        ResourceChunk {
            uid_index: OnceLock::new(),
            records: self.records.into_boxed_slice(),
            bytes: self.bytes.into_boxed_slice(),
            names: self.names.into_boxed_slice(),
            acls: self.acls.into_boxed_slice(),
            prefs: self.prefs.into_boxed_slice(),
            principals: self.principals.into_boxed_slice(),
            min_id,
            max_id,
        }
    }
}

struct SplitChunks<'x> {
    target: &'x mut Vec<Arc<ResourceChunk>>,
    current: ResourceChunkBuilder,
}

impl<'x> SplitChunks<'x> {
    fn new(target: &'x mut Vec<Arc<ResourceChunk>>, capacity: usize) -> Self {
        Self {
            target,
            current: ResourceChunkBuilder::with_capacity(capacity.min(DAV_CHUNK)),
        }
    }

    fn push(&mut self, resource: &GroupwareResourceRef<'_>) {
        if self.current.len() == DAV_CHUNK {
            let full =
                std::mem::replace(&mut self.current, ResourceChunkBuilder::with_capacity(64));
            self.target.push(Arc::new(full.finish()));
        }
        self.current.push_from(resource);
    }

    fn finish(self) {
        if !self.current.is_empty() {
            self.target.push(Arc::new(self.current.finish()));
        }
    }
}

impl ResourceStore {
    pub fn from_sorted(
        containers: Vec<ResourceChunkBuilder>,
        items: Vec<ResourceChunkBuilder>,
        unified_id_space: bool,
    ) -> Self {
        let mut chunks = Vec::with_capacity(containers.len() + items.len());
        let mut total = 0;
        for builder in containers.into_iter().filter(|builder| !builder.is_empty()) {
            debug_assert!(
                builder.records.is_sorted_by_key(|r| r.document_id),
                "chunk records must be ordered by document_id for binary search"
            );
            total += builder.len();
            chunks.push(Arc::new(builder.finish()));
        }
        let containers_end = chunks.len();
        for builder in items.into_iter().filter(|builder| !builder.is_empty()) {
            debug_assert!(
                builder.records.is_sorted_by_key(|r| r.document_id),
                "chunk records must be ordered by document_id for binary search"
            );
            total += builder.len();
            chunks.push(Arc::new(builder.finish()));
        }
        Self {
            chunks,
            containers_end,
            total,
            unified_id_space,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.total
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn count(&self, is_container: bool) -> usize {
        if self.unified_id_space {
            self.iter()
                .filter(|resource| resource.is_container() == is_container)
                .count()
        } else {
            self.chunks[self.run(is_container)]
                .iter()
                .map(|chunk| chunk.records.len())
                .sum()
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = GroupwareResourceRef<'_>> + '_ {
        Self::iter_chunks(&self.chunks)
    }

    pub fn iter_run(&self, is_container: bool) -> impl Iterator<Item = GroupwareResourceRef<'_>> {
        Self::iter_chunks(&self.chunks[self.run(is_container)])
    }

    fn iter_chunks(
        chunks: &[Arc<ResourceChunk>],
    ) -> impl Iterator<Item = GroupwareResourceRef<'_>> {
        chunks.iter().flat_map(|chunk| {
            chunk
                .records
                .iter()
                .map(move |resource| GroupwareResourceRef {
                    chunk: chunk.as_ref(),
                    resource,
                })
        })
    }

    pub fn iter_with_acls(&self) -> impl Iterator<Item = GroupwareResourceRef<'_>> + '_ {
        self.chunks
            .iter()
            .filter(|chunk| !chunk.acls.is_empty())
            .flat_map(|chunk| {
                chunk
                    .records
                    .iter()
                    .map(move |resource| GroupwareResourceRef {
                        chunk: chunk.as_ref(),
                        resource,
                    })
            })
            .filter(|resource| resource.has_acls())
    }

    pub fn heap_size(&self) -> u64 {
        let indexed = self.chunks[self.run(false)]
            .split_last()
            .map_or(0, |(_, indexed)| {
                indexed.iter().map(|chunk| chunk.uid_index_size()).sum()
            });
        self.chunks
            .iter()
            .map(|chunk| chunk.heap_size())
            .sum::<u64>()
            + indexed
    }

    fn run(&self, is_container: bool) -> Range<usize> {
        if self.unified_id_space {
            0..self.chunks.len()
        } else if is_container {
            0..self.containers_end
        } else {
            self.containers_end..self.chunks.len()
        }
    }

    fn chunk_for(&self, run: &Range<usize>, document_id: u32) -> Option<usize> {
        let chunks = &self.chunks[run.clone()];
        let slot = chunks
            .partition_point(|chunk| chunk.min_id <= document_id)
            .checked_sub(1)?;
        Some(run.start + slot)
    }

    fn locate(&self, run: Range<usize>, document_id: u32) -> Option<GroupwareResourceRef<'_>> {
        let chunk = &self.chunks[self.chunk_for(&run, document_id)?];
        if document_id > chunk.max_id {
            return None;
        }
        chunk
            .records
            .binary_search_by_key(&document_id, |r| r.document_id)
            .ok()
            .map(|slot| GroupwareResourceRef {
                chunk: chunk.as_ref(),
                resource: &chunk.records[slot],
            })
    }

    pub fn find_by_uid<'x>(
        &'x self,
        cached_uid: Cow<'x, str>,
    ) -> impl Iterator<Item = GroupwareResourceRef<'x>> + 'x {
        let key = uid_key(cached_uid.as_bytes());
        let (tail, indexed) = self.chunks[self.run(false)]
            .split_last()
            .map_or((&[][..], &[][..]), |(tail, indexed)| {
                (std::slice::from_ref(tail), indexed)
            });
        indexed
            .iter()
            .flat_map(move |chunk| chunk.with_uid_key(key))
            .chain(Self::iter_chunks(tail))
            .filter(move |resource| resource.has_cached_uid(cached_uid.as_bytes()))
    }

    pub fn find(&self, document_id: u32, want_container: bool) -> Option<GroupwareResourceRef<'_>> {
        self.locate(self.run(want_container), document_id)
            .filter(|resource| resource.is_container() == want_container)
    }

    #[inline(always)]
    pub fn find_any(&self, document_id: u32) -> Option<GroupwareResourceRef<'_>> {
        if self.unified_id_space {
            self.locate(self.run(true), document_id)
        } else {
            self.locate(self.run(true), document_id)
                .or_else(|| self.locate(self.run(false), document_id))
        }
    }

    pub fn rebuild(
        &self,
        staging: &ResourceChunk,
        changes: &ahash::AHashMap<(bool, u32), Option<u32>>,
    ) -> Self {
        let unified = self.unified_id_space;
        let mut container_chunks: Vec<Arc<ResourceChunk>> = Vec::new();
        let mut item_chunks: Vec<Arc<ResourceChunk>> = Vec::new();

        for is_container in [true, false] {
            if unified && !is_container {
                continue;
            }
            let key_flag = if unified { true } else { is_container };

            let mut pending: Vec<(u32, Option<u32>)> = changes
                .iter()
                .filter(|((flag, _), _)| *flag == key_flag)
                .map(|((_, document_id), slot)| (*document_id, *slot))
                .collect();
            pending.sort_unstable_by_key(|(document_id, _)| *document_id);
            let mut pending = pending.into_iter().peekable();

            let staged = |slot: u32| GroupwareResourceRef {
                chunk: staging,
                resource: &staging.records[slot as usize],
            };

            let target = if is_container {
                &mut container_chunks
            } else {
                &mut item_chunks
            };

            let run = &self.chunks[self.run(is_container)];
            for (position, chunk) in run.iter().enumerate() {
                let is_last = position + 1 == run.len();
                let owned = |(document_id, slot): &(u32, Option<u32>)| {
                    (is_last && slot.is_some()) || *document_id <= chunk.max_id
                };

                if !pending.peek().is_some_and(owned) {
                    target.push(Arc::clone(chunk));
                    continue;
                }

                let mut builder = SplitChunks::new(target, chunk.records.len() + 4);
                for record in chunk.records.iter() {
                    while let Some((_, slot)) =
                        pending.next_if(|(document_id, _)| *document_id < record.document_id)
                    {
                        if let Some(slot) = slot {
                            builder.push(&staged(slot));
                        }
                    }
                    match pending.next_if(|(document_id, _)| *document_id == record.document_id) {
                        Some((_, Some(slot))) => builder.push(&staged(slot)),
                        Some((_, None)) => {}
                        None => builder.push(&GroupwareResourceRef {
                            chunk,
                            resource: record,
                        }),
                    }
                }
                while let Some((_, slot)) = pending.next_if(owned) {
                    if let Some(slot) = slot {
                        builder.push(&staged(slot));
                    }
                }
                builder.finish();
            }

            let mut builder = SplitChunks::new(target, 4);
            for (_, slot) in pending {
                if let Some(slot) = slot {
                    builder.push(&staged(slot));
                }
            }
            builder.finish();
        }

        let containers_end = container_chunks.len();
        let mut chunks = container_chunks;
        chunks.extend(item_chunks);
        let total = chunks.iter().map(|chunk| chunk.records.len()).sum();

        Self {
            chunks,
            containers_end,
            total,
            unified_id_space: unified,
        }
    }
}

