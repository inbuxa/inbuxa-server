/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{SwapPart, frame::SwapFrame};
use crate::{
    ArenaRef, CachedName, DavPath, FileFlags, GroupwareResource, GroupwareResourceMetadata,
    GroupwareResources, PathChunk, PathIndex, ResourceChunk, ResourceStore,
    TinyCalendarPreferences, UpdateLock, storage::dav::CONTAINER_FLAG,
};
use calcard::common::timezone::Tz;
use rkyv::with::InlineAsBox;
use std::sync::{Arc, OnceLock};
use types::{acl::AclGrant, metadata::MetadataKinds};
use utils::map::bitmap::Bitmap;

const KIND_FILE: u16 = 1;
const KIND_CALENDAR: u16 = 2;
const KIND_CALENDAR_EVENT: u16 = 3;
const KIND_CALENDAR_EVENT_NOTIFICATION: u16 = 4;
const KIND_ADDRESS_BOOK: u16 = 5;
const KIND_CONTACT_CARD: u16 = 6;

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct FlatResource {
    pub ref_a_off: u32,
    pub ref_b_off: u32,
    pub v0: u32,
    pub v1: u32,
    pub v2: u32,
    pub v3: u32,
    pub v4: u32,
    pub etag: u32,
    pub document_id: u32,
    pub ref_a_len: u16,
    pub ref_b_len: u16,
    pub flags: u16,
}

struct ChunkTimes {
    epoch: i64,
    wide: Vec<i64>,
}

impl ChunkTimes {
    fn for_records(records: &[GroupwareResource]) -> Self {
        Self {
            epoch: records
                .iter()
                .flat_map(|record| record.data.absolute_times())
                .min()
                .unwrap_or_default(),
            wide: Vec::new(),
        }
    }

    fn encode(&mut self, time: i64) -> u32 {
        match time.checked_sub(self.epoch) {
            Some(delta) if (0..=i32::MAX as i64).contains(&delta) => delta as u32,
            _ => {
                self.wide.push(time);
                -(self.wide.len() as i32) as u32
            }
        }
    }

    fn decode(&self, raw: u32) -> Option<i64> {
        let delta = raw as i32;
        if delta >= 0 {
            self.epoch.checked_add(delta as i64)
        } else {
            self.wide.get((-(delta as i64) - 1) as usize).copied()
        }
    }
}

impl GroupwareResourceMetadata {
    fn absolute_times(&self) -> impl Iterator<Item = i64> {
        let (start, created_at) = match self {
            GroupwareResourceMetadata::File { modified, .. } => (Some(*modified), None),
            GroupwareResourceMetadata::CalendarEvent {
                start, created_at, ..
            } => (Some(*start), Some(*created_at)),
            GroupwareResourceMetadata::CalendarEventNotification { created_at, .. }
            | GroupwareResourceMetadata::ContactCard { created_at, .. } => {
                (Some(*created_at), None)
            }
            GroupwareResourceMetadata::Calendar { .. }
            | GroupwareResourceMetadata::AddressBook { .. } => (None, None),
        };
        start.into_iter().chain(created_at)
    }

    fn kind(&self) -> u16 {
        match self {
            GroupwareResourceMetadata::File { .. } => KIND_FILE,
            GroupwareResourceMetadata::Calendar { .. } => KIND_CALENDAR,
            GroupwareResourceMetadata::CalendarEvent { .. } => KIND_CALENDAR_EVENT,
            GroupwareResourceMetadata::CalendarEventNotification { .. } => {
                KIND_CALENDAR_EVENT_NOTIFICATION
            }
            GroupwareResourceMetadata::AddressBook { .. } => KIND_ADDRESS_BOOK,
            GroupwareResourceMetadata::ContactCard { .. } => KIND_CONTACT_CARD,
        }
    }
}

impl FlatResource {
    fn pack(resource: &GroupwareResource, times: &mut ChunkTimes) -> Option<Self> {
        let mut flat = FlatResource {
            ref_a_off: 0,
            ref_b_off: 0,
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            v4: 0,
            etag: resource.etag(),
            document_id: resource.document_id,
            ref_a_len: 0,
            ref_b_len: 0,
            flags: 0,
        };

        match &resource.data {
            GroupwareResourceMetadata::File {
                name,
                size,
                parent_id,
                acls,
                modified,
                created_delta,
                flags,
                ..
            } => {
                flat.set_ref_a(name)?;
                flat.set_ref_b(acls)?;
                flat.v0 = *size;
                flat.v1 = *parent_id;
                flat.v2 = times.encode(*modified);
                flat.v3 = *created_delta as u32;
                flat.v4 = flags.0;
            }
            GroupwareResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                metadata,
                ..
            } => {
                flat.flags = u16::from(metadata.bits());
                flat.set_ref_a(name)?;
                flat.set_ref_b(acls)?;
                flat.v0 = preferences.off;
                flat.v1 = preferences.len;
            }
            GroupwareResourceMetadata::CalendarEvent {
                names,
                start,
                duration,
                created_at,
                modified_at,
                uid,
                flags,
                ..
            } => {
                flat.flags = *flags;
                flat.set_ref_a(names)?;
                flat.set_ref_b(uid)?;
                flat.v0 = times.encode(*start);
                flat.v1 = times.encode(*created_at);
                flat.v2 = *duration;
                flat.v3 = *modified_at as u32;
            }
            GroupwareResourceMetadata::CalendarEventNotification {
                names,
                created_at,
                event_id,
                changed_by,
                principals,
                calendar_ids_len,
                flags,
                ..
            } => {
                flat.flags = *flags;
                flat.set_ref_a(names)?;
                flat.set_ref_b(principals)?;
                flat.v0 = times.encode(*created_at);
                flat.v1 = *event_id;
                flat.v2 = *changed_by;
                flat.v3 = *calendar_ids_len as u32;
            }
            GroupwareResourceMetadata::AddressBook {
                name,
                acls,
                metadata,
                ..
            } => {
                flat.flags = u16::from(metadata.bits());
                flat.set_ref_a(name)?;
                flat.set_ref_b(acls)?;
            }
            GroupwareResourceMetadata::ContactCard {
                names,
                created_at,
                modified_at,
                uid,
                flags,
                ..
            } => {
                flat.flags = *flags;
                flat.set_ref_a(names)?;
                flat.set_ref_b(uid)?;
                flat.v0 = times.encode(*created_at);
                flat.v1 = *modified_at as u32;
            }
        }

        Some(flat)
    }

    fn set_ref_a(&mut self, arena: &ArenaRef) -> Option<()> {
        self.ref_a_off = arena.off;
        self.ref_a_len = u16::try_from(arena.len).ok()?;
        Some(())
    }

    fn set_ref_b(&mut self, arena: &ArenaRef) -> Option<()> {
        self.ref_b_off = arena.off;
        self.ref_b_len = u16::try_from(arena.len).ok()?;
        Some(())
    }
}

impl ArchivedFlatResource {
    fn ref_a(&self) -> ArenaRef {
        ArenaRef {
            off: self.ref_a_off.to_native(),
            len: self.ref_a_len.to_native() as u32,
        }
    }

    fn ref_b(&self) -> ArenaRef {
        ArenaRef {
            off: self.ref_b_off.to_native(),
            len: self.ref_b_len.to_native() as u32,
        }
    }

    fn metadata_kinds(&self) -> Option<MetadataKinds> {
        MetadataKinds::from_bits(u8::try_from(self.flags.to_native()).ok()?)
    }

    fn unpack(&self, kind: u16, times: &ChunkTimes) -> Option<GroupwareResource> {
        let data = match kind {
            KIND_FILE => GroupwareResourceMetadata::File {
                name: self.ref_a(),
                size: self.v0.to_native(),
                parent_id: self.v1.to_native(),
                acls: self.ref_b(),
                etag: self.etag.to_native(),
                modified: times.decode(self.v2.to_native())?,
                created_delta: self.v3.to_native() as i32,
                flags: FileFlags(self.v4.to_native()),
            },
            KIND_CALENDAR => GroupwareResourceMetadata::Calendar {
                name: self.ref_a(),
                acls: self.ref_b(),
                preferences: ArenaRef {
                    off: self.v0.to_native(),
                    len: self.v1.to_native(),
                },
                etag: self.etag.to_native(),
                metadata: self.metadata_kinds()?,
            },
            KIND_CALENDAR_EVENT => GroupwareResourceMetadata::CalendarEvent {
                names: self.ref_a(),
                start: times.decode(self.v0.to_native())?,
                duration: self.v2.to_native(),
                created_at: times.decode(self.v1.to_native())?,
                modified_at: self.v3.to_native() as i32,
                uid: self.ref_b(),
                etag: self.etag.to_native(),
                flags: self.flags.to_native(),
            },
            KIND_CALENDAR_EVENT_NOTIFICATION => {
                GroupwareResourceMetadata::CalendarEventNotification {
                    names: self.ref_a(),
                    created_at: times.decode(self.v0.to_native())?,
                    event_id: self.v1.to_native(),
                    etag: self.etag.to_native(),
                    changed_by: self.v2.to_native(),
                    principals: self.ref_b(),
                    calendar_ids_len: u16::try_from(self.v3.to_native()).ok()?,
                    flags: self.flags.to_native(),
                }
            }
            KIND_ADDRESS_BOOK => GroupwareResourceMetadata::AddressBook {
                name: self.ref_a(),
                acls: self.ref_b(),
                etag: self.etag.to_native(),
                metadata: self.metadata_kinds()?,
            },
            KIND_CONTACT_CARD => GroupwareResourceMetadata::ContactCard {
                names: self.ref_a(),
                created_at: times.decode(self.v0.to_native())?,
                modified_at: self.v1.to_native() as i32,
                uid: self.ref_b(),
                etag: self.etag.to_native(),
                flags: self.flags.to_native(),
            },
            _ => return None,
        };

        Some(GroupwareResource {
            document_id: self.document_id.to_native(),
            data,
        })
    }
}

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedResources<'x> {
    pub base_path: String,
    pub item_change_id: u64,
    pub container_change_id: u64,
    pub containers_end: u32,
    pub total: u32,
    pub path_total: u32,
    pub unified_id_space: bool,
    pub chunks: Vec<ArchivedResourceChunk<'x>>,
    pub path_chunks: Vec<ArchivedPathChunk<'x>>,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedResourceChunk<'x> {
    pub records: Vec<FlatResource>,
    #[rkyv(with = InlineAsBox)]
    pub bytes: &'x [u8],
    pub name_offsets: Vec<u32>,
    pub name_lengths: Vec<u16>,
    pub name_parents: Vec<u32>,
    pub acl_accounts: Vec<u32>,
    pub acl_grants: Vec<u64>,
    pub pref_accounts: Vec<u32>,
    pub pref_timezones: Vec<u16>,
    pub pref_flags: Vec<u16>,
    #[rkyv(with = InlineAsBox)]
    pub principals: &'x [u32],
    pub kind: u16,
    pub epoch: i64,
    pub wide_times: Vec<i64>,
}

#[derive(rkyv::Archive, rkyv::Serialize)]
pub struct ArchivedPathChunk<'x> {
    #[rkyv(with = InlineAsBox)]
    pub bytes: &'x [u8],
    pub path_lengths: Vec<u16>,
    pub hierarchy_seqs: Vec<u16>,
    pub parent_ids: Vec<u32>,
    pub document_ids: Vec<u32>,
}

const WIRE_CONTAINER_FLAG: u16 = 1 << 15;

fn fits_within(arena: ArenaRef, limit: usize) -> bool {
    (arena.off as usize)
        .checked_add(arena.len as usize)
        .is_some_and(|end| end <= limit)
}

impl GroupwareResource {
    fn fits_within(
        &self,
        bytes: usize,
        names: usize,
        acls: usize,
        prefs: usize,
        principals_len: usize,
    ) -> bool {
        match &self.data {
            GroupwareResourceMetadata::File {
                name,
                acls: acl_ref,
                flags,
                ..
            } => {
                flags.is_valid()
                    && fits_within(
                        ArenaRef {
                            off: name.off,
                            len: name.len.saturating_add(flags.extra_len() as u32),
                        },
                        bytes,
                    )
                    && fits_within(*acl_ref, acls)
            }
            GroupwareResourceMetadata::AddressBook {
                name,
                acls: acl_ref,
                ..
            } => fits_within(*name, bytes) && fits_within(*acl_ref, acls),
            GroupwareResourceMetadata::Calendar {
                name,
                acls: acl_ref,
                preferences,
                ..
            } => {
                fits_within(*name, bytes)
                    && fits_within(*acl_ref, acls)
                    && fits_within(*preferences, prefs)
            }
            GroupwareResourceMetadata::CalendarEvent {
                names: name_refs,
                uid,
                ..
            }
            | GroupwareResourceMetadata::ContactCard {
                names: name_refs,
                uid,
                ..
            } => fits_within(*name_refs, names) && fits_within(*uid, bytes),
            GroupwareResourceMetadata::CalendarEventNotification {
                names: name_refs,
                principals,
                calendar_ids_len,
                ..
            } => {
                fits_within(*name_refs, names)
                    && fits_within(*principals, principals_len)
                    && *calendar_ids_len as u32 <= principals.len
            }
        }
    }
}

impl GroupwareResources {
    pub fn to_snapshot(&self) -> Option<Vec<u8>> {
        let (chunks, path_chunks) = self.pack()?;
        self.seal_snapshot(chunks, path_chunks)
    }

    #[allow(clippy::type_complexity)]
    fn pack(&self) -> Option<(Vec<ArchivedResourceChunk<'_>>, Vec<ArchivedPathChunk<'_>>)> {
        let mut chunks = Vec::with_capacity(self.resources.chunks.len());
        for chunk in &self.resources.chunks {
            let mut name_offsets = Vec::with_capacity(chunk.names.len());
            let mut name_lengths = Vec::with_capacity(chunk.names.len());
            let mut name_parents = Vec::with_capacity(chunk.names.len());
            for name in chunk.names.iter() {
                name_offsets.push(name.name.off);
                name_lengths.push(u16::try_from(name.name.len).ok()?);
                name_parents.push(name.parent_id);
            }

            let mut acl_accounts = Vec::with_capacity(chunk.acls.len());
            let mut acl_grants = Vec::with_capacity(chunk.acls.len());
            for acl in chunk.acls.iter() {
                acl_accounts.push(acl.account_id);
                acl_grants.push(acl.grants.bitmap);
            }

            let mut pref_accounts = Vec::with_capacity(chunk.prefs.len());
            let mut pref_timezones = Vec::with_capacity(chunk.prefs.len());
            let mut pref_flags = Vec::with_capacity(chunk.prefs.len());
            for pref in chunk.prefs.iter() {
                pref_accounts.push(pref.account_id);
                pref_timezones.push(pref.tz.as_id());
                pref_flags.push(pref.flags);
            }

            let kind = chunk.records.first().map_or(0, |record| record.data.kind());
            if chunk
                .records
                .iter()
                .any(|record| record.data.kind() != kind)
            {
                return None;
            }

            let mut times = ChunkTimes::for_records(&chunk.records);
            let mut records = Vec::with_capacity(chunk.records.len());
            for record in chunk.records.iter() {
                records.push(FlatResource::pack(record, &mut times)?);
            }

            chunks.push(ArchivedResourceChunk {
                records,
                bytes: &chunk.bytes,
                name_offsets,
                name_lengths,
                name_parents,
                acl_accounts,
                acl_grants,
                pref_accounts,
                pref_timezones,
                pref_flags,
                principals: &chunk.principals,
                kind,
                epoch: times.epoch,
                wide_times: times.wide,
            });
        }

        let mut path_chunks = Vec::with_capacity(self.paths.chunks.len());
        for chunk in &self.paths.chunks {
            let mut path_lengths = Vec::with_capacity(chunk.paths.len());
            let mut parent_ids = Vec::with_capacity(chunk.paths.len());
            let mut hierarchy_seqs = Vec::with_capacity(chunk.paths.len());
            let mut document_ids = Vec::with_capacity(chunk.paths.len());
            let mut next_off = 0u32;
            for path in chunk.paths.iter() {
                if path.path.off != next_off {
                    return None;
                }
                next_off += path.path.len;
                path_lengths.push(u16::try_from(path.path.len).ok()?);
                parent_ids.push(path.parent_id);
                let depth = u16::try_from(path.hierarchy_seq & !CONTAINER_FLAG).ok()?;
                if depth >= WIRE_CONTAINER_FLAG {
                    return None;
                }
                hierarchy_seqs.push(if path.hierarchy_seq & CONTAINER_FLAG != 0 {
                    depth | WIRE_CONTAINER_FLAG
                } else {
                    depth
                });
                document_ids.push(path.document_id);
            }
            if next_off as usize != chunk.bytes.len() {
                return None;
            }

            path_chunks.push(ArchivedPathChunk {
                bytes: &chunk.bytes,
                path_lengths,
                hierarchy_seqs,
                parent_ids,
                document_ids,
            });
        }

        Some((chunks, path_chunks))
    }

    fn seal_snapshot(
        &self,
        chunks: Vec<ArchivedResourceChunk<'_>>,
        path_chunks: Vec<ArchivedPathChunk<'_>>,
    ) -> Option<Vec<u8>> {
        let mut out = rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(
            &ArchivedResources {
                base_path: self.base_path.clone(),
                item_change_id: self.item_change_id,
                container_change_id: self.container_change_id,
                containers_end: self.resources.containers_end as u32,
                total: self.resources.total as u32,
                path_total: self.paths.total as u32,
                unified_id_space: self.resources.unified_id_space,
                chunks,
                path_chunks,
            },
            SwapFrame::reserve_header(),
        )
        .ok()?;

        SwapFrame::seal(
            &mut out,
            SwapPart::Resources,
            self.highest_change_id,
            self.resources.total as u32,
        )
        .then_some(out)
    }

    pub fn from_snapshot(buf: &[u8]) -> Option<Self> {
        let frame = SwapFrame::parse(buf)?;
        if frame.part() != SwapPart::Resources {
            return None;
        }

        let archived =
            rkyv::access::<ArchivedArchivedResources, rkyv::rancor::Error>(frame.payload()).ok()?;

        let containers_end = archived.containers_end.to_native() as usize;
        let unified_id_space = archived.unified_id_space;
        if containers_end > archived.chunks.len()
            || (unified_id_space && containers_end != archived.chunks.len())
        {
            return None;
        }

        let mut chunks = Vec::with_capacity(archived.chunks.len());
        let mut total = 0usize;
        for chunk in archived.chunks.iter() {
            let names_len = chunk.name_offsets.len();
            if chunk.name_lengths.len() != names_len || chunk.name_parents.len() != names_len {
                return None;
            }
            let acls_len = chunk.acl_accounts.len();
            if chunk.acl_grants.len() != acls_len {
                return None;
            }
            let prefs_len = chunk.pref_accounts.len();
            if chunk.pref_timezones.len() != prefs_len || chunk.pref_flags.len() != prefs_len {
                return None;
            }

            let bytes: Box<[u8]> = (&*chunk.bytes).into();

            let names: Box<[CachedName]> = chunk
                .name_offsets
                .iter()
                .zip(chunk.name_lengths.iter())
                .zip(chunk.name_parents.iter())
                .map(|((off, len), parent_id)| CachedName {
                    name: ArenaRef {
                        off: off.to_native(),
                        len: len.to_native() as u32,
                    },
                    parent_id: parent_id.to_native(),
                })
                .collect();
            if names
                .iter()
                .any(|name| !fits_within(name.name, bytes.len()))
            {
                return None;
            }

            let acls: Box<[AclGrant]> = chunk
                .acl_accounts
                .iter()
                .zip(chunk.acl_grants.iter())
                .map(|(account_id, grants)| AclGrant {
                    account_id: account_id.to_native(),
                    grants: Bitmap::from(grants.to_native()),
                })
                .collect();

            let principals: Box<[u32]> = chunk
                .principals
                .iter()
                .map(|principal| principal.to_native())
                .collect();

            let prefs: Box<[TinyCalendarPreferences]> = chunk
                .pref_accounts
                .iter()
                .zip(chunk.pref_timezones.iter())
                .zip(chunk.pref_flags.iter())
                .map(|((account_id, tz), flags)| TinyCalendarPreferences {
                    account_id: account_id.to_native(),
                    tz: Tz::from_id(tz.to_native()).unwrap_or_default(),
                    flags: flags.to_native(),
                })
                .collect();

            let times = ChunkTimes {
                epoch: chunk.epoch.to_native(),
                wide: chunk
                    .wide_times
                    .iter()
                    .map(|time| time.to_native())
                    .collect(),
            };
            let kind = chunk.kind.to_native();

            let mut records = Vec::with_capacity(chunk.records.len());
            for record in chunk.records.iter() {
                let record = record.unpack(kind, &times)?;
                if !record.fits_within(
                    bytes.len(),
                    names_len,
                    acls_len,
                    prefs_len,
                    principals.len(),
                ) {
                    return None;
                }
                records.push(record);
            }

            let (Some(min_id), Some(max_id)) = (
                records.first().map(|r| r.document_id),
                records.last().map(|r| r.document_id),
            ) else {
                return None;
            };

            total += records.len();
            chunks.push(Arc::new(ResourceChunk {
                uid_index: OnceLock::new(),
                records: records.into_boxed_slice(),
                bytes,
                names,
                acls,
                prefs,
                principals,
                min_id,
                max_id,
            }));
        }

        if total != archived.total.to_native() as usize {
            return None;
        }

        let mut path_chunks = Vec::with_capacity(archived.path_chunks.len());
        let mut path_total = 0usize;
        for chunk in archived.path_chunks.iter() {
            let paths_len = chunk.path_lengths.len();
            if chunk.parent_ids.len() != paths_len
                || chunk.hierarchy_seqs.len() != paths_len
                || chunk.document_ids.len() != paths_len
            {
                return None;
            }

            let bytes: Box<[u8]> = (&*chunk.bytes).into();
            let mut off = 0u32;
            let paths: Box<[DavPath]> = chunk
                .path_lengths
                .iter()
                .zip(chunk.parent_ids.iter())
                .zip(chunk.hierarchy_seqs.iter())
                .zip(chunk.document_ids.iter())
                .map(|(((len, parent_id), hierarchy_seq), document_id)| {
                    let len = len.to_native() as u32;
                    let path = ArenaRef { off, len };
                    off += len;
                    let hierarchy_seq = hierarchy_seq.to_native();
                    DavPath {
                        path,
                        parent_id: parent_id.to_native(),
                        hierarchy_seq: (hierarchy_seq & !WIRE_CONTAINER_FLAG) as u32
                            | if hierarchy_seq & WIRE_CONTAINER_FLAG != 0 {
                                CONTAINER_FLAG
                            } else {
                                0
                            },
                        document_id: document_id.to_native(),
                    }
                })
                .collect();
            if paths.is_empty() || off as usize != bytes.len() {
                return None;
            }

            path_total += paths_len;
            path_chunks.push(Arc::new(PathChunk { paths, bytes }));
        }

        if path_total != archived.path_total.to_native() as usize {
            return None;
        }

        let mut resources = GroupwareResources {
            base_path: archived.base_path.to_string(),
            paths: Arc::new(PathIndex {
                chunks: path_chunks,
                total: path_total,
            }),
            resources: ResourceStore {
                chunks,
                containers_end,
                total,
                unified_id_space,
            },
            item_change_id: archived.item_change_id.to_native(),
            container_change_id: archived.container_change_id.to_native(),
            highest_change_id: frame.change_id(),
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        };
        resources.recompute_size();
        resources
            .update_lock
            .set_revision(resources.highest_change_id);

        Some(resources)
    }
}

