/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FilePresence, ResourceChunkBuilder};
use crate::{ArenaRef, FileFlags, GroupwareResourceMetadata, GroupwareResourceRef, ResourceChunk};
use types::{media_type::MediaTypeId, metadata::MetadataKinds};

const KIND_MASK: u32 = 0b11;
pub const FILE_KIND_DIRECTORY: u8 = 0;
pub const FILE_KIND_FILE: u8 = 1;
pub const FILE_KIND_SYMLINK: u8 = 2;
const EXECUTABLE: u32 = 1 << 2;
const ROLE_SHIFT: u32 = 3;
const ROLE_MASK: u32 = 0xF;
const MEDIA_SHIFT: u32 = 7;
const MEDIA_MASK: u32 = (1 << MediaTypeId::BITS) - 1;
const EXTRA_SHIFT: u32 = 19;
const EXTRA_MASK: u32 = 0xFF;
const PRESENCE_SHIFT: u32 = EXTRA_SHIFT + 8;
const PRESENCE_MASK: u32 = FilePresence::MASK as u32;
const MEDIA_TYPE_EXACT_SHIFT: u32 = PRESENCE_SHIFT + PRESENCE_MASK.count_ones();
const MEDIA_TYPE_EXACT: u32 = 1 << MEDIA_TYPE_EXACT_SHIFT;
const RESERVED_SHIFT: u32 = MEDIA_TYPE_EXACT_SHIFT + 1;

pub const MAX_FILE_EXTRA_LEN: usize = EXTRA_MASK as usize;
pub const FILE_DEFAULT_MEDIA_TYPE: &str = "application/octet-stream";

impl FileFlags {
    pub fn new(
        kind: u8,
        executable: bool,
        role: u8,
        media_type: MediaTypeId,
        extra_len: u16,
    ) -> Self {
        FileFlags(
            (kind as u32 & KIND_MASK)
                | if executable { EXECUTABLE } else { 0 }
                | (role as u32 & ROLE_MASK) << ROLE_SHIFT
                | (media_type.raw() as u32 & MEDIA_MASK) << MEDIA_SHIFT
                | (extra_len as u32 & EXTRA_MASK) << EXTRA_SHIFT,
        )
    }

    #[inline(always)]
    pub fn kind(self) -> u8 {
        (self.0 & KIND_MASK) as u8
    }

    #[inline(always)]
    pub fn is_directory(self) -> bool {
        self.kind() == FILE_KIND_DIRECTORY
    }

    #[inline(always)]
    pub fn is_executable(self) -> bool {
        self.0 & EXECUTABLE != 0
    }

    #[inline(always)]
    pub fn role(self) -> u8 {
        ((self.0 >> ROLE_SHIFT) & ROLE_MASK) as u8
    }

    #[inline(always)]
    pub fn media_type_id(self) -> MediaTypeId {
        MediaTypeId::from_raw(((self.0 >> MEDIA_SHIFT) & MEDIA_MASK) as u16)
    }

    #[inline(always)]
    pub fn extra_len(self) -> usize {
        ((self.0 >> EXTRA_SHIFT) & EXTRA_MASK) as usize
    }

    pub fn with_presence(self, presence: FilePresence) -> Self {
        FileFlags(
            (self.0 & !(PRESENCE_MASK << PRESENCE_SHIFT))
                | (presence.bits() as u32 & PRESENCE_MASK) << PRESENCE_SHIFT,
        )
    }

    #[inline(always)]
    pub fn presence(self) -> FilePresence {
        FilePresence::from_bits(((self.0 >> PRESENCE_SHIFT) & PRESENCE_MASK) as u16)
    }

    #[inline(always)]
    pub fn metadata_kinds(self) -> MetadataKinds {
        self.presence().kinds()
    }

    #[inline(always)]
    pub fn has_dav_display_name(self) -> bool {
        self.presence().has_dav_display_name()
    }

    pub fn with_exact_media_type(self) -> Self {
        FileFlags(self.0 | MEDIA_TYPE_EXACT)
    }

    #[inline(always)]
    pub fn has_exact_media_type(self) -> bool {
        self.0 & MEDIA_TYPE_EXACT != 0
    }

    pub fn is_valid(self) -> bool {
        self.kind() <= FILE_KIND_SYMLINK
            && self.0 >> RESERVED_SHIFT == 0
            && (self.extra_len() == 0 || self.media_type_id().is_uncatalogued())
    }
}

impl ResourceChunkBuilder {
    pub fn push_file_name(
        &mut self,
        name: &str,
        media_type: Option<&str>,
    ) -> (ArenaRef, MediaTypeId, u16) {
        let media_id = media_type.map_or(MediaTypeId::NONE, MediaTypeId::lookup);
        let name_ref = self.push_str(name);
        if !media_id.is_uncatalogued() {
            return (name_ref, media_id, 0);
        }
        match media_type.filter(|media_type| media_type.len() <= MAX_FILE_EXTRA_LEN) {
            Some(media_type) => {
                self.bytes.extend_from_slice(media_type.as_bytes());
                (name_ref, media_id, media_type.len() as u16)
            }
            None => (name_ref, MediaTypeId::NONE, 0),
        }
    }

    pub(super) fn push_file_bytes(
        &mut self,
        chunk: &ResourceChunk,
        name: ArenaRef,
        flags: FileFlags,
    ) -> ArenaRef {
        let off = self.bytes.len() as u32;
        if let Some(bytes) = chunk
            .bytes
            .get(name.off as usize..(name.off as usize + name.len as usize + flags.extra_len()))
        {
            self.bytes.extend_from_slice(bytes);
        }
        ArenaRef { off, len: name.len }
    }
}

impl<'x> GroupwareResourceRef<'x> {
    #[inline(always)]
    pub fn file_flags(&self) -> Option<FileFlags> {
        match &self.resource.data {
            GroupwareResourceMetadata::File { flags, .. } => Some(*flags),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn file_kind(&self) -> Option<u8> {
        self.file_flags().map(FileFlags::kind)
    }

    #[inline(always)]
    pub fn is_executable(&self) -> bool {
        self.file_flags().is_some_and(FileFlags::is_executable)
    }

    #[inline(always)]
    pub fn file_role(&self) -> u8 {
        self.file_flags().map_or(0, FileFlags::role)
    }

    #[inline(always)]
    pub fn has_dav_display_name(&self) -> bool {
        self.file_flags()
            .is_some_and(FileFlags::has_dav_display_name)
    }

    pub fn media_type(&self) -> Option<&'x str> {
        let flags = self.file_flags()?;
        let id = flags.media_type_id();
        if id.is_uncatalogued() {
            self.file_extra_bytes(flags)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
        } else {
            id.as_str()
        }
        .or((flags.kind() == FILE_KIND_FILE).then_some(FILE_DEFAULT_MEDIA_TYPE))
    }

    fn file_extra_bytes(&self, flags: FileFlags) -> Option<&'x [u8]> {
        match &self.resource.data {
            GroupwareResourceMetadata::File { name, .. } if flags.extra_len() > 0 => {
                let start = name.off as usize + name.len as usize;
                self.chunk.bytes.get(start..start + flags.extra_len())
            }
            _ => None,
        }
    }
}

