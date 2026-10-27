/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Archive, ArchiveBytes, ArchiveVersion, ValueClass};
use crate::{Deserialize, SerializeInfallible, U32_LEN, U64_LEN};
use types::metadata::{EncodedMetadata, MetadataKinds, MetadataView, STORAGE_TRAILER_CAPACITY};

pub const METADATA_COMPRESS_WATERMARK: usize = 1024;

const TRAILER_LEN: usize = U32_LEN + 1;
const _: () = assert!(TRAILER_LEN == STORAGE_TRAILER_CAPACITY);

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum MetadataClass {
    Shared,
    Private { viewer: u32 },
    Viewer { viewer: u32 },
    Owner { owner: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMetadata {
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataBuf {
    bytes: Box<[u8]>,
    stored_len: u32,
    hash: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ViewerState {
    pub change_id: u64,
    pub containers: u32,
}

const VIEWER_STATE_LEN: usize = U64_LEN + U32_LEN;

impl MetadataClass {
    pub(crate) const SHARED: u8 = 0;
    pub(crate) const PRIVATE: u8 = 1;
    pub const VIEWER: u8 = 2;
    pub const OWNER: u8 = 3;
}

impl From<MetadataClass> for ValueClass {
    fn from(class: MetadataClass) -> Self {
        ValueClass::Metadata(class)
    }
}

impl StoredMetadata {
    pub fn new(container: EncodedMetadata) -> trc::Result<Self> {
        Archive::serialize_raw(container.into_bytes(), METADATA_COMPRESS_WATERMARK)
            .map(|bytes| StoredMetadata { bytes })
    }

    pub fn trailer_hash(stored: &[u8]) -> trc::Result<u32> {
        stored
            .split_last()
            .and_then(|(_, contents)| contents.last_chunk::<U32_LEN>())
            .map(|hash| u32::from_be_bytes(*hash))
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Metadata container carries no trailer")
                    .ctx(trc::Key::Value, stored)
                    .caused_by(trc::location!())
            })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn view<'x>(stored: &'x [u8], scratch: &'x mut Vec<u8>) -> trc::Result<MetadataView<'x>> {
        let contents = Archive::<ArchiveBytes>::deserialize_raw(stored, scratch)?;
        unsafe { MetadataView::from_trusted(contents) }.ok_or_else(|| invalid_header(contents))
    }
}

#[cold]
fn invalid_header(contents: &[u8]) -> trc::Error {
    trc::StoreEvent::DataCorruption
        .into_err()
        .details("Invalid metadata container header")
        .ctx(trc::Key::Value, contents)
        .caused_by(trc::location!())
}

impl MetadataBuf {
    pub fn from_view(view: &MetadataView<'_>, stored_len: u32, hash: u32) -> Self {
        MetadataBuf {
            bytes: view.as_bytes().into(),
            stored_len,
            hash,
        }
    }

    pub fn read(stored: &[u8]) -> trc::Result<Self> {
        let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(stored)?;
        match archive.version {
            ArchiveVersion::Hashed { hash }
                if unsafe { MetadataView::from_trusted(&archive.inner) }.is_some() =>
            {
                Ok(MetadataBuf {
                    bytes: archive.inner.into_boxed_slice(),
                    stored_len: u32::try_from(stored.len()).unwrap_or(u32::MAX),
                    hash,
                })
            }
            _ => Err(invalid_header(&archive.inner)),
        }
    }

    pub fn view(&self) -> MetadataView<'_> {
        unsafe { MetadataView::from_trusted(&self.bytes) }.unwrap_or_else(MetadataView::empty)
    }

    pub fn kinds(&self) -> MetadataKinds {
        self.view().kinds()
    }

    pub fn stored_len(&self) -> u32 {
        self.stored_len
    }

    pub fn hash(&self) -> u32 {
        self.hash
    }
}

impl Deserialize for MetadataBuf {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Self::read(bytes)
    }
}

impl SerializeInfallible for ViewerState {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(VIEWER_STATE_LEN);
        bytes.extend_from_slice(&self.change_id.to_be_bytes());
        bytes.extend_from_slice(&self.containers.to_be_bytes());
        bytes
    }
}

impl Deserialize for ViewerState {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        bytes
            .split_first_chunk::<U64_LEN>()
            .and_then(|(change_id, containers)| {
                Some(ViewerState {
                    change_id: u64::from_be_bytes(*change_id),
                    containers: u32::from_be_bytes(containers.try_into().ok()?),
                })
            })
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Invalid metadata viewer state")
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!())
            })
    }
}

