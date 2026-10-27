/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedFileNode, ArchivedFileNodeContent, FileNode, FileNodeContent, content::FileContentKind,
};
use common::storage::index::{
    IndexValue, IndexableAndSerializableObject, IndexableObject, SerializableObject,
    serialize_object,
};
use store::write::{ArchiveCompression, BatchBuilder, Compression, SearchIndex, Slot};
use types::{acl::AclGrant, collection::SyncCollection, metadata::MetadataKinds};

impl IndexableObject for FileNode {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        let mut values = Vec::with_capacity(6);

        values.extend([
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            IndexValue::LogItem {
                prefix: None,
                sync_collection: SyncCollection::FileNode,
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
        ]);

        if let Some(file) = self.file() {
            values.extend([
                IndexValue::SearchIndex {
                    index: SearchIndex::File,
                    hash: FileContentKind::index_hash(
                        FileContentKind::detect(&self.name, file.media_type.as_deref()),
                        file.blob_hash.as_slice(),
                    ),
                },
                IndexValue::Blob {
                    value: file.blob_hash.clone(),
                    size: u64::from(file.size),
                },
            ]);
        }

        values.into_iter()
    }

    fn metadata_kinds(&self) -> MetadataKinds {
        FileNode::metadata_kinds(self)
    }
}

impl IndexableObject for &ArchivedFileNode {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        let mut values = Vec::with_capacity(6);

        values.extend([
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            IndexValue::LogItem {
                prefix: None,
                sync_collection: SyncCollection::FileNode,
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
        ]);

        if let Some(file) = self.file() {
            values.extend([
                IndexValue::SearchIndex {
                    index: SearchIndex::File,
                    hash: FileContentKind::index_hash(
                        FileContentKind::detect(&self.name, file.media_type.as_deref()),
                        file.blob_hash.0.as_slice(),
                    ),
                },
                IndexValue::Blob {
                    value: (&file.blob_hash).into(),
                    size: u64::from(file.size.to_native()),
                },
            ]);
        }

        values.into_iter()
    }

    fn metadata_kinds(&self) -> MetadataKinds {
        ArchivedFileNode::metadata_kinds(self)
    }
}

impl IndexableAndSerializableObject for FileNode {
    fn is_versioned() -> bool {
        true
    }

    fn set_pending_id(&mut self, document_id: u32) -> trc::Result<()> {
        self.parent_id = document_id + 1;
        self.etag = self.compute_etag();
        Ok(())
    }

    fn size_hint(&self) -> usize {
        self.size()
    }
}

impl FileNode {
    pub fn size(&self) -> usize {
        self.name.len()
            + match &self.content {
                FileNodeContent::Directory => 0,
                FileNodeContent::File(file) => {
                    file.size as usize + file.media_type.as_ref().map_or(0, |t| t.len())
                }
                FileNodeContent::Symlink(target) => target.len(),
            }
            + std::mem::size_of::<FileNode>()
    }
}

impl ArchivedFileNode {
    pub fn size(&self) -> usize {
        self.name.len()
            + match &self.content {
                ArchivedFileNodeContent::Directory => 0,
                ArchivedFileNodeContent::File(file) => {
                    file.size.to_native() as usize + file.media_type.as_ref().map_or(0, |t| t.len())
                }
                ArchivedFileNodeContent::Symlink(target) => target.len(),
            }
            + std::mem::size_of::<FileNode>()
    }
}

impl ArchiveCompression for FileNode {
    const COMPRESSION: Compression = Compression::None;
}

impl SerializableObject for FileNode {
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()> {
        let mut node = self;
        node.etag = node.compute_etag();
        let etag = node.etag;
        serialize_object(node, batch, pending_id)?;
        if pending_id.is_none() {
            batch.set_archive_hash(Some(etag));
        }
        Ok(())
    }
}

