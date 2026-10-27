/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedMailbox, Mailbox};
use common::storage::index::{
    ArchivedIdField, IndexValue, IndexableAndSerializableObject, IndexableObject,
    SerializableObject, serialize_object,
};
use store::{
    U32_LEN,
    write::{ArchiveCompression, BatchBuilder, Compression, IndexPropertyClass, Slot, ValueClass},
    xxhash_rust::xxh3::xxh3_128,
};
use types::{
    acl::AclGrant, collection::SyncCollection, field::MailboxField, metadata::MetadataKinds,
};
use utils::hash128::Hash128;

pub(crate) fn name_index_class(lowercase_name: &[u8]) -> ValueClass {
    ValueClass::IndexProperty(IndexPropertyClass::Hash {
        property: MailboxField::Name.into(),
        hash: Hash128::from(xxh3_128(lowercase_name)),
    })
}

fn name_index(name: &str, stored_parent_id: u32) -> IndexValue<'static> {
    let parent_id = stored_parent_id.checked_sub(1).unwrap_or(u32::MAX);
    let mut value = Vec::with_capacity(U32_LEN + name.len());
    value.extend_from_slice(&parent_id.to_be_bytes());
    value.extend(name.bytes().map(|byte| byte.to_ascii_lowercase()));
    IndexValue::ParentProperty {
        field: name_index_class(value.get(U32_LEN..).unwrap_or_default()),
        value,
    }
}

impl IndexableObject for Mailbox {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Email,
            },
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            name_index(&self.name, self.parent_id),
        ]
        .into_iter()
    }

    fn metadata_kinds(&self) -> MetadataKinds {
        Mailbox::metadata_kinds(self)
    }
}

impl IndexableObject for &ArchivedMailbox {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Email,
            },
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            name_index(&self.name, self.parent_id.to_native()),
        ]
        .into_iter()
    }

    fn metadata_kinds(&self) -> MetadataKinds {
        ArchivedMailbox::metadata_kinds(self)
    }
}

impl IndexableAndSerializableObject for Mailbox {
    const PENDING_ID_FIELD: Option<ArchivedIdField> =
        Some(ArchivedIdField::new(std::mem::offset_of!(ArchivedMailbox, parent_id)).one_based());

    fn is_versioned() -> bool {
        false
    }
}

impl ArchiveCompression for Mailbox {
    const COMPRESSION: Compression = Compression::None;
}

impl SerializableObject for Mailbox {
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()> {
        serialize_object(self, batch, pending_id)
    }
}

