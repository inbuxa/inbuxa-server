/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: what the store-check spec (docs/spec/features/store-check.md)
//! reads from the store: each blob the data holds a link to, with who holds
//! it, one slice of the blob index at a time (SV-3), and whether a blob is
//! in the blob store without reading all of it (SV-2, quick).

use super::{BlobOp, ValueClass, key::DeserializeBigEndian, now};
use crate::{
    BlobStore, Deserialize, IterateParams, Store, U16_LEN, U32_LEN, U64_LEN, ValueKey,
    write::BlobLink,
};
use registry::types::id::ObjectId;
use trc::AddContext;
use types::blob_hash::{BLOB_HASH_LEN, BlobHash};

/// Who holds a link to a blob (SV-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobHolder {
    /// A document: an email, a file, a Sieve script, ...
    Document {
        account_id: u32,
        collection: u8,
        document_id: u32,
    },
    /// A queued message.
    Queue { id: u64 },
    /// A deleted item kept to be restored, until its link expires.
    Archived { account_id: u32, item: ObjectId },
}

/// A blob something holds, and whether the store has its commit marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedBlob {
    pub hash: BlobHash,
    pub committed: bool,
    pub holders: Vec<BlobHolder>,
}

impl Store {
    /// Every blob in one slice of the blob index (the first byte of its
    /// hash) that something holds a link to. Uploads nothing holds yet and
    /// expired links are left out: they're the purge's to clear.
    pub async fn linked_blobs(&self, slice: u8) -> trc::Result<Vec<LinkedBlob>> {
        const TEMP_LINK: usize = BLOB_HASH_LEN + U32_LEN + U64_LEN;
        const DOC_LINK: usize = BLOB_HASH_LEN + U32_LEN + 1 + U32_LEN;
        const ID_LINK: usize = BLOB_HASH_LEN + U64_LEN;

        let mut from_hash = BlobHash::default();
        let mut to_hash = BlobHash::new_max();
        from_hash.0[0] = slice;
        to_hash.0[0] = slice;
        let from_key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Commit { hash: from_hash }),
        };
        let to_key = ValueKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::Blob(BlobOp::Link {
                hash: to_hash,
                to: BlobLink::Document,
            }),
        };

        let now = now();
        let mut blobs: Vec<LinkedBlob> = Vec::new();
        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let hash = key
                    .get(0..BLOB_HASH_LEN)
                    .and_then(|h| BlobHash::try_from_hash_slice(h).ok())
                    .ok_or_else(|| {
                        trc::Error::corrupted_key(key, value.into(), trc::location!())
                    })?;
                if blobs.last().is_none_or(|b| b.hash != hash) {
                    blobs.push(LinkedBlob {
                        hash,
                        committed: false,
                        holders: Vec::new(),
                    });
                }
                let blob = blobs.last_mut().unwrap();
                match key.len() {
                    BLOB_HASH_LEN => blob.committed = true,
                    DOC_LINK => blob.holders.push(BlobHolder::Document {
                        account_id: key.deserialize_be_u32(BLOB_HASH_LEN)?,
                        collection: key[BLOB_HASH_LEN + U32_LEN],
                        document_id: key.deserialize_be_u32(BLOB_HASH_LEN + U32_LEN + 1)?,
                    }),
                    ID_LINK => blob.holders.push(BlobHolder::Queue {
                        id: key.deserialize_be_u64(BLOB_HASH_LEN)?,
                    }),
                    TEMP_LINK => {
                        // Only a link that names a kept item: a plain one is
                        // an upload nothing holds yet
                        let until = key.deserialize_be_u64(BLOB_HASH_LEN + U32_LEN)?;
                        if until > now && value.len() == U16_LEN + U64_LEN {
                            blob.holders.push(BlobHolder::Archived {
                                account_id: key.deserialize_be_u32(BLOB_HASH_LEN)?,
                                item: ObjectId::deserialize(value)?,
                            });
                        }
                    }
                    _ => {
                        return Err(trc::Error::corrupted_key(
                            key,
                            value.into(),
                            trc::location!(),
                        ));
                    }
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        blobs.retain(|b| !b.holders.is_empty());
        Ok(blobs)
    }
}

impl BlobStore {
    /// Whether the blob store has anything under `key`, reading as little
    /// of it as each backend allows: a file's metadata, one byte of an
    /// object, or, in a data store, the blob itself.
    pub async fn blob_present(&self, key: &[u8]) -> trc::Result<bool> {
        match self {
            BlobStore::Fs(store) => store.get_blob(key, 0..1).await.map(|b| b.is_some()),
            #[cfg(feature = "s3")]
            BlobStore::S3(store) => match store.get_blob(key, 0..1).await {
                Ok(found) => Ok(found.is_some()),
                // An empty object has no first byte to read
                Err(_) => self.raw_get(key).await.map(|b| b.is_some()),
            },
            #[cfg(feature = "azure")]
            BlobStore::Azure(store) => match store.get_blob(key, 0..1).await {
                Ok(found) => Ok(found.is_some()),
                Err(_) => self.raw_get(key).await.map(|b| b.is_some()),
            },
            BlobStore::Sharded(store) => {
                // Anywhere in the set: a misplaced blob is still there
                for member in &store.members {
                    if Box::pin(member.blob_present(key)).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            BlobStore::Store(_) => self.raw_get(key).await.map(|b| b.is_some()),
        }
    }
}
