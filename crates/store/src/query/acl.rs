/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use trc::AddContext;
use types::collection::Collection;

use crate::{
    Deserialize, IterateParams, Store, Subspace, U32_LEN, ValueKey,
    write::{BatchBuilder, ValueClass, key::DeserializeBigEndian},
};

const MAX_REVOKE_RANGES: usize = 1_000;

pub enum AclQuery {
    SharedWith {
        grant_account_id: u32,
        to_account_id: u32,
        to_collection: u8,
    },
    HasAccess {
        grant_account_id: u32,
    },
}

#[derive(Debug)]
pub struct AclItem {
    pub to_account_id: u32,
    pub to_collection: Collection,
    pub to_document_id: u32,
    pub permissions: u64,
}

impl Store {
    pub async fn acl_query(&self, query: AclQuery) -> trc::Result<Vec<AclItem>> {
        let mut results = Vec::new();
        let (from_key, to_key) = match query {
            AclQuery::SharedWith {
                grant_account_id,
                to_account_id,
                to_collection,
            } => {
                let from_key = ValueKey {
                    account_id: to_account_id,
                    collection: to_collection,
                    document_id: 0,
                    class: ValueClass::Acl(grant_account_id),
                };
                let mut to_key = from_key.clone();
                to_key.document_id = u32::MAX;

                (from_key, to_key)
            }
            AclQuery::HasAccess { grant_account_id } => (
                ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Acl(grant_account_id),
                },
                ValueKey {
                    account_id: u32::MAX,
                    collection: u8::MAX,
                    document_id: u32::MAX,
                    class: ValueClass::Acl(grant_account_id),
                },
            ),
        };

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                results.push(AclItem::deserialize(key)?.with_permissions(u64::deserialize(value)?));

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| results)
    }

    pub async fn acl_owned(&self, account_id: u32) -> trc::Result<Vec<(u32, AclItem)>> {
        let mut results = Vec::new();
        self.iterate(
            IterateParams::new(
                ValueKey {
                    account_id: 0,
                    collection: 0,
                    document_id: 0,
                    class: ValueClass::Acl(0),
                },
                ValueKey {
                    account_id: u32::MAX,
                    collection: u8::MAX,
                    document_id: u32::MAX,
                    class: ValueClass::Acl(u32::MAX),
                },
            )
            .ascending(),
            |key, value| {
                if account_id == key.deserialize_be_u32(U32_LEN)? {
                    results.push((
                        key.deserialize_be_u32(0)?,
                        AclItem::deserialize(key)?.with_permissions(u64::deserialize(value)?),
                    ));
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| results)
    }

    pub async fn acl_revoke_owner(
        &self,
        owner_account_id: u32,
        grantee_ids: &AHashSet<u32>,
    ) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        let mut ranges = 0;
        for grantee_id in grantee_ids {
            if ranges == MAX_REVOKE_RANGES || batch.is_large_batch() {
                self.write_batch(&mut batch)
                    .await
                    .caused_by(trc::location!())?;
                batch = BatchBuilder::new();
                ranges = 0;
            }
            ranges += 1;
            let from = (u64::from(*grantee_id) << 32) | u64::from(owner_account_id);
            batch.clear_range(
                Subspace::Acl,
                from.to_be_bytes().to_vec(),
                from.saturating_add(1).to_be_bytes().to_vec(),
            );
        }
        if !batch.is_empty() {
            self.write_batch(&mut batch)
                .await
                .caused_by(trc::location!())?;
        }
        Ok(())
    }
}

impl Deserialize for AclItem {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(AclItem {
            to_account_id: bytes.deserialize_be_u32(U32_LEN)?,
            to_collection: bytes
                .get(U32_LEN * 2)
                .map(|b| Collection::from(*b))
                .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?,
            to_document_id: bytes.deserialize_be_u32((U32_LEN * 2) + 1)?,
            permissions: 0,
        })
    }
}

impl AclItem {
    fn with_permissions(mut self, permissions: u64) -> Self {
        self.permissions = permissions;
        self
    }
}
