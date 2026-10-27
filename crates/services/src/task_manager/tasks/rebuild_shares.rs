/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::grantee_cleanup::shared_acls;
use common::{Server, cache::invalidate::CacheInvalidationBuilder};
use registry::{schema::prelude::ObjectType, types::EnumImpl};
use std::mem;
use store::{
    SerializeInfallible, ValueKey,
    ahash::{AHashMap, AHashSet},
    roaring::RoaringBitmap,
    write::{BatchBuilder, RegistryClass, ValueClass, assert::AssertValue},
};
use trc::AddContext;
use types::{acl::Acl, collection::Collection, field::Field};
use utils::map::bitmap::Bitmap;

const SHARED_COLLECTIONS: [Collection; 4] = [
    Collection::Mailbox,
    Collection::Calendar,
    Collection::AddressBook,
    Collection::FileNode,
];

struct ShareFix {
    document_id: u32,
    archive: AssertValue,
    grants: Vec<(u32, u64)>,
    revokes: Vec<u32>,
}

pub trait RevokeAccountGrants: Sync + Send {
    fn revoke_account_grants(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<AHashSet<u32>>> + Send;
}

impl RevokeAccountGrants for Server {
    async fn revoke_account_grants(&self, account_id: u32) -> trc::Result<AHashSet<u32>> {
        let grantee_ids = match owned_grantees(self, account_id).await {
            Ok(grantee_ids) => grantee_ids,
            Err(err) => {
                trc::error!(
                    err.account_id(account_id)
                        .details("Failed to read shared containers, scanning every grant")
                        .caused_by(trc::location!())
                );
                self.store()
                    .acl_owned(account_id)
                    .await
                    .caused_by(trc::location!())?
                    .into_iter()
                    .map(|(grantee_id, _)| grantee_id)
                    .collect()
            }
        };
        self.store()
            .acl_revoke_owner(account_id, &grantee_ids)
            .await
            .caused_by(trc::location!())?;
        Ok(grantee_ids)
    }
}

async fn owned_grantees(server: &Server, account_id: u32) -> trc::Result<AHashSet<u32>> {
    let mut grantee_ids = AHashSet::new();
    for collection in SHARED_COLLECTIONS {
        server
            .archives(account_id, collection, Field::ARCHIVE, &(), |_, archive| {
                if let Some(acls) = shared_acls(collection, &archive)? {
                    grantee_ids.extend(acls.iter().map(|grant| u32::from(grant.account_id)));
                }
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
    }
    Ok(grantee_ids)
}

pub(crate) trait RebuildSharesTask: Sync + Send {
    fn rebuild_shares(&self, account_id: u32) -> impl Future<Output = trc::Result<()>> + Send;

    fn invalidate_grantees(
        &self,
        grantee_ids: &mut RoaringBitmap,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl RebuildSharesTask for Server {
    async fn rebuild_shares(&self, account_id: u32) -> trc::Result<()> {
        let account = ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::Account.to_id(),
            item_id: u64::from(account_id),
        });
        if !self
            .store()
            .key_exists(ValueKey::from(account.clone()))
            .await
            .caused_by(trc::location!())?
        {
            return Ok(());
        }

        let mut indexed: AHashMap<(Collection, u32), Vec<(u32, u64)>> = AHashMap::new();
        for (grantee_id, item) in self
            .store()
            .acl_owned(account_id)
            .await
            .caused_by(trc::location!())?
        {
            indexed
                .entry((item.to_collection, item.to_document_id))
                .or_default()
                .push((grantee_id, item.permissions));
        }

        let mut fixes = Vec::new();
        let mut grantee_ids = RoaringBitmap::new();
        let new_batch = || {
            let mut batch = BatchBuilder::new();
            batch.assert_value(account.clone(), AssertValue::Some);
            batch
        };
        let mut batch = new_batch();
        let mut has_changes = false;
        for collection in SHARED_COLLECTIONS {
            self.archives(
                account_id,
                collection,
                Field::ARCHIVE,
                &(),
                |document_id, archive| {
                    let Some(acls) = shared_acls(collection, &archive)? else {
                        return Ok(true);
                    };
                    let mut stale = indexed
                        .remove(&(collection, document_id))
                        .unwrap_or_default();
                    let mut grants = Vec::new();
                    for grant in acls.iter() {
                        let grantee_id = u32::from(grant.account_id);
                        let rights = Bitmap::<Acl>::from(&grant.grants).bitmap;
                        let indexed_rights = stale
                            .iter()
                            .position(|(id, _)| *id == grantee_id)
                            .map(|idx| stale.swap_remove(idx).1);
                        if indexed_rights != Some(rights) {
                            grants.push((grantee_id, rights));
                        }
                    }
                    if !grants.is_empty() || !stale.is_empty() {
                        fixes.push(ShareFix {
                            document_id,
                            archive: AssertValue::Archive(archive.version),
                            grants,
                            revokes: stale
                                .into_iter()
                                .map(|(grantee_id, _)| grantee_id)
                                .collect(),
                        });
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
            fixes.extend(
                indexed
                    .extract_if(|(indexed_collection, _), _| *indexed_collection == collection)
                    .map(|((_, document_id), stale)| ShareFix {
                        document_id,
                        archive: AssertValue::None,
                        grants: Vec::new(),
                        revokes: stale
                            .into_iter()
                            .map(|(grantee_id, _)| grantee_id)
                            .collect(),
                    }),
            );

            for fix in fixes.drain(..) {
                batch
                    .with_account_id(account_id)
                    .with_collection(collection)
                    .with_document(fix.document_id)
                    .assert_value(Field::ARCHIVE, fix.archive);
                for (grantee_id, rights) in fix.grants {
                    batch.acl_grant(grantee_id, rights.serialize());
                    grantee_ids.insert(grantee_id);
                }
                for grantee_id in fix.revokes {
                    batch.acl_revoke(grantee_id);
                    grantee_ids.insert(grantee_id);
                }
                has_changes = true;
                if batch.is_large_batch() {
                    self.store()
                        .write_batch(&mut batch)
                        .await
                        .caused_by(trc::location!())?;
                    self.invalidate_grantees(&mut grantee_ids).await?;
                    batch = new_batch();
                    has_changes = false;
                }
            }
        }

        if has_changes {
            self.store()
                .write_batch(&mut batch)
                .await
                .caused_by(trc::location!())?;
            self.invalidate_grantees(&mut grantee_ids).await?;
        }

        Ok(())
    }

    async fn invalidate_grantees(&self, grantee_ids: &mut RoaringBitmap) -> trc::Result<()> {
        if grantee_ids.is_empty() {
            return Ok(());
        }
        let mut changes = CacheInvalidationBuilder::default();
        for grantee_id in mem::take(grantee_ids) {
            self.invalidate_grantee(&mut changes, grantee_id).await;
        }
        self.invalidate_caches(changes)
            .await
            .caused_by(trc::location!())
    }
}
