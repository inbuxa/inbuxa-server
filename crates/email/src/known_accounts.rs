/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! With directory queries off, who an account may still see and share with:
//! the accounts it already has to do with. Reading names and granting access
//! use the same list, so a grant can't be used to learn a name it couldn't
//! read otherwise.

use crate::cache::MessageCacheFetch;
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::cache::GroupwareCache;
use std::future::Future;
use store::roaring::RoaringBitmap;
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::{Collection, SyncCollection},
};

pub trait KnownAccounts: Sync + Send {
    /// The account itself, its groups, whoever shared with it, and whoever is
    /// on an item it manages.
    fn known_accounts(
        &self,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;
}

impl KnownAccounts for Server {
    async fn known_accounts(&self, access_token: &AccessToken) -> trc::Result<RoaringBitmap> {
        let mut known = RoaringBitmap::from_iter(access_token.all_ids());
        let mut add = |account_id: u32, grants: &[AclGrant]| {
            if !grants.is_empty()
                && (access_token.is_member(account_id)
                    || grants.effective_acl(access_token).contains(Acl::Share))
            {
                known.extend(grants.iter().map(|grant| grant.account_id));
            }
        };

        for (collection, sync_collection) in [
            (Collection::Calendar, SyncCollection::Calendar),
            (Collection::AddressBook, SyncCollection::AddressBook),
            (Collection::FileNode, SyncCollection::FileNode),
        ] {
            let account_ids = access_token
                .all_ids_by_collection(collection)
                .collect::<RoaringBitmap>();
            for account_id in account_ids {
                let resources = self
                    .fetch_dav_resources(access_token.account_id(), account_id, sync_collection)
                    .await
                    .caused_by(trc::location!())?;
                for resource in &resources.resources {
                    if let Some(grants) = resource.acls() {
                        add(account_id, grants);
                    }
                }
            }
        }

        let account_ids = access_token
            .all_ids_by_collection(Collection::Mailbox)
            .collect::<RoaringBitmap>();
        for account_id in account_ids {
            let cache = self
                .get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?;
            for mailbox in cache.mailboxes.items.iter() {
                add(account_id, mailbox.acls.as_slice());
            }
        }

        Ok(known)
    }
}
