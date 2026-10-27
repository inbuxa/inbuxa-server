/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    DavResourcePath, GroupwareResourceRef, GroupwareResources, auth::AccessToken,
    storage::dav::CachedUid,
};
use store::roaring::RoaringBitmap;
use types::acl::{Acl, AclGrant};
use utils::map::bitmap::Bitmap;

fn grant_matches(
    access_token: &AccessToken,
    acl: &AclGrant,
    check_acls: &Bitmap<Acl>,
    match_any: bool,
) -> bool {
    // inbuxa: AU-1.6: a grant matches the token's own account and its groups,
    // not every account an Impersonate holder can reach (GHSA-m992-gp7g-wc2j)
    if !access_token.is_member_directly(acl.account_id) {
        return false;
    }
    let mut grants = acl.grants;
    grants.intersection(check_acls);
    grants == *check_acls || (match_any && !grants.is_empty())
}

impl GroupwareResources {
    pub fn shared_containers(
        &self,
        access_token: &AccessToken,
        check_acls: impl IntoIterator<Item = Acl>,
        match_any: bool,
    ) -> RoaringBitmap {
        let check_acls = Bitmap::<Acl>::from_iter(check_acls);
        let mut document_ids = RoaringBitmap::new();

        for resource in self.resources_with_acls() {
            if resource
                .acls()
                .iter()
                .any(|acl| grant_matches(access_token, acl, &check_acls, match_any))
            {
                document_ids.insert(resource.document_id());
            }
        }

        document_ids
    }

    pub fn is_shared_item(
        &self,
        item: &GroupwareResourceRef<'_>,
        access_token: &AccessToken,
        check_acls: &Bitmap<Acl>,
        match_any: bool,
    ) -> bool {
        item.child_names().iter().any(|name| {
            self.resources
                .find(name.parent_id, true)
                .is_some_and(|container| {
                    container
                        .acls()
                        .iter()
                        .any(|acl| grant_matches(access_token, acl, check_acls, match_any))
                })
        })
    }

    pub fn shared_items(
        &self,
        access_token: &AccessToken,
        check_acls: impl IntoIterator<Item = Acl>,
        match_any: bool,
    ) -> RoaringBitmap {
        let mut document_ids = RoaringBitmap::new();
        for container_id in &self.shared_containers(access_token, check_acls, match_any) {
            document_ids.extend(self.children_ids(container_id));
        }
        document_ids
    }

    pub fn has_access_to_container(
        &self,
        access_token: &AccessToken,
        document_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> bool {
        let mut grants = self.container_acl(access_token, document_id);
        grants.intersection(&check_acls.into());
        !grants.is_empty()
    }

    pub fn container_acl(&self, access_token: &AccessToken, document_id: u32) -> Bitmap<Acl> {
        let mut account_acls = Bitmap::<Acl>::new();

        if let Some(resource) = self.resources.find_any(document_id) {
            for acl in resource.acls() {
                // inbuxa: AU-1.6, as in grant_matches
                if access_token.is_member_directly(acl.account_id) {
                    account_acls.union(&acl.grants);
                }
            }
        }

        account_acls
    }

    pub fn uid_matches(&self, uid: &str) -> RoaringBitmap {
        self.resources
            .find_by_uid(uid.cached_uid())
            .map(|resource| resource.document_id())
            .collect()
    }

    pub fn children_with_uid<'x>(
        &'x self,
        container_id: u32,
        uid: &'x str,
    ) -> impl Iterator<Item = DavResourcePath<'x>> + 'x {
        self.resources
            .find_by_uid(uid.cached_uid())
            .filter(move |resource| {
                resource
                    .child_names()
                    .iter()
                    .any(|name| name.parent_id == container_id)
            })
            .filter_map(move |resource| self.child_path(resource.document_id(), container_id))
    }

    pub fn event_ids_with_flags(&self, mask: u16) -> RoaringBitmap {
        let [document_ids] = self.event_ids_with_flag_masks([mask]);
        document_ids
    }

    pub fn event_ids_with_flag_masks<const N: usize>(&self, masks: [u16; N]) -> [RoaringBitmap; N] {
        let mut document_ids = std::array::from_fn(|_| RoaringBitmap::new());
        for resource in self.resources.iter_run(false) {
            if let Some(flags) = resource.event_flags() {
                let document_id = resource.document_id();
                for (mask, document_ids) in masks.iter().zip(document_ids.iter_mut()) {
                    if flags & *mask != 0 {
                        document_ids.insert(document_id);
                    }
                }
            }
        }
        document_ids
    }

    pub fn document_ids(&self, is_container: bool) -> impl Iterator<Item = u32> {
        self.resources
            .iter_run(is_container)
            .filter_map(move |resource| {
                if resource.is_container() == is_container {
                    Some(resource.document_id())
                } else {
                    None
                }
            })
    }

    pub fn has_container_id(&self, id: &u32) -> bool {
        self.resources.find(*id, true).is_some()
    }

    pub fn has_item_id(&self, id: &u32) -> bool {
        self.resources.find(*id, false).is_some()
    }
}

