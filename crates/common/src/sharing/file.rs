/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{GroupwareResources, auth::AccessToken};
use ahash::AHashMap;
use store::roaring::RoaringBitmap;
use types::acl::Acl;
use utils::map::bitmap::Bitmap;

const MAX_ANCESTOR_WALK: usize = 256;

#[derive(Debug, Default)]
pub struct FileNodeAccess {
    pub readable: RoaringBitmap,
    pub discoverable: RoaringBitmap,
    grants: AHashMap<u32, Bitmap<Acl>>,
}

impl FileNodeAccess {
    #[inline(always)]
    pub fn acl(&self, document_id: u32) -> Bitmap<Acl> {
        self.grants.get(&document_id).copied().unwrap_or_default()
    }

    #[inline(always)]
    pub fn has_acl(&self, document_id: u32, acl: Acl) -> bool {
        self.grants
            .get(&document_id)
            .is_some_and(|grants| grants.contains(acl))
    }

    pub fn node_rights(&self, document_id: u32, parent_id: Option<u32>) -> Bitmap<Acl> {
        let mut acl = self.acl(document_id);
        if self.may_unbind_from(parent_id) {
            acl.insert(Acl::RemoveItems);
        }
        acl
    }

    pub fn may_delete(&self, document_id: u32, parent_id: Option<u32>) -> bool {
        self.discoverable.contains(document_id)
            && (self.has_acl(document_id, Acl::RemoveItems) || self.may_unbind_from(parent_id))
    }

    pub fn may_destroy(&self, mut subtree: impl Iterator<Item = (u32, Option<u32>)>) -> bool {
        subtree.all(|(document_id, parent_id)| self.may_delete(document_id, parent_id))
    }

    fn may_unbind_from(&self, parent_id: Option<u32>) -> bool {
        parent_id.is_some_and(|parent_id| self.has_acl(parent_id, Acl::RemoveItems))
    }

    pub fn with_acl(&self, acl: Acl) -> RoaringBitmap {
        self.grants
            .iter()
            .filter(|(_, grants)| grants.contains(acl))
            .map(|(document_id, _)| *document_id)
            .collect()
    }
}

impl GroupwareResources {
    pub fn file_acl(&self, access_token: &AccessToken, document_id: u32) -> Bitmap<Acl> {
        let mut grants = Bitmap::new();
        let mut current = self.resources.find_any(document_id);
        for _ in 0..MAX_ANCESTOR_WALK {
            let Some(resource) = current else {
                break;
            };
            if resource.is_container() {
                for acl in resource.acls() {
                    if access_token.is_member(acl.account_id) {
                        grants.union(&acl.grants);
                    }
                }
            }
            current = resource
                .parent_id()
                .and_then(|parent_id| self.resources.find_any(parent_id));
        }
        grants
    }

    pub fn file_discoverable(&self, access_token: &AccessToken, document_id: u32) -> bool {
        is_readable(&self.file_acl(access_token, document_id))
            || self
                .file_access(access_token)
                .discoverable
                .contains(document_id)
    }

    pub fn file_access(&self, access_token: &AccessToken) -> FileNodeAccess {
        let mut direct = DirectGrants::new();
        for resource in self.resources_with_acls() {
            if !resource.is_container() {
                continue;
            }
            let mut found = Bitmap::new();
            for acl in resource.acls() {
                if access_token.is_member(acl.account_id) {
                    found.union(&acl.grants);
                }
            }
            if !found.is_empty() {
                direct.insert(resource.document_id(), found);
            }
        }
        if direct.is_empty() {
            return FileNodeAccess::default();
        }

        let grants = if self.paths.len() == self.resources.len() {
            self.inherit_from_paths(&direct)
        } else {
            self.inherit_from_parents(&direct)
        };

        let readable = grants
            .iter()
            .filter(|(_, found)| is_readable(found))
            .map(|(document_id, _)| *document_id)
            .collect::<RoaringBitmap>();
        let mut discoverable = readable.clone();
        for &document_id in direct.keys() {
            discoverable.insert(document_id);
            let mut current = self
                .resources
                .find_any(document_id)
                .and_then(|node| node.parent_id());
            for _ in 0..MAX_ANCESTOR_WALK {
                let Some(parent_id) = current else {
                    break;
                };
                if !discoverable.insert(parent_id) {
                    break;
                }
                current = self
                    .resources
                    .find_any(parent_id)
                    .and_then(|node| node.parent_id());
            }
        }
        FileNodeAccess {
            readable,
            discoverable,
            grants,
        }
    }

    fn inherit_from_paths(&self, direct: &DirectGrants) -> DirectGrants {
        let mut grants = DirectGrants::with_capacity(direct.len());
        let mut members = RoaringBitmap::new();
        for (root, acl) in direct.iter().filter_map(|(document_id, acl)| {
            self.any_resource_path_by_id(*document_id)
                .map(|root| (root, acl))
        }) {
            members.clear();
            members.insert(root.document_id());
            grants.entry(root.document_id()).or_default().union(acl);
            for (_, path) in self.paths.range(format!("{}/", root.path())) {
                if members.contains(path.parent_id) {
                    members.insert(path.document_id);
                    grants.entry(path.document_id).or_default().union(acl);
                }
            }
        }
        grants
    }

    fn inherit_from_parents(&self, direct: &DirectGrants) -> DirectGrants {
        let mut grants = DirectGrants::new();
        let mut unshared = RoaringBitmap::new();
        let mut chain = Vec::with_capacity(16);
        for resource in self.resources.iter() {
            let mut current = Some(resource.document_id());
            let mut found = Bitmap::new();
            chain.clear();
            while let Some(document_id) = current {
                if let Some(inherited) = grants.get(&document_id) {
                    found = *inherited;
                    break;
                } else if unshared.contains(document_id) || chain.len() >= MAX_ANCESTOR_WALK {
                    break;
                }
                chain.push(document_id);
                current = self
                    .resources
                    .find_any(document_id)
                    .and_then(|node| node.parent_id());
            }
            for document_id in chain.drain(..).rev() {
                if let Some(acl) = direct.get(&document_id) {
                    found.union(acl);
                }
                if found.is_empty() {
                    unshared.insert(document_id);
                } else {
                    grants.insert(document_id, found);
                }
            }
        }
        grants
    }
}

type DirectGrants = AHashMap<u32, Bitmap<Acl>>;

fn is_readable(acl: &Bitmap<Acl>) -> bool {
    acl.contains(Acl::Read) || acl.contains(Acl::ReadItems)
}

