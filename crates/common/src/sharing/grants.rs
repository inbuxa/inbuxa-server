/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::object::{JmapRight, calendar::CalendarRight};
use rkyv::vec::ArchivedVec;
use types::{
    acl::{Acl, AclGrant, ArchivedAclGrant},
    collection::Collection,
};
use utils::map::bitmap::Bitmap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareViolation {
    TooManyShares(usize),
    OwnerShared,
    RightNotHeld,
}

pub trait AclGrantLookup {
    fn grants_of(&self, account_id: u32) -> Bitmap<Acl>;
}

impl AclGrantLookup for [AclGrant] {
    fn grants_of(&self, account_id: u32) -> Bitmap<Acl> {
        self.iter()
            .find(|grant| grant.account_id == account_id)
            .map_or_else(Bitmap::new, |grant| grant.grants)
    }
}

impl AclGrantLookup for ArchivedVec<ArchivedAclGrant> {
    fn grants_of(&self, account_id: u32) -> Bitmap<Acl> {
        self.iter()
            .find(|grant| u32::from(grant.account_id) == account_id)
            .map_or_else(Bitmap::new, |grant| Bitmap::from(&grant.grants))
    }
}

pub struct ShareUpdate<'x, G: AclGrantLookup + ?Sized> {
    pub collection: Collection,
    pub owner_id: u32,
    pub actor: Option<Bitmap<Acl>>,
    pub current: &'x G,
    pub max_shares: usize,
}

impl<G: AclGrantLookup + ?Sized> ShareUpdate<'_, G> {
    pub fn validate(&self, grants: &[AclGrant]) -> Result<(), ShareViolation> {
        if grants.len() > self.max_shares {
            return Err(ShareViolation::TooManyShares(self.max_shares));
        }
        if grants.iter().any(|grant| grant.account_id == self.owner_id) {
            return Err(ShareViolation::OwnerShared);
        }
        if let Some(actor) = self.actor {
            let actor = actor.with_implied_rights(self.collection).into_inner();
            if grants.iter().any(|grant| {
                let current = self
                    .current
                    .grants_of(grant.account_id)
                    .with_implied_rights(self.collection)
                    .into_inner();
                grant.grants.into_inner() & !current & !actor != 0
            }) {
                return Err(ShareViolation::RightNotHeld);
            }
        }
        Ok(())
    }
}

pub trait ImpliedRights {
    fn with_implied_rights(self, collection: Collection) -> Self;
}

impl ImpliedRights for Bitmap<Acl> {
    fn with_implied_rights(mut self, collection: Collection) -> Self {
        if collection == Collection::Calendar {
            for right in CalendarRight::all_rights() {
                let implied_by = right.implied_by_acl();
                if !implied_by.is_empty() && implied_by.iter().all(|acl| self.contains(*acl)) {
                    self.insert_many(right.to_acl().iter().copied());
                }
            }
        }
        self
    }
}

