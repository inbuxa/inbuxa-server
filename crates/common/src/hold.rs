/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: which legal holds cover an account (audit-hold-lock spec, LH-2,
//! LH-11), for the paths that destroy data. Read from the store every time,
//! not cached: a hold placed on one node must bind every node at once, and
//! there are few holds.

use crate::Server;
use ahash::AHashMap;
use inbuxa_features::{
    hold::{self, HELD_UNTIL, Hold, Keeping, Member, is_held_until},
    undelete::records,
};
use registry::schema::{prelude::ObjectType, structs::ArchivedItem};
use store::{registry::RegistryQuery, write::now};
use trc::AddContext;
use types::id::Id;

/// The grace a released item gets at least (LH-10): a release made in error
/// can be undone by placing a new hold within it.
const RELEASE_GRACE: u64 = 30 * 86_400;

/// What a settle pass changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Settled {
    pub frozen: usize,
    pub released: usize,
}

impl Server {
    /// The active holds covering `account_id`, through its own name, its
    /// addresses' domains, its groups or its tenant. Empty for an account
    /// that no longer exists: a deleted one is kept by LH-8's own check.
    pub async fn holds_on(&self, account_id: u32) -> trc::Result<Vec<Hold>> {
        let Ok(account) = self.account(account_id).await else {
            return Ok(Vec::new());
        };
        let mut domains = account
            .addresses
            .iter()
            .map(|address| address.domain_id)
            .collect::<Vec<_>>();
        domains.sort_unstable();
        domains.dedup();
        let member = Member {
            account: account_id,
            domains,
            groups: account.id_member_of.iter().copied().collect(),
            tenant: account.id_tenant,
        };
        hold::covering(self.store(), &member).await
    }

    /// How `account_id`'s deleted items are kept: its holds' ranges and the
    /// undelete period in force now (LH-4, UD-6a).
    pub async fn keeping(&self, account_id: u32) -> trc::Result<Keeping> {
        let retention = inbuxa_features::undelete::settings::retention(self.registry())
            .await?
            .items;
        Ok(Keeping::new(retention, &self.holds_on(account_id).await?))
    }

    /// LH-6, LH-10, LH-11: brings the whole archive in line with the active
    /// holds. An archived item a hold covers is frozen (no deadline), its
    /// old deadline noted; a frozen one no hold covers any more gets that
    /// deadline back, or release plus 30 days if later. Run after every
    /// change to a hold; it changes nothing twice.
    pub async fn settle_archive(&self) -> trc::Result<Settled> {
        let data = self.store();
        let registry = self.registry();
        let any_active = !hold::active(data).await?.is_empty();
        let now = now();
        let mut keeping: AHashMap<u32, Option<Keeping>> = AHashMap::new();
        let mut settled = Settled::default();
        for id in records::all(data, registry).await? {
            let Some(item) = registry.object::<ArchivedItem>(id).await? else {
                continue;
            };
            let account_id = item.account_id().document_id();
            if !keeping.contains_key(&account_id) {
                // An account that's gone can't be placed in a domain or
                // tenant any more: None, and its items are left as they are
                let known = self.account(account_id).await.is_ok();
                let value = if known { Some(self.keeping(account_id).await?) } else { None };
                keeping.insert(account_id, value);
            }
            let until = item.archived_until().timestamp().max(0) as u64;
            let held = is_held_until(until);
            let covered = match keeping.get(&account_id).and_then(Option::as_ref) {
                Some(keeping) => match &item {
                    ArchivedItem::Email(email) => {
                        keeping.covers(Some(email.received_at.timestamp().max(0) as u64))
                    }
                    ArchivedItem::CalendarEvent(event) => keeping
                        .covers_event(event.start_time.map(|t| t.timestamp().max(0) as u64)),
                    _ => keeping.covers(None),
                },
                // Gone: release only once no hold is active anywhere
                None => held && any_active,
            };
            if covered && !held {
                hold::set_original_deadline(data, id.id(), Some(until)).await?;
                records::set_deadline(data, registry, id, &item, HELD_UNTIL).await?;
                settled.frozen += 1;
            } else if !covered && held {
                let original = hold::original_deadline(data, id.id()).await?.unwrap_or(0);
                records::set_deadline(data, registry, id, &item, original.max(now + RELEASE_GRACE))
                    .await?;
                hold::set_original_deadline(data, id.id(), None).await?;
                settled.released += 1;
            }
        }
        Ok(settled)
    }

    /// Every account an active hold covers now. Empty, without looking at
    /// accounts, when nothing is held.
    pub async fn held_accounts(&self) -> trc::Result<ahash::AHashSet<u32>> {
        let mut held = ahash::AHashSet::new();
        if hold::active(self.store()).await?.is_empty() {
            return Ok(held);
        }
        for id in self
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Account))
            .await
            .caused_by(trc::location!())?
        {
            let account_id = id.document_id();
            if self.is_held(account_id).await? {
                held.insert(account_id);
            }
        }
        Ok(held)
    }

    /// Whether any active hold covers `account_id` at all.
    pub async fn is_held(&self, account_id: u32) -> trc::Result<bool> {
        Ok(!self.holds_on(account_id).await?.is_empty())
    }
}
