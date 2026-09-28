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
use inbuxa_features::hold::{self, Hold, Keeping, Member};

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

    /// Whether any active hold covers `account_id` at all.
    pub async fn is_held(&self, account_id: u32) -> trc::Result<bool> {
        Ok(!self.holds_on(account_id).await?.is_empty())
    }
}
