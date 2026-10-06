/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The retention settings, read from `x:DataRetention` each time they're
//! needed, so a change takes effect at once, with no settings reload (UD-6a).

use registry::schema::structs::DataRetention;
use store::RegistryStore;
use types::id::Id;

/// How long deleted things are kept, in seconds. `None` keeps nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Retention {
    /// `archiveDeletedItemsFor` (UD-1).
    pub items: Option<u64>,
    /// `archiveDeletedAccountsFor` (UD-15).
    pub accounts: Option<u64>,
}

/// The retention in force now.
pub async fn retention(registry: &RegistryStore) -> trc::Result<Retention> {
    let settings = registry
        .object::<DataRetention>(Id::singleton())
        .await?
        .unwrap_or_default();
    Ok(Retention {
        items: settings
            .archive_deleted_items_for
            .map(|d| d.as_secs())
            .filter(|secs| *secs > 0),
        accounts: settings
            .archive_deleted_accounts_for
            .map(|d| d.as_secs())
            .filter(|secs| *secs > 0),
    })
}
