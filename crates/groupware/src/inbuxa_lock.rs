/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: a locked account's grants on its calendars, address books, file
//! folders and top-level files (audit-hold-lock spec, AL-7, AL-10). The
//! mailbox half, and the whole, are in `email::inbuxa_lock`; this half is
//! here so DAV, which sees only these, can grant on what it creates.

use crate::{cache::GroupwareCache, calendar::Calendar, contact::AddressBook, file::FileNode};
use common::{
    DavResourceMetadata, Server,
    auth::AccountTenantIds,
    cache::invalidate::CacheInvalidationBuilder,
    ipc::CacheInvalidation,
};
use inbuxa_features::lock::{self, Lock, Replaced};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive, BatchBuilder, now},
};
use trc::AddContext;
use types::collection::{Collection, SyncCollection};

/// The collections this half covers.
pub const DAV_COLLECTIONS: [Collection; 3] = [
    Collection::Calendar,
    Collection::AddressBook,
    Collection::FileNode,
];

/// Who a lock's grant changes are recorded as having been made by: the
/// locked account itself, as the server acting for it.
pub async fn changed_by(server: &Server, account_id: u32) -> AccountTenantIds {
    AccountTenantIds {
        account_id,
        tenant_id: server.account(account_id).await.ok().and_then(|a| a.id_tenant),
    }
}

/// Grants on calendars, address books, file folders and top-level files,
/// into `batch`, with what they replaced into `replaced`.
#[allow(clippy::too_many_arguments)]
pub async fn apply_dav_grants(
    server: &Server,
    account_id: u32,
    old: Option<&Lock>,
    new: Option<&Lock>,
    now: u64,
    replaced: &mut Vec<Replaced>,
    batch: &mut BatchBuilder,
) -> trc::Result<()> {
    let changed_by = changed_by(server, account_id).await;
    for (sync, collection) in [
        (SyncCollection::Calendar, Collection::Calendar),
        (SyncCollection::AddressBook, Collection::AddressBook),
        (SyncCollection::FileNode, Collection::FileNode),
    ] {
        let resources = server
            .fetch_dav_resources(account_id, account_id, sync)
            .await
            .caused_by(trc::location!())?;
        for resource in &resources.resources {
            // A folder covers what's in it; a file outside any folder
            // needs its own grant
            let top_level_file = matches!(
                &resource.data,
                DavResourceMetadata::File {
                    parent_id: None,
                    ..
                }
            );
            if !resource.is_container() && !top_level_file {
                continue;
            }
            let Some(current) = resource.acls() else {
                continue;
            };
            let Some(acls) = lock::merge_grants(
                current,
                collection,
                resource.document_id,
                false,
                old,
                new,
                now,
                replaced,
            ) else {
                continue;
            };
            let Some(archive) = server
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    collection,
                    resource.document_id,
                ))
                .await
                .caused_by(trc::location!())?
            else {
                continue;
            };
            match collection {
                Collection::Calendar => {
                    let current = archive
                        .to_unarchived::<Calendar>()
                        .caused_by(trc::location!())?;
                    let mut changed = current
                        .deserialize::<Calendar>()
                        .caused_by(trc::location!())?;
                    changed.acls = acls;
                    changed
                        .update(changed_by, current, account_id, resource.document_id, batch)
                        .caused_by(trc::location!())?;
                }
                Collection::AddressBook => {
                    let current = archive
                        .to_unarchived::<AddressBook>()
                        .caused_by(trc::location!())?;
                    let mut changed = current
                        .deserialize::<AddressBook>()
                        .caused_by(trc::location!())?;
                    changed.acls = acls;
                    changed
                        .update(changed_by, current, account_id, resource.document_id, batch)
                        .caused_by(trc::location!())?;
                }
                _ => {
                    let current = archive
                        .to_unarchived::<FileNode>()
                        .caused_by(trc::location!())?;
                    let mut changed = current
                        .deserialize::<FileNode>()
                        .caused_by(trc::location!())?;
                    changed.acls = acls;
                    changed
                        .update(
                            changed_by,
                            current,
                            account_id,
                            resource.document_id,
                            false,
                            batch,
                        )
                        .caused_by(trc::location!())?;
                }
            }
        }
    }
    Ok(())
}

/// Every token a lock change touches is rebuilt on its next use, on every
/// node: the locked account's and each delegate's, before and after.
pub async fn invalidate(
    server: &Server,
    account_id: u32,
    old: Option<&Lock>,
    new: Option<&Lock>,
) -> trc::Result<()> {
    let mut builder = CacheInvalidationBuilder::default();
    builder.invalidate(CacheInvalidation::AccessToken(account_id));
    for delegate in old.into_iter().chain(new).flat_map(|l| &l.delegates) {
        builder.invalidate(CacheInvalidation::AccessToken(delegate.account_id));
    }
    server.invalidate_caches(builder).await
}

/// Whether two lists of replaced rights say the same, in any order.
pub fn same_replaced(a: &[Replaced], b: &[Replaced]) -> bool {
    let key = |r: &Replaced| (r.collection, r.document_id, r.delegate, r.rights);
    let mut a = a.iter().map(key).collect::<Vec<_>>();
    let mut b = b.iter().map(key).collect::<Vec<_>>();
    a.sort();
    b.sort();
    a == b
}

/// Grants the lock on `account_id`, if any, on calendars, address books and
/// files made since. For DAV, after a delegate creates one there.
pub async fn reconcile_dav(server: &Server, account_id: u32) -> trc::Result<()> {
    let data = server.store();
    let Some(current) = lock::get(data, account_id).await? else {
        return Ok(());
    };
    // Mailbox entries aren't this half's to change
    let mut replaced = current
        .replaced
        .iter()
        .filter(|r| !DAV_COLLECTIONS.iter().any(|c| *c as u8 == r.collection))
        .cloned()
        .collect::<Vec<_>>();
    let mut batch = BatchBuilder::new();
    apply_dav_grants(
        server,
        account_id,
        Some(&current),
        Some(&current),
        now(),
        &mut replaced,
        &mut batch,
    )
    .await?;
    if batch.is_empty() {
        return Ok(());
    }
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;
    if !same_replaced(&replaced, &current.replaced) {
        let updated = Lock {
            replaced,
            ..current.clone()
        };
        lock::set(data, &updated, Some(&current)).await?;
    }
    invalidate(server, account_id, Some(&current), Some(&current)).await
}
