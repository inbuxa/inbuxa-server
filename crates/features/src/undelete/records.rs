/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `x:ArchivedItem` records, written as upstream writes them: the record and
//! its account index, with no link to the account, so deleting an account
//! isn't refused while it has archived items. Upstream's account removal
//! task clears exactly these two keys.

use crate::undelete::data::{self, Change};
use registry::schema::prelude::Property;
use registry::{
    schema::{prelude::ObjectType, structs::ArchivedItem},
    types::{EnumImpl, ObjectImpl, index::IndexValue},
};
use store::{
    RegistryStore, SerializeInfallible, Store,
    registry::RegistryQuery,
    write::{BatchBuilder, BlobLink, BlobOp, RegistryClass, ValueClass, now},
};
use trc::AddContext;
use types::id::Id;

fn account_index(account_id: u32, item_id: u64) -> ValueClass {
    ValueClass::Registry(RegistryClass::Index {
        index_id: Property::AccountId.to_id(),
        object_id: ObjectType::ArchivedItem.to_id(),
        item_id,
        key: IndexValue::U64(account_id as u64).serialize(),
    })
}

fn item_class(item_id: u64) -> ValueClass {
    ValueClass::Registry(RegistryClass::Item {
        object_id: ObjectType::ArchivedItem.to_id(),
        item_id,
    })
}

/// Writes a new archived item, holding its kept copy until `archivedUntil`,
/// with what restore needs beside it. Returns its id.
pub async fn insert(
    data: &Store,
    registry: &RegistryStore,
    item: &ArchivedItem,
    extra: &data::Extra,
) -> trc::Result<Id> {
    let item_id = registry.assign_id();
    let id = Id::new(item_id);
    let account_id = item.account_id().document_id();
    let blob_hash = item.blob_id().hash.clone();

    // The kept copy and the fork's records first, in the data store
    let mut batch = BatchBuilder::new();
    batch.with_account_id(account_id).set(
        BlobOp::Link {
            hash: blob_hash.clone(),
            to: BlobLink::Temporary {
                until: item.archived_until().timestamp() as u64,
            },
        },
        vec![],
    );
    data::set_extra(&mut batch, id, extra)?;
    data::set_blob_item(&mut batch, account_id, blob_hash.as_slice(), id);
    data::log_change(
        &mut batch,
        account_id,
        registry.assign_id(),
        id,
        Change::Created,
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    // Then the record, as upstream writes it
    let mut batch = BatchBuilder::new();
    batch
        .set(item_class(item_id), item.to_pickled_vec())
        .set(account_index(account_id, item_id), vec![]);
    registry
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(id)
}

/// Moves an archived item's deadline, and its kept copy's with it: frozen
/// by a hold (LH-6) or given a real one on release (LH-10). Returns the
/// item as it now is.
pub async fn set_deadline(
    data: &Store,
    registry: &RegistryStore,
    id: Id,
    item: &ArchivedItem,
    until: u64,
) -> trc::Result<ArchivedItem> {
    let account_id = item.account_id().document_id();
    let blob_hash = item.blob_id().hash.clone();
    let before = item.archived_until().timestamp() as u64;
    let mut updated = item.clone();
    updated.set_archived_until(registry::types::datetime::UTCDateTime::from_timestamp(until as i64));

    // The new link first, so the kept copy is never unlinked in between
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .set(
            BlobOp::Link {
                hash: blob_hash.clone(),
                to: BlobLink::Temporary { until },
            },
            vec![],
        );
    if before != until {
        batch.clear(BlobOp::Link {
            hash: blob_hash,
            to: BlobLink::Temporary { until: before },
        });
    }
    data::log_change(&mut batch, account_id, registry.assign_id(), id, Change::Updated);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    let mut batch = BatchBuilder::new();
    batch.set(item_class(id.id()), updated.to_pickled_vec());
    registry
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(updated)
}

/// Removes an archived item and releases its kept copy: on restore (UD-9),
/// on destroy (UD-12) and past its deadline (UD-13).
pub async fn remove(
    data: &Store,
    registry: &RegistryStore,
    id: Id,
    item: &ArchivedItem,
) -> trc::Result<()> {
    let account_id = item.account_id().document_id();
    let blob_hash = item.blob_id().hash.clone();

    let mut batch = BatchBuilder::new();
    batch
        .clear(item_class(id.id()))
        .clear(account_index(account_id, id.id()));
    registry
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    let mut batch = BatchBuilder::new();
    batch.with_account_id(account_id).clear(BlobOp::Link {
        hash: blob_hash.clone(),
        to: BlobLink::Temporary {
            until: item.archived_until().timestamp() as u64,
        },
    });
    data::clear_extra(&mut batch, id);
    data::clear_blob_item(&mut batch, account_id, blob_hash.as_slice());
    data::clear_restore_requested(&mut batch, id);
    data::log_change(
        &mut batch,
        account_id,
        registry.assign_id(),
        id,
        Change::Destroyed,
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// Whether an item is past its deadline: then it isn't restorable, even
/// before clean-up removes it (UD-13).
pub fn is_expired(item: &ArchivedItem) -> bool {
    item.archived_until().timestamp() <= now() as i64
}

/// An account's archived items that are still restorable. Expired ones found
/// on the way are removed (UD-13).
pub async fn of_account(
    data: &Store,
    registry: &RegistryStore,
    account_id: u32,
) -> trc::Result<Vec<(Id, ArchivedItem)>> {
    let mut items = Vec::new();
    for id in registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::ArchivedItem).with_account(account_id))
        .await
        .caused_by(trc::location!())?
    {
        if let Some(item) = registry.object::<ArchivedItem>(id).await? {
            if is_expired(&item) {
                remove(data, registry, id, &item).await?;
            } else {
                items.push((id, item));
            }
        }
    }
    Ok(items)
}

/// One archived item, if it exists, belongs to the account and is still
/// restorable.
pub async fn get(
    data: &Store,
    registry: &RegistryStore,
    account_id: u32,
    id: Id,
) -> trc::Result<Option<ArchivedItem>> {
    match registry.object::<ArchivedItem>(id).await? {
        Some(item) if item.account_id().document_id() == account_id => {
            if is_expired(&item) {
                remove(data, registry, id, &item).await?;
                Ok(None)
            } else {
                Ok(Some(item))
            }
        }
        _ => Ok(None),
    }
}

/// Every archived item on the server, account by account. Items are
/// indexed by account only, so the registry's query without a filter,
/// which reads its all-ids index, finds none of them.
pub async fn all(data: &Store, registry: &RegistryStore) -> trc::Result<Vec<Id>> {
    let mut accounts = registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Account))
        .await
        .caused_by(trc::location!())?
        .into_iter()
        .map(|id| id.document_id())
        .collect::<Vec<_>>();
    // Deleted accounts still kept have archived items too
    accounts.extend(data::kept_accounts(data).await?.into_iter().map(|(id, _)| id));
    accounts.sort_unstable();
    accounts.dedup();
    let mut items = Vec::new();
    for account_id in accounts {
        items.extend(
            registry
                .query::<Vec<Id>>(RegistryQuery::new(ObjectType::ArchivedItem).with_account(account_id))
                .await
                .caused_by(trc::location!())?,
        );
    }
    Ok(items)
}

/// Removes every expired archived item on the server (UD-13), for the
/// scheduled clean-up.
pub async fn remove_expired(data: &Store, registry: &RegistryStore) -> trc::Result<usize> {
    let mut removed = 0;
    for id in all(data, registry).await? {
        if let Some(item) = registry.object::<ArchivedItem>(id).await?
            && is_expired(&item)
        {
            remove(data, registry, id, &item).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// The archived item a restore task is for, found by its kept copy, with
/// what restore needs beside it. Items archived before the fork have no
/// pointer and no extra data: they're found by scanning the account's items.
/// `None` once it's already been restored (UD-11).
pub async fn for_restore(
    data: &Store,
    registry: &RegistryStore,
    account_id: u32,
    blob_hash: &[u8],
) -> trc::Result<Option<(Id, ArchivedItem, Option<crate::undelete::data::Extra>)>> {
    let id = match data::blob_item(data, account_id, blob_hash).await? {
        Some(id) => Some(id),
        None => of_account(data, registry, account_id)
            .await?
            .into_iter()
            .find(|(_, item)| item.blob_id().hash.as_slice() == blob_hash)
            .map(|(id, _)| id),
    };
    let Some(id) = id else {
        return Ok(None);
    };
    let Some(item) = get(data, registry, account_id, id).await? else {
        return Ok(None);
    };
    let extra = data::extra(data, id).await?;
    Ok(Some((id, item, extra)))
}
