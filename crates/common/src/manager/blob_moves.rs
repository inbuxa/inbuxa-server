/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: blob-store-change spec (docs/spec/features/blob-store-change.md),
//! at start-up: records where the blob store is and, when it moved, the
//! change (BM-2), then opens the old store of every unresolved change so
//! what the new store lacks is read from it (BM-3), and the store of a
//! planned change so deletes follow to it (blob-store-copy-ahead spec,
//! CA-4). It also notes where this node's blob store is, for a cleanup of
//! an old store to check (blob-store-cleanup spec, OC-2).

use inbuxa_features::blob_move::{self as model, Started};
use registry::schema::{prelude::ObjectType, structs};
use store::{
    BlobStore, Store,
    build::blob::blob_store_location,
    registry::bootstrap::Bootstrap,
    write::{
        blob_move::{OldBlobStore, PlannedBlobStore},
        now,
    },
};
use types::id::Id;

/// The blob store to use: `blob`, reading through to the old stores of
/// unresolved changes, and with deletes following to a planned store. It's
/// wrapped even when there are none, so a change planned later takes effect
/// without a restart (CA-3).
pub async fn at_start(bp: &mut Bootstrap, blob: BlobStore) -> BlobStore {
    let data = bp.data_store.clone();
    if matches!(data, Store::None) || matches!(blob, BlobStore::Store(Store::None)) {
        return blob;
    }
    let settings = bp.setting_infallible::<structs::BlobStore>().await;
    let location = blob_store_location(&settings);
    let warn = |bp: &mut Bootstrap, message: String| {
        bp.build_warning(ObjectType::BlobStore.singleton(), message);
    };

    let mut recorded = None;
    match model::at_start(
        &data,
        location.clone(),
        &settings,
        bp.node_id() as u64,
        now(),
    )
    .await
    {
        Ok(Started::Same) => {}
        Ok(Started::Changed(id)) => {
            recorded = Some(id);
            if let Ok(Some(change)) = model::get(&data, id).await {
                warn(
                    bp,
                    format!(
                        "The blob store moved from {} to {}. Blobs written before stay in {}; \
                         they're read from it and kept in the new store as they're needed. \
                         Copy the rest over with inbuxa:BlobStoreChange {}.",
                        change.from,
                        change.to,
                        change.from,
                        Id::from(id)
                    ),
                );
            }
        }
        Err(err) => {
            warn(
                bp,
                format!("Couldn't record where the blob store is: {err}"),
            );
            return located(blob.wrapped(Vec::new()), &location);
        }
    }

    let unresolved = match model::unresolved(&data).await {
        Ok(changes) => changes,
        Err(err) => {
            warn(bp, format!("Couldn't read the blob store changes: {err}"));
            return located(blob.wrapped(Vec::new()), &location);
        }
    };
    let mut old = Vec::with_capacity(unresolved.len());
    for change in unresolved {
        // BM-4 resolves a change whose old store is this one; one recorded
        // before that rule could still say so
        if change.from == location {
            continue;
        }
        let Some(settings) = change.old_settings.clone() else {
            continue;
        };
        let mut warnings = Vec::new();
        match BlobStore::open(settings, &data, &mut warnings).await {
            Ok(store) => {
                old.push(OldBlobStore {
                    change_id: change.id,
                    store,
                });
                if recorded == Some(change.id) {
                    continue;
                }
                warn(
                    bp,
                    format!(
                        "The blob store changed from {} to {}, and blobs only {} has are \
                         read from it. Copy them over or dismiss the change \
                         (inbuxa:BlobStoreChange {}).",
                        change.from,
                        change.to,
                        change.from,
                        Id::from(change.id)
                    ),
                );
            }
            Err(err) => warn(
                bp,
                format!(
                    "The blob store used before the change to {} ({}) couldn't be opened, \
                     so blobs only it has can't be read: {err}",
                    change.to, change.from
                ),
            ),
        }
        for warning in warnings {
            warn(bp, warning);
        }
    }

    let wrapped = located(blob.wrapped(old), &location);
    if let Err(err) = model::note_node(&data, bp.node_id() as u64, &location, now()).await {
        warn(
            bp,
            format!("Couldn't note where this node's blob store is: {err}"),
        );
    }
    match model::planned(&data).await {
        Ok(Some(plan)) => {
            let mut warnings = Vec::new();
            let settings = plan.target_settings.clone().unwrap_or_default();
            match BlobStore::open(settings, &data, &mut warnings).await {
                Ok(store) => {
                    if let Some(moving) = wrapped.moving() {
                        moving.set_planned(Some(PlannedBlobStore {
                            change_id: plan.id,
                            store,
                        }));
                    }
                }
                Err(err) => warn(
                    bp,
                    format!(
                        "The blob store planned for {} couldn't be opened, so deletes don't \
                         follow to it until it can (inbuxa:BlobStoreChange {}): {err}",
                        plan.to,
                        Id::from(plan.id)
                    ),
                ),
            }
            for warning in warnings {
                warn(bp, warning);
            }
        }
        Ok(None) => {}
        Err(err) => warn(bp, format!("Couldn't read the planned blob store: {err}")),
    }
    wrapped
}

/// OC-2: the blob store, knowing where it is.
fn located(store: BlobStore, location: &str) -> BlobStore {
    if let Some(moving) = store.moving() {
        moving.set_location(location.to_string());
    }
    store
}
