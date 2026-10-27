/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::task_manager::{
    outcome::{Failure, Outcome, RetryClass},
    tasks::grantee_cleanup::GranteeCleanupTask,
};
use common::{Server, cache::invalidate::CacheInvalidationBuilder, ipc::CacheInvalidation};
use email::{message::metadata::MetadataStructure, sieve::SieveScript};
use groupware::file::FileNode;
use registry::{
    schema::{
        enums::TaskAccountMaintenanceType,
        prelude::{ObjectType, Property},
        structs::{ArchivedItem, Task, TaskAccountMaintenance, TaskDestroyAccount, TaskStatus},
    },
    types::EnumImpl,
};
use store::{
    SerializeInfallible, ValueKey,
    registry::RegistryQuery,
    search::SearchQuery,
    write::{
        Archive, ArchiveBytes, BatchBuilder, BlobLink, BlobOp, RegistryClass, SearchIndex,
        ValueClass,
    },
};
use trc::AddContext;
use types::{
    blob_hash::BlobHash,
    collection::Collection,
    field::{EmailField, Field},
    id::Id,
};

const DESTROY_WINDOW: usize = 5_000;

pub(crate) trait DestroyAccountTask: Sync + Send {
    fn destroy_account(&self, task: &TaskDestroyAccount) -> impl Future<Output = Outcome> + Send;
}

impl DestroyAccountTask for Server {
    async fn destroy_account(&self, task: &TaskDestroyAccount) -> Outcome {
        match destroy_account(self, task).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let result = Outcome::error(&err);
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .details("Failed to destroy account")
                );
                result
            }
        }
    }
}

async fn destroy_account(server: &Server, task: &TaskDestroyAccount) -> trc::Result<Outcome> {
    let account_id = task.account_id.document_id();

    // inbuxa: LH-8, LH-10: a kept account waits for its time, and a held one
    // for its release; "destroy now" clears the kept record first
    if let Some(kept) =
        inbuxa_features::undelete::data::kept_account(&server.core.storage.data, account_id).await?
    {
        let now = store::write::now();
        let held = inbuxa_features::hold::is_held_until(kept.kept_until)
            || server.is_kept_held(account_id, &kept).await?;
        if held || kept.kept_until > now {
            let retry_at = if held { now + 86_400 } else { kept.kept_until };
            return Ok(Outcome::Retry(Failure::new(
                RetryClass::Throttled { retry_at },
                "The account is still kept: a legal hold applies, or its time hasn't come.",
            )));
        }
    }

    if server
        .store()
        .key_exists(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
            object_id: ObjectType::Account.to_id(),
            item_id: account_id as u64,
        })))
        .await
        .caused_by(trc::location!())?
    {
        return Ok(Outcome::Done(vec![Task::AccountMaintenance(
            TaskAccountMaintenance {
                account_id: task.account_id,
                maintenance_type: TaskAccountMaintenanceType::RebuildShares,
                status: TaskStatus::now(),
            },
        )]));
    }

    server
        .remove_grantee_references(account_id, task.member_group_ids.as_slice())
        .await
        .caused_by(trc::location!())?;

    // Destroy public keys, masked emails and OAuth grants
    // inbuxa: masked emails are ours (ME-18), whatever the features
    let objects = [
        ObjectType::PublicKey,
        ObjectType::MaskedEmail,
        ObjectType::OAuthGrant,
    ];
    for object in objects {
        let mut batch = BatchBuilder::new();
        let ids = server
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(object).with_account(account_id))
            .await?;
        let object_id = object.to_id();

        for id in ids {
            batch
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id: id.id(),
                }))
                .clear(ValueClass::Registry(RegistryClass::IndexId {
                    object_id,
                    item_id: id.id(),
                }))
                .clear(ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId as u16,
                    object_id,
                    item_id: id.id(),
                    key: (account_id as u64).serialize(),
                }))
                .clear(ValueClass::Registry(RegistryClass::Reference {
                    to_object_id: ObjectType::Account as u16,
                    to_item_id: account_id as u64,
                    from_object_id: object_id,
                    from_item_id: id.id(),
                }))
                .bulk_commit_point();
        }

        if !batch.is_empty() {
            server.store().write_batch(&mut batch).await?;
        }
    }

    // inbuxa: UD-15: the account's hold and undelete's own records go first
    inbuxa_features::undelete::accounts::forget(
        &server.core.storage.data,
        server.registry(),
        account_id,
    )
    .await?;

    // Remove archived items
    let mut batch = BatchBuilder::new();
    let ids = server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::ArchivedItem).with_account(account_id))
        .await?;
    for id in ids {
        let object_id = ObjectType::ArchivedItem.to_id();
        let item_id = id.id();

        if let Some(item) = server.registry().object::<ArchivedItem>(id).await? {
            let until = item.archived_until().timestamp() as u64;
            let blob_hash = item.into_blob_id().hash;

            batch
                .with_account_id(account_id)
                .clear(BlobOp::Link {
                    hash: blob_hash,
                    to: BlobLink::Temporary { until },
                })
                .clear(ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId.to_id(),
                    object_id,
                    item_id,
                    key: (account_id as u64).serialize(),
                }))
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id,
                }));
        }
    }
    if !batch.is_empty() {
        server.store().write_batch(&mut batch).await?;
    }

    // Remove search index
    for index in [
        SearchIndex::Email,
        SearchIndex::Contacts,
        SearchIndex::Calendar,
        SearchIndex::File,
    ] {
        if let Some(store) = server.search_store().internal_fts() {
            store.unindex_account(index, account_id).await?;
        } else {
            server
                .search_store()
                .unindex(SearchQuery::new(index).with_account_id(account_id))
                .await?;
        }

        server
            .store()
            .clear_search_index_queue(index, account_id)
            .await?;
    }

    // Unlink all accounts's blobs
    destroy_account_blobs(server, account_id).await?;

    server
        .destroy_viewer_metadata(account_id)
        .await
        .caused_by(trc::location!())?;
    server
        .destroy_owner_metadata(account_id)
        .await
        .caused_by(trc::location!())?;

    // Drop the resident caches and the writer's pending state on every node
    server
        .invalidate_caches(
            CacheInvalidationBuilder::from(CacheInvalidation::MessageCache(account_id))
                .with_invalidation(CacheInvalidation::GroupwareResources(account_id))
                .with_invalidation(CacheInvalidation::PrivateMetadata(account_id)),
        )
        .await?;
    server.inner.cache.swap.forget(account_id);

    // Remove persisted cache snapshots
    server.inner.cache.swap.remove_account(account_id).await;

    // Destroy account data
    server
        .store()
        .danger_destroy_account(account_id)
        .await
        .caused_by(trc::location!())?;

    Ok(Outcome::done())
}

pub async fn destroy_account_blobs(server: &Server, account_id: u32) -> trc::Result<()> {
    let window = server.store().is_postgresql().then_some(DESTROY_WINDOW);
    let mut links = Vec::new();
    let mut batch = BatchBuilder::new();
    batch.with_account_id(account_id);

    let class = ValueClass::Immutable(EmailField::Metadata.into());
    let mut next = Some(0);
    while let Some(from_document_id) = next {
        next = server
            .values_window(
                account_id,
                Collection::Email,
                &class,
                from_document_id,
                window,
                |document_id, structure: MetadataStructure| {
                    links.push((document_id, structure.unarchive()?.blob_hash()));
                    Ok(())
                },
            )
            .await
            .caused_by(trc::location!())?;
        clear_links(
            server,
            account_id,
            Collection::Email,
            &mut links,
            &mut batch,
        )
        .await?;
    }

    let class = ValueClass::Property(Field::ARCHIVE.into());
    for collection in [Collection::FileNode, Collection::SieveScript] {
        let mut next = Some(0);
        while let Some(from_document_id) = next {
            next = server
                .values_window(
                    account_id,
                    collection,
                    &class,
                    from_document_id,
                    window,
                    |document_id, archive: Archive<ArchiveBytes>| {
                        let blob_hash = match collection {
                            Collection::FileNode => archive
                                .unarchive::<FileNode>()?
                                .file()
                                .map(|file| BlobHash::from(&file.blob_hash)),
                            _ => Some(BlobHash::from(
                                &archive.unarchive::<SieveScript>()?.blob_hash,
                            )),
                        };
                        if let Some(blob_hash) = blob_hash {
                            links.push((document_id, blob_hash));
                        }
                        Ok(())
                    },
                )
                .await
                .caused_by(trc::location!())?;
            clear_links(server, account_id, collection, &mut links, &mut batch).await?;
        }
    }

    if !batch.is_empty() {
        server
            .store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
    }

    Ok(())
}

async fn clear_links(
    server: &Server,
    account_id: u32,
    collection: Collection,
    links: &mut Vec<(u32, BlobHash)>,
    batch: &mut BatchBuilder,
) -> trc::Result<()> {
    for (document_id, hash) in links.drain(..) {
        if batch.is_large_bulk_batch() {
            server
                .store()
                .write_batch(batch)
                .await
                .caused_by(trc::location!())?;
            *batch = BatchBuilder::new();
            batch.with_account_id(account_id);
        }
        batch
            .with_collection(collection)
            .with_document(document_id)
            .clear(ValueClass::Blob(BlobOp::Link {
                hash,
                to: BlobLink::Document,
            }));
    }
    Ok(())
}
