/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::cache::{MessageCacheFetch, email::MessageCacheAccess};
use crate::message::messagedata::EmailMessageData;
use crate::sieve::SeenIdHash;
use crate::submission::{DeliveryResults, EmailSubmission};
use common::{MessageStoreCache, Server, auth::ChangedBy, storage::index::ObjectIndexBuilder};
use groupware::calendar::storage::ItipAutoExpunge;
use std::{future::Future, time::Duration};
use store::write::key::DeserializeBigEndian;
use store::write::{Archive, ArchiveBytes, IndexPropertyClass, SearchIndex, now};
use store::{Deserialize, IterateParams, U32_LEN, U64_LEN, ValueKey};
use store::{
    roaring::RoaringBitmap,
    write::{BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::collection::{Collection, SyncCollection, VanishedCollection};
use types::field::{EmailField, EmailSubmissionField};
use utils::snowflake::SnowflakeIdGenerator;

pub trait EmailDeletion: Sync + Send {
    fn emails_delete(
        &self,
        account_id: u32,
        changed_by: ChangedBy,
        batch: &mut BatchBuilder,
        document_ids: RoaringBitmap,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;

    fn purge_account(&self, account_id: u32) -> impl Future<Output = trc::Result<()>> + Send;

    fn purge_email_submissions(
        &self,
        account_id: u32,
        hold_period: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn emails_auto_expunge(
        &self,
        account_id: u32,
        hold_period: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn purge_sieve_seen_ids(
        &self,
        account_id: u32,
        cutoff: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn log_emptied_threads(
        &self,
        account_id: u32,
        batch: &mut BatchBuilder,
        thread_ids: RoaringBitmap,
        deleted_ids: &RoaringBitmap,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl EmailDeletion for Server {
    async fn emails_delete(
        &self,
        account_id: u32,
        changed_by: ChangedBy,
        batch: &mut BatchBuilder,
        document_ids: RoaringBitmap,
    ) -> trc::Result<RoaringBitmap> {
        let cache = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        let flagged_ids = document_ids
            .iter()
            .filter(|document_id| {
                cache
                    .email_by_id(document_id)
                    .is_some_and(|message| !cache.metadata_kinds(message).is_empty())
            })
            .collect::<RoaringBitmap>();
        let containers = self
            .preload_container_cleanup(changed_by, account_id, Collection::Email, &flagged_ids)
            .await
            .caused_by(trc::location!())?;
        let mut deleted_ids = RoaringBitmap::new();
        let mut thread_ids = RoaringBitmap::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email);
        self.message_datas(account_id, &document_ids, |document_id, metadata| {
            // Add changes to batch
            for mailbox in metadata.mailboxes.iter() {
                batch.log_vanished_item(
                    VanishedCollection::Email,
                    (mailbox.mailbox_id, mailbox.uid),
                );
            }
            thread_ids.insert(metadata.thread_id);
            if !metadata.metadata_kinds().is_empty() {
                containers.release_or_assert_absent(batch, account_id, document_id);
            }
            let index_builder = ObjectIndexBuilder::<_, ()>::new();
            batch
                .with_document(document_id)
                .custom(index_builder.with_current(metadata))
                .caused_by(trc::location!())?
                .queue_document_unindex(SearchIndex::Email, account_id, document_id)
                .commit_point();

            deleted_ids.insert(document_id);

            Ok(true)
        })
        .await?;

        log_threads_emptied(&cache, batch, account_id, &thread_ids, &deleted_ids);

        let not_destroyed = if document_ids.len() == deleted_ids.len() {
            RoaringBitmap::new()
        } else {
            deleted_ids ^= document_ids;
            deleted_ids
        };

        Ok(not_destroyed)
    }

    async fn log_emptied_threads(
        &self,
        account_id: u32,
        batch: &mut BatchBuilder,
        thread_ids: RoaringBitmap,
        deleted_ids: &RoaringBitmap,
    ) -> trc::Result<()> {
        if !thread_ids.is_empty() {
            let cache = self
                .get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?;
            log_threads_emptied(&cache, batch, account_id, &thread_ids, deleted_ids);
        }

        Ok(())
    }

    async fn purge_account(&self, account_id: u32) -> trc::Result<()> {
        // Auto-expunge deleted and junk messages
        if let Some(hold_period) = self.core.email.mail_autoexpunge_after {
            self.emails_auto_expunge(account_id, hold_period)
                .await
                .caused_by(trc::location!())?;
        }

        // Auto-expunge iMIP messages
        if let Some(hold_period) = self.core.groupware.itip_inbox_auto_expunge {
            self.itip_auto_expunge(account_id, hold_period)
                .await
                .caused_by(trc::location!())?;
        }

        // Delete old e-mail submissions
        if let Some(hold_period) = self.core.email.email_submission_autoexpunge_after {
            self.purge_email_submissions(account_id, hold_period)
                .await
                .caused_by(trc::location!())?;
        }

        // Purge changelogs
        self.delete_changes(
            account_id,
            self.core.email.changes_max_history,
            self.core.email.share_notification_max_history,
        )
        .await
        .caused_by(trc::location!())?;

        self.purge_private_metadata(account_id, self.core.email.changes_max_history)
            .await
            .caused_by(trc::location!())?;

        // Purge expired Sieve duplicate and vacation ids
        self.purge_sieve_seen_ids(account_id, now())
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    async fn purge_sieve_seen_ids(&self, account_id: u32, cutoff: u64) -> trc::Result<()> {
        let (from, to) = SeenIdHash::account_range(account_id);
        let mut expired = Vec::new();
        self.store()
            .iterate(IterateParams::new(from, to).ascending(), |key, value| {
                if u64::deserialize(value)? <= cutoff {
                    expired.push(SeenIdHash::from_key(key).ok_or_else(|| {
                        trc::Error::corrupted_key(key, value.into(), trc::location!())
                    })?);
                }
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;

        let mut expired = expired.into_iter().peekable();
        while expired.peek().is_some() {
            let mut batch = BatchBuilder::new();
            SeenIdHash::with_context(account_id, &mut batch);
            for hash in expired.by_ref() {
                batch.clear(hash.class());
                if batch.is_large_batch() {
                    break;
                }
            }
            self.store()
                .write_batch(&mut batch)
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }

    async fn emails_auto_expunge(&self, account_id: u32, hold_period: u64) -> trc::Result<()> {
        // Filter messages by received date
        let mut destroy_ids = RoaringBitmap::new();
        let cutoff = now().saturating_sub(hold_period);
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: 0,
                        class: ValueClass::Property(EmailField::DeletedAt.into()),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: u32::MAX,
                        class: ValueClass::Property(EmailField::DeletedAt.into()),
                    },
                )
                .ascending(),
                |key, value| {
                    let deleted_at = value.deserialize_be_u64(0)?;
                    if deleted_at <= cutoff {
                        destroy_ids.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if destroy_ids.is_empty() {
            return Ok(());
        }

        trc::event!(
            Store(trc::StoreEvent::AutoExpunge),
            Collection = Collection::Email.as_str(),
            AccountId = account_id,
            Total = destroy_ids.len(),
        );

        // Delete messages
        let mut batch = BatchBuilder::new();
        let changed_by = ChangedBy {
            account_id,
        };
        self.emails_delete(account_id, changed_by, &mut batch, destroy_ids)
            .await?;
        self.commit_batch(batch).await?;

        Ok(())
    }

    async fn purge_email_submissions(&self, account_id: u32, hold_period: u64) -> trc::Result<()> {
        let expire_until = now().saturating_sub(hold_period);
        let mut destroy_ids = Vec::new();
        let mut live_queue_ids = Vec::new();
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::EmailSubmission.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: EmailSubmissionField::Metadata.into(),
                            value: 0,
                        }),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::EmailSubmission.into(),
                        document_id: u32::MAX,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: EmailSubmissionField::Metadata.into(),
                            value: u64::MAX,
                        }),
                    },
                )
                .ascending(),
                |key, value| {
                    let send_at = key.deserialize_be_u64(key.len() - U32_LEN - U64_LEN)?;
                    if send_at <= expire_until {
                        destroy_ids.push((key.deserialize_be_u32(key.len() - U32_LEN)?, send_at));
                    } else {
                        live_queue_ids.push(value.deserialize_be_u64(METADATA_QUEUE_ID_OFFSET)?);
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let mut orphan_queue_ids = Vec::new();
        if let Some(max_queue_id) =
            SnowflakeIdGenerator::from_duration(Duration::from_secs(ORPHAN_RESULT_GRACE))
        {
            live_queue_ids.sort_unstable();
            let (from_key, to_key) = DeliveryResults::range(account_id, max_queue_id);
            self.store()
                .iterate(
                    IterateParams::new(from_key, to_key).ascending().no_values(),
                    |key, _| {
                        let queue_id = key.deserialize_be_u64(key.len() - U32_LEN - U64_LEN)?;
                        if live_queue_ids.binary_search(&queue_id).is_err() {
                            orphan_queue_ids.push(queue_id);
                        }

                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
        }

        if destroy_ids.is_empty() && orphan_queue_ids.is_empty() {
            return Ok(());
        }

        trc::event!(
            Store(trc::StoreEvent::AutoExpunge),
            Collection = Collection::EmailSubmission.as_str(),
            AccountId = account_id,
            Total = destroy_ids.len(),
        );

        let mut batch = BatchBuilder::new();
        for queue_id in orphan_queue_ids {
            DeliveryResults::clear(&mut batch, account_id, queue_id);
            batch.commit_point();
        }

        for (document_id, send_at) in destroy_ids {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::EmailSubmission)
                .with_document(document_id);

            if let Some(submission) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::EmailSubmission,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            {
                let submission = submission
                    .to_unarchived::<EmailSubmission>()
                    .caused_by(trc::location!())?;
                let queue_id = submission.inner.queue_id.as_ref().map(u64::from);
                batch
                    .custom(ObjectIndexBuilder::<_, ()>::new().with_current(submission))
                    .caused_by(trc::location!())?;
                if let Some(queue_id) = queue_id {
                    DeliveryResults::clear(&mut batch, account_id, queue_id);
                }
            } else {
                batch.clear(ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: EmailSubmissionField::Metadata.into(),
                    value: send_at,
                }));
            }

            batch.commit_point();
        }

        self.commit_batch(batch).await?;

        Ok(())
    }
}

const METADATA_QUEUE_ID_OFFSET: usize = U32_LEN * 3;
const ORPHAN_RESULT_GRACE: u64 = 86400;
const EMPTIED_THREADS_PER_COMMIT: usize = 10_000;

fn log_threads_emptied(
    cache: &MessageStoreCache,
    batch: &mut BatchBuilder,
    account_id: u32,
    thread_ids: &RoaringBitmap,
    deleted_ids: &RoaringBitmap,
) {
    let emptied = cache.emails.emptied_threads(thread_ids, deleted_ids);
    for (pos, chunk) in emptied.chunks(EMPTIED_THREADS_PER_COMMIT).enumerate() {
        if pos > 0 {
            batch.add_commit_point();
        }
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Thread);
        for &thread_id in chunk {
            batch
                .with_document(thread_id)
                .log_container_delete(SyncCollection::Thread);
        }
    }
}
