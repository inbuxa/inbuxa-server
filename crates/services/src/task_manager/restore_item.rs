/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::BuildAccessToken};
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::{INBOX_ID, TRASH_ID},
    message::ingest::{EmailIngest, IngestEmail, IngestSource},
};
use inbuxa_features::undelete;
use types::keyword::Keyword;
use mail_parser::MessageParser;
use registry::schema::{enums::ArchivedItemType, structs::TaskRestoreArchivedItem};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::task_manager::TaskResult;

pub(crate) trait RestoreItemTask: Sync + Send {
    fn restore_item(
        &self,
        task: &TaskRestoreArchivedItem,
    ) -> impl Future<Output = TaskResult> + Send;
}

impl RestoreItemTask for Server {
    async fn restore_item(&self, task: &TaskRestoreArchivedItem) -> TaskResult {
        match restore_item(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .details("Failed to restore item")
                );
                result
            }
        }
    }
}

async fn restore_item(server: &Server, task: &TaskRestoreArchivedItem) -> trc::Result<TaskResult> {
    match task.archived_item_type {
        ArchivedItemType::Email => {
            let account_id = task.account_id.document_id();
            let access_token = server
                .access_token(account_id)
                .await
                .caused_by(trc::location!())?;

            // inbuxa: UD-8, UD-11: the item, and where it goes back
            let data = &server.core.storage.data;
            let Some((item_id, item, extra)) = undelete::records::for_restore(
                data,
                server.registry(),
                account_id,
                task.blob_id.hash.as_slice(),
            )
            .await?
            else {
                return Ok(TaskResult::Success(vec![]));
            };
            let (mailbox_ids, keywords) = match extra {
                Some(undelete::data::Extra::Email {
                    mailboxes,
                    keywords,
                }) => {
                    let cache = server
                        .get_cached_messages(account_id)
                        .await
                        .caused_by(trc::location!())?;
                    (
                        undelete::email::restore_mailboxes(
                            &mailboxes,
                            |id| cache.has_mailbox_id(&id),
                            INBOX_ID,
                            TRASH_ID,
                        ),
                        keywords.iter().map(|k| Keyword::parse(k)).collect(),
                    )
                }
                _ => (vec![INBOX_ID], vec![]),
            };

            let Some(bytes) = server
                .blob_store()
                .get_blob(task.blob_id.hash.as_slice(), 0..usize::MAX)
                .await?
            else {
                return Ok(TaskResult::permanent("Blob not found"));
            };

            match server
                .email_ingest(IngestEmail {
                    raw_message: &bytes,
                    message: MessageParser::new().parse(&bytes),
                    blob_hash: Some(&task.blob_id.hash),
                    access_token: &access_token.build(),
                    mailbox_ids,
                    keywords,
                    received_at: (task.created_at.timestamp() as u64).into(),
                    source: IngestSource::Restore,
                    session_id: 0,
                })
                .await
            {
                Ok(_) => {
                    // inbuxa: UD-9: the archived record goes, and its copy is released
                    undelete::records::remove(data, server.registry(), item_id, &item).await?;
                    Ok(TaskResult::Success(vec![]))
                }
                // inbuxa: UD-10: over quota, the item stays archived and the task says why
                Err(err)
                    if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota))
                        || err.matches(trc::EventType::Limit(trc::LimitEvent::TenantQuota)) =>
                {
                    let mut batch = BatchBuilder::new();
                    undelete::data::clear_restore_requested(&mut batch, item_id);
                    data.write(batch.build_all()).await?;
                    Ok(TaskResult::permanent(
                        "Not restored: the account or its tenant is over quota.".to_string(),
                    ))
                }
                Err(mut err)
                    if err.matches(trc::EventType::MessageIngest(
                        trc::MessageIngestEvent::Error,
                    )) =>
                {
                    Ok(TaskResult::permanent(
                        err.take_value(trc::Key::Reason)
                            .and_then(|v| v.into_string())
                            .unwrap()
                            .to_string(),
                    ))
                }
                Err(err) => Err(err.caused_by(trc::location!())),
            }
        }
        // inbuxa: UD-1, UD-8: the other kinds the fork archives
        ArchivedItemType::FileNode
        | ArchivedItemType::CalendarEvent
        | ArchivedItemType::ContactCard
        | ArchivedItemType::SieveScript => {
            let Some((item_id, item, extra)) = undelete::records::for_restore(
                &server.core.storage.data,
                server.registry(),
                task.account_id.document_id(),
                task.blob_id.hash.as_slice(),
            )
            .await?
            else {
                return Ok(TaskResult::Success(vec![]));
            };
            match crate::task_manager::inbuxa_restore::restore_other(
                server, task, item_id, &item, extra,
            )
            .await?
            {
                None => Ok(TaskResult::Success(vec![])),
                Some(reason) => {
                    crate::task_manager::inbuxa_restore::not_restored(server, item_id, reason)
                        .await
                }
            }
        }
    }
}
