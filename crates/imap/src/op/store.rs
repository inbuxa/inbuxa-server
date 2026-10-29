/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{FromModSeq, ImapContext};
use crate::{
    core::{SelectedMailbox, Session, SessionData},
    spawn_op,
};
use ahash::AHashSet;
use common::{network::SessionStream, storage::index::ObjectIndexBuilder};
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::TRASH_ID,
    message::{ingest::EmailIngest, metadata::MessageData},
};
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    protocol::{
        Flag, ImapResponse,
        fetch::{DataItem, FetchItem},
        merge_ranges,
        store::{Arguments, Operation, Response},
    },
    receiver::Request,
};
use registry::schema::enums::Permission;
use std::{sync::Arc, time::Instant};
use store::{
    READ_BATCH_SIZE, ValueKey,
    query::log::{Change, Query},
    write::{AlignedBytes, Archive, BatchBuilder},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    keyword::Keyword,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_store(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
        spawn: bool,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapStore)?;

        let op_start = Instant::now();
        let arguments = request.parse_store()?;
        let (data, mailbox) = self.state.select_data();
        let is_condstore = self.is_condstore || mailbox.is_condstore;
        let is_utf8 = self.is_utf8;
        let is_uidonly = self.is_uidonly;
        let message_limit = self.server.core.imap.max_messages_per_command;

        if spawn {
            spawn_op!(data, {
                let response = data
                    .store(
                        arguments,
                        mailbox,
                        is_uid,
                        is_condstore,
                        is_utf8,
                        is_uidonly,
                        message_limit,
                        op_start,
                    )
                    .await?;

                data.write_bytes(response).await
            })
        } else {
            let response = data
                .store(
                    arguments,
                    mailbox,
                    is_uid,
                    is_condstore,
                    is_utf8,
                    is_uidonly,
                    message_limit,
                    op_start,
                )
                .await?;

            data.write_bytes(response).await
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn store(
        &self,
        arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        is_uid: bool,
        is_condstore: bool,
        is_utf8: bool,
        is_uidonly: bool,
        message_limit: u32,
        op_start: Instant,
    ) -> trc::Result<Vec<u8>> {
        // Resync messages if needed
        let account_id = mailbox.id.account_id;
        self.synchronize_messages(&mailbox)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Convert IMAP ids to JMAP ids.
        let mut ids = mailbox
            .sequence_to_ids(&arguments.sequence_set, is_uid)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        if ids.is_empty() {
            return Ok(StatusResponse::completed(Command::Store(is_uid))
                .with_tag(arguments.tag)
                .into_bytes());
        }

        // Verify that the user can modify messages in this mailbox.
        // inbuxa: \Deleted needs the right to remove messages and every other
        // flag the right to modify them (RFC 4314 "t" and "w"). Keywords
        // belong to the message, so on a shared account the right has to
        // hold on every mailbox the message is in, not only the selected one.
        let access_token = self
            .refresh_access_token()
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        let shared_rights = if !access_token.is_member(account_id) {
            let cache = self
                .server
                .get_cached_messages(account_id)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
            Some((
                cache.shared_mailboxes(&access_token, Acl::ModifyItems),
                cache.shared_mailboxes(&access_token, Acl::RemoveItems),
            ))
        } else {
            None
        };
        let is_replace = matches!(arguments.operation, Operation::Set);
        let wants_modify = is_replace || arguments.keywords.iter().any(|f| *f != Flag::Deleted);
        let wants_remove = is_replace || arguments.keywords.contains(&Flag::Deleted);
        if let Some((modify_ids, remove_ids)) = &shared_rights
            && !(wants_modify && modify_ids.contains(mailbox.id.mailbox_id)
                || wants_remove && remove_ids.contains(mailbox.id.mailbox_id))
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(
                    "You do not have the required permissions to modify messages in this mailbox.",
                )
                .id(arguments.tag)
                .code(ResponseCode::NoPerm)
                .caused_by(trc::location!()));
        }

        // Filter out unchanged since ids
        let mut response_code = None;
        let mut unchanged_failed = false;
        if let Some(unchanged_since) = arguments.unchanged_since {
            // Obtain changes since the modseq.
            let changelog = self
                .server
                .store()
                .changes(
                    account_id,
                    SyncCollection::Email.into(),
                    Query::from_modseq(unchanged_since),
                )
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;

            let mut modified = mailbox
                .sequence_missing_ranges(&arguments.sequence_set, is_uid)
                .await;

            // Add all IDs that changed in this mailbox
            for (id, is_delete) in changelog.changes.into_iter().filter_map(|change| {
                change.item_id().map(|id| {
                    (
                        (id & u32::MAX as u64) as u32,
                        matches!(change, Change::DeleteItem(_)),
                    )
                })
            }) {
                if let Some(imap_id) = ids.remove(&id) {
                    if is_uid {
                        modified.push((imap_id.uid, imap_id.uid));
                    } else {
                        modified.push((imap_id.seqnum, imap_id.seqnum));
                        if is_delete {
                            unchanged_failed = true;
                        }
                    }
                }
            }

            if !modified.is_empty() {
                response_code = ResponseCode::Modified {
                    ranges: merge_ranges(modified),
                }
                .into();
            }
        }

        // Build response
        let mut response = if !unchanged_failed {
            StatusResponse::completed(Command::Store(is_uid))
        } else {
            StatusResponse::no("Some of the messages no longer exist.")
        }
        .with_tag(arguments.tag);
        if let Some(response_code) = response_code {
            response = response.with_code(response_code)
        }
        if ids.is_empty() {
            trc::event!(
                Imap(trc::ImapEvent::Store),
                SpanId = self.session_id,
                AccountId = mailbox.id.account_id,
                MailboxId = mailbox.id.mailbox_id,
                Type = format!("{:?}", arguments.operation),
                Details = arguments
                    .keywords
                    .iter()
                    .map(|c| trc::Value::from(format!("{c:?}")))
                    .collect::<Vec<_>>(),
                Elapsed = op_start.elapsed()
            );

            return Ok(response.into_bytes());
        }
        // RFC 9738 requires the highest UIDs to be processed first when truncating.
        let message_limit = message_limit as usize;
        let mut untagged = Vec::new();
        if ids.len() > message_limit {
            let mut uids = ids.values().map(|imap_id| imap_id.uid).collect::<Vec<_>>();
            let cutoff = uids.len() - message_limit;
            let lowest_uid = *uids.select_nth_unstable(cutoff).1;
            ids.retain(|_, imap_id| imap_id.uid >= lowest_uid);

            let code = ResponseCode::MessageLimit {
                limit: message_limit as u32,
                uid: lowest_uid.into(),
            };
            if response.code.is_none() {
                response = response.with_code(code);
            } else {
                untagged = StatusResponse::ok("Some messages were not modified.")
                    .with_code(code)
                    .into_bytes();
            }
        }

        let mut items = Response {
            is_utf8,
            items: Vec::with_capacity(ids.len()),
        };

        // Process each change
        let set_keywords = arguments
            .keywords
            .iter()
            .map(|k| Keyword::from(k.clone()))
            .collect::<Vec<_>>();
        let mut changed_mailboxes = AHashSet::new();
        let mut batch = BatchBuilder::new();

        let ids = ids.into_iter().collect::<Vec<_>>();
        for chunk in ids.chunks(READ_BATCH_SIZE) {
            // inbuxa: one round trip per batch of messages instead of one each
            let keys = chunk
                .iter()
                .map(|(id, _)| ValueKey::archive(account_id, Collection::Email, *id))
                .collect::<Vec<_>>();
            let archives = self
                .server
                .store()
                .get_values::<Archive<AlignedBytes>>(&keys)
                .await
                .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?;

            for ((id, imap_id), data_) in chunk.iter().zip(archives) {
                // Obtain message data
                let Some(data_) = data_ else {
                    continue;
                };

                // Deserialize
                let data = data_
                    .to_unarchived::<MessageData>()
                    .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?;
                let mut new_data = data.inner.to_builder();

                // inbuxa: the rights this message allows (see above); flags
                // the user may not change are left as they are
                let (may_modify, may_remove) = match &shared_rights {
                    Some((modify_ids, remove_ids)) => (
                        new_data
                            .mailboxes
                            .iter()
                            .all(|m| modify_ids.contains(m.mailbox_id)),
                        new_data
                            .mailboxes
                            .iter()
                            .all(|m| remove_ids.contains(m.mailbox_id)),
                    ),
                    None => (true, true),
                };
                let may_change = |keyword: &Keyword| {
                    if keyword == &Keyword::Deleted {
                        may_remove
                    } else {
                        may_modify
                    }
                };

                // Apply changes
                match arguments.operation {
                    Operation::Set if may_modify && may_remove => {
                        new_data.set_keywords(set_keywords.clone());
                    }
                    Operation::Set => {
                        new_data.keywords.retain(|keyword| {
                            !may_change(keyword) || set_keywords.contains(keyword)
                        });
                        for keyword in set_keywords.iter().filter(|k| may_change(k)) {
                            new_data.add_keyword(keyword.clone());
                        }
                    }
                    Operation::Add => {
                        for keyword in set_keywords.iter().filter(|k| may_change(k)) {
                            new_data.add_keyword(keyword.clone());
                        }
                    }
                    Operation::Clear => {
                        for keyword in set_keywords.iter().filter(|k| may_change(k)) {
                            new_data.remove_keyword(keyword);
                        }
                    }
                }
                let seen_changed = new_data.has_keyword(&Keyword::Seen)
                    != data.inner.keywords.iter().any(|k| k == &Keyword::Seen);

                if !new_data.has_keyword_changes(data.inner) {
                    continue;
                }

                // Train spam filter
                let mut train_spam = None;
                for keyword in new_data.added_keywords(data.inner) {
                    if keyword == &Keyword::Junk {
                        train_spam = Some(true);
                        break;
                    } else if keyword == &Keyword::NotJunk && !data.inner.has_mailbox_id(TRASH_ID) {
                        // Only train as ham if not in Trash (Apple likes to add NotJunk to trashed items, which would be spammy)
                        train_spam = Some(false);
                        break;
                    }
                }
                if train_spam.is_none() {
                    for keyword in new_data.removed_keywords(data.inner) {
                        if keyword == &Keyword::Junk {
                            if !data.inner.has_mailbox_id(TRASH_ID) {
                                train_spam = Some(false);
                            }
                            break;
                        }
                    }
                }

                // Convert keywords to flags
                let flags = if !arguments.is_silent {
                    new_data
                        .keywords
                        .iter()
                        .cloned()
                        .map(Flag::from)
                        .collect::<Vec<_>>()
                } else {
                    vec![]
                };

                // Set all current mailboxes as changed if the Seen tag changed
                if seen_changed {
                    for mailbox_id in new_data.mailboxes.iter() {
                        changed_mailboxes.insert(mailbox_id.mailbox_id);
                    }
                }

                // Write changes
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Email)
                    .with_document(*id)
                    .custom(
                        ObjectIndexBuilder::new()
                            .with_current(data)
                            .with_changes(new_data.seal()),
                    )
                    .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?;

                // Add spam train task
                if let Some(learn_spam) = train_spam {
                    self.server
                        .add_account_spam_sample(
                            &mut batch,
                            account_id,
                            *id,
                            learn_spam,
                            self.session_id,
                        )
                        .await
                        .imap_ctx(response.tag.as_ref().unwrap(), trc::location!())?;
                }

                // Set commit point
                batch.commit_point();

                // Add item to response
                if !arguments.is_silent {
                    let mut data_items = vec![DataItem::Flags { flags }];
                    if is_uid {
                        data_items.push(DataItem::Uid { uid: imap_id.uid });
                    }
                    items.items.push(FetchItem {
                        id: if is_uidonly {
                            imap_id.uid
                        } else {
                            imap_id.seqnum
                        },
                        is_uidonly,
                        items: data_items,
                    });
                } else if is_condstore {
                    items.items.push(FetchItem {
                        id: if is_uidonly {
                            imap_id.uid
                        } else {
                            imap_id.seqnum
                        },
                        is_uidonly,
                        items: if is_uid {
                            vec![DataItem::Uid { uid: imap_id.uid }]
                        } else {
                            vec![]
                        },
                    });
                }
            }
        }

        // Log mailbox changes
        if !changed_mailboxes.is_empty() {
            for parent_id in changed_mailboxes {
                batch.log_container_property_change(SyncCollection::Email, parent_id);
            }
        }

        // Write changes
        if !batch.is_empty() {
            match self
                .server
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(mailbox.id.account_id))
                .caused_by(trc::location!())
            {
                Ok(change_id) => {
                    if is_condstore {
                        let modseq = change_id + 1;
                        for item in items.items.iter_mut() {
                            item.items.push(DataItem::ModSeq { modseq });
                        }
                    }
                }
                Err(err) if err.is_assertion_failure() => {
                    items.items.clear();
                    response.rtype = ResponseType::No;
                    response.message = "Some messages were modified by another process.".into();
                }
                Err(err) => {
                    return Err(err.id(response.tag.unwrap()));
                }
            }
        }

        trc::event!(
            Imap(trc::ImapEvent::Store),
            SpanId = self.session_id,
            AccountId = mailbox.id.account_id,
            MailboxId = mailbox.id.mailbox_id,
            DocumentId = ids
                .iter()
                .map(|id| trc::Value::from(id.0))
                .collect::<Vec<_>>(),
            Type = format!("{:?}", arguments.operation),
            Details = arguments
                .keywords
                .iter()
                .map(|c| trc::Value::from(format!("{c:?}")))
                .collect::<Vec<_>>(),
            Elapsed = op_start.elapsed()
        );

        // Send response
        let items = items.serialize();
        Ok(response.serialize(if untagged.is_empty() {
            items
        } else {
            untagged.extend_from_slice(&items);
            untagged
        }))
    }
}
