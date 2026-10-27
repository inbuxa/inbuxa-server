/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ImapContext;
use crate::core::{Session, State};
use common::network::SessionStream;
use email::cache::MessageCacheFetch;
use imap_proto::{Command, StatusResponse, receiver::Request};
use registry::schema::enums::Permission;
use std::time::Instant;
use tokio::sync::OwnedSemaphorePermit;
use types::acl::Acl;

impl<T: SessionStream> Session<T> {
    pub async fn handle_close(
        &mut self,
        request: Request<Command>,
        _permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        let op_start = Instant::now();
        let (data, mailbox) = self.state.select_data();

        let mut skipped_expunge = None;
        if mailbox.is_select && data.access_token.has_permission(Permission::ImapExpunge) {
            let cache = data
                .server
                .get_cached_messages(mailbox.id.account_id)
                .await
                .imap_ctx(&request.tag, trc::location!())?;
            match data
                .check_mailbox_acl(
                    Some(&cache),
                    mailbox.id.account_id,
                    mailbox.id.mailbox_id,
                    Acl::RemoveItems,
                )
                .await
            {
                Ok(true) => {
                    data.expunge(mailbox.clone(), cache, None, u32::MAX, op_start)
                        .await
                        .imap_ctx(&request.tag, trc::location!())?;
                }
                Ok(false) => {}
                Err(err) => skipped_expunge = Some(err),
            }
        }

        trc::event!(
            Imap(trc::ImapEvent::Close),
            SpanId = self.session_id,
            AccountId = mailbox.id.account_id,
            MailboxId = mailbox.id.mailbox_id,
            CausedBy = skipped_expunge,
            Elapsed = op_start.elapsed()
        );

        self.state = State::Authenticated { data };
        self.write_bytes(
            StatusResponse::completed(Command::Close)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}
