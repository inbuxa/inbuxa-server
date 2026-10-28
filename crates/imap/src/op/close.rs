/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::time::Instant;

use crate::core::{SelectedMailbox, Session, SessionData, State};
use common::network::SessionStream;
use imap_proto::{Command, StatusResponse, receiver::Request};
use registry::schema::enums::Permission;
use trc::AddContext;
use types::acl::Acl;

impl<T: SessionStream> Session<T> {
    pub async fn handle_close(&mut self, request: Request<Command>) -> trc::Result<()> {
        let op_start = Instant::now();
        let (data, mailbox) = self.state.select_data();

        // inbuxa: CLOSE removes \Deleted messages the way EXPUNGE does, so it
        // takes the same rights. Without them the mailbox is closed and
        // nothing is removed (RFC 3501 CLOSE has no failure response).
        if mailbox.is_select
            && may_expunge(&data, &mailbox)
                .await
                .caused_by(trc::location!())?
        {
            data.expunge(mailbox.clone(), None, u32::MAX, op_start)
                .await
                .caused_by(trc::location!())?;
        }

        trc::event!(
            Imap(trc::ImapEvent::Close),
            SpanId = self.session_id,
            AccountId = mailbox.id.account_id,
            MailboxId = mailbox.id.mailbox_id,
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

// inbuxa: the checks EXPUNGE makes before removing anything: the ImapExpunge
// permission, a delegation that may delete (AL-6), and RemoveItems on the
// mailbox.
async fn may_expunge<T: SessionStream>(
    data: &SessionData<T>,
    mailbox: &SelectedMailbox,
) -> trc::Result<bool> {
    let access_token = data.refresh_access_token().await?;
    if !access_token.has_permission(Permission::ImapExpunge)
        || access_token
            .delegation(mailbox.id.account_id)
            .is_some_and(|delegation| !delegation.access.may_destroy())
    {
        return Ok(false);
    }
    data.check_mailbox_acl(
        mailbox.id.account_id,
        mailbox.id.mailbox_id,
        Acl::RemoveItems,
    )
    .await
}
