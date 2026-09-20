/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::time::Instant;

use crate::core::Session;
use common::network::SessionStream;
use imap_proto::{Command, StatusResponse, receiver::Request};

impl<T: SessionStream> Session<T> {
    pub async fn handle_logout(&mut self, request: Request<Command>) -> trc::Result<()> {
        let op_start = Instant::now();

        let mut response =
            StatusResponse::bye(concat!(types::brand!(), " IMAP4rev2 bids you farewell.").to_string()).into_bytes();

        trc::event!(
            Imap(trc::ImapEvent::Logout),
            SpanId = self.session_id,
            Elapsed = op_start.elapsed()
        );

        response.extend(
            StatusResponse::completed(Command::Logout)
                .with_tag(request.tag)
                .into_bytes(),
        );
        self.write_bytes(response).await
    }
}
