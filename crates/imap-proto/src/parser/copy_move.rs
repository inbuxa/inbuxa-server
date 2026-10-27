/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::copy_move,
    receiver::{Request, bad},
};

use super::parse_sequence_set;

impl Request<Command> {
    pub fn parse_copy_move(self, is_utf8: bool) -> trc::Result<copy_move::Arguments> {
        if self.tokens.len() > 1 {
            let mut tokens = self.tokens.into_iter();

            Ok(copy_move::Arguments {
                sequence_set: parse_sequence_set(
                    &tokens
                        .next()
                        .ok_or_else(|| bad(self.tag.clone(), "Missing sequence set."))?
                        .unwrap_bytes(),
                )
                .map_err(|v| bad(self.tag.clone(), v))?,
                mailbox_name: tokens
                    .next()
                    .ok_or_else(|| bad(self.tag.clone(), "Missing mailbox name."))?
                    .unwrap_mailbox_name(is_utf8)
                    .map_err(|v| bad(self.tag.clone(), v))?,
                tag: self.tag,
            })
        } else {
            Err(self.into_error("Missing arguments."))
        }
    }
}

