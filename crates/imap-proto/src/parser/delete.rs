/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::delete,
    receiver::{Request, bad},
};

impl Request<Command> {
    pub fn parse_delete(self, is_utf8: bool) -> trc::Result<delete::Arguments> {
        match self.tokens.len() {
            1 => Ok(delete::Arguments {
                mailbox_name: self
                    .tokens
                    .into_iter()
                    .next()
                    .unwrap()
                    .unwrap_mailbox_name(is_utf8)
                    .map_err(|v| bad(self.tag.clone(), v))?,
                tag: self.tag,
            }),
            0 => Err(self.into_error("Missing mailbox name.")),
            _ => Err(self.into_error("Too many arguments.")),
        }
    }
}

