/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::rename,
    receiver::{Request, bad},
};

impl Request<Command> {
    pub fn parse_rename(self, is_utf8: bool) -> trc::Result<rename::Arguments> {
        match self.tokens.len() {
            2 => {
                let mut tokens = self.tokens.into_iter();
                Ok(rename::Arguments {
                    mailbox_name: tokens
                        .next()
                        .unwrap()
                        .unwrap_mailbox_name(is_utf8)
                        .map_err(|v| bad(self.tag.clone(), v))?,
                    new_mailbox_name: tokens
                        .next()
                        .unwrap()
                        .unwrap_mailbox_name(is_utf8)
                        .map_err(|v| bad(self.tag.clone(), v))?,
                    tag: self.tag,
                })
            }
            0 => Err(self.into_error("Missing argument.")),
            1 => Err(self.into_error("Missing new mailbox name.")),
            _ => Err(self.into_error("Too many arguments.")),
        }
    }
}

