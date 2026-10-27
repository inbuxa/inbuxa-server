/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::list::{self, SelectionOption},
    receiver::{Request, bad},
};

impl Request<Command> {
    pub fn parse_lsub(self, is_utf8: bool) -> trc::Result<list::Arguments> {
        if self.tokens.len() > 1 {
            let mut tokens = self.tokens.into_iter();

            Ok(list::Arguments::Extended {
                reference_name: tokens
                    .next()
                    .ok_or_else(|| bad(self.tag.clone(), "Missing reference name."))?
                    .unwrap_string()
                    .map_err(|v| bad(self.tag.clone(), v))?,
                mailbox_name: vec![
                    tokens
                        .next()
                        .ok_or_else(|| bad(self.tag.clone(), "Missing mailbox name."))?
                        .unwrap_mailbox_name(is_utf8)
                        .map_err(|v| bad(self.tag.clone(), v))?,
                ],
                selection_options: vec![SelectionOption::Subscribed],
                return_options: vec![],
                tag: self.tag,
            })
        } else {
            Err(self.into_error("Missing arguments."))
        }
    }
}

