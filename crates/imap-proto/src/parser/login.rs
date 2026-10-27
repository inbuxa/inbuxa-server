/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::login,
    receiver::{Request, bad},
};

impl Request<Command> {
    pub fn parse_login(self) -> trc::Result<login::Arguments> {
        match self.tokens.len() {
            2 => {
                let mut tokens = self.tokens.into_iter();
                Ok(login::Arguments {
                    username: tokens
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| bad(self.tag.clone(), v))?,
                    password: tokens
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| bad(self.tag.clone(), v))?,
                    tag: self.tag,
                })
            }
            0 => Err(self.into_error("Missing arguments.")),
            _ => Err(self.into_error("Too many arguments.")),
        }
    }
}

