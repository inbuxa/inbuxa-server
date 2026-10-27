/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::{capability::Capability, enable},
    receiver::{Request, Token, bad},
};

impl Request<Command> {
    pub fn parse_enable(self) -> trc::Result<enable::Arguments> {
        if self.tokens.is_empty() {
            return Err(self.into_error("Missing arguments."));
        }

        let mut capabilities = Vec::with_capacity(self.tokens.len());
        for token in self.tokens {
            match token {
                Token::Argument(name) => capabilities.extend(Capability::parse(&name)),
                _ => return Err(bad(self.tag, "Invalid capability name.")),
            }
        }

        Ok(enable::Arguments {
            tag: self.tag,
            capabilities,
        })
    }
}

impl Capability {
    pub fn parse(value: &[u8]) -> Option<Self> {
        hashify::fnc_map_ignore_case!(value,
            "IMAP4rev2" => Some(Self::IMAP4rev2),
            "STARTTLS" => Some(Self::StartTLS),
            "LOGINDISABLED" => Some(Self::LoginDisabled),
            "CONDSTORE" => Some(Self::CondStore),
            "QRESYNC" => Some(Self::QResync),
            "UTF8=ACCEPT" => Some(Self::Utf8Accept),
            "OBJECTID+" => Some(Self::ObjectIdPlus),
            "UIDONLY" => Some(Self::UidOnly),
            _ => None,
        )
    }
}

