/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::format_compact;

use crate::{
    Command,
    protocol::{create, list::Attribute},
    receiver::{Request, Token, bad},
};

impl Request<Command> {
    pub fn parse_create(self, is_utf8: bool) -> trc::Result<create::Arguments> {
        if !self.tokens.is_empty() {
            let mut tokens = self.tokens.into_iter();
            let mailbox_name = tokens
                .next()
                .unwrap()
                .unwrap_mailbox_name_strict(is_utf8)
                .map_err(|v| bad(self.tag.clone(), v))?;
            let mailbox_role = if let Some(Token::ParenthesisOpen) = tokens.next() {
                match tokens.next() {
                    Some(Token::Argument(param)) if param.eq_ignore_ascii_case(b"USE") => (),
                    _ => {
                        return Err(bad(self.tag, "Failed to parse, expected 'USE'."));
                    }
                }
                if tokens
                    .next()
                    .is_none_or(|token| !token.is_parenthesis_open())
                {
                    return Err(bad(self.tag, "Expected '(' after 'USE'."));
                }
                match tokens.next() {
                    Some(Token::Argument(value)) => match Attribute::parse_special_use(&value) {
                        Some(Attribute::All) => {
                            return Err(bad(
                                self.tag,
                                "A mailbox with the \"\\All\" attribute already exists.",
                            ));
                        }
                        Some(tag) => Some(tag),
                        None => {
                            return Err(bad(
                                self.tag,
                                format_compact!(
                                    "Special use attribute {:?} is not supported.",
                                    String::from_utf8_lossy(&value)
                                ),
                            ));
                        }
                    },
                    _ => {
                        return Err(bad(self.tag, "Invalid SPECIAL-USE attribute."));
                    }
                }
            } else {
                None
            };

            Ok(create::Arguments {
                mailbox_name,
                mailbox_role,
                tag: self.tag,
            })
        } else {
            Err(self.into_error("Missing arguments."))
        }
    }
}

impl Attribute {
    pub fn parse_special_use(value: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(value, Attribute,
            "\\Archive" => Attribute::Archive,
            "\\Drafts" => Attribute::Drafts,
            "\\Junk" => Attribute::Junk,
            "\\Sent" => Attribute::Sent,
            "\\Trash" => Attribute::Trash,
            "\\Important" => Attribute::Important,
            "\\Memos" => Attribute::Memos,
            "\\Scheduled" => Attribute::Scheduled,
            "\\Snoozed" => Attribute::Snoozed,
            "\\All" => Attribute::All,
        )
        .copied()
    }
}

