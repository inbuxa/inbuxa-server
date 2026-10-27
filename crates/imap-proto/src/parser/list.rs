/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::{
        list::{self, ReturnOption, SelectionOption},
        metadata::Entry,
        status::Status,
    },
    receiver::{Request, Token, bad},
};
use std::mem::discriminant;

impl Request<Command> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse_list(self, is_utf8: bool) -> trc::Result<list::Arguments> {
        match self.tokens.len() {
            0 | 1 => Err(self.into_error("Missing arguments.")),
            2 => {
                let mut tokens = self.tokens.into_iter();
                Ok(list::Arguments::Basic {
                    reference_name: tokens
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| bad(self.tag.clone(), v))?,
                    mailbox_name: tokens
                        .next()
                        .unwrap()
                        .unwrap_mailbox_name(is_utf8)
                        .map_err(|v| bad(self.tag.clone(), v))?,
                    tag: self.tag,
                })
            }
            _ => {
                let mut tokens = self.tokens.into_iter();
                let mut selection_options = Vec::new();
                let mut return_options = Vec::new();
                let mut mailbox_name = Vec::new();

                let reference_name = match tokens.next().unwrap() {
                    Token::ParenthesisOpen => {
                        while let Some(token) = tokens.next() {
                            match token {
                                Token::ParenthesisClose => break,
                                Token::Argument(value) => {
                                    selection_options.push(
                                        SelectionOption::parse(&value)
                                            .map_err(|v| bad(self.tag.clone(), v))?,
                                    );
                                }
                                _ => {
                                    return Err(bad(
                                        self.tag.clone(),
                                        "Invalid selection option argument.",
                                    ));
                                }
                            }
                        }
                        tokens
                            .next()
                            .ok_or_else(|| bad(self.tag.clone(), "Missing reference name."))?
                            .unwrap_string()
                            .map_err(|v| bad(self.tag.clone(), v))?
                    }
                    token => token
                        .unwrap_string()
                        .map_err(|v| bad(self.tag.clone(), v))?,
                };

                match tokens
                    .next()
                    .ok_or_else(|| bad(self.tag.clone(), "Missing mailbox name."))?
                {
                    Token::ParenthesisOpen => {
                        while let Some(token) = tokens.next() {
                            match token {
                                Token::ParenthesisClose => break,
                                token => {
                                    mailbox_name.push(
                                        token
                                            .unwrap_string()
                                            .map_err(|v| bad(self.tag.clone(), v))?,
                                    );
                                }
                            }
                        }
                    }
                    token => {
                        mailbox_name.push(
                            token
                                .unwrap_mailbox_name(is_utf8)
                                .map_err(|v| bad(self.tag.clone(), v))?,
                        );
                    }
                }

                if tokens
                    .next()
                    .is_some_and(|token| token.eq_ignore_ascii_case(b"return"))
                {
                    if tokens
                        .next()
                        .is_none_or(|token| !token.is_parenthesis_open())
                    {
                        return Err(bad(
                            self.tag.clone(),
                            "Invalid return option, expected parenthesis.",
                        ));
                    }

                    while let Some(token) = tokens.next() {
                        match token {
                            Token::ParenthesisClose => break,
                            Token::Argument(value) => {
                                let mut return_option = ReturnOption::parse(&value)
                                    .map_err(|v| bad(self.tag.clone(), v))?;
                                if let ReturnOption::Status(status) = &mut return_option {
                                    if tokens
                                        .next()
                                        .is_none_or(|token| !token.is_parenthesis_open())
                                    {
                                        return Err(bad(
                                            self.tag,
                                            "Invalid return option, expected parenthesis after STATUS.",
                                        ));
                                    }
                                    while let Some(token) = tokens.next() {
                                        match token {
                                            Token::ParenthesisClose => break,
                                            Token::Argument(value) => {
                                                status.push(
                                                    Status::parse(&value)
                                                        .map_err(|v| bad(self.tag.clone(), v))?,
                                                );
                                            }
                                            _ => {
                                                return Err(bad(
                                                    self.tag,
                                                    "Invalid status return option argument.",
                                                ));
                                            }
                                        }
                                    }
                                } else if let ReturnOption::Metadata(entries) = &mut return_option {
                                    if tokens
                                        .next()
                                        .is_none_or(|token| !token.is_parenthesis_open())
                                    {
                                        return Err(bad(
                                            self.tag,
                                            "Invalid return option, expected parenthesis after METADATA.",
                                        ));
                                    }
                                    *entries = Entry::parse_list(&mut tokens)
                                        .map_err(|v| bad(self.tag.clone(), v))?;
                                    entries.sort_unstable();
                                    entries.dedup();
                                }
                                return_options.retain(|existing| {
                                    discriminant(existing) != discriminant(&return_option)
                                });
                                return_options.push(return_option);
                            }
                            _ => {
                                return Err(bad(
                                    self.tag.clone(),
                                    "Invalid return option argument.",
                                ));
                            }
                        }
                    }
                }

                Ok(list::Arguments::Extended {
                    tag: self.tag,
                    reference_name,
                    mailbox_name,
                    selection_options,
                    return_options,
                })
            }
        }
    }
}

impl SelectionOption {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        hashify::fnc_map_ignore_case!(value,
            "SUBSCRIBED" => Some(Self::Subscribed),
            "REMOTE" => Some(Self::Remote),
            "RECURSIVEMATCH" => Some(Self::RecursiveMatch),
            "SPECIAL-USE" => Some(Self::SpecialUse),
            _ => None,
        )
        .ok_or_else(|| {
            format!(
                "Unsupported selection option '{}'.",
                String::from_utf8_lossy(value)
            )
            .into()
        })
    }
}

impl ReturnOption {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        hashify::fnc_map_ignore_case!(value,
            "SUBSCRIBED" => Some(Self::Subscribed),
            "CHILDREN" => Some(Self::Children),
            "STATUS" => Some(Self::Status(Vec::with_capacity(2))),
            "SPECIAL-USE" => Some(Self::SpecialUse),
            "METADATA" => Some(Self::Metadata(Vec::new())),
            "OBJECTID" => Some(Self::ObjectId),
            _ => None,
        )
        .ok_or_else(|| format!("Invalid return option {:?}", String::from_utf8_lossy(value)).into())
    }
}

