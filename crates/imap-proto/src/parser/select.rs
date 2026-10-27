/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::format_compact;

use crate::{
    Command,
    protocol::{
        ObjectId,
        select::{self, QResync},
    },
    receiver::{Request, Token, bad},
};

use super::{parse_number, parse_sequence_set};

impl Request<Command> {
    pub fn parse_select(self, is_utf8: bool) -> trc::Result<select::Arguments> {
        if !self.tokens.is_empty() {
            let mut tokens = self.tokens.into_iter().peekable();

            // Mailbox name
            let mailbox_name = tokens
                .next()
                .unwrap()
                .unwrap_mailbox_name(is_utf8)
                .map_err(|v| bad(self.tag.clone(), v))?;

            // CONDSTORE parameters
            let mut condstore = false;
            let mut qresync = None;
            let mut objectid = None;
            match tokens.next() {
                Some(Token::ParenthesisOpen) => {
                    while let Some(token) = tokens.next() {
                        match token {
                            Token::Argument(param) if param.eq_ignore_ascii_case(b"CONDSTORE") => {
                                condstore = true;
                            }
                            Token::Argument(param) if param.eq_ignore_ascii_case(b"QRESYNC") => {
                                if tokens
                                    .next()
                                    .is_none_or(|token| !token.is_parenthesis_open())
                                {
                                    return Err(bad(self.tag, "Expected '(' after 'QRESYNC'."));
                                }

                                let uid_validity = parse_number::<u32>(
                                    &tokens
                                        .next()
                                        .ok_or_else(|| {
                                            bad(
                                                self.tag.clone(),
                                                "Missing uidvalidity parameter for QRESYNC.",
                                            )
                                        })?
                                        .unwrap_bytes(),
                                )
                                .map_err(|v| bad(self.tag.clone(), v))?;
                                let modseq = parse_number::<u64>(
                                    &tokens
                                        .next()
                                        .ok_or_else(|| {
                                            bad(
                                                self.tag.clone(),
                                                "Missing modseq parameter for QRESYNC.",
                                            )
                                        })?
                                        .unwrap_bytes(),
                                )
                                .map_err(|v| bad(self.tag.clone(), v))?;

                                let mut known_uids = None;
                                let mut seq_match = None;
                                let has_seq_match = match tokens.peek() {
                                    Some(Token::Argument(value)) => {
                                        known_uids = parse_sequence_set(value)
                                            .map_err(|v| bad(self.tag.clone(), v))?
                                            .into();
                                        tokens.next();
                                        if matches!(tokens.peek(), Some(Token::ParenthesisOpen)) {
                                            tokens.next();
                                            true
                                        } else {
                                            false
                                        }
                                    }
                                    Some(Token::ParenthesisOpen) => {
                                        tokens.next();
                                        true
                                    }
                                    _ => false,
                                };

                                if has_seq_match {
                                    seq_match = Some((
                                        parse_sequence_set(
                                            &tokens
                                                .next()
                                                .ok_or_else(|| {
                                                    bad(
                                            self.tag.clone(),
                                            "Missing known-sequence-set parameter for QRESYNC.",
                                        )
                                                })?
                                                .unwrap_bytes(),
                                        )
                                        .map_err(|v| bad(self.tag.clone(), v))?,
                                        parse_sequence_set(
                                            &tokens
                                                .next()
                                                .ok_or_else(|| {
                                                    bad(
                                                self.tag.clone(),
                                                "Missing known-uid-set parameter for QRESYNC.",
                                            )
                                                })?
                                                .unwrap_bytes(),
                                        )
                                        .map_err(|v| bad(self.tag.clone(), v))?,
                                    ));
                                    if tokens
                                        .next()
                                        .is_none_or(|token| !token.is_parenthesis_close())
                                    {
                                        return Err(bad(self.tag, "Missing ')' for 'QRESYNC'."));
                                    }
                                }

                                if tokens
                                    .next()
                                    .is_none_or(|token| !token.is_parenthesis_close())
                                {
                                    return Err(bad(self.tag, "Missing ')' for 'QRESYNC'."));
                                }

                                qresync = QResync {
                                    uid_validity,
                                    modseq,
                                    known_uids,
                                    seq_match,
                                }
                                .into();
                            }
                            Token::Argument(param) if param.eq_ignore_ascii_case(b"OBJECTID") => {
                                let mut oid = ObjectId::default();
                                let mut is_matchable = true;
                                if matches!(tokens.peek(), Some(Token::ParenthesisOpen)) {
                                    tokens.next();
                                    while let Some(token) = tokens.next() {
                                        match token {
                                            Token::ParenthesisClose => break,
                                            Token::Argument(key) => {
                                                let value = tokens
                                                    .next()
                                                    .ok_or_else(|| {
                                                        bad(
                                                            self.tag.clone(),
                                                            "Expected value after OBJECTID key.",
                                                        )
                                                    })?
                                                    .unwrap_bytes();
                                                let id = ObjectId::decode_id(&value);
                                                hashify::fnc_map_ignore_case!(key.as_slice(),
                                                    "MAILBOXID" => {
                                                        is_matchable &= id.is_some();
                                                        oid.mailbox_id = id;
                                                    },
                                                    "ACCOUNTID" => {
                                                        is_matchable &= id.is_some();
                                                        oid.account_id = id;
                                                    },
                                                    "EMAILID" => { oid.email_id = id; },
                                                    "THREADID" => { oid.thread_id = id; },
                                                    _ => {}
                                                );
                                            }
                                            _ => {
                                                return Err(bad(
                                                    self.tag,
                                                    format_compact!(
                                                        "Unexpected value '{}'.",
                                                        token
                                                    ),
                                                ));
                                            }
                                        }
                                    }
                                }
                                if !is_matchable {
                                    oid.mailbox_id = None;
                                }
                                objectid = Some(oid);
                            }
                            Token::ParenthesisClose => {
                                break;
                            }
                            _ => {
                                return Err(bad(
                                    self.tag,
                                    format_compact!("Unexpected value '{}'.", token),
                                ));
                            }
                        }
                    }
                }
                Some(token) => {
                    return Err(bad(
                        self.tag,
                        format_compact!("Unexpected value '{}'.", token),
                    ));
                }
                None => (),
            }

            Ok(select::Arguments {
                mailbox_name,
                tag: self.tag,
                condstore,
                qresync,
                objectid,
            })
        } else {
            Err(self.into_error("Missing mailbox name."))
        }
    }
}

