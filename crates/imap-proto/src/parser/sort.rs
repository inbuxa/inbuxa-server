/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::decoders::charsets::charset_decoder;

use crate::{
    Command,
    protocol::search::{Arguments, Comparator, Sort},
    receiver::{Request, Token, bad},
};

use super::search::{parse_filters, parse_result_options};

impl Request<Command> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse_sort(self) -> trc::Result<Arguments> {
        if self.tokens.is_empty() {
            return Err(self.into_error("Missing sort criteria."));
        }

        let mut tokens = self.tokens.into_iter().peekable();
        let mut sort = Vec::new();

        let (result_options, is_esearch) = match tokens.peek() {
            Some(Token::Argument(value)) if value.eq_ignore_ascii_case(b"return") => {
                tokens.next();
                (
                    parse_result_options(&mut tokens).map_err(|v| bad(self.tag.clone(), v))?,
                    true,
                )
            }
            _ => (Vec::new(), false),
        };

        if tokens
            .next()
            .is_none_or(|token| !token.is_parenthesis_open())
        {
            return Err(bad(
                self.tag.clone(),
                "Expected sort criteria between parentheses.",
            ));
        }

        let mut is_ascending = true;
        while let Some(token) = tokens.next() {
            match token {
                Token::ParenthesisClose => break,
                Token::Argument(value) => {
                    if value.eq_ignore_ascii_case(b"REVERSE") {
                        is_ascending = false;
                    } else {
                        sort.push(Comparator {
                            sort: Sort::parse(&value).map_err(|v| bad(self.tag.clone(), v))?,
                            ascending: is_ascending,
                        });
                        is_ascending = true;
                    }
                }
                _ => {
                    return Err(bad(self.tag.clone(), "Invalid result option argument."));
                }
            }
        }

        if sort.is_empty() {
            return Err(bad(self.tag.clone(), "Missing sort criteria."));
        }

        let decoder = charset_decoder(
            &tokens
                .next()
                .ok_or_else(|| bad(self.tag.clone(), "Missing charset."))?
                .unwrap_bytes(),
        );

        let filter = parse_filters(&mut tokens, decoder).map_err(|v| bad(self.tag.clone(), v))?;
        match filter.len() {
            0 => Err(bad(self.tag.clone(), "No filters found in command.")),
            _ => Ok(Arguments {
                sort: sort.into(),
                result_options,
                filter,
                is_esearch,
                tag: self.tag,
            }),
        }
    }
}

impl Sort {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        hashify::fnc_map_ignore_case!(value,
            "ARRIVAL" => Some(Self::Arrival),
            "CC" => Some(Self::Cc),
            "DATE" => Some(Self::Date),
            "FROM" => Some(Self::From),
            "SIZE" => Some(Self::Size),
            "SUBJECT" => Some(Self::Subject),
            "TO" => Some(Self::To),
            "DISPLAYFROM" => Some(Self::DisplayFrom),
            "DISPLAYTO" => Some(Self::DisplayTo),
            _ => None,
        )
        .ok_or_else(|| format!("Invalid sort criteria {:?}", String::from_utf8_lossy(value)).into())
    }
}

