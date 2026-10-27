/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::decoders::charsets::charset_decoder;

use crate::{
    Command,
    protocol::thread::{self, Algorithm},
    receiver::{Request, bad},
};

use super::search::parse_filters;

impl Request<Command> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse_thread(self) -> trc::Result<thread::Arguments> {
        if self.tokens.is_empty() {
            return Err(self.into_error("Missing thread criteria."));
        }

        let mut tokens = self.tokens.into_iter().peekable();
        let algorithm = Algorithm::parse(
            &tokens
                .next()
                .ok_or_else(|| bad(self.tag.clone(), "Missing threading algorithm."))?
                .unwrap_bytes(),
        )
        .map_err(|v| bad(self.tag.clone(), v))?;

        let decoder = charset_decoder(
            &tokens
                .next()
                .ok_or_else(|| bad(self.tag.clone(), "Missing charset."))?
                .unwrap_bytes(),
        );

        let filter = parse_filters(&mut tokens, decoder).map_err(|v| bad(self.tag.clone(), v))?;
        match filter.len() {
            0 => Err(bad(self.tag.clone(), "No filters found in command.")),
            _ => Ok(thread::Arguments {
                algorithm,
                filter,
                tag: self.tag,
            }),
        }
    }
}

impl Algorithm {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        hashify::fnc_map_ignore_case!(value,
            "ORDEREDSUBJECT" => Some(Self::OrderedSubject),
            "REFERENCES" => Some(Self::References),
            _ => None,
        )
        .ok_or_else(|| {
            format!(
                "Invalid threading algorithm {:?}",
                String::from_utf8_lossy(value)
            )
            .into()
        })
    }
}

