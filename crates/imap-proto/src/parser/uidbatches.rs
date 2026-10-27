/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::uidbatches,
    receiver::{Request, bad},
};

use super::parse_number;

impl Request<Command> {
    pub fn parse_uidbatches(self) -> trc::Result<uidbatches::Arguments> {
        let mut tokens = self.tokens.into_iter();
        let batch_size = parse_number::<u32>(
            &tokens
                .next()
                .ok_or_else(|| bad(self.tag.clone(), "Missing batch size."))?
                .unwrap_bytes(),
        )
        .map_err(|v| bad(self.tag.clone(), v))?;

        if batch_size == 0 {
            return Err(bad(self.tag.clone(), "Batch size cannot be zero."));
        }

        let batch_range = match tokens.next() {
            Some(token) => {
                let token = token
                    .unwrap_string()
                    .map_err(|v| bad(self.tag.clone(), v))?;
                let (from, to) = token.split_once(':').ok_or_else(|| {
                    bad(
                        self.tag.clone(),
                        "Expected a batch range in the form 'from:to'.",
                    )
                })?;
                let from = parse_number::<u32>(from.trim().as_bytes())
                    .map_err(|v| bad(self.tag.clone(), v))?;
                let to = parse_number::<u32>(to.trim().as_bytes())
                    .map_err(|v| bad(self.tag.clone(), v))?;

                if from == 0 || to == 0 {
                    return Err(bad(self.tag.clone(), "Batch numbers start at one."));
                }

                Some((from, to))
            }
            None => None,
        };

        if tokens.next().is_some() {
            return Err(bad(self.tag.clone(), "Too many arguments for UIDBATCHES."));
        }

        Ok(uidbatches::Arguments {
            tag: self.tag,
            batch_size,
            batch_range,
        })
    }
}

