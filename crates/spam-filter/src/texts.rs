/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::modules::html::{HtmlText, HtmlToken};
use common::config::mailstore::spamfilter::SpamTextLimits;
use mail_parser::{Message, MessagePart, PartId};
use memchr::{memrchr, memrchr3};
use std::{borrow::Cow, sync::OnceLock};


const MAX_TEXT_BYTES_PER_RAW_BYTE: usize = 3;

pub struct MessageTexts<'x> {
    texts: Vec<PartText<'x>>,
    html_texts: Box<[OnceLock<HtmlText>]>,
}

pub enum PartText<'x> {
    NotText,
    Whole(Cow<'x, str>),
    Prefix(Cow<'x, str>),
    Skipped,
}

impl<'x> MessageTexts<'x> {
    pub fn new(message: &'x Message<'x>, limits: SpamTextLimits) -> Self {
        let max_text = message
            .raw()
            .len()
            .saturating_mul(MAX_TEXT_BYTES_PER_RAW_BYTE);
        if max_text
            <= limits
                .max_body
                .min(limits.max_attachment)
                .min(limits.max_message)
        {
            return Self::with_texts(
                message
                    .parts()
                    .map(|part| part.text().map_or(PartText::NotText, PartText::Whole))
                    .collect(),
            );
        }

        let mut texts: Vec<_> = message
            .parts()
            .map(|part| {
                if part.is_text() {
                    PartText::Skipped
                } else {
                    PartText::NotText
                }
            })
            .collect();

        let html = message.html_body().find(MessagePart::is_text);
        let text = message
            .text_body()
            .find(MessagePart::is_text)
            .filter(|text| html.is_none_or(|html| html.id() != text.id()));
        let primary = [html.map(|part| part.id()), text.map(|part| part.id())];
        let other_body = message.parts().filter(|part| {
            part.is_text() && is_body_part(*part) && !primary.contains(&Some(part.id()))
        });
        let rest = message
            .parts()
            .filter(|part| part.is_text() && !is_body_part(*part));

        let mut budget = limits.max_message;
        for part in [html, text]
            .into_iter()
            .flatten()
            .chain(other_body)
            .chain(rest)
        {
            let part_limit = if is_body_part(part) {
                limits.max_body
            } else {
                limits.max_attachment
            };
            let text = PartText::bounded(part, part_limit.min(budget));
            budget = budget.saturating_sub(text.text().map_or(0, str::len));
            if let Some(slot) = texts.get_mut(part.id() as usize) {
                *slot = text;
            }
        }

        Self::with_texts(texts)
    }

    fn with_texts(texts: Vec<PartText<'x>>) -> Self {
        MessageTexts {
            html_texts: texts.iter().map(|_| OnceLock::new()).collect(),
            texts,
        }
    }

    pub fn get(&self, part_id: PartId) -> Option<&str> {
        self.part(part_id)?.text()
    }

    pub fn part(&self, part_id: PartId) -> Option<&PartText<'x>> {
        self.texts.get(part_id as usize)
    }

    pub fn is_cut(&self, part_id: PartId) -> bool {
        self.part(part_id).is_some_and(PartText::is_cut)
    }

    pub fn html_text(&self, part_id: PartId, html_tokens: &[HtmlToken<'_>]) -> Option<&HtmlText> {
        self.html_texts
            .get(part_id as usize)
            .map(|text| text.get_or_init(|| HtmlText::new(html_tokens)))
    }
}

impl<'x> PartText<'x> {
    fn bounded(part: MessagePart<'x>, limit: usize) -> Self {
        if limit == 0 {
            return PartText::Skipped;
        }
        let Some(text) = part.text_prefix_bytes(limit.saturating_add(char::MAX_LEN_UTF8)) else {
            return PartText::NotText;
        };
        if text.len() <= limit {
            return PartText::Whole(text);
        }
        match cut_end(&text, limit) {
            0 => PartText::Skipped,
            end => PartText::Prefix(match text {
                Cow::Borrowed(text) => Cow::Borrowed(text.get(..end).unwrap_or(text)),
                Cow::Owned(mut text) => {
                    text.truncate(end);
                    Cow::Owned(text)
                }
            }),
        }
    }

    pub fn text(&self) -> Option<&str> {
        match self {
            PartText::Whole(text) | PartText::Prefix(text) => Some(text),
            PartText::NotText | PartText::Skipped => None,
        }
    }

    pub fn is_cut(&self) -> bool {
        matches!(self, PartText::Prefix(_) | PartText::Skipped)
    }
}

fn cut_end(text: &str, limit: usize) -> usize {
    let start = limit / 2;
    text.as_bytes()
        .get(start..limit)
        .and_then(|tail| memrchr(b'\n', tail).or_else(|| memrchr3(b' ', b'\t', b'>', tail)))
        .map_or_else(|| text.floor_char_boundary(limit), |pos| start + pos + 1)
}

pub(crate) fn is_body_part(part: MessagePart<'_>) -> bool {
    part.message().id() == 0 && (part.in_text_body() || part.in_html_body())
}
