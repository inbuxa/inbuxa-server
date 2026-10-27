/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::{
    index::extractors::VisitText,
    metadata::{ArchivedMessageMetadata, HeaderId, HeaderList, MAX_VALUE_LEN, build::floor_str},
};
use mail_parser::{HeaderForm, HeaderName, HeaderValue, Message, thread_name};
use std::borrow::Cow;
use store::xxhash_rust::xxh3::xxh3_128;

#[derive(Debug, Default)]
pub struct ThreadFields<'m> {
    pub subject: &'m str,
    pub message_id: Option<String>,
    pub message_ids: Vec<u128>,
    pub sent_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadSubject<'x> {
    Resolved(&'x str),
    InHeaders,
}

impl<'m> ThreadFields<'m> {
    pub fn scan(message: &'m Message<'_>) -> Self {
        let mut fields = ThreadFields::default();
        let mut date_seen = false;
        for header in message.root_part().headers().iter().rev() {
            let value = header.value();
            match header.name() {
                HeaderName::MessageId => value.visit_text(|id| {
                    if !id.is_empty() {
                        if fields.message_id.is_none() {
                            fields.message_id = id.to_string().into();
                        }
                        fields.message_ids.push(xxh3_128(id.as_bytes()));
                    }
                }),
                HeaderName::InReplyTo | HeaderName::References | HeaderName::ResentMessageId => {
                    value.visit_text(|id| {
                        if !id.is_empty() {
                            fields.message_ids.push(xxh3_128(id.as_bytes()));
                        }
                    });
                }
                HeaderName::Subject if fields.subject.is_empty() => {
                    fields.subject = subject_thread_name(value);
                }
                HeaderName::Date if !date_seen => {
                    date_seen = true;
                    fields.sent_at = value.as_datetime().map(|date| date.to_timestamp());
                }
                _ => (),
            }
        }
        fields.message_ids.sort_unstable();
        fields.message_ids.dedup();
        fields
    }
}

impl ArchivedMessageMetadata {
    pub fn thread_subject(&self) -> ThreadSubject<'_> {
        let root = self.root();
        let name = thread_name(root.envelope().subject().unwrap_or_default());
        if !name.is_empty()
            || root
                .root_part()
                .headers()
                .all(HeaderId::SUBJECT)
                .nth(1)
                .is_none()
        {
            ThreadSubject::Resolved(name)
        } else {
            ThreadSubject::InHeaders
        }
    }

    pub fn thread_subject_in(&self, headers: &[u8]) -> Cow<'_, str> {
        self.thread_subject_with(self.root().root_part().headers(), headers)
    }

    pub fn thread_subject_with(&self, root: HeaderList<'_>, headers: &[u8]) -> Cow<'_, str> {
        if let ThreadSubject::Resolved(name) = self.thread_subject() {
            return Cow::Borrowed(name);
        }
        root.iter()
            .rev()
            .filter(|header| header.id() == HeaderId::SUBJECT)
            .find_map(|header| {
                let parsed = HeaderForm::Text.parse(header.raw_value(headers)?);
                let name = subject_thread_name(parsed.value());
                (!name.is_empty()).then(|| name.to_string())
            })
            .map_or(Cow::Borrowed(""), Cow::Owned)
    }
}

fn subject_thread_name<'x>(value: HeaderValue<'x>) -> &'x str {
    let subject = match value {
        HeaderValue::Text(text) => text,
        HeaderValue::TextList(list) => list.first().unwrap_or_default(),
        _ => "",
    };
    thread_name(floor_str(subject, MAX_VALUE_LEN))
}

