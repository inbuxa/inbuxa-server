/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */


use super::{BodyValueOptions, JmapMap, JmapValue};
use crate::message::metadata::ArchivedMessageMetadata;
use jmap_proto::object::email::EmailProperty;
use jmap_tools::{Key, Value};

const NODE_BYTES: u64 = size_of::<(Key<'static, EmailProperty>, JmapValue<'static>)>() as u64;
const PROPERTY_BYTES: u64 = 2 * NODE_BYTES;
const ADDRESS_BYTES: u64 = 4 * NODE_BYTES;
const PART_PROPERTY_BYTES: u64 = 2 * NODE_BYTES;
const BODY_VALUE_BYTES: u64 = 4 * NODE_BYTES;
const LARGE_EMAIL_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmailEstimate {
    content: bool,
    fixed: u64,
    envelope_properties: u64,
    header_properties: u64,
    structure_properties: u64,
    part_bytes: u64,
    body_values: Option<BodyValueOptions>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmailCost {
    pub bytes: u64,
    pub light: u64,
    body_values: u64,
    headers: u64,
}

impl EmailEstimate {
    pub fn new(
        properties: &[EmailProperty],
        body_properties: &[EmailProperty],
        options: &BodyValueOptions,
    ) -> Self {
        let mut estimate = EmailEstimate {
            content: false,
            fixed: properties.len() as u64 * PROPERTY_BYTES,
            envelope_properties: 0,
            header_properties: 0,
            structure_properties: 0,
            part_bytes: 0,
            body_values: None,
        };
        let mut body_headers = 0;
        for property in body_properties {
            estimate.part_bytes += PART_PROPERTY_BYTES;
            match property {
                EmailProperty::Header(header) => {
                    estimate.part_bytes += header.header.len() as u64;
                    body_headers += 1;
                }
                EmailProperty::Headers => body_headers += 1,
                _ => {}
            }
        }
        for property in properties {
            match property {
                EmailProperty::Header(header) => {
                    estimate.fixed += header.header.len() as u64;
                    estimate.header_properties += 1;
                }
                EmailProperty::Headers => estimate.header_properties += 1,
                EmailProperty::Subject
                | EmailProperty::MessageId
                | EmailProperty::InReplyTo
                | EmailProperty::References
                | EmailProperty::Sender
                | EmailProperty::From
                | EmailProperty::To
                | EmailProperty::Cc
                | EmailProperty::Bcc
                | EmailProperty::ReplyTo => estimate.envelope_properties = 1,
                EmailProperty::TextBody
                | EmailProperty::HtmlBody
                | EmailProperty::Attachments
                | EmailProperty::BodyStructure => estimate.structure_properties += 1,
                EmailProperty::BodyValues if options.fetches_any() => {
                    estimate.body_values = Some(*options);
                }
                _ => {}
            }
        }
        estimate.content = estimate.header_properties != 0
            || estimate.body_values.is_some()
            || (body_headers != 0 && estimate.structure_properties != 0);
        if body_headers != 0 {
            estimate.header_properties += body_headers * estimate.structure_properties;
        }
        estimate
    }

    pub fn cost(&self, metadata: &ArchivedMessageMetadata) -> EmailCost {
        let strings = metadata.strings.len() as u64;
        let mut cost = EmailCost {
            bytes: self.fixed,
            light: 0,
            body_values: 0,
            headers: self.header_properties * metadata.headers_len() as u64,
        };
        if self.envelope_properties != 0 {
            cost.bytes += strings
                + metadata.addresses.len() as u64 * ADDRESS_BYTES
                + metadata.texts.len() as u64 * NODE_BYTES;
        }
        if self.structure_properties != 0 {
            cost.bytes += self.structure_properties
                * (strings
                    + metadata.parts.len() as u64 * self.part_bytes
                    + metadata.params.len() as u64 * NODE_BYTES);
        }
        if !self.content && cost.bytes < LARGE_EMAIL_BYTES {
            return EmailCost {
                light: cost.bytes,
                ..EmailCost::default()
            };
        }
        if let Some(options) = &self.body_values {
            let max_bytes = options.max_bytes as u64;
            for part in metadata.root().parts().filter(|part| options.fetches(part)) {
                let decoded = u64::from(part.decoded_size());
                cost.body_values += if max_bytes != 0 {
                    decoded.min(max_bytes)
                } else {
                    decoded
                };
                cost.bytes += BODY_VALUE_BYTES;
            }
        }
        cost.bytes += cost.body_values + cost.headers;
        cost
    }

    pub fn overrun(&self, email: &JmapMap<'_>, cost: &EmailCost) -> u64 {
        if !self.content {
            return 0;
        }
        let mut body_values = 0;
        let mut headers = 0;
        for (key, value) in email.iter() {
            match key {
                Key::Property(EmailProperty::BodyValues) => {
                    if let Value::Object(values) = value {
                        body_values += values
                            .iter()
                            .filter_map(|(_, value)| match value {
                                Value::Object(value) => {
                                    match value.get(&Key::Property(EmailProperty::Value)) {
                                        Some(Value::Str(text)) => Some(text.len() as u64),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            })
                            .sum::<u64>();
                    }
                }
                Key::Property(EmailProperty::Header(_) | EmailProperty::Headers) => {
                    headers += tree_bytes(value);
                }
                Key::Property(
                    EmailProperty::TextBody
                    | EmailProperty::HtmlBody
                    | EmailProperty::Attachments
                    | EmailProperty::BodyStructure,
                ) if self.header_properties != 0 => {
                    headers += part_header_bytes(value);
                }
                _ => {}
            }
        }
        body_values.saturating_sub(cost.body_values) + headers.saturating_sub(cost.headers)
    }
}

fn tree_bytes(value: &JmapValue<'_>) -> u64 {
    match value {
        Value::Str(text) => text.len() as u64,
        Value::Array(items) => items.iter().map(|item| NODE_BYTES + tree_bytes(item)).sum(),
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| NODE_BYTES + key_bytes(key) + tree_bytes(value))
            .sum(),
        _ => 0,
    }
}

fn part_header_bytes(value: &JmapValue<'_>) -> u64 {
    match value {
        Value::Array(items) => items.iter().map(part_header_bytes).sum(),
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| match key {
                Key::Property(EmailProperty::Header(_) | EmailProperty::Headers) => {
                    NODE_BYTES + key_bytes(key) + tree_bytes(value)
                }
                Key::Property(EmailProperty::SubParts) => part_header_bytes(value),
                _ => 0,
            })
            .sum(),
        _ => 0,
    }
}

fn key_bytes(key: &Key<'_, EmailProperty>) -> u64 {
    match key {
        Key::Property(EmailProperty::Header(header)) => header.header.len() as u64,
        Key::Property(_) => 0,
        Key::Borrowed(key) => key.len() as u64,
        Key::Owned(key) => key.len() as u64,
    }
}
