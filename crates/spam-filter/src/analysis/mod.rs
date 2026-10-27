/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Recipient, SpamFilterContext, SpamFilterInput, SpamFilterOutput, SpamFilterResult, TextPart,
};
use common::{Server, config::mailstore::spamfilter::Location};
use compact_str::CompactString;
use mail_parser::{Header, HeaderForm};
use memchr::memchr2_iter;
use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
};

pub mod classifier;
pub mod date;
pub mod dmarc;
pub mod domain;
pub mod ehlo;
pub mod from;
pub mod headers;
pub mod html;
pub mod init;
pub mod ip;
pub mod messageid;
pub mod mime;
mod mime_types;
pub mod pyzor;
pub mod received;
pub mod recipient;
pub mod replyto;
pub mod rules;
pub mod score;
pub mod subject;
pub mod url;


impl SpamFilterInput<'_> {
    pub fn header_as_address(&self, header: &Header<'_>) -> Option<String> {
        HeaderForm::Addresses
            .parse(header.raw_value())
            .value()
            .as_address()?
            .first()?
            .address()
            .map(str::to_string)
    }
}

impl SpamFilterOutput<'_> {
    pub fn all_recipients(&self) -> impl Iterator<Item = &Recipient> {
        self.recipients_to
            .iter()
            .chain(self.recipients_cc.iter())
            .chain(self.recipients_bcc.iter())
    }

    pub fn text_body(&self, input: &SpamFilterInput<'_>) -> Option<&str> {
        input
            .first_body_part()
            .and_then(|idx| self.text_parts.get(idx as usize))
            .and_then(|part| match part {
                TextPart::Plain { text_body, .. } => Some(*text_body),
                TextPart::Html { text_body, .. } => Some(*text_body),
                TextPart::None => None,
            })
    }
}

impl SpamFilterContext<'_> {
    pub fn text_body(&self) -> Option<&str> {
        self.output.text_body(&self.input)
    }
}

impl SpamFilterResult {
    pub fn add_tag(&mut self, tag: impl Into<CompactString>) {
        self.tags.insert(tag.into());
    }

    pub fn has_tag(&self, tag: impl AsRef<str>) -> bool {
        self.tags.contains(tag.as_ref())
    }

    pub fn classifier_probability(&self) -> Option<f32> {
        let mut total = 0.0f32;
        let mut count = 0u32;
        for confidence in self.classifier_confidence.iter().flatten() {
            total += confidence;
            count += 1;
        }
        (count > 0).then(|| total / count as f32)
    }
}

#[derive(Debug)]
pub struct ElementLocation<T> {
    pub element: T,
    pub location: Location,
}

impl<T: Hash> Hash for ElementLocation<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.element.hash(state);
    }
}

impl<T: PartialEq> PartialEq for ElementLocation<T> {
    fn eq(&self, other: &Self) -> bool {
        self.element.eq(&other.element)
    }
}

impl<T: Eq> Eq for ElementLocation<T> {}

impl std::borrow::Borrow<crate::Email> for ElementLocation<Recipient> {
    fn borrow(&self) -> &crate::Email {
        &self.element.email
    }
}

impl std::borrow::Borrow<str> for ElementLocation<crate::analysis::url::UrlParts<'_>> {
    fn borrow(&self) -> &str {
        self.element.url.as_str()
    }
}

impl<T> ElementLocation<T> {
    pub fn new(element: T, location: impl Into<Location>) -> Self {
        Self {
            element,
            location: location.into(),
        }
    }
}

pub(crate) async fn is_trusted_domain(server: &Server, domain: &str, span_id: u64) -> bool {
    if let Some(store) = server.get_lookup_store("trusted-domains") {
        match store.key_exists(domain).await {
            Ok(true) => return true,
            Ok(false) => (),
            Err(err) => {
                trc::error!(err.span_id(span_id).caused_by(trc::location!()));
            }
        }
    }

    match server.domain(domain).await {
        Ok(result) => result.is_some(),
        Err(err) => {
            trc::error!(err.span_id(span_id).caused_by(trc::location!()));
            false
        }
    }
}

pub(crate) async fn is_url_redirector(server: &Server, url: &str, span_id: u64) -> bool {
    if let Some(store) = server.get_lookup_store("url-redirectors") {
        match store.key_exists(url).await {
            Ok(result) => result,
            Err(err) => {
                trc::error!(err.span_id(span_id).caused_by(trc::location!()));
                false
            }
        }
    } else {
        false
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ExcessEncoding {
    None,
    QuotedPrintable,
    Base64,
    Other,
}

#[inline]
pub(crate) fn excess_encoding(text: &str) -> ExcessEncoding {
    if !text.contains("=?") || !text.contains("?=") {
        return ExcessEncoding::None;
    }

    let bytes = text.as_bytes();
    let mut has_qp = false;
    let mut has_base64 = false;

    for (pos, _) in text.match_indices('?') {
        if bytes.get(pos + 2) == Some(&b'?') {
            match bytes.get(pos + 1) {
                Some(b'q' | b'Q') => has_qp = true,
                Some(b'b' | b'B') => has_base64 = true,
                _ => {}
            }
        }
    }

    if has_qp {
        ExcessEncoding::QuotedPrintable
    } else if has_base64 {
        ExcessEncoding::Base64
    } else {
        ExcessEncoding::Other
    }
}

pub(crate) fn eq_lowercase_str(left: &str, right: &str) -> bool {
    if left.is_ascii() && right.is_ascii() {
        left.eq_ignore_ascii_case(right)
    } else {
        left.to_lowercase() == right.to_lowercase()
    }
}

pub(crate) fn to_lowercase_cow(text: &str) -> Cow<'_, str> {
    if text.is_ascii() {
        if text.as_bytes().iter().any(u8::is_ascii_uppercase) {
            Cow::Owned(text.to_ascii_lowercase())
        } else {
            Cow::Borrowed(text)
        }
    } else {
        Cow::Owned(text.to_lowercase())
    }
}

pub(crate) fn eq_lowercase(text: &str, lowercase_literal: &str) -> bool {
    debug_assert!(
        lowercase_literal
            .bytes()
            .all(|b| b.is_ascii() && !b.is_ascii_uppercase())
    );
    text.chars()
        .flat_map(char::to_lowercase)
        .eq(lowercase_literal.chars())
}

pub(crate) fn starts_with_ignore_ascii_case(text: &str, prefix: &str) -> bool {
    text.as_bytes()
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix.as_bytes()))
}

pub(crate) fn contains_ignore_ascii_case(text: &str, needle: &str) -> bool {
    let haystack = text.as_bytes();
    let Some((&first, rest)) = needle.as_bytes().split_first() else {
        return true;
    };
    memchr2_iter(
        first.to_ascii_lowercase(),
        first.to_ascii_uppercase(),
        haystack,
    )
    .any(|pos| {
        haystack
            .get(pos + 1..pos + 1 + rest.len())
            .is_some_and(|tail| tail.eq_ignore_ascii_case(rest))
    })
}

