/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::{
    index::{
        MAX_MESSAGE_PARTS, attachment::AttachmentText, extractors::VisitText,
        subject::search_subject,
    },
    metadata::{
        AddressHeader, AddressItem, Addresses, ArchivedMessageMetadata, EnvelopeView, HeaderId,
        HeaderList, Occurrence, PartFlags, PartKind, PartSource, PartView,
    },
};
use common::config::mailstore::email::ExtractLimits;
use mail_parser::{HeaderForm, HeaderValue, html_to_text};
use nlp::{
    language::{
        Language,
        detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
    },
    tokenizers::word::WordTokenizer,
};
use std::{borrow::Cow, str::from_utf8};
use store::{
    ahash::AHashSet,
    backend::MAX_TOKEN_LENGTH,
    search::{EmailSearchField, IndexDocument, SearchField},
    write::SearchIndex,
};

struct DocumentBuilder<'x> {
    document: IndexDocument,
    detector: LanguageDetector,
    attachments: AttachmentText,
    index_fields: &'x AHashSet<SearchField>,
}

impl ArchivedMessageMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn index_document(
        &self,
        account_id: u32,
        document_id: u32,
        headers: &[u8],
        blob: &[u8],
        index_fields: &AHashSet<SearchField>,
        default_language: Language,
        extract_limits: &ExtractLimits,
    ) -> IndexDocument {
        let mut builder = DocumentBuilder {
            document: IndexDocument::new(SearchIndex::Email)
                .with_account_id(account_id)
                .with_document_id(document_id),
            detector: LanguageDetector::new(),
            attachments: AttachmentText::new(extract_limits),
            index_fields,
        };
        let raw = self.raw_message(Some(headers), blob);
        let source = PartSource::Raw(raw);
        let root = self.root();
        let mut language = Language::Unknown;

        for part in root.parts().take(MAX_MESSAGE_PARTS) {
            let part_language = part.language().unwrap_or(language);
            if part.id() == 0 {
                language = part_language;
                builder.index_envelope(root.envelope().addresses_of_interest());
                builder.index_root_headers(part.headers(), headers, part_language);
            }

            match part.kind() {
                PartKind::Text | PartKind::Html => {
                    let field = if part.flags().contains(PartFlags::IN_TEXT_BODY)
                        || part.flags().contains(PartFlags::IN_HTML_BODY)
                    {
                        EmailSearchField::Body
                    } else {
                        EmailSearchField::Attachment
                    };
                    if !builder.is_enabled(field.clone()) {
                        continue;
                    }
                    let Some(text) = part.plain_text(&source) else {
                        continue;
                    };
                    builder.index_part_text(part, &text, part_language, field);
                }
                PartKind::Binary if builder.is_enabled(EmailSearchField::Attachment) => {
                    builder.attachments.index_binary(
                        part,
                        &source,
                        &mut builder.document,
                        &mut builder.detector,
                        part_language,
                    );
                }
                PartKind::Message if builder.is_enabled(EmailSearchField::Attachment) => {
                    let Some(nested) = part.nested() else {
                        continue;
                    };
                    let nested_language =
                        nested.root_part().language().unwrap_or(Language::Unknown);
                    let nested_source = self.source(nested, raw);
                    if let Some(subject) = nested.envelope().subject() {
                        builder.index_text(EmailSearchField::Attachment, subject, nested_language);
                    }
                    let Some(nested_source) = nested_source else {
                        continue;
                    };
                    for sub_part in nested.parts().take(MAX_MESSAGE_PARTS) {
                        let language = sub_part.language().unwrap_or(nested_language);
                        match sub_part.kind() {
                            PartKind::Text | PartKind::Html => {
                                if let Some(text) = sub_part.plain_text(&nested_source) {
                                    builder.index_part_text(
                                        sub_part,
                                        &text,
                                        language,
                                        EmailSearchField::Attachment,
                                    );
                                }
                            }
                            PartKind::Binary => builder.attachments.index_binary(
                                sub_part,
                                &nested_source,
                                &mut builder.document,
                                &mut builder.detector,
                                language,
                            ),
                            _ => (),
                        }
                    }
                }
                _ => {}
            }
        }

        #[cfg(not(stalwart_tests))]
        builder.document.set_unknown_language(
            builder
                .detector
                .most_frequent_language()
                .unwrap_or(default_language),
        );

        #[cfg(stalwart_tests)]
        builder.document.set_unknown_language(default_language);
        builder.document
    }
}

impl DocumentBuilder<'_> {
    fn is_enabled(&self, field: EmailSearchField) -> bool {
        self.index_fields.is_empty() || self.index_fields.contains(&SearchField::Email(field))
    }

    fn index_text(&mut self, field: EmailSearchField, text: &str, language: Language) {
        if language.is_unknown() {
            self.detector.detect(text, MIN_LANGUAGE_SCORE);
        }
        self.document
            .index_text(SearchField::Email(field), text, language);
    }

    fn index_part_text(
        &mut self,
        part: PartView<'_>,
        text: &str,
        language: Language,
        field: EmailSearchField,
    ) {
        if self.is_enabled(field.clone())
            && !self.attachments.index_rtf(
                part,
                text,
                &mut self.document,
                &mut self.detector,
                language,
                field.clone(),
            )
        {
            self.index_text(field, text, language);
        }
    }

    fn index_envelope<'a>(&mut self, fields: [(EmailSearchField, Addresses<'a>); 4]) {
        for (field, addresses) in fields {
            if self.is_enabled(field.clone()) {
                let search_field = SearchField::Email(field);
                addresses.visit_text(|text| {
                    self.document
                        .index_text(search_field.clone(), text, Language::None);
                });
            }
        }
    }

    fn indexes_headers(&self) -> bool {
        #[cfg(not(stalwart_tests))]
        let index_headers = self
            .index_fields
            .contains(&SearchField::Email(EmailSearchField::Headers));

        #[cfg(stalwart_tests)]
        let index_headers = true;

        index_headers
    }

    fn index_root_headers(&mut self, root: HeaderList<'_>, headers: &[u8], language: Language) {
        let index_headers = self.indexes_headers();
        let index_subject = self.is_enabled(EmailSearchField::Subject);
        for header in root.iter().rev() {
            match header.id() {
                id @ (HeaderId::FROM | HeaderId::TO | HeaderId::CC | HeaderId::BCC) => {
                    if index_headers && let Some(name) = id.as_str() {
                        self.document
                            .insert_key_value(EmailSearchField::Headers, name, "");
                    }
                }
                HeaderId::SUBJECT => {
                    if index_headers {
                        self.document
                            .insert_key_value(EmailSearchField::Headers, "subject", "");
                    }
                    if index_subject
                        && let Some(raw) = headers.get(header.value_range())
                        && let Some(subject) = HeaderForm::Text.parse(raw).value().as_text()
                    {
                        self.index_text(
                            EmailSearchField::Subject,
                            &search_subject(subject),
                            language,
                        );
                    }
                }
                id if index_headers => {
                    let Some(field) = headers.get(header.field_range()) else {
                        continue;
                    };
                    let name = match id.as_str() {
                        Some(name) => Cow::Borrowed(name),
                        None => String::from_utf8_lossy(header.raw_name_in(field)),
                    };
                    let value = id.key_value(header.raw_value_in(field));
                    self.document
                        .insert_key_value(EmailSearchField::Headers, name, value);
                }
                _ => {}
            }
        }
    }
}

impl HeaderId {
    fn key_value_form(self) -> Option<HeaderForm> {
        match self {
            HeaderId::REPLY_TO | HeaderId::SENDER | HeaderId::LIST_ID => {
                Some(HeaderForm::Addresses)
            }
            HeaderId::COMMENTS
            | HeaderId::CONTENT_DESCRIPTION
            | HeaderId::CONTENT_LOCATION
            | HeaderId::CONTENT_TRANSFER_ENCODING => Some(HeaderForm::Text),
            HeaderId::IN_REPLY_TO
            | HeaderId::MESSAGE_ID
            | HeaderId::REFERENCES
            | HeaderId::RESENT_MESSAGE_ID
            | HeaderId::CONTENT_ID => Some(HeaderForm::MessageIds),
            HeaderId::KEYWORDS | HeaderId::CONTENT_LANGUAGE => Some(HeaderForm::CommaList),
            _ => None,
        }
    }

    fn key_value(self, raw: &[u8]) -> String {
        let mut value = String::with_capacity(raw.len());
        let mut push = |text: &str| {
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(text);
        };
        if let Some(form) = self.key_value_form() {
            let parsed = form.parse(raw);
            match parsed.value() {
                parsed @ HeaderValue::Address(_) => {
                    parsed.visit_addresses(|_, text| push(text));
                    return value;
                }
                parsed @ (HeaderValue::Text(_) | HeaderValue::TextList(_)) => {
                    parsed.visit_text(&mut push);
                    return value;
                }
                _ => {}
            }
        }
        for word in WordTokenizer::new(from_utf8(raw).unwrap_or_default(), MAX_TOKEN_LENGTH) {
            push(word.word.as_ref());
        }
        value
    }
}

impl<'a> PartView<'a> {
    pub fn plain_text<'x>(&self, source: &PartSource<'x>) -> Option<Cow<'x, str>> {
        let text = self.text(source)?.text;
        Some(if self.kind() == PartKind::Html {
            Cow::Owned(html_to_text(&text))
        } else {
            text
        })
    }
}

impl<'a> Addresses<'a> {
    fn visit_text(&self, mut visitor: impl FnMut(&'a str)) {
        for item in self.iter() {
            match item {
                AddressItem::Mailbox(mailbox) => {
                    mailbox
                        .name
                        .into_iter()
                        .chain(mailbox.address)
                        .for_each(&mut visitor);
                }
                AddressItem::Group(group) => {
                    group.name.into_iter().for_each(&mut visitor);
                    for mailbox in group.members.mailboxes() {
                        mailbox
                            .name
                            .into_iter()
                            .chain(mailbox.address)
                            .for_each(&mut visitor);
                    }
                }
            }
        }
    }
}

impl<'a> EnvelopeView<'a> {
    fn addresses_of_interest(&self) -> [(EmailSearchField, Addresses<'a>); 4] {
        [
            (
                EmailSearchField::From,
                self.addresses(AddressHeader::From, Occurrence::All),
            ),
            (
                EmailSearchField::To,
                self.addresses(AddressHeader::To, Occurrence::All),
            ),
            (
                EmailSearchField::Cc,
                self.addresses(AddressHeader::Cc, Occurrence::All),
            ),
            (
                EmailSearchField::Bcc,
                self.addresses(AddressHeader::Bcc, Occurrence::All),
            ),
        ]
    }
}

