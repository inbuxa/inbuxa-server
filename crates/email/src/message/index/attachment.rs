/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::metadata::{ArchivedMessageMetadata, PartKind, PartSource, PartView};
use common::config::mailstore::email::ExtractLimits;
use nlp::language::{
    Language,
    detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use store::search::{EmailSearchField, IndexDocument, SearchField};
use text_extract::{Extractor, Format, Hints, Limits};

const MESSAGE_TEXT_DOCUMENTS: usize = 2;
const MAX_LANGUAGE_SAMPLE: usize = 64 << 10;

pub(super) struct AttachmentText {
    extractor: Option<Extractor>,
    limits: Limits,
    text: String,
    remaining_text: usize,
    remaining_decompressed: u64,
}

pub fn document_limits(config: &ExtractLimits) -> Limits {
    Limits {
        max_input_bytes: config.max_document_size,
        max_output_bytes: config.max_text_size,
        max_entries: config.max_archive_entries,
        max_parts: config.max_parts,
        max_part_bytes: config.max_part_size.min(config.max_decompressed_size),
        max_total_bytes: config.max_decompressed_size,
        max_rtf_depth: config.max_rtf_depth,
        max_pdf_objects: config.max_pdf_objects,
    }
}

impl<'a> PartView<'a> {
    pub fn extraction_hints(&self) -> Hints<'a> {
        let mut hints = Hints::new();
        if let Some(content_type) = self.content_type() {
            hints = hints.with_media_type_parts(
                content_type.ctype(),
                content_type.subtype().unwrap_or_default(),
            );
        }
        if let Some(name) = self.attachment_name() {
            hints = hints.with_file_name(name);
        }
        hints
    }

    pub fn has_extractable_text(&self) -> bool {
        match self.kind() {
            PartKind::Binary => self.extraction_hints().may_be_supported(),
            PartKind::Text => self.is_rtf_text(),
            _ => false,
        }
    }

    fn is_rtf_text(&self) -> bool {
        match self.content_type() {
            Some(content_type) if content_type.ctype().eq_ignore_ascii_case("text") => content_type
                .subtype()
                .is_some_and(|subtype| subtype.eq_ignore_ascii_case("rtf")),
            _ => self.extraction_hints().format() == Some(Format::Rtf),
        }
    }
}

impl ArchivedMessageMetadata {
    pub fn has_extractable_attachments(&self) -> bool {
        self.parts().any(|part| part.has_extractable_text())
    }
}

impl AttachmentText {
    pub(super) fn new(config: &ExtractLimits) -> Self {
        AttachmentText {
            extractor: None,
            limits: document_limits(config),
            text: String::new(),
            remaining_text: config.max_text_size.saturating_mul(MESSAGE_TEXT_DOCUMENTS),
            remaining_decompressed: config.max_decompressed_size,
        }
    }

    pub(super) fn index_binary(
        &mut self,
        part: PartView<'_>,
        source: &PartSource<'_>,
        document: &mut IndexDocument,
        detector: &mut LanguageDetector,
        language: Language,
    ) {
        let hints = part.extraction_hints();
        if !hints.may_be_supported()
            || self.remaining_text == 0
            || part.decoded_size() as usize > self.limits.max_input_bytes
        {
            return;
        }
        if self.extract(&part.decoded(source), hints) {
            self.index(document, detector, language);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn index_rtf(
        &mut self,
        part: PartView<'_>,
        contents: &str,
        document: &mut IndexDocument,
        detector: &mut LanguageDetector,
        language: Language,
        field: EmailSearchField,
    ) -> bool {
        if part.is_rtf_text() && self.extract(contents.as_bytes(), part.extraction_hints()) {
            self.index_field(document, detector, language, field);
            true
        } else {
            false
        }
    }

    fn extract(&mut self, contents: &[u8], hints: Hints<'_>) -> bool {
        if self.remaining_text == 0
            || (self.remaining_decompressed == 0 && hints.format() != Some(Format::Rtf))
        {
            return false;
        }
        let defaults = &self.limits;
        let extractor = self
            .extractor
            .get_or_insert_with(|| Extractor::new(defaults.clone()));
        let limits = extractor.limits_mut();
        limits.max_output_bytes = defaults.max_output_bytes.min(self.remaining_text);
        limits.max_total_bytes = defaults.max_total_bytes.min(self.remaining_decompressed);
        self.text.clear();
        let text = &mut self.text;
        match catch_unwind(AssertUnwindSafe(|| {
            extractor.extract(contents, hints, text)
        })) {
            Ok(Ok(extraction)) => {
                self.remaining_text = self.remaining_text.saturating_sub(extraction.bytes_written);
                self.remaining_decompressed = self
                    .remaining_decompressed
                    .saturating_sub(extraction.bytes_decompressed);
                !self.text.is_empty()
            }
            Ok(Err(failure)) => {
                self.remaining_decompressed = self
                    .remaining_decompressed
                    .saturating_sub(failure.bytes_decompressed);
                false
            }
            Err(_) => {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "Attachment text extraction panicked",
                );
                self.extractor = None;
                self.remaining_text = 0;
                false
            }
        }
    }

    fn index(
        &self,
        document: &mut IndexDocument,
        detector: &mut LanguageDetector,
        language: Language,
    ) {
        self.index_field(document, detector, language, EmailSearchField::Attachment);
    }

    fn index_field(
        &self,
        document: &mut IndexDocument,
        detector: &mut LanguageDetector,
        language: Language,
        field: EmailSearchField,
    ) {
        if language.is_unknown() {
            detector.detect(language_sample(&self.text), MIN_LANGUAGE_SCORE);
        }
        document.index_text(SearchField::Email(field), &self.text, language);
    }
}

fn language_sample(text: &str) -> &str {
    if text.len() <= MAX_LANGUAGE_SAMPLE {
        return text;
    }
    text.get(..text.floor_char_boundary(MAX_LANGUAGE_SAMPLE))
        .unwrap_or_default()
}

