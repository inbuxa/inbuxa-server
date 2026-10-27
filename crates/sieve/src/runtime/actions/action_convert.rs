/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::super::tests::TestResult;
use crate::{
    Context, Sieve,
    bytecode::ops,
    runtime::{
        RuntimeError,
        message::{
            body::TextForm,
            edits::{BodyEdit, BodyFormat, BodyKind, TransferEncoding},
            headers::HeaderRef,
            parts::{PartCursor, ROOT_PART, Scope},
        },
    },
};
use mail_parser::{HeaderName, PartKind};

#[derive(Clone, Copy)]
enum Conversion {
    TextToHtml,
    TextPlainToHtml,
    HtmlToText,
}

impl<'x> Context<'x> {
    pub(crate) fn exec_convert(
        &mut self,
        script: &'x Sieve<'x>,
        convert: &ops::Convert,
    ) -> Result<TestResult, RuntimeError> {
        let from_media_type = self.eval_value(script, convert.from_media_type)?;
        let to_media_type = self.eval_value(script, convert.to_media_type)?;

        let from_media_type = from_media_type.to_string();
        let to_media_type = to_media_type.to_string();

        if from_media_type.eq_ignore_ascii_case(to_media_type.as_ref()) {
            return Ok(TestResult::Bool(false ^ convert.is_not));
        }

        let conversion = if (from_media_type.eq_ignore_ascii_case("text")
            || from_media_type.starts_with("text/"))
            && to_media_type.eq_ignore_ascii_case("text/html")
        {
            if from_media_type.eq_ignore_ascii_case("text") {
                Conversion::TextPlainToHtml
            } else {
                Conversion::TextToHtml
            }
        } else if from_media_type.eq_ignore_ascii_case("text/html")
            && to_media_type.eq_ignore_ascii_case("text/plain")
        {
            Conversion::HtmlToText
        } else {
            return Ok(TestResult::Bool(false ^ convert.is_not));
        };
        let mut did_convert = false;
        let mut parts = match self.root_part() {
            Some(root) => PartCursor::subtree(root, true, Scope::Message),
            None => PartCursor::default(),
        };
        while let Some(part) = self.advance(&mut parts) {
            let (text, kind, content_type) = match (self.part_kind(part), conversion) {
                (PartKind::Html, Conversion::HtmlToText) => (
                    self.part_text(part, TextForm::Plain),
                    BodyKind::Text,
                    "text/plain; charset=utf-8",
                ),
                (PartKind::Text, Conversion::TextToHtml) => (
                    self.part_text(part, TextForm::Html),
                    BodyKind::Html,
                    "text/html; charset=utf-8",
                ),
                (PartKind::Text, Conversion::TextPlainToHtml)
                    if self
                        .part_content_type(part)
                        .is_some_and(|(_, subtype)| subtype.eq_ignore_ascii_case("plain")) =>
                {
                    (
                        self.part_text(part, TextForm::Html),
                        BodyKind::Html,
                        "text/html; charset=utf-8",
                    )
                }
                _ => continue,
            };
            let Some(text) = text else {
                continue;
            };
            let part_id = part.id();
            let (encoding, encoded_len) = TransferEncoding::select(text);
            let previous_size = match self.edits.body(part_id) {
                Some(edited) => edited.encoded_len,
                None => part.raw().len(),
            };

            let mut headers = Vec::new();
            if part_id == ROOT_PART {
                let mut add_mime_version = true;
                let previous = self.part_headers(part);
                headers.reserve(previous.size_hint().0 + 3);
                headers.extend(previous.filter(|header| {
                    let name = header.name();
                    add_mime_version &= name != HeaderName::MimeVersion;
                    !name.is_content_header()
                }));
                if add_mime_version {
                    headers.push(self.add_header(HeaderName::MimeVersion, "1.0"));
                }
            }
            headers.push(self.add_header(HeaderName::ContentType, content_type));
            if let Some(cte) = encoding.header_value() {
                headers.push(self.add_header(HeaderName::ContentTransferEncoding, cte));
            }

            let headers_size = headers.iter().map(HeaderRef::len).sum::<usize>();
            self.message_size =
                (self.message_size + headers_size + encoded_len + 2).saturating_sub(previous_size);
            self.edits.set_headers(part_id, headers);
            self.set_part_body(
                part_id,
                BodyEdit {
                    text,
                    kind,
                    format: BodyFormat::Content,
                    encoding,
                    encoded_len,
                },
            );
            did_convert = true;
        }

        if did_convert {
            self.has_changes = true;
        }

        Ok(TestResult::Bool(did_convert ^ convert.is_not))
    }
}
