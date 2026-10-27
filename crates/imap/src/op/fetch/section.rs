/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    source::{DecodedSources, SourceView},
    structure::Binary,
};
use email::message::metadata::{
    HeaderList, HeaderMatcher, HeaderView, MessageView, PartFlags, PartKind, PartView, RawMessage,
};
use imap_proto::protocol::{
    fetch::{BodyContents, Section},
    push_int,
};
use std::ops::Range;
use utils::chained_bytes::ChainedBytes;

const CONTENT_PREFIX: &[u8] = b"content-";
const MAX_FIELDS_CAPACITY: usize = 16 * 1024;

pub(super) trait MessageSections {
    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
    );
    fn header<'x>(&self, raw: RawMessage<'x>) -> Option<ChainedBytes<'x>>;
    fn body_section<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[Section],
        partial: Option<(u32, u32)>,
        matcher: Option<&HeaderMatcher>,
    ) -> Option<BodyContents<'x>>;
    fn binary<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[u32],
        partial: Option<(u32, u32)>,
    ) -> Binary<BodyContents<'x>>;
    fn binary_size(&self, sections: &[u32]) -> Binary<usize>;
}

impl MessageSections for MessageView<'_> {
    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
    ) {
        let part = self.root_part();
        let fields = part.headers();
        let gap = part.header_gap(&SourceView::Bytes(headers));
        if gap.is_empty() {
            fields.write_header_fields(buf, headers, section, matcher, |_| true);
        } else {
            fields.write_header_fields(buf, headers, section, matcher, |header| {
                !gap.contains(&header.field_range().start)
            });
        }
    }

    fn header<'x>(&self, raw: RawMessage<'x>) -> Option<ChainedBytes<'x>> {
        let part = self.root_part();
        let source = SourceView::Raw(raw);
        source.view_without(part.header_range(), part.header_gap(&source))
    }

    fn body_section<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[Section],
        partial: Option<(u32, u32)>,
        matcher: Option<&HeaderMatcher>,
    ) -> Option<BodyContents<'x>> {
        let mut part = self.root_part();
        if sections.is_empty() {
            return raw
                .view(part.raw_range())
                .map(|bytes| BodyContents::Bytes(bytes).partial(partial));
        }

        let mut sections_iter = sections.iter().enumerate().peekable();
        while let Some((section_num, section)) = sections_iter.next() {
            match section {
                Section::Part { num } => {
                    part = if part.is_multipart() {
                        part.child((*num).saturating_sub(1) as usize)?
                    } else if *num == 1
                        && (section_num == sections.len() - 1
                            || part.is_message()
                            || (part.is_message_root()
                                && matches!(sections_iter.peek(), Some((_, Section::Mime)))))
                    {
                        part
                    } else {
                        return None;
                    };

                    if part.is_message()
                        && let Some((
                            _,
                            Section::Part { .. }
                            | Section::Header
                            | Section::HeaderFields { .. }
                            | Section::Text,
                        )) = sections_iter.peek()
                    {
                        part = part.nested()?.root_part();
                    }
                }
                Section::Header => {
                    let source = sources.source(part.message(), raw)?;
                    return source
                        .view_without(part.header_range(), part.header_gap(&source))
                        .map(|bytes| BodyContents::Bytes(bytes).partial(partial));
                }
                Section::HeaderFields { not, fields } => {
                    let built;
                    let matcher = match matcher {
                        Some(matcher) => matcher,
                        None => {
                            built = HeaderMatcher::new(fields.iter().map(String::as_str));
                            &built
                        }
                    };
                    return part.fields_section(sources, raw, partial, |source| {
                        part.collect_fields(source, |header, field| {
                            matcher.matches_field(header, field) != *not
                        })
                    });
                }
                Section::Text => {
                    let message = part.message();
                    let source = sources.source(message, raw)?;
                    let mut range = part.body_range();
                    if part.is_message_root()
                        && let Some(container) = message.container()
                    {
                        let end = if message
                            .source_part()
                            .is_some_and(|source_part| source_part.id() == container.id())
                        {
                            source.len()
                        } else {
                            container.offset_end()
                        };
                        if end > range.end {
                            range.end = end;
                        }
                    }
                    return source
                        .view(range)
                        .map(|bytes| BodyContents::Bytes(bytes).partial(partial));
                }
                Section::Mime => {
                    if !part.is_message_root() {
                        return sources
                            .source(part.message(), raw)?
                            .view(part.header_range())
                            .map(|bytes| BodyContents::Bytes(bytes).partial(partial));
                    }
                    return part.fields_section(sources, raw, partial, |source| {
                        part.collect_fields(source, |header, field| header.is_mime_field(field))
                    });
                }
            }
        }

        sources
            .source(part.message(), raw)?
            .view(part.body_range())
            .map(|bytes| BodyContents::Bytes(bytes).partial(partial))
    }

    fn binary<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[u32],
        partial: Option<(u32, u32)>,
    ) -> Binary<BodyContents<'x>> {
        let Some(part) = self.root_part().descend(sections) else {
            return Binary::Missing;
        };
        if part.flags().contains(PartFlags::UNKNOWN_TRANSFER_ENCODING) {
            return Binary::UnknownCte;
        }
        let contents = match part.kind() {
            PartKind::Text | PartKind::Html | PartKind::Binary | PartKind::InlineBinary => {
                match sources.leaf(part, raw) {
                    Some(bytes) => BodyContents::Bytes(bytes),
                    None => return Binary::Missing,
                }
            }
            PartKind::Message => {
                let Some(nested) = part.nested() else {
                    return Binary::Missing;
                };
                match sources.source(nested, raw) {
                    Some(source) => source
                        .view(nested.root_part().raw_range())
                        .map_or(BodyContents::Owned(Vec::new()), BodyContents::Bytes),
                    None => return Binary::Missing,
                }
            }
            PartKind::Multipart => match sources.source(part.message(), raw) {
                Some(source) => source
                    .view(part.raw_range())
                    .map_or(BodyContents::Owned(Vec::new()), BodyContents::Bytes),
                None => return Binary::Missing,
            },
        };
        Binary::Found(contents.partial(partial))
    }

    fn binary_size(&self, sections: &[u32]) -> Binary<usize> {
        let Some(part) = self.root_part().descend(sections) else {
            return Binary::Missing;
        };
        if part.flags().contains(PartFlags::UNKNOWN_TRANSFER_ENCODING) {
            return Binary::UnknownCte;
        }
        Binary::Found(match part.kind() {
            PartKind::Multipart => part.raw_range().len(),
            _ => part.decoded_size() as usize,
        })
    }
}

trait PartSections<'a>: Sized {
    fn descend(self, sections: &[u32]) -> Option<Self>;
    fn fields_section<'x>(
        &self,
        sources: &'x mut DecodedSources,
        raw: RawMessage<'x>,
        partial: Option<(u32, u32)>,
        collect: impl FnOnce(&SourceView<'_>) -> Vec<u8>,
    ) -> Option<BodyContents<'x>>;
    fn header_gap(&self, source: &SourceView<'_>) -> Range<usize>;
    fn collect_fields(
        &self,
        source: &SourceView<'_>,
        select: impl Fn(HeaderView<'_>, &[u8]) -> bool,
    ) -> Vec<u8>;
}

impl<'a> PartSections<'a> for PartView<'a> {
    fn descend(self, sections: &[u32]) -> Option<Self> {
        let mut part = self;
        let mut sections_iter = sections.iter().enumerate().peekable();
        while let Some((section_num, num)) = sections_iter.next() {
            part = if part.is_multipart() {
                part.child((*num).saturating_sub(1) as usize)?
            } else if *num == 1 && (section_num == sections.len() - 1 || part.is_message()) {
                part
            } else {
                return None;
            };
            if part.is_message() && sections_iter.peek().is_some() {
                part = part.nested()?.root_part();
            }
        }
        Some(part)
    }

    fn fields_section<'x>(
        &self,
        sources: &'x mut DecodedSources,
        raw: RawMessage<'x>,
        partial: Option<(u32, u32)>,
        collect: impl FnOnce(&SourceView<'_>) -> Vec<u8>,
    ) -> Option<BodyContents<'x>> {
        let source = sources.source(self.message(), raw)?;
        Some(BodyContents::Owned(collect(&source)).partial(partial))
    }

    fn header_gap(&self, source: &SourceView<'_>) -> Range<usize> {
        if !self.is_message_root() {
            return 0..0;
        }
        let message = self.message();
        let prefix = if message.id() == 0 {
            message.metadata().extra_headers_len()
        } else {
            0
        };
        let start = self.offset_header().saturating_add(prefix);
        let first_field = |header: HeaderView<'_>| {
            let range = header.field_range();
            (range.start >= start
                && (header.id().is_known()
                    || source
                        .get(range.clone())
                        .is_some_and(|field| header.raw_name_in(&field).is_field_name())))
            .then_some(range.start)
        };
        let end = self.headers().iter().find_map(first_field);
        start..end.unwrap_or(start)
    }

    fn collect_fields(
        &self,
        source: &SourceView<'_>,
        select: impl Fn(HeaderView<'_>, &[u8]) -> bool,
    ) -> Vec<u8> {
        let gap = self.header_gap(source);
        let mut headers = Vec::with_capacity(self.header_range().len().min(MAX_FIELDS_CAPACITY));
        for header in self.headers().iter() {
            let range = header.field_range();
            if !gap.contains(&range.start)
                && let Some(field) = source.get(range)
                && select(header, &field)
            {
                headers.extend_from_slice(&field);
            }
        }
        headers.extend_from_slice(b"\r\n");
        headers
    }
}

trait HeaderFieldsWriter {
    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
        keep: impl Fn(&HeaderView<'_>) -> bool,
    );
}

impl HeaderFieldsWriter for HeaderList<'_> {
    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
        keep: impl Fn(&HeaderView<'_>) -> bool,
    ) {
        let not = matches!(section, Section::HeaderFields { not: true, .. });
        let selected = || {
            self.iter().filter(|header| {
                keep(header)
                    && matcher.matches(*header, headers) != not
                    && headers.get(header.field_range()).is_some()
            })
        };
        let len = selected()
            .map(|header| header.field_range().len())
            .sum::<usize>()
            + 2;
        buf.extend_from_slice(b"BODY[");
        section.serialize(buf);
        buf.extend_from_slice(b"] {");
        push_int(buf, len);
        buf.extend_from_slice(b"}\r\n");
        for header in selected() {
            if let Some(field) = headers.get(header.field_range()) {
                buf.extend_from_slice(field);
            }
        }
        buf.extend_from_slice(b"\r\n");
    }
}

trait FieldName {
    fn is_field_name(&self) -> bool;
}

impl FieldName for [u8] {
    fn is_field_name(&self) -> bool {
        !self.is_empty() && self.iter().all(|byte| matches!(byte, 33..=57 | 59..=126))
    }
}

trait MimeField {
    fn is_mime_field(&self, field: &[u8]) -> bool;
}

impl MimeField for HeaderView<'_> {
    fn is_mime_field(&self, field: &[u8]) -> bool {
        self.id().is_mime()
            || self
                .raw_name_in(field)
                .get(..CONTENT_PREFIX.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(CONTENT_PREFIX))
    }
}

