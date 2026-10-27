/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        ArchivedPartialDateTime, PartialDateTime,
        format::{AsciiPush, BufferedWrite},
        parser::Timestamp,
        writer::{
            DOCUMENT_BUFFER, ENTRY_BUFFER, FoldingWriter, JscompRef, LineWriter, NeedsQuotes,
            write_jscomps, write_param_value, write_text,
        },
    },
    vcard::{media_type::legacy_media_type, *},
};
use std::fmt::{self, Display, Write};

impl ArchivedVCard {
    pub fn write_to(&self, out: &mut impl Write, version: VCardVersion) -> fmt::Result {
        out.write_buffered::<DOCUMENT_BUFFER>(|buf| {
            self.write_entries(&mut FoldingWriter::new(buf), version)
        })
    }

    fn write_entries<W: Write + AsciiPush + ?Sized>(
        &self,
        out: &mut FoldingWriter<'_, W>,
        version: VCardVersion,
    ) -> fmt::Result {
        out.write_raw(version.begin_and_version())?;
        for entry in self.entries.iter() {
            if !matches!(
                entry.name,
                ArchivedVCardProperty::Version
                    | ArchivedVCardProperty::Begin
                    | ArchivedVCardProperty::End
            ) {
                entry.write_line(out, true, version)?;
            }
        }

        out.write_raw("END:VCARD\r\n")
    }
}

impl ArchivedVCardEntry {
    #[deprecated(since = "0.4.0", note = "use write_with_version")]
    pub fn write_to(&self, out: &mut impl Write, with_value: bool, is_v4: bool) -> fmt::Result {
        self.write_with_version(
            out,
            with_value,
            if is_v4 {
                VCardVersion::V4_0
            } else {
                VCardVersion::V3_0
            },
        )
    }

    pub fn write_with_version(
        &self,
        out: &mut impl Write,
        with_value: bool,
        version: VCardVersion,
    ) -> fmt::Result {
        out.write_buffered::<ENTRY_BUFFER>(|buf| {
            self.write_line(&mut FoldingWriter::new(buf), with_value, version)
        })
    }

    pub(crate) fn write_line<W: Write + AsciiPush + ?Sized>(
        &self,
        out: &mut FoldingWriter<'_, W>,
        with_value: bool,
        version: VCardVersion,
    ) -> fmt::Result {
        let is_v4 = matches!(version, VCardVersion::V4_0);

        if let Some(group_name) = self.group.as_ref() {
            out.write_atomic(group_name)?;
            out.write_atomic(".")?;
        }

        out.write_atomic(self.name.as_str())?;
        let mut types = None;
        let mut last_param: Option<&ArchivedVCardParameterName> = None;
        let legacy_binary = if is_v4 {
            None
        } else {
            self.values.iter().find_map(|v| match v {
                ArchivedVCardValue::Binary(data) => Some(data),
                _ => None,
            })
        };

        for param in self.params.iter() {
            if !is_v4
                && match param.name {
                    ArchivedVCardParameterName::PropId | ArchivedVCardParameterName::Jscomps => {
                        true
                    }
                    ArchivedVCardParameterName::Mediatype => legacy_binary.is_some(),
                    _ => false,
                }
            {
                continue;
            }

            if last_param.is_some_and(|last_param| last_param == &param.name) {
                out.write_atomic(",")?;
            } else {
                out.write_atomic(";")?;
                out.write_atomic(param.name.as_str())?;
                if !matches!(param.value, ArchivedVCardParameterValue::Null) {
                    out.write_atomic("=")?;
                }
                last_param = Some(&param.name);
            }

            match &param.value {
                ArchivedVCardParameterValue::Text(v)
                    if param.name == VCardParameterName::Jsptr && !v.as_str().needs_quotes() =>
                {
                    out.write_atomic("\"")?;
                    write_param_value(out, v, is_v4)?;
                    out.write_atomic("\"")?;
                }
                ArchivedVCardParameterValue::Text(v) => {
                    write_param_value(out, v, is_v4)?;
                }
                ArchivedVCardParameterValue::Integer(i) => {
                    out.push_u64(i.to_native().into())?;
                }
                ArchivedVCardParameterValue::Timestamp(v) => {
                    Timestamp(v.to_native()).push_to(out)?;
                }
                ArchivedVCardParameterValue::Bool(v) => {
                    out.write_atomic(if *v { "TRUE" } else { "FALSE" })?;
                }
                ArchivedVCardParameterValue::ValueType(v) => {
                    if types.is_none() {
                        types = Some(v);
                    }
                    write_param_value(out, v.as_str(), is_v4)?;
                }
                ArchivedVCardParameterValue::Type(v) => {
                    write_param_value(out, v.as_str(), is_v4)?;
                }
                ArchivedVCardParameterValue::Calscale(v) => {
                    write_param_value(out, v.as_str(), is_v4)?;
                }
                ArchivedVCardParameterValue::Level(v) => {
                    write_param_value(out, v.as_str(), is_v4)?;
                }
                ArchivedVCardParameterValue::Phonetic(v) => {
                    write_param_value(out, v.as_str(), is_v4)?;
                }
                ArchivedVCardParameterValue::Jscomps(v) => {
                    out.write_atomic("\"")?;
                    write_jscomps(out, v)?;
                    out.write_atomic("\"")?;
                    last_param = None;
                }
                ArchivedVCardParameterValue::Null => {
                    last_param = None;
                }
            }
        }

        let is_v21_base64 = matches!(version, VCardVersion::V2_1) && legacy_binary.is_some();
        let max_values = if is_v4 {
            usize::MAX
        } else {
            self.name.legacy_max_values()
        };

        if !is_v4 {
            if let Some(data) = legacy_binary {
                out.write_atomic(if is_v21_base64 {
                    ";ENCODING=BASE64"
                } else {
                    ";ENCODING=b"
                })?;

                if let Some(media_type) = data.content_type.as_deref()
                    && !self
                        .params
                        .iter()
                        .any(|param| param.name == VCardParameterName::Type)
                    && let Some(token) = legacy_media_type(self.name.as_str(), media_type)
                {
                    out.write_atomic(";TYPE=")?;
                    out.write_atomic(&token)?;
                }
            }

            if self.values.iter().take(max_values).any(|v| match v {
                ArchivedVCardValue::Text(s) => !s.is_ascii(),
                ArchivedVCardValue::Component(items) => items.iter().any(|s| !s.is_ascii()),
                _ => false,
            }) {
                out.write_atomic(";CHARSET=UTF-8")?;
            }
        }

        out.write_atomic(":")?;

        if with_value {
            let (default_type, value_separator) = self.name.default_types();
            let default_type = default_type.unwrap_vcard();

            let mut separator = ";";
            let mut escape_semicolon =
                matches!(types.unwrap_or(&default_type), ArchivedVCardValueType::Text);
            let mut escape_comma = escape_semicolon;

            match value_separator {
                ValueSeparator::Comma => {
                    escape_comma = true;
                    separator = ",";
                }
                ValueSeparator::Semicolon => escape_semicolon = true,
                ValueSeparator::SemicolonAndComma => {
                    escape_semicolon = true;
                    escape_comma = true;
                }
                _ => {}
            }

            for (pos, value) in self.values.iter().take(max_values).enumerate() {
                if pos > 0 {
                    out.write_atomic(separator)?;
                }

                match value {
                    ArchivedVCardValue::Text(v) => {
                        write_text(out, v, escape_semicolon, escape_comma)?;
                    }
                    ArchivedVCardValue::Component(v) => {
                        for (pos, item) in v.iter().enumerate() {
                            if pos > 0 {
                                out.write_atomic(",")?;
                            }
                            write_text(out, item, true, true)?;
                        }
                    }
                    ArchivedVCardValue::Integer(v) => {
                        out.push_i64(v.to_native())?;
                    }
                    ArchivedVCardValue::Float(v) => {
                        write!(out, "{v}")?;
                    }
                    ArchivedVCardValue::Boolean(v) => {
                        out.write_atomic(if *v { "TRUE" } else { "FALSE" })?;
                    }
                    ArchivedVCardValue::PartialDateTime(v) => {
                        let typ = if pos == 0 {
                            types
                        } else {
                            self.parameters(&VCardParameterName::Value)
                                .nth(pos)
                                .and_then(|v| v.as_value_type())
                                .and_then(|v| v.iana().copied())
                        }
                        .unwrap_or(&default_type);
                        let date = PartialDateTime::from(v);
                        let typ = VCardValueType::from(typ);
                        if is_v4 {
                            date.push_vcard(out, &typ)?;
                        } else {
                            date.push_legacy_vcard(out, &typ)?;
                        }
                    }
                    ArchivedVCardValue::Binary(v) => {
                        if is_v4 {
                            let media_type = v.content_type.as_deref().unwrap_or_default();
                            out.write_str("data:")?;
                            out.write_str(media_type)?;
                            if escape_semicolon {
                                out.write_atomic("\\;")?;
                            } else {
                                out.write_str(";")?;
                            }
                            out.write_atomic("base64\\,")?;
                        }
                        out.write_base64(&v.data)?;
                    }
                    ArchivedVCardValue::Sex(v) => {
                        out.write_atomic(v.as_str())?;
                    }
                    ArchivedVCardValue::GramGender(v) => {
                        out.write_atomic(v.as_str())?;
                    }
                    ArchivedVCardValue::Kind(v) => {
                        out.write_atomic(v.as_str())?;
                    }
                }
            }
        }
        out.end_line()?;
        if is_v21_base64 {
            out.end_line()?;
        }
        Ok(())
    }
}

impl ArchivedPartialDateTime {
    pub fn format_as_vcard(
        &self,
        out: &mut impl Write,
        fmt: &ArchivedVCardValueType,
    ) -> fmt::Result {
        PartialDateTime::from(self).format_as_vcard(out, &VCardValueType::from(fmt))
    }

    pub fn format_as_legacy_vcard(
        &self,
        out: &mut impl Write,
        fmt: &ArchivedVCardValueType,
    ) -> fmt::Result {
        PartialDateTime::from(self).format_as_legacy_vcard(out, &VCardValueType::from(fmt))
    }
}

impl From<&ArchivedVCardValueType> for VCardValueType {
    fn from(value_type: &ArchivedVCardValueType) -> Self {
        match value_type {
            ArchivedVCardValueType::Boolean => VCardValueType::Boolean,
            ArchivedVCardValueType::Date => VCardValueType::Date,
            ArchivedVCardValueType::DateAndOrTime => VCardValueType::DateAndOrTime,
            ArchivedVCardValueType::DateTime => VCardValueType::DateTime,
            ArchivedVCardValueType::Float => VCardValueType::Float,
            ArchivedVCardValueType::Integer => VCardValueType::Integer,
            ArchivedVCardValueType::LanguageTag => VCardValueType::LanguageTag,
            ArchivedVCardValueType::Text => VCardValueType::Text,
            ArchivedVCardValueType::Time => VCardValueType::Time,
            ArchivedVCardValueType::Timestamp => VCardValueType::Timestamp,
            ArchivedVCardValueType::Uri => VCardValueType::Uri,
            ArchivedVCardValueType::UtcOffset => VCardValueType::UtcOffset,
        }
    }
}

impl Display for ArchivedVCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f, self.version().unwrap_or_default())
    }
}

impl<'x> From<&'x ArchivedJscomp> for JscompRef<'x> {
    fn from(jscomp: &'x ArchivedJscomp) -> Self {
        match jscomp {
            ArchivedJscomp::Entry { position, value } => JscompRef::Entry {
                position: position.to_native(),
                value: value.to_native(),
            },
            ArchivedJscomp::Separator(separator) => JscompRef::Separator(separator),
        }
    }
}

