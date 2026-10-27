/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Error, RawElement, Token, UnexpectedToken, XmlValueParser,
    value::{extension_namespace, known_namespace},
};
use crate::schema::{Attribute, AttributeValue, Element, NamedElement};
use quick_xml::{
    NsReader, XmlVersion,
    events::{BytesRef, Event, attributes::AttrError},
    name::ResolveResult,
};
use std::{borrow::Cow, mem};

pub struct Tokenizer<'x> {
    pub(super) xml: NsReader<&'x [u8]>,
    pub(super) last_is_end: bool,
    content: bool,
}

impl<'x> Tokenizer<'x> {
    pub fn new(input: &'x [u8]) -> Self {
        let mut xml = NsReader::from_reader(input);
        xml.config_mut();
        Self {
            xml,
            last_is_end: false,
            content: false,
        }
    }

    pub fn token(&mut self) -> super::Result<Token<'x>> {
        loop {
            if self.last_is_end {
                self.last_is_end = false;
                return Ok(Token::ElementEnd);
            }

            let (resolve_result, event) = self.xml.read_resolved_event()?;
            let tag = match event {
                Event::Start(tag) => tag,
                Event::Empty(tag) => {
                    self.last_is_end = true;
                    tag
                }
                Event::End(_) => {
                    return Ok(Token::ElementEnd);
                }
                event @ (Event::Text(_) | Event::CData(_) | Event::GeneralRef(_))
                    if self.content =>
                {
                    return Ok(Token::Content(event));
                }
                Event::Text(text) if text.bytes().any(|ch| !ch.is_ascii_whitespace()) => {
                    return Ok(Token::Text(text.xml_content(XmlVersion::Implicit1_0)));
                }
                Event::GeneralRef(entity) => {
                    return Ok(Token::Text(general_ref_text(entity)));
                }
                Event::CData(bytes) => {
                    return Ok(Token::Bytes(match bytes.into_inner() {
                        Cow::Borrowed(text) => Cow::Borrowed(text.as_bytes()),
                        Cow::Owned(text) => Cow::Owned(text.into_bytes()),
                    }));
                }
                Event::Eof => return Ok(Token::Eof),
                _ => {
                    continue;
                }
            };

            // Parse element
            let name = tag.name();
            match resolve_result {
                ResolveResult::Bound(raw_ns) if !raw_ns.0.is_empty() => {
                    let element =
                        Element::try_parse(name.local_name().into_inner().as_bytes()).copied();
                    let raw = RawElement::new(tag);
                    return Ok(match (known_namespace(raw_ns.0), element) {
                        (Some((ns, uri)), Some(element)) => Token::ElementStart {
                            name: NamedElement { ns: *ns, element },
                            raw: raw.with_namespace_static(uri),
                        },
                        (Some((_, uri)), None) => {
                            Token::UnknownElement(raw.with_namespace_static(uri))
                        }
                        (None, _) => Token::UnknownElement(match extension_namespace(raw_ns.0) {
                            Some(uri) => raw.with_namespace_static(uri),
                            None => raw.with_namespace(raw_ns),
                        }),
                    });
                }
                ResolveResult::Unknown(p) => {
                    return Err(Error::Xml(Box::new(quick_xml::Error::Namespace(
                        quick_xml::name::NamespaceError::UnknownPrefix(p),
                    ))));
                }
                _ => {
                    return Ok(Token::UnknownElement(RawElement::new(tag)));
                }
            }
        }
    }

    pub fn unwrap_named_element(&mut self) -> super::Result<NamedElement> {
        match self.token()? {
            Token::ElementStart { name, .. } => Ok(name),
            found => Err(Error::UnexpectedToken(Box::new(UnexpectedToken {
                expected: None,
                found: found.into_owned(),
            }))),
        }
    }

    pub fn expect_named_element(&mut self, expected: NamedElement) -> super::Result<()> {
        self.expect_named_element_raw(expected).map(|_| ())
    }

    pub fn expect_named_element_raw(
        &mut self,
        expected: NamedElement,
    ) -> super::Result<RawElement<'x>> {
        match self.token()? {
            Token::ElementStart { name, raw } if name == expected => Ok(raw),
            found => Err(Error::UnexpectedToken(Box::new(UnexpectedToken {
                expected: Token::ElementStart {
                    name: expected,
                    raw: RawElement::default(),
                }
                .into(),
                found: found.into_owned(),
            }))),
        }
    }

    pub fn expect_named_element_or_eof(
        &mut self,
        expected: NamedElement,
    ) -> super::Result<Option<RawElement<'x>>> {
        match self.token()? {
            Token::ElementStart { name, raw } if name == expected => Ok(Some(raw)),
            Token::Eof => Ok(None),
            found => Err(Error::UnexpectedToken(Box::new(UnexpectedToken {
                expected: Token::ElementStart {
                    name: expected,
                    raw: RawElement::default(),
                }
                .into(),
                found: found.into_owned(),
            }))),
        }
    }

    pub fn expect_element_end(&mut self) -> super::Result<()> {
        match self.token()? {
            Token::ElementEnd => Ok(()),
            found => Err(Error::UnexpectedToken(Box::new(UnexpectedToken {
                expected: Token::ElementEnd.into(),
                found: found.into_owned(),
            }))),
        }
    }

    pub fn seek_element_end(&mut self) -> super::Result<()> {
        let mut depth = 1;
        loop {
            match self.token()? {
                Token::ElementStart { .. } | Token::UnknownElement(_) => depth += 1,
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                Token::Eof => return Err(Token::Eof.into_unexpected()),
                _ => {}
            }
        }
    }

    pub(super) fn with_content<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> super::Result<T>,
    ) -> super::Result<T> {
        self.content = true;
        let result = read(self);
        self.content = false;
        result
    }

    pub fn collect_string_value(&mut self) -> super::Result<Option<String>> {
        if mem::take(&mut self.last_is_end) {
            return Ok(None);
        }
        self.with_content(Tokenizer::collect_string_content)
    }

    fn collect_string_content(&mut self) -> super::Result<Option<String>> {
        let mut depth = 1u32;
        let mut value = String::new();
        let mut has_content = false;

        loop {
            match self.token()? {
                Token::ElementStart { .. } | Token::UnknownElement(_) => depth += 1,
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Token::Content(Event::Text(text)) => {
                    has_content |= text.bytes().any(|ch| !ch.is_ascii_whitespace());
                    append_text(&mut value, text.xml_content(XmlVersion::Implicit1_0));
                }
                Token::Content(Event::CData(bytes)) => {
                    has_content = true;
                    append_text(&mut value, bytes.into_inner());
                }
                Token::Content(Event::GeneralRef(entity)) => {
                    has_content = true;
                    append_text(&mut value, general_ref_text(entity));
                }
                Token::Eof => return Err(Token::Eof.into_unexpected()),
                Token::Content(_) | Token::Text(_) | Token::Bytes(_) => {}
            }
        }

        Ok(has_content.then_some(value))
    }

    pub fn parse_value<T: XmlValueParser>(&mut self) -> super::Result<Option<Result<T, String>>> {
        let mut depth = 1;
        let mut result: Option<Result<T, String>> = None;

        loop {
            match self.token()? {
                Token::ElementStart { .. } | Token::UnknownElement(_) => depth += 1,
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Token::Text(text) => {
                    if let Some(value) = T::parse_str(&text) {
                        result = Some(Ok(value));
                    } else {
                        result = Some(Err(text.into_owned()));
                    }
                }
                Token::Bytes(bytes) => {
                    if let Some(value) = T::parse_bytes(&bytes) {
                        result = Some(Ok(value));
                    } else {
                        result = Some(Err(String::from_utf8_lossy(&bytes).into_owned()));
                    }
                }
                Token::Content(_) => {}
                Token::Eof => return Err(Token::Eof.into_unexpected()),
            }
        }

        Ok(result)
    }

    pub fn collect_elements<T>(&mut self) -> super::Result<Vec<T>>
    where
        T: TryFrom<NamedElement>,
    {
        let mut elements = Vec::with_capacity(2);
        let mut depth = 1;

        loop {
            match self.token()? {
                Token::ElementStart { name, .. } => {
                    if depth == 1
                        && let Ok(element) = T::try_from(name)
                    {
                        elements.push(element);
                    }

                    depth += 1;
                }
                Token::UnknownElement(_) => {
                    depth += 1;
                }
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Token::Eof => break,
                _ => {}
            }
        }
        Ok(elements)
    }
}

pub(super) fn append_text(value: &mut String, piece: Cow<'_, str>) {
    if value.is_empty() {
        *value = piece.into_owned();
    } else {
        value.push_str(&piece);
    }
}

fn general_ref_text(entity: BytesRef<'_>) -> Cow<'_, str> {
    if let Some(text) = hashify::map!(entity.as_bytes(), &'static str,
        "lt" => "<",
        "gt" => ">",
        "amp" => "&",
        "apos" => "'",
        "quot" => "\""
    ) {
        return Cow::Borrowed(text);
    }
    if let Ok(Some(ch)) = entity.resolve_char_ref() {
        return Cow::Owned(ch.to_string());
    }
    entity.xml_content(XmlVersion::Implicit1_0)
}

impl RawElement<'_> {
    pub fn attributes<T: AttributeValue>(
        &self,
    ) -> impl Iterator<Item = super::Result<Attribute<T>>> + '_ {
        self.element.attributes().filter_map(|attr| match attr {
            Ok(attr) => match attr.normalized_value(XmlVersion::Implicit1_0) {
                Ok(value) => Attribute::from_param(attr.key.into_inner().as_bytes(), value).map(Ok),
                Err(err) => Some(Err(err.into())),
            },
            Err(err) => Some(Err(err.into())),
        })
    }
}

impl From<quick_xml::Error> for Error {
    fn from(err: quick_xml::Error) -> Self {
        Error::Xml(Box::new(err))
    }
}

impl From<AttrError> for Error {
    fn from(err: AttrError) -> Self {
        Error::Xml(Box::new(err.into()))
    }
}

