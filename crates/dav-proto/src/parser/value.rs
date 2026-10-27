/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Error, RawElement, Result, Token,
    tokenizer::{Tokenizer, append_text},
};
use crate::schema::Namespace;
use quick_xml::{
    XmlVersion,
    escape::EscapeError,
    events::{
        BytesRef, BytesStart, Event,
        attributes::{Attribute, Attributes},
    },
    name::{NamespaceError, QName, ResolveResult},
};
use std::{borrow::Cow, mem};
use types::metadata::{XmlAttribute, XmlElement, XmlError, XmlName, XmlNode, XmlValue};


const XML_LANG: &str = "xml:lang";
const XMLNS: &str = "xmlns";

enum LangScope<'s> {
    Property(&'s mut Option<String>),
    Element,
}

impl<'x> Tokenizer<'x> {
    pub fn collect_xml_value(
        &mut self,
        property: &RawElement<'x>,
        lang: Option<&str>,
    ) -> Result<XmlValue<'static>> {
        let mut own_lang = None;
        let attributes =
            self.value_attributes(&property.element, LangScope::Property(&mut own_lang))?;
        let lang = match own_lang {
            Some(lang) => Some(lang),
            None => lang.map(str::to_string),
        };
        let mut value = XmlValue {
            lang: lang.filter(|lang| !lang.is_empty()).map(Cow::Owned),
            attributes,
            children: Vec::new(),
        };

        if !mem::take(&mut self.last_is_end) {
            self.collect_xml_children(&mut value)?;
        }

        value.validate().map_err(Error::Value)?;
        Ok(value)
    }

    fn collect_xml_children(&mut self, value: &mut XmlValue<'static>) -> Result<()> {
        self.with_content(|tokenizer| tokenizer.collect_xml_content(value))
    }

    fn collect_xml_content(&mut self, value: &mut XmlValue<'static>) -> Result<()> {
        let mut open: Vec<XmlElement<'static>> = Vec::new();
        let mut text = String::new();

        loop {
            let raw = match self.token()? {
                Token::ElementStart { raw, .. } | Token::UnknownElement(raw) => raw,
                Token::ElementEnd => {
                    flush_text(&mut text, children_of(&mut open, value));
                    match open.pop() {
                        Some(element) => {
                            children_of(&mut open, value).push(XmlNode::Element(element))
                        }
                        None => return Ok(()),
                    }
                    continue;
                }
                Token::Content(Event::Text(content)) => {
                    append_text(&mut text, content.xml_content(XmlVersion::Implicit1_0));
                    continue;
                }
                Token::Content(Event::CData(content)) => {
                    append_text(&mut text, content.xml_content(XmlVersion::Implicit1_0));
                    continue;
                }
                Token::Content(Event::GeneralRef(reference)) => {
                    push_reference(&mut text, &reference)?;
                    continue;
                }
                Token::Eof => return Err(Token::Eof.into_unexpected()),
                Token::Content(_) | Token::Text(_) | Token::Bytes(_) => continue,
            };

            if open.len() >= XmlValue::MAX_DEPTH {
                return Err(Error::Value(XmlError::NestingTooDeep));
            }
            let namespace = raw.namespace.as_deref().map(namespace_uri).transpose()?;
            let (local_name, prefix) = raw.element.name().decompose();
            let element = XmlElement {
                name: XmlName {
                    namespace,
                    name: Cow::Owned(local_name.into_inner().to_string()),
                },
                prefix: prefix.map(|prefix| Cow::Owned(prefix.into_inner().to_string())),
                attributes: self.value_attributes(&raw.element, LangScope::Element)?,
                children: Vec::new(),
            };

            flush_text(&mut text, children_of(&mut open, value));
            open.push(element);
        }
    }

    fn value_attributes(
        &self,
        tag: &BytesStart<'_>,
        mut scope: LangScope<'_>,
    ) -> Result<Vec<XmlAttribute<'static>>> {
        let mut attributes = Vec::new();
        for attribute in unchecked_attributes(tag) {
            let attribute = attribute?;
            if attribute.key.as_namespace_binding().is_some() {
                continue;
            }
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)?
                .into_owned();
            if let LangScope::Property(lang) = &mut scope
                && attribute.key.into_inner() == XML_LANG
            {
                if lang.replace(value).is_some() {
                    return Err(Error::Value(XmlError::DuplicateAttribute));
                }
                continue;
            }
            let (resolved, local_name) = self.xml.resolver().resolve_attribute(attribute.key);
            attributes.push(XmlAttribute {
                name: XmlName {
                    namespace: resolved_namespace(resolved)?,
                    name: Cow::Owned(local_name.into_inner().to_string()),
                },
                value: Cow::Owned(value),
            });
        }
        Ok(attributes)
    }
}

pub(crate) struct InheritedLang<'a, 'x> {
    scopes: [&'a RawElement<'x>; 3],
    resolved: Option<Option<String>>,
}

impl<'a, 'x> InheritedLang<'a, 'x> {
    pub fn new(
        prop: &'a RawElement<'x>,
        set: &'a RawElement<'x>,
        request: &'a RawElement<'x>,
    ) -> Self {
        InheritedLang {
            scopes: [prop, set, request],
            resolved: None,
        }
    }

    pub fn get(&mut self) -> Result<Option<&str>> {
        if self.resolved.is_none() {
            let mut lang = None;
            for scope in self.scopes {
                let scope_lang = scope.xml_lang()?;
                if lang.is_none() {
                    lang = scope_lang;
                }
            }
            self.resolved = Some(lang);
        }
        Ok(self.resolved.as_ref().and_then(Option::as_deref))
    }
}

impl RawElement<'_> {
    pub fn dead_name(&self) -> Result<XmlName<'static>> {
        let name = XmlName {
            namespace: self.namespace.as_deref().map(namespace_uri).transpose()?,
            name: Cow::Owned(self.element.local_name().into_inner().to_string()),
        };
        name.validate_property().map_err(Error::Value)?;
        Ok(name)
    }

    pub fn xml_lang(&self) -> Result<Option<String>> {
        if self.element.attributes_raw().trim_ascii_start().is_empty() {
            return Ok(None);
        }
        for attribute in unchecked_attributes(&self.element) {
            let attribute = attribute?;
            if attribute.key.into_inner() == XML_LANG {
                return Ok(Some(
                    attribute
                        .normalized_value(XmlVersion::Implicit1_0)?
                        .into_owned(),
                ));
            }
        }
        Ok(None)
    }
}

fn unchecked_attributes<'t>(tag: &'t BytesStart<'_>) -> Attributes<'t> {
    let mut attributes = tag.attributes();
    attributes.with_checks(false);
    attributes
}

fn children_of<'v>(
    open: &'v mut [XmlElement<'static>],
    value: &'v mut XmlValue<'static>,
) -> &'v mut Vec<XmlNode<'static>> {
    match open.last_mut() {
        Some(element) => &mut element.children,
        None => &mut value.children,
    }
}

fn flush_text(text: &mut String, children: &mut Vec<XmlNode<'static>>) {
    if !text.is_empty() {
        children.push(XmlNode::Text(Cow::Owned(mem::take(text))));
    }
}

fn push_reference(text: &mut String, reference: &BytesRef<'_>) -> Result<()> {
    if let Some(ch) = reference.resolve_char_ref()? {
        text.push(ch);
        return Ok(());
    }
    let name: &str = reference;
    match hashify::map!(name.as_bytes(), &'static str,
        "lt" => "<",
        "gt" => ">",
        "amp" => "&",
        "apos" => "'",
        "quot" => "\""
    ) {
        Some(replacement) => {
            text.push_str(replacement);
            Ok(())
        }
        None => Err(xml(EscapeError::UnrecognizedEntity(
            0..name.len(),
            name.to_string(),
        ))),
    }
}

fn resolved_namespace(resolved: ResolveResult<'_>) -> Result<Option<Cow<'static, str>>> {
    match resolved {
        ResolveResult::Bound(namespace) => namespace_uri(namespace.into_inner()).map(Some),
        ResolveResult::Unbound => Ok(None),
        ResolveResult::Unknown(prefix) => Err(xml(NamespaceError::UnknownPrefix(prefix))),
    }
}

pub(super) fn known_namespace(raw: &str) -> Option<&'static (Namespace, &'static str)> {
    Namespace::try_parse_uri(raw.as_bytes()).or_else(|| {
        raw.contains('&')
            .then(|| normalized_uri(raw).ok())
            .flatten()
            .and_then(|uri| Namespace::try_parse_uri(uri.as_bytes()))
    })
}

pub(super) fn extension_namespace(raw: &str) -> Option<&'static str> {
    hashify::map!(raw.as_bytes(), &'static str,
        "http://apple.com/ns/ical/" => "http://apple.com/ns/ical/",
        "http://me.com/_namespace/" => "http://me.com/_namespace/",
        "urn:mobileme:davservices" => "urn:mobileme:davservices",
        "http://owncloud.org/ns" => "http://owncloud.org/ns",
        "http://nextcloud.org/ns" => "http://nextcloud.org/ns",
        "http://sabredav.org/ns" => "http://sabredav.org/ns"
    )
    .copied()
}

fn namespace_uri(raw: &str) -> Result<Cow<'static, str>> {
    if let Some((_, uri)) = Namespace::try_parse_uri(raw.as_bytes()) {
        Ok(Cow::Borrowed(uri))
    } else if let Some(uri) = extension_namespace(raw) {
        Ok(Cow::Borrowed(uri))
    } else if raw
        .bytes()
        .any(|byte| matches!(byte, b'&' | b'\t' | b'\n' | b'\r'))
    {
        normalized_uri(raw)
            .map(|uri| Cow::Owned(uri.into_owned()))
            .map_err(xml)
    } else {
        Ok(Cow::Owned(raw.to_string()))
    }
}

fn normalized_uri(raw: &str) -> quick_xml::Result<Cow<'_, str>> {
    Attribute {
        key: QName(XMLNS),
        value: Cow::Borrowed(raw),
    }
    .normalized_value(XmlVersion::Implicit1_0)
}

fn xml(err: impl Into<quick_xml::Error>) -> Error {
    Error::Xml(Box::new(err.into()))
}
