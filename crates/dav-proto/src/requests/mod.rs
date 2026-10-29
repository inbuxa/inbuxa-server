/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    parser::{DavParser, RawElement, Token, tokenizer::Tokenizer},
    schema::Namespace,
};
use types::dead_property::{DeadElementTag, DeadProperty, DeadPropertyTag};

pub mod acl;
pub mod lockinfo;
pub mod mkcol;
pub mod propertyupdate;
pub mod propfind;
pub mod report;

impl DavParser for DeadProperty {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut depth = 1;
        let mut items = DeadProperty::default();

        loop {
            match stream.token()? {
                Token::ElementStart { raw, .. } | Token::UnknownElement(raw) => {
                    items.0.push(DeadPropertyTag::ElementStart((&raw).into()));
                    depth += 1;
                }
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    items.0.push(DeadPropertyTag::ElementEnd);
                }
                Token::Text(text) => {
                    items.0.push(DeadPropertyTag::Text(text.into_owned()));
                }
                Token::Bytes(bytes) => {
                    items.0.push(DeadPropertyTag::Text(
                        String::from_utf8_lossy(&bytes).into_owned(),
                    ));
                }
                Token::Eof => {
                    break;
                }
            }
        }

        Ok(items)
    }
}

pub trait NsDeadProperty {
    fn single_with_ns(namespace: Namespace, name: &str) -> Self;
}

impl NsDeadProperty for DeadProperty {
    fn single_with_ns(namespace: Namespace, name: &str) -> Self {
        DeadProperty(vec![
            DeadPropertyTag::ElementStart(DeadElementTag {
                name: format!("{}:{name}", namespace.prefix()),
                attrs: None,
            }),
            DeadPropertyTag::ElementEnd,
        ])
    }
}

impl From<&RawElement<'_>> for DeadElementTag {
    fn from(raw: &RawElement<'_>) -> Self {
        let name = std::str::from_utf8(raw.element.local_name().as_ref())
            .unwrap_or("invalid-utf8")
            .trim_ascii()
            .to_string();
        let name = if is_xml_name(&name) {
            name
        } else {
            "invalid-name".to_string()
        };
        let mut attrs = String::with_capacity(raw.element.attributes_raw().len());
        if let Some(namespace) = &raw.namespace {
            attrs.push_str("xmlns=\"");
            push_attribute_value(
                &mut attrs,
                std::str::from_utf8(namespace).unwrap_or("invalid-utf8"),
            );
            attrs.push('"');
        }

        for attr in raw.element.attributes().flatten() {
            if attr.key.as_ref() == b"xmlns" || attr.key.as_ref().starts_with(b"xmlns:") {
                // Skip namespace attributes
                continue;
            }
            if let (Ok(key), Ok(value)) = (
                std::str::from_utf8(attr.key.as_ref()),
                std::str::from_utf8(attr.value.as_ref()),
            ) && is_xml_name(key)
            {
                if !attrs.is_empty() {
                    attrs.push(' ');
                }
                attrs.push_str(key);
                attrs.push('=');
                attrs.push('"');
                push_attribute_value(&mut attrs, value);
                attrs.push('"');
            }
        }

        DeadElementTag {
            name,
            attrs: (!attrs.is_empty()).then_some(attrs),
        }
    }
}

/// inbuxa: element and attribute names are echoed back as they came in, so
/// nothing that could end the tag or start markup may be in them
pub(crate) fn is_xml_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '&' | '=' | '/'))
}

/// inbuxa: a stored attribute value is always written inside double quotes,
/// so it's unescaped as received (it may have been quoted with ') and escaped
/// again for that
fn push_attribute_value(out: &mut String, raw: &str) {
    let value = quick_xml::escape::unescape(raw).unwrap_or(std::borrow::Cow::Borrowed(raw));
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use calcard::vcard::VCardVersion;

    use crate::{
        parser::{DavParser, tokenizer::Tokenizer},
        schema::{
            property::{CardDavProperty, DavProperty},
            request::{Acl, LockInfo, MkCol, PropFind, PropertyUpdate, Report},
        },
    };

    // inbuxa: dead properties are stored from one user's PROPPATCH or LOCK
    // and shown to everyone who can read the resource: what comes back out
    // must be the same well-formed XML, whatever quoting came in
    #[test]
    fn dead_property_round_trip_is_well_formed() {
        let xml = r#"<?xml version="1.0" encoding="utf-8" ?>
            <D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:z">
              <D:set>
                <D:prop>
                  <Z:note a='x" ><evil/>' b="&amp;&quot;" c='&lt;q&gt;'><Z:outer><Z:inner>text</Z:inner><Z:empty/></Z:outer></Z:note>
                </D:prop>
              </D:set>
            </D:propertyupdate>"#;

        let update = PropertyUpdate::parse(&mut Tokenizer::new(xml.as_bytes())).unwrap();
        let output = update
            .set
            .iter()
            .map(|property| property.to_string())
            .collect::<String>();
        let wrapped = format!("<root>{output}</root>");

        let mut reader = quick_xml::Reader::from_str(&wrapped);
        let mut elements = Vec::new();
        let mut attributes = Vec::new();
        loop {
            match reader.read_event() {
                Ok(quick_xml::events::Event::Start(element))
                | Ok(quick_xml::events::Event::Empty(element)) => {
                    elements
                        .push(String::from_utf8(element.local_name().as_ref().to_vec()).unwrap());
                    for attribute in element.attributes() {
                        let attribute = attribute.unwrap();
                        attributes.push((
                            String::from_utf8(attribute.key.as_ref().to_vec()).unwrap(),
                            quick_xml::escape::unescape(
                                std::str::from_utf8(&attribute.value).unwrap(),
                            )
                            .unwrap()
                            .into_owned(),
                        ));
                    }
                }
                Ok(quick_xml::events::Event::Eof) => break,
                Ok(_) => {}
                Err(err) => panic!("malformed output {output:?}: {err}"),
            }
        }

        assert_eq!(
            elements,
            ["root", "note", "outer", "inner", "empty"],
            "{output}"
        );
        for (name, value) in [("a", r#"x" ><evil/>"#), ("b", r#"&""#), ("c", "<q>")] {
            assert!(
                attributes.contains(&(name.to_string(), value.to_string())),
                "{name}={value:?} not in {attributes:?}"
            );
        }
    }

    #[test]
    fn parse_address_data_version() {
        let xml = r#"<?xml version="1.0" encoding="utf-8" ?>
            <C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
              <D:prop>
                <C:address-data content-type="text/vcard" version="3.0">
                  <C:prop name="FN"/>
                </C:address-data>
              </D:prop>
            </C:addressbook-query>"#;

        let mut tokenizer = Tokenizer::new(xml.as_bytes());
        let report = Report::parse(&mut tokenizer).unwrap();
        let Report::AddressbookQuery(query) = report else {
            panic!("expected addressbook-query, got {report:?}");
        };
        let PropFind::Prop(properties) = query.properties else {
            panic!("expected prop, got {:?}", query.properties);
        };

        let version = properties.iter().find_map(|property| match property {
            DavProperty::CardDav(CardDavProperty::AddressData { version, .. }) => Some(*version),
            _ => None,
        });

        assert_eq!(version, Some(Some(VCardVersion::V3_0)));
    }

    #[test]
    fn parse_requests() {
        for entry in std::fs::read_dir("resources/requests").unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();

            if path.extension().map(|ext| ext == "xml").unwrap_or(false) {
                println!("Parsing: {:?}", path);
                let filename = path.file_name().unwrap().to_str().unwrap();
                let xml = std::fs::read_to_string(&path).unwrap();
                let mut tokenizer = Tokenizer::new(xml.as_bytes());

                let json_path = path.with_extension("json");
                let json_output = match filename.split_once('-').unwrap().0 {
                    "propfind" => match PropFind::parse(&mut tokenizer) {
                        Ok(propfind) => serde_json::to_string_pretty(&propfind).unwrap(),
                        Err(_) => String::new(),
                    },
                    "propertyupdate" => serde_json::to_string_pretty(
                        &PropertyUpdate::parse(&mut tokenizer).unwrap(),
                    )
                    .unwrap(),
                    "mkcol" => serde_json::to_string_pretty(&MkCol::parse(&mut tokenizer).unwrap())
                        .unwrap(),
                    "lockinfo" => {
                        serde_json::to_string_pretty(&LockInfo::parse(&mut tokenizer).unwrap())
                            .unwrap()
                    }
                    "report" => {
                        serde_json::to_string_pretty(&Report::parse(&mut tokenizer).unwrap())
                            .unwrap()
                    }
                    "acl" => {
                        serde_json::to_string_pretty(&Acl::parse(&mut tokenizer).unwrap()).unwrap()
                    }
                    _ => {
                        panic!("Unknown method: {}", filename);
                    }
                };

                /*if json_path.exists() {
                    let expected = std::fs::read_to_string(json_path).unwrap();
                    assert_eq!(json_output, expected);
                } else {*/
                std::fs::write(json_path, json_output).unwrap();
                //}
            }
        }
    }
}
