/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::resources_dir;
use email::message::metadata::{ArchivedMessageMetadata, ExtraHeaders, MessageMetadata};
use imap::op::fetch::{
    source::DecodedSources,
    structure::{Binary, ImapMetadata},
};
use imap_proto::{
    ResponseCode, StatusResponse,
    protocol::fetch::{BodyContents, DataItem, Section},
};
use mail_parser::MessageParser;
use std::{borrow::Cow, fs};

pub fn test() {
    println!("Running BODYSTRUCTURE...");

    for file_name in fs::read_dir(resources_dir()).unwrap() {
        let mut file_name = file_name.as_ref().unwrap().path();
        if file_name.extension().is_none_or(|e| e != "txt") {
            continue;
        }

        let mut buf = Vec::new();
        let raw_message = fs::read(&file_name).unwrap();
        let message_ = MessageParser::new().parse(&raw_message).unwrap();
        // inbuxa: 1.0 builds the metadata in one step and reads the raw
        // message through it; decoded parts live in a DecodedSources per read
        let built = MessageMetadata::build(&message_, &ExtraHeaders::default(), Default::default());
        let archive = rkyv::to_bytes::<rkyv::rancor::Error>(&built.metadata).unwrap();
        let metadata =
            rkyv::access::<ArchivedMessageMetadata, rkyv::rancor::Error>(&archive).unwrap();
        let raw = metadata.raw_message(Some(&built.raw_headers), &raw_message);

        // Serialize body and bodystructure
        for (is_extended, is_utf8) in [(false, false), (true, false), (true, true)] {
            let mut buf_ = Vec::new();
            metadata.write_structure(&mut buf_, is_extended, is_utf8);
            if !is_extended {
                buf.extend_from_slice(b"BODY ");
            } else if !is_utf8 {
                buf.extend_from_slice(b"BODYSTRUCTURE ");
            } else {
                buf.extend_from_slice(b"BODYSTRUCTURE UTF8=ACCEPT ");
            }

            // Poor man's indentation
            let mut indent_count = 0;
            let mut in_quote = false;
            for ch in buf_ {
                if ch == b'(' && !in_quote {
                    buf.extend_from_slice(b"(\n");
                    indent_count += 1;
                    for _ in 0..indent_count {
                        buf.extend_from_slice(b"   ");
                    }
                } else if ch == b')' && !in_quote {
                    buf.push(b'\n');
                    indent_count -= 1;
                    for _ in 0..indent_count {
                        buf.extend_from_slice(b"   ");
                    }
                    buf.push(b')');
                } else {
                    if ch == b'"' {
                        in_quote = !in_quote;
                    }
                    buf.push(ch);
                }
            }
            buf.extend_from_slice(b"\n\n");
        }

        // Serialize body parts
        let mut iter = 1..9;
        let mut stack = Vec::new();
        let mut sections = Vec::new();
        loop {
            'inner: while let Some(part_id) = iter.next() {
                if part_id == 1 {
                    for section in [
                        None,
                        Some(Section::Header),
                        Some(Section::Text),
                        Some(Section::Mime),
                    ] {
                        let mut body_sections = sections
                            .iter()
                            .map(|id| Section::Part { num: *id })
                            .collect::<Vec<_>>();
                        let is_first = if let Some(section) = section {
                            body_sections.push(section);
                            false
                        } else {
                            true
                        };

                        let mut sources = DecodedSources::default();
                        if let Some(contents) =
                            metadata.body_section(raw, &mut sources, &body_sections, None, None)
                        {
                            DataItem::BodySection {
                                sections: Cow::Borrowed(&body_sections),
                                origin_octet: None,
                                contents,
                            }
                            .serialize(&mut buf);

                            if is_first {
                                let mut sources = DecodedSources::default();
                                match metadata.binary(raw, &mut sources, &sections, None) {
                                    Binary::Found(contents) => {
                                        buf.push(b'\n');
                                        DataItem::Binary {
                                            sections: Cow::Borrowed(&sections),
                                            offset: None,
                                            contents: match contents {
                                                BodyContents::Text(text) => {
                                                    BodyContents::Text(text)
                                                }
                                                bytes => BodyContents::Text(
                                                    std::str::from_utf8(
                                                        &bytes.as_chained().to_vec(),
                                                    )
                                                    .unwrap_or("[binary content]")
                                                    .to_string()
                                                    .into(),
                                                ),
                                            },
                                        }
                                        .serialize(&mut buf);
                                    }
                                    Binary::Missing => (),
                                    Binary::UnknownCte => {
                                        buf.push(b'\n');
                                        buf.extend_from_slice(
                                            &StatusResponse::no(format!(
                                                "Failed to decode part {} of message {}.",
                                                sections
                                                    .iter()
                                                    .map(|s| s.to_string())
                                                    .collect::<Vec<_>>()
                                                    .join("."),
                                                0
                                            ))
                                            .with_code(ResponseCode::UnknownCte)
                                            .serialize(Vec::new()),
                                        );
                                    }
                                }

                                if let Binary::Found(size) = metadata.binary_size(&sections) {
                                    buf.push(b'\n');
                                    DataItem::BinarySize {
                                        sections: Cow::Borrowed(&sections),
                                        size,
                                    }
                                    .serialize(&mut buf);
                                }
                            }

                            buf.extend_from_slice(b"\n----------------------------------\n");
                        } else {
                            break 'inner;
                        }
                    }
                }
                sections.push(part_id);
                stack.push(iter);
                iter = 1..9;
            }
            if let Some(prev_iter) = stack.pop() {
                sections.pop();
                iter = prev_iter;
            } else {
                break;
            }
        }

        // Check header fields and partial sections
        for sections in [
            vec![Section::HeaderFields {
                not: false,
                fields: vec!["From".into(), "To".into()],
            }],
            vec![Section::HeaderFields {
                not: true,
                fields: vec!["Subject".into(), "Cc".into()],
            }],
        ] {
            let mut sources = DecodedSources::default();
            DataItem::BodySection {
                contents: metadata
                    .body_section(raw, &mut sources, &sections, None, None)
                    .unwrap(),
                sections: Cow::Borrowed(&sections),
                origin_octet: None,
            }
            .serialize(&mut buf);
            buf.extend_from_slice(b"\n----------------------------------\n");
            let mut sources = DecodedSources::default();
            DataItem::BodySection {
                contents: metadata
                    .body_section(raw, &mut sources, &sections, (10, 25).into(), None)
                    .unwrap(),
                sections: Cow::Borrowed(&sections),
                origin_octet: 10.into(),
            }
            .serialize(&mut buf);
            buf.extend_from_slice(b"\n----------------------------------\n");
        }

        file_name.set_extension("imap");

        let expected_result = fs::read(&file_name).unwrap();

        if buf != expected_result {
            file_name.set_extension("imap_failed");
            fs::write(&file_name, buf).unwrap();
            panic!("Failed test, written output to {}", file_name.display());
        }
    }
}
