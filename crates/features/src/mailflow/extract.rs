/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The text of an attachment, for the detectors (§2.3), or why there isn't
//! one.
//!
//! Read: text files (plain, CSV, JSON, XML, HTML), Office Open XML (DOCX,
//! XLSX, PPTX) and OpenDocument (ODT, ODS, ODP) documents, and ZIP archives
//! one level deep. **Can't be inspected**: encrypted or password-protected
//! files, PDF (settled answer 2), the older binary Office formats, archives
//! inside archives, and anything past the limits. Everything else (images,
//! audio, programs) has no text to read and is neither.
//!
//! Office files are ZIP archives of XML, read here with the `zip` and
//! `quick-xml` crates the server already uses: no outside converter runs.

use quick_xml::{Reader, XmlVersion, events::Event};
use std::io::{Cursor, Read};

/// How much may be unpacked from one attachment, and from how many entries.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_unpacked: u64,
    pub max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_unpacked: 50 * 1024 * 1024,
            max_entries: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extracted {
    /// The text to check.
    Text(String),
    /// A kind of file with no text in it: nothing to check, nothing missed.
    NoText,
    /// A file that may hold text the detectors couldn't read.
    NotInspectable(Why),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    Encrypted,
    Pdf,
    LegacyOffice,
    NestedArchive,
    TooLarge,
    Damaged,
}

impl Why {
    pub fn as_str(&self) -> &'static str {
        match self {
            Why::Encrypted => "encrypted",
            Why::Pdf => "pdf",
            Why::LegacyOffice => "legacy-office",
            Why::NestedArchive => "nested-archive",
            Why::TooLarge => "too-large",
            Why::Damaged => "damaged",
        }
    }
}

const OLE_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

/// What an attachment says, from its declared type, its file name and, above
/// all, its first bytes.
pub fn extract(
    content_type: &str,
    file_name: Option<&str>,
    data: &[u8],
    limits: &Limits,
) -> Extracted {
    extract_at(content_type, file_name, data, limits, 0)
}

fn extract_at(
    content_type: &str,
    file_name: Option<&str>,
    data: &[u8],
    limits: &Limits,
    depth: u8,
) -> Extracted {
    let content_type = content_type.to_ascii_lowercase();
    let extension = file_name
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default();

    if data.len() as u64 > limits.max_unpacked {
        return Extracted::NotInspectable(Why::TooLarge);
    }
    if data.starts_with(b"%PDF-") || content_type == "application/pdf" || extension == "pdf" {
        return Extracted::NotInspectable(Why::Pdf);
    }
    if data.starts_with(OLE_MAGIC) {
        // An encrypted OOXML file is an OLE container holding the encrypted
        // package; any other OLE file is a legacy .doc, .xls or .ppt
        return Extracted::NotInspectable(if has_utf16(data, "EncryptedPackage") {
            Why::Encrypted
        } else {
            Why::LegacyOffice
        });
    }
    if data.starts_with(ZIP_MAGIC) {
        if depth > 0 {
            return Extracted::NotInspectable(Why::NestedArchive);
        }
        return zip(data, limits);
    }
    if is_text(&content_type, &extension) {
        let text = decode_text(data);
        return Extracted::Text(
            if content_type == "text/html" || matches!(extension.as_str(), "html" | "htm") {
                strip_html(&text)
            } else {
                text
            },
        );
    }
    Extracted::NoText
}

fn is_text(content_type: &str, extension: &str) -> bool {
    content_type.starts_with("text/")
        || matches!(
            content_type,
            "application/json"
                | "application/xml"
                | "application/csv"
                | "application/x-csv"
                | "message/rfc822"
        )
        || matches!(
            extension,
            "txt"
                | "csv"
                | "tsv"
                | "json"
                | "xml"
                | "md"
                | "log"
                | "html"
                | "htm"
                | "eml"
                | "ics"
                | "vcf"
        )
}

/// UTF-16 with a byte order mark, else UTF-8 (lossy).
fn decode_text(data: &[u8]) -> String {
    let utf16 = |bytes: &[u8], big: bool| {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| {
                if big {
                    u16::from_be_bytes([c[0], c[1]])
                } else {
                    u16::from_le_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match data {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(data).into_owned(),
    }
}

fn has_utf16(data: &[u8], needle: &str) -> bool {
    let needle: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
    data.windows(needle.len()).any(|w| w == needle.as_slice())
}

/// Tags out, the common entities decoded, block ends as new lines.
fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut skip_until: Option<&str> = None;
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    let bytes = html.as_bytes();
    while i < bytes.len() {
        if let Some(end) = skip_until {
            match lower[i..].find(end) {
                Some(at) => {
                    i += at + end.len();
                    skip_until = None;
                }
                None => break,
            }
            continue;
        }
        let c = bytes[i];
        if in_tag {
            if c == b'>' {
                in_tag = false;
            }
            i += 1;
            continue;
        }
        if c == b'<' {
            if lower[i..].starts_with("<script") {
                skip_until = Some("</script>");
            } else if lower[i..].starts_with("<style") {
                skip_until = Some("</style>");
            } else {
                if [
                    "<br", "<p", "</p", "<div", "</div", "<tr", "<li", "<td", "<th",
                ]
                .iter()
                .any(|t| lower[i..].starts_with(t))
                {
                    out.push(
                        if lower[i..].starts_with("<td") || lower[i..].starts_with("<th") {
                            '\t'
                        } else {
                            '\n'
                        },
                    );
                }
                in_tag = true;
            }
            i += 1;
            continue;
        }
        // Copy up to the next tag
        let next = html[i..].find('<').map_or(html.len(), |at| i + at);
        out.push_str(&html[i..next]);
        i = next;
    }
    for (entity, text) in [
        ("&nbsp;", " "),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
        ("&amp;", "&"),
    ] {
        out = out.replace(entity, text);
    }
    out
}

/// A ZIP file: an Office document, an OpenDocument, or an archive.
fn zip(data: &[u8], limits: &Limits) -> Extracted {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        return Extracted::NotInspectable(Why::Damaged);
    };
    if archive.len() > limits.max_entries {
        return Extracted::NotInspectable(Why::TooLarge);
    }
    let mut names = Vec::with_capacity(archive.len());
    let mut declared: u64 = 0;
    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index_raw(i) else {
            return Extracted::NotInspectable(Why::Damaged);
        };
        if entry.encrypted() {
            return Extracted::NotInspectable(Why::Encrypted);
        }
        declared = declared.saturating_add(entry.size());
        names.push(entry.name().to_string());
    }
    if declared > limits.max_unpacked {
        return Extracted::NotInspectable(Why::TooLarge);
    }
    let mut budget = limits.max_unpacked;
    let mut read =
        |archive: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str| -> Result<Vec<u8>, Why> {
            let entry = archive.by_name(name).map_err(|_| Why::Damaged)?;
            let mut bytes = Vec::new();
            // Declared sizes can lie: stop at the budget whatever they say
            entry
                .take(budget + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Why::Damaged)?;
            if bytes.len() as u64 > budget {
                return Err(Why::TooLarge);
            }
            budget -= bytes.len() as u64;
            Ok(bytes)
        };

    let has = |name: &str| names.iter().any(|n| n == name);
    let mut text = String::new();
    let result: Result<(), Why> = (|| {
        if has("[Content_Types].xml") {
            // Office Open XML: the parts that hold what a person wrote
            let mut shared = Vec::new();
            if has("xl/sharedStrings.xml") {
                shared = xml_strings(&read(&mut archive, "xl/sharedStrings.xml")?, "si");
            }
            for name in names.iter().filter(|n| ooxml_text_part(n)) {
                let xml = read(&mut archive, name)?;
                if name.starts_with("xl/worksheets/") {
                    xlsx_sheet(&xml, &mut text);
                } else {
                    xml_text(&xml, &mut text);
                }
                text.push('\n');
            }
            text.extend(shared.iter().map(|s| format!("{s}\n")));
        } else if names.first().is_some_and(|n| n == "mimetype")
            && read(&mut archive, "mimetype")?.starts_with(b"application/vnd.oasis.opendocument")
        {
            // OpenDocument: an encrypted one says so in its manifest
            if has("META-INF/manifest.xml")
                && contains(
                    &read(&mut archive, "META-INF/manifest.xml")?,
                    b"encryption-data",
                )
            {
                return Err(Why::Encrypted);
            }
            for name in ["content.xml", "styles.xml"] {
                if has(name) {
                    xml_text(&read(&mut archive, name)?, &mut text);
                    text.push('\n');
                }
            }
        } else {
            // An archive: each file inside, one level deep
            for name in names.iter().filter(|n| !n.ends_with('/')) {
                let bytes = read(&mut archive, name)?;
                match extract_at("", Some(name), &bytes, limits, 1) {
                    Extracted::Text(inner) => {
                        text.push_str(&inner);
                        text.push('\n');
                    }
                    Extracted::NoText => {}
                    Extracted::NotInspectable(why) => return Err(why),
                }
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => Extracted::Text(text),
        Err(why) => Extracted::NotInspectable(why),
    }
}

fn ooxml_text_part(name: &str) -> bool {
    let xml = name.ends_with(".xml");
    xml && (name == "word/document.xml"
        || [
            "word/header",
            "word/footer",
            "word/footnotes",
            "word/endnotes",
            "word/comments",
        ]
        .iter()
        .any(|p| name.starts_with(p))
        || name.starts_with("xl/worksheets/sheet")
        || name.starts_with("ppt/slides/slide")
        || name.starts_with("ppt/notesSlides/"))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The local name of a tag, without its namespace prefix.
fn local(name: &[u8]) -> &[u8] {
    name.rsplit(|b| *b == b':').next().unwrap_or(name)
}

fn push_entity(entity: &[u8], out: &mut String) {
    match entity {
        b"lt" => out.push('<'),
        b"gt" => out.push('>'),
        b"amp" => out.push('&'),
        b"apos" => out.push('\''),
        b"quot" => out.push('"'),
        _ => {
            let code = match entity {
                [b'#', b'x' | b'X', hex @ ..] => std::str::from_utf8(hex)
                    .ok()
                    .and_then(|h| u32::from_str_radix(h, 16).ok()),
                [b'#', dec @ ..] => std::str::from_utf8(dec).ok().and_then(|d| d.parse().ok()),
                _ => None,
            };
            if let Some(c) = code.and_then(char::from_u32) {
                out.push(c);
            }
        }
    }
}

/// Every text node, runs joined as written, a new line after each paragraph
/// or row and a tab after each cell, so a number split across runs is whole
/// again.
fn xml_text(xml: &[u8], out: &mut String) {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Text(t)) => {
                if let Ok(text) = t.xml_content(XmlVersion::Implicit1_0) {
                    out.push_str(&text);
                }
            }
            Ok(Event::CData(t)) => out.push_str(&String::from_utf8_lossy(&t)),
            Ok(Event::GeneralRef(entity)) => push_entity(&entity, out),
            Ok(Event::End(e)) => match local(e.name().as_ref()) {
                b"p" | b"h" | b"tr" | b"row" | b"table-row" | b"br" => out.push('\n'),
                b"tc" | b"c" | b"table-cell" | b"tab" => out.push('\t'),
                _ => {}
            },
            Ok(Event::Empty(e)) => match local(e.name().as_ref()) {
                b"br" | b"line-break" => out.push('\n'),
                b"tab" | b"s" => out.push(' '),
                _ => {}
            },
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
}

/// The text of each `item` element (a shared string in XLSX).
fn xml_strings(xml: &[u8], item: &str) -> Vec<String> {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut items = Vec::new();
    let mut current: Option<String> = None;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if local(e.name().as_ref()) == item.as_bytes() => {
                current = Some(String::new())
            }
            Ok(Event::End(e)) if local(e.name().as_ref()) == item.as_bytes() => {
                items.extend(current.take());
            }
            Ok(Event::Text(t)) => {
                if let (Some(s), Ok(text)) =
                    (current.as_mut(), t.xml_content(XmlVersion::Implicit1_0))
                {
                    s.push_str(&text);
                }
            }
            Ok(Event::GeneralRef(entity)) => {
                if let Some(s) = current.as_mut() {
                    push_entity(&entity, s);
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    items
}

/// A worksheet's cell values: numbers and inline strings. Cells holding a
/// shared string are skipped here; the shared strings are read whole.
fn xlsx_sheet(xml: &[u8], out: &mut String) {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut shared_cell = false;
    let mut in_value = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match local(e.name().as_ref()) {
                b"c" => {
                    shared_cell = e
                        .attributes()
                        .flatten()
                        .any(|a| a.key.as_ref() == b"t" && a.value.as_ref() == b"s");
                }
                b"v" | b"t" => in_value = true,
                _ => {}
            },
            Ok(Event::End(e)) => match local(e.name().as_ref()) {
                b"v" | b"t" => in_value = false,
                b"c" => out.push('\t'),
                b"row" => out.push('\n'),
                _ => {}
            },
            // A shared string's cell holds only its index: the string itself
            // is added with the shared strings
            Ok(Event::Text(t)) if in_value && !shared_cell => {
                if let Ok(text) = t.xml_content(XmlVersion::Implicit1_0) {
                    out.push_str(&text);
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn zip_of(files: &[(&str, &str)]) -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in files {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    fn text_of(extracted: Extracted) -> String {
        match extracted {
            Extracted::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn plain_text_and_html() {
        let limits = Limits::default();
        assert_eq!(
            text_of(extract("text/plain", None, b"card 4242", &limits)),
            "card 4242"
        );
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("héllo".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(
            text_of(extract(
                "application/octet-stream",
                Some("a.csv"),
                &utf16,
                &limits
            )),
            "héllo"
        );
        let html = "<html><style>p{}</style><p>Card&nbsp;4242</p><script>x()</script><td>a</td><td>b</td></html>";
        let text = text_of(extract("text/html", None, html.as_bytes(), &limits));
        assert!(
            text.contains("Card 4242") && !text.contains("x()") && !text.contains("p{}"),
            "{text:?}"
        );
        assert_eq!(
            extract("image/png", Some("a.png"), b"\x89PNG....", &limits),
            Extracted::NoText
        );
    }

    #[test]
    fn docx_joins_split_runs() {
        let doc = r#"<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Card 4242 42</w:t></w:r><w:r><w:t>42 4242 4242</w:t></w:r></w:p><w:p><w:r><w:t>A &amp; B</w:t></w:r></w:p></w:body></w:document>"#;
        let docx = zip_of(&[
            ("[Content_Types].xml", "<Types/>"),
            ("word/document.xml", doc),
        ]);
        let text = text_of(extract(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            Some("a.docx"),
            &docx,
            &Limits::default(),
        ));
        assert!(text.contains("Card 4242 4242 4242 4242\nA & B"), "{text:?}");
    }

    #[test]
    fn xlsx_numbers_and_shared_strings() {
        let sheet = r#"<worksheet><sheetData><row><c r="A1" t="s"><v>0</v></c><c r="B1"><v>4242424242424242</v></c></row></sheetData></worksheet>"#;
        let shared = r#"<sst><si><t>IBAN GB29 NWBK 6016 1331 9268 19</t></si></sst>"#;
        let xlsx = zip_of(&[
            ("[Content_Types].xml", "<Types/>"),
            ("xl/sharedStrings.xml", shared),
            ("xl/worksheets/sheet1.xml", sheet),
        ]);
        let text = text_of(extract("", Some("book.xlsx"), &xlsx, &Limits::default()));
        assert!(
            text.contains("4242424242424242") && text.contains("GB29 NWBK 6016 1331 9268 19"),
            "{text:?}"
        );
        // The shared string's index isn't read as a value
        assert!(
            !text.contains("\t0\t") && !text.starts_with('0'),
            "{text:?}"
        );
    }

    #[test]
    fn opendocument_and_encrypted_opendocument() {
        let content = r#"<office:document-content xmlns:text="t"><text:p>SSN 078-05-1120</text:p></office:document-content>"#;
        let odt = zip_of(&[
            ("mimetype", "application/vnd.oasis.opendocument.text"),
            ("content.xml", content),
        ]);
        assert!(
            text_of(extract("", Some("a.odt"), &odt, &Limits::default()))
                .contains("SSN 078-05-1120")
        );
        let manifest = r#"<manifest:manifest><manifest:file-entry><manifest:encryption-data/></manifest:file-entry></manifest:manifest>"#;
        let locked = zip_of(&[
            ("mimetype", "application/vnd.oasis.opendocument.text"),
            ("META-INF/manifest.xml", manifest),
            ("content.xml", "x"),
        ]);
        assert_eq!(
            extract("", Some("a.odt"), &locked, &Limits::default()),
            Extracted::NotInspectable(Why::Encrypted)
        );
    }

    #[test]
    fn archives() {
        let limits = Limits::default();
        let archive = zip_of(&[
            ("notes/a.txt", "card 4242424242424242"),
            ("b.png", "\u{89}PNG"),
        ]);
        assert!(
            text_of(extract("application/zip", Some("x.zip"), &archive, &limits))
                .contains("4242424242424242")
        );
        let nested = zip_of(&[(
            "inner.zip",
            std::str::from_utf8(&[b'P', b'K', 3, 4]).unwrap(),
        )]);
        assert_eq!(
            extract("application/zip", Some("x.zip"), &nested, &limits),
            Extracted::NotInspectable(Why::NestedArchive)
        );

        // Password-protected
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file(
            "secret.txt",
            SimpleFileOptions::default().with_aes_encryption(zip::AesMode::Aes256, "pw"),
        )
        .unwrap();
        zip.write_all(b"4242424242424242").unwrap();
        let locked = zip.finish().unwrap().into_inner();
        assert_eq!(
            extract("application/zip", Some("x.zip"), &locked, &limits),
            Extracted::NotInspectable(Why::Encrypted)
        );

        // Past the limits
        let small = Limits {
            max_unpacked: 10,
            max_entries: 1,
        };
        assert_eq!(
            extract("application/zip", Some("x.zip"), &archive, &small),
            Extracted::NotInspectable(Why::TooLarge)
        );
        assert_eq!(
            extract("application/zip", None, b"PK\x03\x04garbage", &limits),
            Extracted::NotInspectable(Why::Damaged)
        );
    }

    #[test]
    fn not_inspectable_kinds() {
        let limits = Limits::default();
        assert_eq!(
            extract("application/octet-stream", None, b"%PDF-1.7 ...", &limits),
            Extracted::NotInspectable(Why::Pdf)
        );
        let mut ole = OLE_MAGIC.to_vec();
        ole.extend(std::iter::repeat_n(0, 64));
        assert_eq!(
            extract("", Some("old.doc"), &ole, &limits),
            Extracted::NotInspectable(Why::LegacyOffice)
        );
        ole.extend("EncryptedPackage".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(
            extract("", Some("new.docx"), &ole, &limits),
            Extracted::NotInspectable(Why::Encrypted)
        );
    }
}
