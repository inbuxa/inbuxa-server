/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Transport actions that change a message (§2.4): headers, the subject,
//! disclaimers. Each takes the raw message and returns the new one, or
//! `None` when there's nothing to change.
//!
//! Only what the action names changes. A disclaimer edits the message's
//! main text and HTML bodies (not attachments, not attached messages):
//! each is decoded, changed and written back as UTF-8 quoted-printable,
//! with its other headers kept. A disclaimer already there isn't added
//! again, so a reply thread carries it once.

use base64::{Engine, engine::general_purpose::STANDARD};
use mail_builder::encoders::quoted_printable::QuotedPrintableEncoder;
use mail_parser::{HeaderName, MessageParser, PartType};

use super::rules::Position;

/// A header value, as an RFC 2047 encoded word when it isn't plain ASCII.
pub fn header_value(value: &str) -> String {
    if value.is_ascii() {
        value.to_string()
    } else {
        format!("=?utf-8?B?{}?=", STANDARD.encode(value))
    }
}

/// `Name: value` added at the top of the message.
pub fn add_header(message: &[u8], name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + name.len() + value.len() + 4);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(header_value(value).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(message);
    out
}

/// Every top-level header called `name` taken out.
pub fn remove_header(message: &[u8], name: &str) -> Option<Vec<u8>> {
    let parsed = MessageParser::new().parse_headers(message)?;
    let mut ranges: Vec<(usize, usize)> = parsed
        .headers()
        .iter()
        .filter(|h| h.name.as_str().eq_ignore_ascii_case(name))
        .map(|h| (h.offset_field as usize, h.offset_end as usize))
        .collect();
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_unstable();
    let mut out = Vec::with_capacity(message.len());
    let mut at = 0;
    for (start, end) in ranges {
        out.extend_from_slice(&message[at..start]);
        at = end;
    }
    out.extend_from_slice(&message[at..]);
    Some(out)
}

/// The Subject header replaced by `subject` (added if there was none).
pub fn set_subject(message: &[u8], subject: &str) -> Vec<u8> {
    let line = format!("Subject: {}\r\n", header_value(subject));
    let parsed = MessageParser::new().parse_headers(message);
    match parsed
        .as_ref()
        .and_then(|p| p.headers().iter().find(|h| h.name == HeaderName::Subject))
    {
        Some(header) => {
            let mut out = Vec::with_capacity(message.len() + line.len());
            out.extend_from_slice(&message[..header.offset_field as usize]);
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(&message[header.offset_end as usize..]);
            out
        }
        None => {
            let mut out = line.into_bytes();
            out.extend_from_slice(message);
            out
        }
    }
}

/// `prefix` put before the subject, unless it's already there.
pub fn prefix_subject(message: &[u8], prefix: &str) -> Option<Vec<u8>> {
    let parsed = MessageParser::new().parse_headers(message)?;
    let subject = parsed.subject().unwrap_or_default();
    if subject.trim_start().starts_with(prefix.trim()) {
        return None;
    }
    Some(set_subject(
        message,
        &format!("{} {}", prefix.trim(), subject.trim_start()),
    ))
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', "<br>\n")
}

fn with_text_disclaimer(body: &str, text: &str, position: Position) -> String {
    let text = text.trim_end();
    match position {
        Position::Top => format!("{text}\r\n\r\n{body}"),
        Position::Bottom => format!("{}\r\n\r\n{text}\r\n", body.trim_end()),
    }
}

fn with_html_disclaimer(body: &str, html: &str, position: Position) -> String {
    let lower = body.to_ascii_lowercase();
    match position {
        Position::Top => match lower
            .find("<body")
            .and_then(|at| lower[at..].find('>').map(|end| at + end + 1))
        {
            Some(at) => format!("{}{html}{}", &body[..at], &body[at..]),
            None => format!("{html}{body}"),
        },
        Position::Bottom => match lower.rfind("</body>") {
            Some(at) => format!("{}{html}{}", &body[..at], &body[at..]),
            None => format!("{body}{html}"),
        },
    }
}

/// The disclaimer added to each main text and HTML body. `html` is the HTML
/// version, or the text escaped when there's none.
pub fn add_disclaimer(
    message: &[u8],
    text: &str,
    html: Option<&str>,
    position: Position,
) -> Option<Vec<u8>> {
    let parsed = MessageParser::new().parse(message)?;
    let html = html
        .map(str::to_string)
        .unwrap_or_else(|| format!("<p>{}</p>", escape_html(text.trim())));
    let marker = text.trim();

    let mut body_parts: Vec<u32> = parsed
        .text_body
        .iter()
        .chain(parsed.html_body.iter())
        .copied()
        .collect();
    body_parts.sort_unstable();
    body_parts.dedup();

    // (start, end, replacement) for each part, applied from the last
    let mut edits: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    for id in body_parts {
        let Some(part) = parsed.parts.get(id as usize) else {
            continue;
        };
        let (new_body, content_type) = match &part.body {
            PartType::Text(body) => {
                if body.contains(marker) {
                    continue;
                }
                (with_text_disclaimer(body, text, position), "text/plain")
            }
            PartType::Html(body) => {
                if body.contains(marker) || body.contains(html.as_str()) {
                    continue;
                }
                (with_html_disclaimer(body, &html, position), "text/html")
            }
            _ => continue,
        };
        // The part's own headers, less the two this changes
        let mut headers = Vec::new();
        for header in part.headers() {
            if matches!(
                header.name,
                HeaderName::ContentType | HeaderName::ContentTransferEncoding
            ) {
                continue;
            }
            headers.extend_from_slice(
                &message[header.offset_field as usize..header.offset_end as usize],
            );
        }
        headers.extend_from_slice(
            format!("Content-Type: {content_type}; charset=utf-8\r\n").as_bytes(),
        );
        headers.extend_from_slice(b"Content-Transfer-Encoding: quoted-printable\r\n\r\n");
        let encoded = QuotedPrintableEncoder::new()
            .preserve_line_breaks()
            .encode(new_body.as_bytes())
            .ok()?;
        headers.extend_from_slice(&encoded);
        // A single-part message's headers are the message's: its first
        // header is where the part starts
        let start = part.headers().first().map_or(part.offset_header, |h| {
            h.offset_field.min(part.offset_header)
        }) as usize;
        edits.push((start, part.offset_end as usize, headers));
    }
    if edits.is_empty() {
        return None;
    }
    edits.sort_by_key(|(start, _, _)| std::cmp::Reverse(*start));
    let mut out = message.to_vec();
    for (start, end, replacement) in edits {
        out.splice(start..end.min(out.len()), replacement);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(message: &[u8]) -> mail_parser::Message<'_> {
        MessageParser::new().parse(message).expect("parses")
    }

    const PLAIN: &[u8] = b"From: a@example.com\r\nTo: b@elsewhere.org\r\nSubject: Hello\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCaf=E9 at noon.\r\n";

    const ALTERNATIVE: &[u8] = b"From: a@example.com\r\nSubject: Plans\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n--outer\r\nContent-Type: multipart/alternative; boundary=\"inner\"\r\n\r\n--inner\r\nContent-Type: text/plain\r\n\r\nSee you.\r\n--inner\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\nPGh0bWw+PGJvZHk+PHA+U2VlIHlvdS48L3A+PC9ib2R5PjwvaHRtbD4=\r\n--inner--\r\n--outer\r\nContent-Type: text/plain; name=\"notes.txt\"\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\n\r\nAttachment text.\r\n--outer--\r\n";

    #[test]
    fn headers() {
        let added = add_header(PLAIN, "X-Mail-Rule", "External");
        assert_eq!(
            parse(&added).header_raw("X-Mail-Rule").map(str::trim),
            Some("External")
        );
        let removed = remove_header(&added, "x-mail-rule").unwrap();
        assert_eq!(removed, PLAIN);
        assert!(remove_header(PLAIN, "X-Absent").is_none());
        let utf8 = add_header(PLAIN, "X-Note", "Überprüft");
        // An RFC 2047 word: mail readers decode it, the wire stays ASCII
        assert_eq!(
            parse(&utf8).header_raw("X-Note").map(str::trim),
            Some("=?utf-8?B?w5xiZXJwcsO8ZnQ=?=")
        );
    }

    #[test]
    fn subjects() {
        let prefixed = prefix_subject(PLAIN, "[External]").unwrap();
        assert_eq!(parse(&prefixed).subject(), Some("[External] Hello"));
        assert!(prefix_subject(&prefixed, "[External]").is_none());
        let accented = set_subject(PLAIN, "Réunion à midi");
        assert_eq!(parse(&accented).subject(), Some("Réunion à midi"));
        assert!(accented.is_ascii(), "encoded as an RFC 2047 word");
        let none = set_subject(b"From: a@example.com\r\n\r\nBody\r\n", "New");
        assert_eq!(parse(&none).subject(), Some("New"));
    }

    #[test]
    fn disclaimer_on_a_single_part() {
        let out = add_disclaimer(PLAIN, "Sent by Example Co.", None, Position::Bottom).unwrap();
        let parsed = parse(&out);
        let body = parsed.body_text(0).unwrap();
        assert!(body.starts_with("Café at noon."), "{body:?}");
        assert!(body.trim_end().ends_with("Sent by Example Co."), "{body:?}");
        assert_eq!(parsed.subject(), Some("Hello"));
        assert_eq!(
            parsed.header_raw("To").map(str::trim),
            Some("b@elsewhere.org")
        );
        // Once only
        assert!(add_disclaimer(&out, "Sent by Example Co.", None, Position::Bottom).is_none());
    }

    #[test]
    fn disclaimer_on_alternatives_leaves_attachments() {
        let out = add_disclaimer(
            ALTERNATIVE,
            "Confidential.",
            Some("<p><i>Confidential.</i></p>"),
            Position::Top,
        )
        .unwrap();
        let parsed = parse(&out);
        assert!(
            parsed
                .body_text(0)
                .unwrap()
                .starts_with("Confidential.\r\n\r\nSee you."),
            "{:?}",
            parsed.body_text(0)
        );
        let html = parsed.body_html(0).unwrap();
        assert!(
            html.contains("<body><p><i>Confidential.</i></p><p>See you.</p>"),
            "{html}"
        );
        assert_eq!(parsed.attachment_count(), 1);
        assert_eq!(
            parsed.attachment(0).unwrap().text_contents(),
            Some("Attachment text.")
        );
        assert!(!String::from_utf8_lossy(&out).contains("Confidential.\r\n\r\nAttachment"));
    }
}
