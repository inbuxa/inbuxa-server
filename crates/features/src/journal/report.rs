/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The journal report (JR-3, JR-4), as coffeylabs.org/specs/journal-report/
//! defines it: a `multipart/report` whose first part is a summary for people,
//! whose second lists the envelope for programs, and whose third is the
//! message as it was queued, byte for byte, as `message/rfc822`.
//!
//! Reports already stored keep the layout they were written in, a
//! `multipart/mixed` of the summary and the message, and [`original`] reads
//! both.

use super::Direction;
use mail_builder::headers::{Header, date::Date, text::Text};
use mail_parser::{MessageParser, MimeHeaders};
use sha2::{Digest, Sha256};

/// The `report-type` of the `multipart/report`: RFC 6522 has it be the
/// subtype of the second part.
pub const REPORT_TYPE: &str = "vnd.coffeylabs.journal-report";
/// The media type of the part programs read.
pub const MEDIA_TYPE: &str = "application/vnd.coffeylabs.journal-report";
/// The version that part declares.
pub const VERSION: u32 = 1;

/// The longest value the summary shows: a line of a message that travels as
/// 8bit can't pass 998 bytes, and the original holds the whole of it.
const SUMMARY_VALUE_MAX: usize = 900;
/// The longest address taken from a sender's ORCPT parameter (RFC 5321
/// allows a path of 256; this leaves room for internationalized ones).
const VIA_MAX: usize = 320;

/// One envelope recipient, with the address it was given as (a list's, for
/// the list's members).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub address: String,
    pub orcpt: Option<String>,
    /// The mail flow rule that added or redirected to it.
    pub added_by: Option<String>,
}

/// What the queue knows about a message.
#[derive(Debug, Clone)]
pub struct Envelope<'x> {
    pub sender: &'x str,
    pub authenticated: bool,
    pub recipients: &'x [Recipient],
    pub queue_id: u64,
    /// Seconds.
    pub received: u64,
    pub direction: Direction,
    pub held: bool,
}

/// How a recipient came to be on the envelope, as far as the message and
/// the envelope show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addressed {
    To,
    Cc,
    /// Reached through another address, such as a list's: the ORCPT named it.
    List(String),
    /// A mail flow rule added it or redirected to it.
    Rule(String),
    /// In neither To nor Cc, with nothing to say why. A blind copy looks like
    /// this, and so does a list's post, or a message arriving for an alias.
    NotInHeaders,
}

/// What a report says, besides the envelope's own fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fields {
    pub subject: String,
    pub message_id: String,
    pub recipients: Vec<(String, Addressed)>,
}

/// One line's worth of a value: no line breaks, no control characters.
fn line(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// The address an ORCPT names, without its `rfc822;` type. A sender writes
/// this parameter, so anything that isn't plainly an address is dropped: it
/// goes into a field programs read.
fn orcpt_address(orcpt: &str) -> Option<String> {
    let orcpt = orcpt.trim();
    let bare = match orcpt.split_once(';') {
        Some((kind, address)) if kind.eq_ignore_ascii_case("rfc822") => address,
        _ => orcpt,
    };
    let address = bare.trim().to_lowercase();
    let plain = address.len() <= VIA_MAX
        && address.contains('@')
        && !address.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ';' | '"' | ',')
        });
    plain.then_some(address)
}

/// Sorts the envelope's recipients by how they were addressed.
pub fn fields(envelope: &Envelope<'_>, original: &[u8]) -> Fields {
    let parsed = MessageParser::default().parse_headers(original);
    let headed = |which: Option<&mail_parser::Address<'_>>| -> Vec<String> {
        which
            .map(|list| {
                list.iter()
                    .filter_map(|addr| addr.address())
                    .map(|address| address.to_lowercase())
                    .collect()
            })
            .unwrap_or_default()
    };
    let (subject, message_id, header_to, header_cc) = match &parsed {
        Some(message) => (
            message.subject().map(line).unwrap_or_default(),
            message
                .message_id()
                .map(|id| format!("<{}>", line(id)))
                .unwrap_or_default(),
            headed(message.to()),
            headed(message.cc()),
        ),
        None => Default::default(),
    };

    let recipients = envelope
        .recipients
        .iter()
        .map(|rcpt| {
            let address = rcpt.address.to_lowercase();
            let via = rcpt
                .orcpt
                .as_deref()
                .and_then(orcpt_address)
                .filter(|via| *via != address);
            let addressed = if let Some(rule) = &rcpt.added_by {
                Addressed::Rule(line(rule))
            } else if header_to.contains(&address) {
                Addressed::To
            } else if header_cc.contains(&address) {
                Addressed::Cc
            } else if let Some(via) = via {
                Addressed::List(via)
            } else {
                Addressed::NotInHeaders
            };
            (line(&rcpt.address), addressed)
        })
        .collect();

    Fields {
        subject,
        message_id,
        recipients,
    }
}

/// At most `max` bytes of a value, cut between characters.
fn fit(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// The report's first part, for people. One recipient a line, so a long
/// list can't make a line too long to travel. Programs read the second part.
pub fn text(envelope: &Envelope<'_>, fields: &Fields) -> String {
    let mut out = String::new();
    let mut field = |name: &str, value: &str| {
        if !value.is_empty() {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(fit(value, SUMMARY_VALUE_MAX));
            out.push_str("\r\n");
        }
    };
    let sender = if envelope.sender.is_empty() {
        "<>".to_string()
    } else {
        line(envelope.sender)
    };
    field("Sender", &sender);
    field(
        "Authenticated",
        if envelope.authenticated { "yes" } else { "no" },
    );
    field("Subject", &fields.subject);
    field("Message-ID", &fields.message_id);
    field("Queue ID", &format!("{:x}", envelope.queue_id));
    field(
        "Received",
        &mail_parser::DateTime::from_timestamp(envelope.received as i64).to_rfc3339(),
    );
    field("Direction", envelope.direction.as_str());
    let of = |wanted: &dyn Fn(&Addressed) -> bool| -> Vec<&str> {
        fields
            .recipients
            .iter()
            .filter(|(_, addressed)| wanted(addressed))
            .map(|(address, _)| address.as_str())
            .collect()
    };
    for address in of(&|a| *a == Addressed::To) {
        field("To", address);
    }
    for address in of(&|a| *a == Addressed::Cc) {
        field("Cc", address);
    }
    for address in of(&|a| *a == Addressed::NotInHeaders) {
        field("Not in To or Cc", address);
    }
    for (address, addressed) in &fields.recipients {
        if let Addressed::List(via) = addressed {
            field("Expanded", &format!("{via} -> {address}"));
        }
    }
    for (address, addressed) in &fields.recipients {
        if let Addressed::Rule(rule) = addressed {
            field("Added by rule", &format!("{rule} -> {address}"));
        }
    }
    if envelope.held {
        field("Held for review", "yes");
    }
    out
}

/// A value of the second part's `rule` parameter.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// The report's second part, for programs: one field a line, and one
/// `Original-Rcpt-To` for each envelope recipient. Field names are fixed
/// English, modeled on RFC 5965's where they mean the same.
pub fn machine(envelope: &Envelope<'_>, fields: &Fields, host: &str) -> String {
    let mut out = format!(
        "Version: {VERSION}\r\n\
         Reporting-MTA: dns; {}\r\n\
         Queue-ID: {:x}\r\n\
         Arrival-Date: {}\r\n\
         Direction: {}\r\n\
         Authenticated: {}\r\n\
         Held: {}\r\n\
         Original-Mail-From: <{}>\r\n",
        line(host),
        envelope.queue_id,
        Date::new(envelope.received as i64).to_rfc822(),
        envelope.direction.as_str(),
        if envelope.authenticated { "yes" } else { "no" },
        if envelope.held { "yes" } else { "no" },
        line(envelope.sender),
    );
    for (address, addressed) in &fields.recipients {
        out.push_str("Original-Rcpt-To: <");
        out.push_str(address);
        out.push_str(">; addressed=");
        match addressed {
            Addressed::To => out.push_str("to"),
            Addressed::Cc => out.push_str("cc"),
            Addressed::List(via) => {
                out.push_str("list; via=<");
                out.push_str(via);
                out.push('>');
            }
            Addressed::Rule(rule) => {
                out.push_str("rule; rule=");
                out.push_str(&quoted(rule));
            }
            Addressed::NotInHeaders => out.push_str("not-in-headers"),
        }
        out.push_str("\r\n");
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a body holds, which decides how it may travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    SevenBit,
    EightBit,
    /// NULs, or a line past 998 bytes.
    Binary,
}

impl Body {
    pub fn of(bytes: &[u8]) -> Body {
        if bytes.contains(&0) || bytes.split(|b| *b == b'\n').any(|l| l.len() > 998) {
            Body::Binary
        } else if bytes.is_ascii() {
            Body::SevenBit
        } else {
            Body::EightBit
        }
    }

    fn encoding(&self) -> &'static str {
        match self {
            Body::SevenBit => "7bit",
            Body::EightBit => "8bit",
            Body::Binary => "binary",
        }
    }
}

/// The whole report: headers, the summary, the envelope, then the original
/// untouched. `from` is the address the report is from; `host` names the
/// server in its Message-ID and its `Reporting-MTA`.
pub fn build(
    envelope: &Envelope<'_>,
    original: &[u8],
    from: &str,
    host: &str,
) -> (Vec<u8>, Fields) {
    let fields = fields(envelope, original);
    let summary = text(envelope, &fields);
    let envelope_part = machine(envelope, &fields, host);
    // A boundary that can't occur in the original
    let mut boundary = format!("journal-{}", &hex(&Sha256::digest(original))[..32]);
    while original
        .windows(boundary.len())
        .any(|window| window == boundary.as_bytes())
    {
        boundary.push('x');
    }

    let mut out: Vec<u8> =
        Vec::with_capacity(original.len() + summary.len() + envelope_part.len() + 1024);
    out.extend_from_slice(format!("From: Journal <{}>\r\n", line(from)).as_bytes());
    out.extend_from_slice(b"Date: ");
    out.extend_from_slice(Date::new(envelope.received as i64).to_rfc822().as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"Subject: ");
    let subject = if fields.subject.is_empty() {
        "Journal report".to_string()
    } else {
        format!("Journal report: {}", fields.subject)
    };
    Text::new(subject).write_header(&mut out, "Subject: ".len());
    out.extend_from_slice(
        format!(
            "Message-ID: <journal.{:x}.{}@{}>\r\n",
            envelope.queue_id,
            envelope.received,
            line(host)
        )
        .as_bytes(),
    );
    out.extend_from_slice(format!("X-Inbuxa-Journal: {:x}\r\n", envelope.queue_id).as_bytes());
    out.extend_from_slice(b"MIME-Version: 1.0\r\n");
    out.extend_from_slice(
        format!(
            "Content-Type: multipart/report; report-type=\"{REPORT_TYPE}\";\r\n\
             \tboundary=\"{boundary}\"\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        format!(
            "Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: {}\r\n\r\n",
            Body::of(summary.as_bytes()).encoding()
        )
        .as_bytes(),
    );
    out.extend_from_slice(summary.as_bytes());
    out.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        format!(
            "Content-Type: {MEDIA_TYPE}\r\n\
             Content-Transfer-Encoding: {}\r\n\r\n",
            Body::of(envelope_part.as_bytes()).encoding()
        )
        .as_bytes(),
    );
    out.extend_from_slice(envelope_part.as_bytes());
    out.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    out.extend_from_slice(b"Content-Type: message/rfc822\r\n");
    out.extend_from_slice(b"Content-Disposition: attachment; filename=\"original.eml\"\r\n");
    out.extend_from_slice(
        format!(
            "Content-Transfer-Encoding: {}\r\n\r\n",
            Body::of(original).encoding()
        )
        .as_bytes(),
    );
    out.extend_from_slice(original);
    // The line break before a boundary belongs to the boundary: the
    // original keeps its own last one
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (out, fields)
}

/// Where the original starts and ends inside a report, in this layout or the
/// earlier one.
pub fn original(report: &[u8]) -> Option<&[u8]> {
    let parsed = MessageParser::default().parse(report)?;
    let part = parsed.attachments().find(|part| {
        part.content_type().is_some_and(|c| {
            c.ctype().eq_ignore_ascii_case("message")
                && c.subtype()
                    .is_some_and(|s| s.eq_ignore_ascii_case("rfc822"))
        })
    })?;
    let start = part.raw_body_offset() as usize;
    let end = part.raw_end_offset() as usize;
    report.get(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_parser::PartType;

    const ORIGINAL: &[u8] = b"From: alice@example.com\r\n\
To: Bank <pay@bank.example>\r\n\
Cc: bob@example.com\r\n\
Subject: Q3 figures\r\n\
Message-ID: <abc@example.com>\r\n\
\r\n\
The figures.\r\n";

    fn rcpt(address: &str, orcpt: Option<&str>) -> Recipient {
        Recipient {
            address: address.into(),
            orcpt: orcpt.map(Into::into),
            added_by: None,
        }
    }

    fn envelope(recipients: &[Recipient]) -> Envelope<'_> {
        Envelope {
            sender: "alice@example.com",
            authenticated: true,
            recipients,
            queue_id: 0x1a2b,
            received: 1_790_000_000,
            direction: Direction::Outgoing,
            held: false,
        }
    }

    #[test]
    fn recipients_sorted_by_how_they_were_addressed() {
        let recipients = [
            rcpt("pay@bank.example", None),
            rcpt("Bob@example.com", Some("rfc822;bob@example.com")),
            rcpt("carol@example.com", None),
            rcpt("dan@example.com", Some("finance@example.com")),
            rcpt("erin@example.com", Some("rfc822;Finance@example.com")),
        ];
        let fields = fields(&envelope(&recipients), ORIGINAL);
        assert_eq!(fields.subject, "Q3 figures");
        assert_eq!(fields.message_id, "<abc@example.com>");
        let list = Addressed::List("finance@example.com".to_string());
        assert_eq!(
            fields.recipients,
            vec![
                ("pay@bank.example".to_string(), Addressed::To),
                ("Bob@example.com".to_string(), Addressed::Cc),
                ("carol@example.com".to_string(), Addressed::NotInHeaders),
                ("dan@example.com".to_string(), list.clone()),
                ("erin@example.com".to_string(), list),
            ]
        );
    }

    #[test]
    fn report_carries_the_original_untouched() {
        let recipients = [
            rcpt("pay@bank.example", None),
            rcpt("carol@example.com", None),
        ];
        let (report, _) = build(
            &envelope(&recipients),
            ORIGINAL,
            "postmaster@example.com",
            "mx.example.com",
        );
        let text = String::from_utf8_lossy(&report);
        assert!(text.contains("Sender: alice@example.com\r\n"));
        assert!(text.contains("Not in To or Cc: carol@example.com\r\n"));
        assert!(text.contains("Queue ID: 1a2b\r\n"));
        assert!(text.contains("Direction: outgoing\r\n"));
        assert!(text.contains("Subject: Journal report: Q3 figures\r\n"));
        assert!(!text.contains("Held for review"));
        assert_eq!(original(&report), Some(ORIGINAL));
        let unterminated = &ORIGINAL[..ORIGINAL.len() - 2];
        let (report, _) = build(
            &envelope(&recipients),
            unterminated,
            "postmaster@example.com",
            "mx.example.com",
        );
        assert_eq!(original(&report), Some(unterminated));
    }

    #[test]
    fn report_has_the_three_parts_of_a_multipart_report() {
        let recipients = [
            rcpt("pay@bank.example", None),
            rcpt("carol@example.com", None),
        ];
        let (report, _) = build(
            &envelope(&recipients),
            ORIGINAL,
            "postmaster@example.com",
            "mx.example.com",
        );
        let parsed = MessageParser::default().parse(&report).unwrap();
        let root = parsed.content_type().unwrap();
        assert_eq!(root.ctype(), "multipart");
        assert_eq!(root.subtype(), Some("report"));
        assert_eq!(root.attribute("report-type"), Some(REPORT_TYPE));
        let PartType::Multipart(children) = &parsed.parts[0].body else {
            panic!("not a multipart");
        };
        let types: Vec<String> = children
            .iter()
            .map(|id| {
                let c = parsed.parts[*id as usize].content_type().unwrap();
                format!("{}/{}", c.ctype(), c.subtype().unwrap_or_default())
            })
            .collect();
        assert_eq!(types, ["text/plain", MEDIA_TYPE, "message/rfc822"]);
    }

    #[test]
    fn the_envelope_part_says_how_each_was_addressed() {
        let mut copied = rcpt("archive@example.com", None);
        copied.added_by = Some("Copy \"finance\"".into());
        let recipients = [
            rcpt("pay@bank.example", None),
            rcpt("bob@example.com", None),
            rcpt("carol@example.com", None),
            rcpt("dan@example.com", Some("rfc822;finance@example.com")),
            copied,
        ];
        let env = envelope(&recipients);
        let fields = fields(&env, ORIGINAL);
        let part = machine(&env, &fields, "mx.example.com");
        let date = Date::new(env.received as i64).to_rfc822();
        assert_eq!(
            part,
            format!(
                "Version: 1\r\n\
                 Reporting-MTA: dns; mx.example.com\r\n\
                 Queue-ID: 1a2b\r\n\
                 Arrival-Date: {date}\r\n\
                 Direction: outgoing\r\n\
                 Authenticated: yes\r\n\
                 Held: no\r\n\
                 Original-Mail-From: <alice@example.com>\r\n\
                 Original-Rcpt-To: <pay@bank.example>; addressed=to\r\n\
                 Original-Rcpt-To: <bob@example.com>; addressed=cc\r\n\
                 Original-Rcpt-To: <carol@example.com>; addressed=not-in-headers\r\n\
                 Original-Rcpt-To: <dan@example.com>; addressed=list; via=<finance@example.com>\r\n\
                 Original-Rcpt-To: <archive@example.com>; addressed=rule; rule=\"Copy \\\"finance\\\"\"\r\n"
            )
        );
    }

    #[test]
    fn an_orcpt_that_isnt_an_address_is_ignored() {
        for orcpt in [
            "rfc822;x@example.com>; addressed=to",
            "rfc822;not an address",
            "rfc822;nothing",
        ] {
            let recipients = [rcpt("carol@example.com", Some(orcpt))];
            let fields = fields(&envelope(&recipients), ORIGINAL);
            assert_eq!(fields.recipients[0].1, Addressed::NotInHeaders, "{orcpt}");
        }
    }

    #[test]
    fn rule_added_recipients_say_so() {
        let mut copied = rcpt("archive@example.com", None);
        copied.added_by = Some("Copy finance".into());
        let recipients = [rcpt("pay@bank.example", None), copied];
        let env = envelope(&recipients);
        let fields = fields(&env, ORIGINAL);
        let body = text(&env, &fields);
        assert!(!body.contains("Not in To or Cc"), "{body}");
        assert!(body.contains("Added by rule: Copy finance -> archive@example.com\r\n"));
    }

    #[test]
    fn values_stay_on_one_line() {
        let recipients = [rcpt("x@example.com", None)];
        let mut env = envelope(&recipients);
        env.sender = "evil@example.com\r\nOriginal-Rcpt-To: <nobody@example.com>";
        env.held = true;
        let body = text(&env, &Fields::default());
        assert_eq!(body.matches("\r\n").count(), body.lines().count());
        assert!(
            body.contains("Sender: evil@example.com  Original-Rcpt-To: <nobody@example.com>\r\n")
        );
        assert!(body.contains("Held for review: yes\r\n"));
        let part = machine(&env, &Fields::default(), "mx.example.com");
        assert_eq!(part.matches("\r\nOriginal-Rcpt-To").count(), 0, "{part}");
        assert!(part.contains("Held: yes\r\n"));
    }

    #[test]
    fn an_empty_sender_is_shown_as_such() {
        let recipients = [rcpt("x@example.com", None)];
        let mut env = envelope(&recipients);
        env.sender = "";
        assert!(text(&env, &Fields::default()).starts_with("Sender: <>\r\n"));
        assert!(
            machine(&env, &Fields::default(), "mx.example.com")
                .contains("Original-Mail-From: <>\r\n")
        );
    }

    #[test]
    fn a_long_list_or_subject_doesnt_make_the_report_binary() {
        let recipients: Vec<Recipient> = (0..200)
            .map(|n| rcpt(&format!("person{n}@example.com"), None))
            .collect();
        // Folded, so the original's own lines fit
        let folded = vec!["é".repeat(100); 8].join("\r\n ");
        let long = format!("Subject: {folded}\r\n\r\nBody\r\n");
        let (report, fields) = build(
            &envelope(&recipients),
            long.as_bytes(),
            "postmaster@example.com",
            "mx.example.com",
        );
        assert!(fields.subject.len() > SUMMARY_VALUE_MAX);
        assert_eq!(Body::of(&report), Body::EightBit);
        assert_eq!(original(&report), Some(long.as_bytes()));
    }

    #[test]
    fn body_says_how_a_report_can_travel() {
        assert_eq!(Body::of(b"plain\r\n"), Body::SevenBit);
        assert_eq!(Body::of("caf\u{e9}\r\n".as_bytes()), Body::EightBit);
        assert_eq!(Body::of(b"a\0b"), Body::Binary);
        assert_eq!(Body::of("x".repeat(999).as_bytes()), Body::Binary);
        assert_eq!(Body::of("x".repeat(998).as_bytes()), Body::SevenBit);
        let recipients = [rcpt("x@example.com", None)];
        let long = format!("Subject: x\r\n\r\n{}\r\n", "y".repeat(2000));
        let (report, _) = build(
            &envelope(&recipients),
            long.as_bytes(),
            "postmaster@example.com",
            "mx.example.com",
        );
        assert_eq!(Body::of(&report), Body::Binary);
        let text = String::from_utf8_lossy(&report);
        assert!(text.contains("Content-Transfer-Encoding: binary\r\n"));
        assert_eq!(original(&report), Some(long.as_bytes()));
    }

    #[test]
    fn reports_in_the_earlier_layout_still_give_their_original() {
        let mut report = b"From: Journal <postmaster@example.com>\r\n\
Subject: Journal report: Q3 figures\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"journal-old\"\r\n\
\r\n\
--journal-old\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: 8bit\r\n\
\r\n\
Sender: alice@example.com\r\n\
Bcc: carol@example.com\r\n\
\r\n\
--journal-old\r\n\
Content-Type: message/rfc822\r\n\
Content-Disposition: attachment; filename=\"original.eml\"\r\n\
Content-Transfer-Encoding: 8bit\r\n\
\r\n"
            .to_vec();
        report.extend_from_slice(ORIGINAL);
        report.extend_from_slice(b"\r\n--journal-old--\r\n");
        assert_eq!(original(&report), Some(ORIGINAL));
    }
}
