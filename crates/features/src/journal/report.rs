/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The journal report (JR-3, JR-4): a message whose first part lists the
//! envelope, one field a line, and whose second part is the message as it
//! was queued, byte for byte, as `message/rfc822`. Field names are fixed
//! English: a report is a record, and scripts read it.

use super::Direction;
use mail_builder::headers::{Header, date::Date, text::Text};
use mail_parser::MessageParser;
use sha2::{Digest, Sha256};

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

/// What a report says, besides the envelope's own fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fields {
    pub subject: String,
    pub message_id: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    /// Envelope recipients in neither To nor Cc, nor reached through a list.
    pub bcc: Vec<String>,
    /// A list's address, and its members among the recipients.
    pub expanded: Vec<(String, Vec<String>)>,
    /// A rule's name, and the recipients it added.
    pub added: Vec<(String, Vec<String>)>,
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

/// The address an ORCPT names, without its `rfc822;` type.
fn orcpt_address(orcpt: &str) -> String {
    let orcpt = orcpt.trim();
    let bare = match orcpt.split_once(';') {
        Some((kind, address)) if kind.eq_ignore_ascii_case("rfc822") => address,
        _ => orcpt,
    };
    bare.trim().to_lowercase()
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

    let mut fields = Fields {
        subject,
        message_id,
        ..Default::default()
    };
    for rcpt in envelope.recipients {
        let address = rcpt.address.to_lowercase();
        let via = rcpt
            .orcpt
            .as_deref()
            .map(orcpt_address)
            .filter(|via| !via.is_empty() && *via != address);
        if let Some(rule) = &rcpt.added_by {
            match fields.added.iter_mut().find(|(name, _)| name == rule) {
                Some((_, added)) => added.push(line(&rcpt.address)),
                None => fields.added.push((line(rule), vec![line(&rcpt.address)])),
            }
        } else if header_to.contains(&address) {
            fields.to.push(line(&rcpt.address));
        } else if header_cc.contains(&address) {
            fields.cc.push(line(&rcpt.address));
        } else if let Some(via) = via {
            match fields.expanded.iter_mut().find(|(list, _)| *list == via) {
                Some((_, members)) => members.push(line(&rcpt.address)),
                None => fields
                    .expanded
                    .push((line(&via), vec![line(&rcpt.address)])),
            }
        } else {
            fields.bcc.push(line(&rcpt.address));
        }
    }
    fields
}

/// The report's first part.
pub fn text(envelope: &Envelope<'_>, fields: &Fields) -> String {
    let mut out = String::new();
    let mut field = |name: &str, value: &str| {
        if !value.is_empty() {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
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
    field("To", &fields.to.join(", "));
    field("Cc", &fields.cc.join(", "));
    field("Bcc", &fields.bcc.join(", "));
    for (list, members) in &fields.expanded {
        field("Expanded", &format!("{list} -> {}", members.join(", ")));
    }
    for (rule, added) in &fields.added {
        field("Added by rule", &format!("{rule} -> {}", added.join(", ")));
    }
    if envelope.held {
        field("Held for review", "yes");
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether a message can travel as 8bit: no NULs, no line past 998 bytes.
fn fits_8bit(message: &[u8]) -> bool {
    !message.contains(&0) && message.split(|b| *b == b'\n').all(|l| l.len() <= 998)
}

/// The whole report: headers, the fields, then the original untouched.
/// `from` is the address the report is from; `host` names the server in its
/// Message-ID.
pub fn build(
    envelope: &Envelope<'_>,
    original: &[u8],
    from: &str,
    host: &str,
) -> (Vec<u8>, Fields) {
    let fields = fields(envelope, original);
    let body = text(envelope, &fields);
    // A boundary that can't occur in the original
    let mut boundary = format!("journal-{}", &hex(&Sha256::digest(original))[..32]);
    while original
        .windows(boundary.len())
        .any(|window| window == boundary.as_bytes())
    {
        boundary.push('x');
    }

    let mut out: Vec<u8> = Vec::with_capacity(original.len() + body.len() + 1024);
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
        format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n").as_bytes(),
    );
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n",
    );
    out.extend_from_slice(body.as_bytes());
    out.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    out.extend_from_slice(b"Content-Type: message/rfc822\r\n");
    out.extend_from_slice(b"Content-Disposition: attachment; filename=\"original.eml\"\r\n");
    out.extend_from_slice(if fits_8bit(original) {
        b"Content-Transfer-Encoding: 8bit\r\n\r\n".as_slice()
    } else {
        b"Content-Transfer-Encoding: binary\r\n\r\n".as_slice()
    });
    out.extend_from_slice(original);
    // The line break before a boundary belongs to the boundary: the
    // original keeps its own last one
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (out, fields)
}

/// Where the original starts and ends inside a report [`build`] made.
pub fn original(report: &[u8]) -> Option<&[u8]> {
    let parsed = MessageParser::default().parse(report)?;
    let part = parsed.attachment(0)?;
    let start = part.raw_body_offset() as usize;
    let end = part.raw_end_offset() as usize;
    report.get(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(fields.to, vec!["pay@bank.example"]);
        assert_eq!(fields.cc, vec!["Bob@example.com"]);
        assert_eq!(fields.bcc, vec!["carol@example.com"]);
        assert_eq!(
            fields.expanded,
            vec![(
                "finance@example.com".to_string(),
                vec![
                    "dan@example.com".to_string(),
                    "erin@example.com".to_string()
                ]
            )]
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
        assert!(text.contains("Bcc: carol@example.com\r\n"));
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
    fn rule_added_recipients_say_so() {
        let mut copied = rcpt("archive@example.com", None);
        copied.added_by = Some("Copy finance".into());
        let recipients = [rcpt("pay@bank.example", None), copied];
        let env = envelope(&recipients);
        let fields = fields(&env, ORIGINAL);
        assert!(fields.bcc.is_empty(), "{fields:?}");
        assert!(
            text(&env, &fields).contains("Added by rule: Copy finance -> archive@example.com\r\n")
        );
    }

    #[test]
    fn values_stay_on_one_line() {
        let recipients = [rcpt("x@example.com", None)];
        let mut env = envelope(&recipients);
        env.sender = "evil@example.com\r\nBcc: nobody@example.com";
        env.held = true;
        let body = text(&env, &Fields::default());
        assert_eq!(body.matches("\r\n").count(), body.lines().count());
        assert!(body.contains("Sender: evil@example.com  Bcc: nobody@example.com\r\n"));
        assert!(body.contains("Held for review: yes\r\n"));
    }

    #[test]
    fn an_empty_sender_is_shown_as_such() {
        let recipients = [rcpt("x@example.com", None)];
        let mut env = envelope(&recipients);
        env.sender = "";
        assert!(text(&env, &Fields::default()).starts_with("Sender: <>\r\n"));
    }
}
