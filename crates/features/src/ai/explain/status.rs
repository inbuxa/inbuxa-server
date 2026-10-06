/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Reference notes on SMTP replies for explaining a delivery failure (EX-7),
//! in this project's own words, from RFC 5321 §4.2 (reply codes), RFC 3463
//! (enhanced status codes) and the codes later RFCs registered (RFC 7372,
//! RFC 7505).

/// Notes for a basic reply code and an enhanced code, as far as they are
/// known. Unknown parts add nothing.
pub fn notes(code: Option<u16>, enhanced: Option<&str>) -> Vec<String> {
    let mut notes = Vec::new();
    let class = enhanced
        .and_then(|e| e.split('.').next())
        .and_then(|c| c.parse::<u8>().ok())
        .or_else(|| code.map(|c| (c / 100) as u8));
    match class {
        Some(2) => notes.push("A 2xx reply or class 2 status means success.".to_string()),
        Some(4) => notes.push(
            "A 4xx reply or class 4 status is a temporary failure: the sending server keeps \
retrying until its retry period ends, and the same message may later go through."
                .to_string(),
        ),
        Some(5) => notes.push(
            "A 5xx reply or class 5 status is a permanent failure: retrying the same message \
won't help until something changes, and the sender is sent a bounce."
                .to_string(),
        ),
        _ => {}
    }
    let Some(enhanced) = enhanced else {
        return notes;
    };
    let mut parts = enhanced.split('.');
    let (_, subject, detail) = (parts.next(), parts.next(), parts.next());
    if let Some(note) = subject.and_then(|s| s.parse::<u16>().ok()).and_then(subject_note) {
        notes.push(note.to_string());
    }
    if let (Some(subject), Some(detail)) = (subject, detail)
        && let Some(note) = detail_note(subject, detail)
    {
        notes.push(format!("x.{subject}.{detail}: {note}"));
    }
    notes
}

fn subject_note(subject: u16) -> Option<&'static str> {
    Some(match subject {
        0 => "Subject x.0 is 'other or undefined': the code alone says little; the reply text matters.",
        1 => "Subject x.1 concerns the address: the mailbox or domain named in the envelope.",
        2 => "Subject x.2 concerns the recipient's mailbox itself: full, disabled, or refusing.",
        3 => "Subject x.3 concerns the receiving mail system: its capacity, configuration or features.",
        4 => "Subject x.4 concerns the network or routing: DNS, connections, or loops.",
        5 => "Subject x.5 concerns the SMTP conversation: a command or its order was refused.",
        6 => "Subject x.6 concerns the message's content or format.",
        7 => "Subject x.7 concerns security or policy: authentication checks, reputation, or rules on the receiving side.",
        _ => return None,
    })
}

fn detail_note(subject: &str, detail: &str) -> Option<&'static str> {
    Some(match (subject, detail) {
        ("1", "1") => "the mailbox doesn't exist at the receiving domain",
        ("1", "2") => "the recipient's domain doesn't exist or can't receive mail",
        ("1", "3") => "the recipient address isn't valid",
        ("1", "10") => "the domain publishes a null MX: it accepts no mail",
        ("2", "1") => "the mailbox is disabled or not accepting mail",
        ("2", "2") => "the mailbox is full",
        ("2", "3") => "the message is larger than this mailbox accepts",
        ("3", "4") => "the message is larger than the receiving system accepts",
        ("4", "1") => "no answer from the receiving host",
        ("4", "2") => "the connection was lost or refused",
        ("4", "3") => "a directory or DNS lookup failed",
        ("4", "4") => "no route to the destination: often a missing or broken MX record",
        ("4", "6") => "a mail loop was detected",
        ("4", "7") => "delivery took too long and expired",
        ("5", "3") => "too many recipients for one message",
        ("7", "0") => "refused for a security or policy reason not given more precisely",
        ("7", "1") => "the receiving server's policy doesn't allow this delivery",
        ("7", "8") => "authentication credentials were refused",
        ("7", "23") => "the sender's SPF check failed",
        ("7", "24") => "the SPF check couldn't be completed",
        ("7", "25") => "the sending IP's reverse DNS check failed",
        ("7", "26") => "several authentication checks failed together, typically SPF and DKIM, so DMARC failed",
        ("7", "27") => "the sender's domain publishes a null MX, so it can't receive the bounce",
        ("7", "28") => "the sender is sending too much mail to this receiver",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_for_a_dmarc_rejection() {
        let n = notes(Some(550), Some("5.7.26"));
        assert_eq!(n.len(), 3);
        assert!(n[0].contains("permanent"));
        assert!(n[1].starts_with("Subject x.7"));
        assert!(n[2].starts_with("x.7.26:"));
    }

    #[test]
    fn partial_and_unknown() {
        assert_eq!(notes(Some(421), None).len(), 1);
        assert!(notes(None, None).is_empty());
        let n = notes(None, Some("4.9.99"));
        assert_eq!(n.len(), 1);
        assert!(n[0].contains("temporary"));
    }
}
