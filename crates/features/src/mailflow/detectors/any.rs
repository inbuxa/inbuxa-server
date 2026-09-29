/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Detectors that aren't tied to one country (§2.3, region "Any").

use super::{
    Detector, Findings, Region, Strength, checks, digits, stands_alone, valid_date, word_near,
};
use regex::Regex;
use std::sync::LazyLock;

pub static DETECTORS: &[Detector] = &[
    Detector::new(
        "payment-card",
        "Payment card number",
        Region::Any,
        Strength::Checked,
        payment_card,
    ),
    Detector::new("iban", "IBAN", Region::Any, Strength::Checked, iban),
    Detector::new(
        "swift-bic",
        "SWIFT/BIC code",
        Region::Any,
        Strength::NeedsWord,
        swift_bic,
    ),
    Detector::new(
        "email-addresses",
        "Email addresses",
        Region::Any,
        Strength::Checked,
        email_addresses,
    ),
    Detector::new(
        "phone-numbers",
        "Phone numbers",
        Region::Any,
        Strength::NeedsWord,
        phone_numbers,
    ),
    Detector::new(
        "date-of-birth",
        "Date of birth",
        Region::Any,
        Strength::NeedsWord,
        date_of_birth,
    ),
    Detector::new(
        "passport",
        "Passport number",
        Region::Any,
        Strength::NeedsWord,
        passport,
    ),
    Detector::new(
        "private-key",
        "Private key",
        Region::Any,
        Strength::Checked,
        private_key,
    ),
    Detector::new(
        "credentials",
        "Cloud and service credentials",
        Region::Any,
        Strength::Checked,
        credentials,
    ),
];

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("detector pattern")
}

// --- Payment cards --------------------------------------------------------

/// Issuer prefixes (ISO/IEC 7812 IINs) and the lengths each network issues.
fn card_network(number: &str) -> bool {
    let len = number.len();
    let prefix = |n: usize| number[..n].parse::<u32>().unwrap_or(0);
    match number.as_bytes()[0] {
        // Visa
        b'4' => matches!(len, 13 | 16 | 19),
        b'5' => {
            // Mastercard 51–55; Maestro 50, 56–58
            (51..=55).contains(&prefix(2)) && len == 16
                || matches!(prefix(2), 50 | 56..=58) && (12..=19).contains(&len)
        }
        // Mastercard 2221–2720
        b'2' => (2221..=2720).contains(&prefix(4)) && len == 16,
        b'3' => {
            // American Express 34, 37; JCB 3528–3589; Diners 300–305, 36, 38, 39
            matches!(prefix(2), 34 | 37) && len == 15
                || (3528..=3589).contains(&prefix(4)) && (16..=19).contains(&len)
                || ((300..=305).contains(&prefix(3)) || matches!(prefix(2), 36 | 38 | 39))
                    && (14..=19).contains(&len)
        }
        // Discover 6011, 644–649, 65; UnionPay 62; Maestro 6x
        b'6' => (12..=19).contains(&len),
        _ => false,
    }
}

fn is_card(number: &str) -> bool {
    (12..=19).contains(&number.len()) && card_network(number) && checks::luhn(number)
}

static CARD: LazyLock<Regex> = LazyLock::new(|| re(r"\b\d(?:[ -]?\d){11,18}\b"));

fn payment_card(text: &str, findings: &mut Findings) {
    for m in CARD.find_iter(text) {
        if !stands_alone(text, m.start(), m.end()) {
            continue;
        }
        let whole = digits(m.as_str());
        if is_card(&whole) {
            findings.insert(whole);
            continue;
        }
        // Two numbers side by side ("4242 4242 4242 4242 2031"): try each
        // run of whole groups
        let groups: Vec<String> = m.as_str().split([' ', '-']).map(digits).collect();
        'runs: for from in 0..groups.len() {
            let mut number = String::new();
            for group in &groups[from..] {
                number.push_str(group);
                if is_card(&number) {
                    findings.insert(number);
                    break 'runs;
                }
            }
        }
    }
}

// --- IBAN -----------------------------------------------------------------

static IBAN: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,30}"));

fn iban(text: &str, findings: &mut Findings) {
    // The pattern can run on into the next words, even the next IBAN: after
    // each hit, look again from where that IBAN ended
    let mut from = 0;
    while let Some(m) = IBAN.find_at(text, from) {
        from = m.start() + 1;
        let compact = m.as_str().replace(' ', "").to_ascii_uppercase();
        let Some(len) = checks::iban_length(&compact[..2]) else {
            continue;
        };
        if compact.len() < len {
            continue;
        }
        // Where the country's length ends in the text, spaces counted
        let mut seen = 0;
        let Some(end) = m
            .as_str()
            .char_indices()
            .find(|(_, c)| {
                if *c != ' ' {
                    seen += 1;
                }
                seen == len
            })
            .map(|(i, c)| m.start() + i + c.len_utf8())
        else {
            continue;
        };
        let candidate = &compact[..len];
        if stands_alone(text, m.start(), end) && checks::iban(candidate) {
            findings.insert(candidate);
            from = end;
        }
    }
}

// --- SWIFT/BIC ------------------------------------------------------------

static BIC: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"));

const BIC_WORDS: &[&str] = &[
    "swift",
    "bic",
    "swift/bic",
    "bank",
    "banque",
    "bankverbindung",
];

fn swift_bic(text: &str, findings: &mut Findings) {
    for m in BIC.find_iter(text) {
        let code = m.as_str();
        if checks::is_country(&code[4..6]) && word_near(text, m.start(), m.end(), BIC_WORDS) {
            findings.insert(code);
        }
    }
}

// --- Contact lists --------------------------------------------------------

static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b"));

fn email_addresses(text: &str, findings: &mut Findings) {
    for m in EMAIL.find_iter(text) {
        findings.insert(m.as_str().to_lowercase());
    }
}

/// International form: found alone. National form: only with a word.
static PHONE_INTL: LazyLock<Regex> = LazyLock::new(|| re(r"\+\d{1,3}(?:[ .-]?\(?\d{1,4}\)?){2,5}"));
static PHONE_NATIONAL: LazyLock<Regex> =
    LazyLock::new(|| re(r"\(?\d{2,4}\)?[ .-]\d{3,4}[ .-]\d{3,4}"));

const PHONE_WORDS: &[&str] = &[
    "phone",
    "tel",
    "telephone",
    "mobile",
    "cell",
    "fax",
    "telefon",
    "téléphone",
    "teléfono",
    "telefono",
    "handy",
    "portable",
    "móvil",
    "cellulare",
    "mobiel",
];

fn phone_numbers(text: &str, findings: &mut Findings) {
    let mut international = Vec::new();
    for m in PHONE_INTL.find_iter(text) {
        let number = digits(m.as_str());
        if (8..=15).contains(&number.len()) && stands_alone(text, m.start() + 1, m.end()) {
            findings.insert(number);
            international.push(m.range());
        }
    }
    for m in PHONE_NATIONAL.find_iter(text) {
        let number = digits(m.as_str());
        // Not the tail of an international number already counted
        if international.iter().any(|r| r.contains(&m.start())) {
            continue;
        }
        if (9..=11).contains(&number.len())
            && stands_alone(text, m.start(), m.end())
            && !text[..m.start()].ends_with('+')
            && word_near(text, m.start(), m.end(), PHONE_WORDS)
        {
            findings.insert(number);
        }
    }
}

// --- Date of birth --------------------------------------------------------

static DATE_ISO: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{4})-(\d{2})-(\d{2})\b"));
static DATE_NUMERIC: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b(\d{1,2})[./-](\d{1,2})[./-](\d{4})\b"));
static DATE_WORDS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:(\d{1,2})\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?\s+(\d{4})|(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+(\d{1,2}),?\s+(\d{4}))\b",
    )
});

const BIRTH_WORDS: &[&str] = &[
    "born",
    "birth",
    "dob",
    "d.o.b",
    "birthday",
    "birthdate",
    "geburtsdatum",
    "geboren",
    "naissance",
    "né le",
    "née le",
    "nacimiento",
    "nacido",
    "nacida",
    "nascita",
    "nato il",
    "nata il",
    "geboortedatum",
    "födelsedatum",
    "fødselsdato",
    "syntymäaika",
    "urodzenia",
    "nascimento",
];

fn month_number(name: &str) -> u32 {
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let name = name.to_lowercase();
    MONTHS
        .iter()
        .position(|m| *m == name)
        .map_or(0, |i| i as u32 + 1)
}

fn date_of_birth(text: &str, findings: &mut Findings) {
    let mut add = |start: usize, end: usize, key: String| {
        if word_near(text, start, end, BIRTH_WORDS) {
            findings.insert(key);
        }
    };
    let num = |s: &str| s.parse::<u32>().unwrap_or(0);
    for c in DATE_ISO.captures_iter(text) {
        let (y, m, d) = (num(&c[1]), num(&c[2]), num(&c[3]));
        let whole = c.get(0).unwrap();
        if valid_date(y, m, d) {
            add(whole.start(), whole.end(), format!("{y:04}{m:02}{d:02}"));
        }
    }
    for c in DATE_NUMERIC.captures_iter(text) {
        let (a, b, y) = (num(&c[1]), num(&c[2]), num(&c[3]));
        let whole = c.get(0).unwrap();
        // Day first or month first: either reading that is a real date
        if valid_date(y, b, a) || valid_date(y, a, b) {
            add(whole.start(), whole.end(), whole.as_str().to_string());
        }
    }
    for c in DATE_WORDS.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let (d, m, y) = match (c.get(1), c.get(4)) {
            (Some(d), _) => (num(d.as_str()), month_number(&c[2]), num(&c[3])),
            (_, Some(m)) => (num(&c[5]), month_number(m.as_str()), num(&c[6])),
            _ => continue,
        };
        if valid_date(y, m, d) {
            add(whole.start(), whole.end(), format!("{y:04}{m:02}{d:02}"));
        }
    }
}

// --- Passport -------------------------------------------------------------

static PASSPORT: LazyLock<Regex> = LazyLock::new(|| re(r"\b[A-Z0-9]{6,9}\b"));

const PASSPORT_WORDS: &[&str] = &[
    "passport",
    "passeport",
    "reisepass",
    "pasaporte",
    "passaporto",
    "paspoort",
    "passnummer",
    "pass-nr",
    "passport no",
    "pasaporte n.º",
    "passaporte",
];

fn passport(text: &str, findings: &mut Findings) {
    for m in PASSPORT.find_iter(text) {
        let value = m.as_str();
        if value.bytes().filter(u8::is_ascii_digit).count() >= 5
            && word_near(text, m.start(), m.end(), PASSPORT_WORDS)
        {
            findings.insert(value);
        }
    }
}

// --- Keys and credentials -------------------------------------------------

static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----\s*([A-Za-z0-9+/=:\s-]{0,64})",
    )
});

fn private_key(text: &str, findings: &mut Findings) {
    for c in PRIVATE_KEY.captures_iter(text) {
        // Each key once, by the start of its body
        let body: String = c[1].chars().filter(|c| !c.is_whitespace()).collect();
        let whole = c.get(0).unwrap();
        findings.insert(if body.is_empty() {
            format!("@{}", whole.start())
        } else {
            body
        });
    }
}

/// Published token formats: AWS access key IDs, GitHub tokens, Slack
/// tokens, Stripe live secret and restricted keys, Google API keys.
static CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"\b(?:",
        r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
        r"|gh[pousr]_[A-Za-z0-9]{36}",
        r"|github_pat_[A-Za-z0-9_]{82}",
        r"|xox[abposr]-[A-Za-z0-9-]{10,72}",
        r"|(?:sk|rk)_live_[A-Za-z0-9]{24,99}",
        r"|AIza[0-9A-Za-z_-]{35}",
        r")\b"
    ))
});

fn credentials(text: &str, findings: &mut Findings) {
    for m in CREDENTIAL.find_iter(text) {
        findings.insert(m.as_str());
    }
}

#[cfg(test)]
mod tests {
    use crate::mailflow::detectors::by_id;

    fn count(id: &str, text: &str) -> usize {
        by_id(id).unwrap().count(text)
    }

    #[test]
    fn payment_cards() {
        // Networks' and processors' published test numbers
        let text = "Visa 4242 4242 4242 4242, MC 5555-5555-5555-4444, Amex 378282246310005, \
                    Discover 6011111111111117, JCB 3566002020360505, Diners 30569309025904, \
                    UnionPay 6200000000000005, Mastercard 2-series 2223003122003222";
        assert_eq!(count("payment-card", text), 8);
        // Luhn fails, wrong network length, inside a longer number
        assert_eq!(count("payment-card", "4242424242424241"), 0);
        assert_eq!(count("payment-card", "378282246310005 0"), 1);
        assert_eq!(count("payment-card", "order 94242424242424242 shipped"), 0);
        // The same number twice counts once
        assert_eq!(
            count("payment-card", "4242424242424242 and 4242-4242-4242-4242"),
            1
        );
        // A card followed by a year
        assert_eq!(count("payment-card", "card 4242 4242 4242 4242 2031"), 1);
    }

    #[test]
    fn ibans() {
        let text =
            "Pay GB29 NWBK 6016 1331 9268 19 or de89370400440532013000 (NL91ABNA0417164300).";
        assert_eq!(count("iban", text), 3);
        assert_eq!(count("iban", "GB29 NWBK 6016 1331 9268 18"), 0);
        // Runs into the next word: still found at the country's length
        assert_eq!(count("iban", "IBAN NL91ABNA0417164300 BIC ABNANL2A"), 1);
    }

    #[test]
    fn swift_codes_need_a_word() {
        assert_eq!(count("swift-bic", "SWIFT: DEUTDEFF500"), 1);
        assert_eq!(count("swift-bic", "BIC NWBKGB2L"), 1);
        assert_eq!(count("swift-bic", "HAPPYDAYS DEUTDEFF"), 0);
        // Not a country in positions 5–6
        assert_eq!(count("swift-bic", "BIC DEUTZZFF"), 0);
    }

    #[test]
    fn email_and_phone_lists() {
        let list = "a@example.com, B@Example.com, c.d+x@mail.example.org, a@example.com";
        assert_eq!(count("email-addresses", list), 3);
        assert_eq!(
            count("phone-numbers", "+44 20 7946 0958, +1 (415) 555-2671"),
            2
        );
        assert_eq!(count("phone-numbers", "call 020 7946 0958"), 0);
        assert_eq!(count("phone-numbers", "Tel: 020 7946 0958"), 1);
        assert_eq!(count("phone-numbers", "invoice 020 7946 0958"), 0);
        // One number, not also its national tail
        assert_eq!(count("phone-numbers", "Tel: +44 20 7946 0958"), 1);
    }

    #[test]
    fn dates_of_birth() {
        assert_eq!(count("date-of-birth", "DOB: 1984-02-29"), 1);
        assert_eq!(count("date-of-birth", "Geburtsdatum 31.12.1970"), 1);
        assert_eq!(count("date-of-birth", "born on March 3, 1962"), 1);
        assert_eq!(count("date-of-birth", "date of birth 3 Mar 1962"), 1);
        // Not a real date, no word, a meeting
        assert_eq!(count("date-of-birth", "DOB: 1985-02-29"), 0);
        assert_eq!(count("date-of-birth", "invoice 1984-02-29"), 0);
        assert_eq!(count("date-of-birth", "Meeting on 12/05/2026"), 0);
    }

    #[test]
    fn passports_need_a_word() {
        assert_eq!(count("passport", "Passport number: 533380006"), 1);
        assert_eq!(count("passport", "Reisepass C01X00T47"), 1);
        assert_eq!(count("passport", "Order 533380006 shipped"), 0);
        // Mostly letters: a word, not a number
        assert_eq!(count("passport", "passport PASSWORD"), 0);
    }

    #[test]
    fn keys_and_credentials() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(count("private-key", key), 1);
        assert_eq!(count("private-key", "-----BEGIN PUBLIC KEY-----\nMFkw"), 0);
        // Documentation examples of each format
        let tokens = "AKIAIOSFODNN7EXAMPLE ghp_0123456789abcdefghijklmnopqrstuvwxyz \
                      AIzaSyA-0123456789abcdefghijklmnopqrstu";
        assert_eq!(count("credentials", tokens), 3);
        assert_eq!(count("credentials", "AKIA123 ghp_short"), 0);
    }
}
