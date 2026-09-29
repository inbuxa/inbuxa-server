/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! United Kingdom identifiers (§2.3): HMRC's National Insurance number and
//! Unique Taxpayer Reference, and the NHS number.

use super::{Detector, Findings, Region, Strength, word_near};
use regex::Regex;
use std::sync::LazyLock;

pub static DETECTORS: &[Detector] = &[
    Detector::new(
        "uk-nino",
        "UK National Insurance number",
        Region::Uk,
        Strength::Checked,
        nino,
    ),
    Detector::new(
        "uk-nhs",
        "UK NHS number",
        Region::Uk,
        Strength::Checked,
        nhs,
    ),
    Detector::new(
        "uk-utr",
        "UK Unique Taxpayer Reference",
        Region::Uk,
        Strength::NeedsWord,
        utr,
    ),
];

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("detector pattern")
}

/// Two letters, six digits (often in pairs), a suffix A–D.
static NINO: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b([A-Z])([A-Z]) ?(\d{2}) ?(\d{2}) ?(\d{2}) ?([A-D])\b"));

/// HMRC's rules: D, F, I, Q, U and V are never used; O never second; and
/// BG, GB, KN, NK, NT, TN and ZZ are never allocated.
fn nino_prefix(first: char, second: char) -> bool {
    const NEVER: &str = "DFIQUV";
    let pair: String = [first, second].iter().collect();
    !NEVER.contains(first)
        && !NEVER.contains(second)
        && second != 'O'
        && !["BG", "GB", "KN", "NK", "NT", "TN", "ZZ"].contains(&pair.as_str())
}

fn nino(text: &str, findings: &mut Findings) {
    for c in NINO.captures_iter(text) {
        let first = c[1].to_ascii_uppercase().chars().next().unwrap();
        let second = c[2].to_ascii_uppercase().chars().next().unwrap();
        if nino_prefix(first, second) {
            findings.insert(format!(
                "{first}{second}{}{}{}{}",
                &c[3],
                &c[4],
                &c[5],
                c[6].to_ascii_uppercase()
            ));
        }
    }
}

/// `NNN NNN NNNN` stands alone; ten bare digits need a word.
static NHS: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{3})([ -]?)(\d{3})([ -]?)(\d{4})\b"));

/// Mod 11: weights 10 down to 2 over the first nine digits; the check digit
/// is 11 minus the remainder (11 becomes 0; 10 is never issued).
pub fn nhs_valid(n: &str) -> bool {
    let d: Vec<u32> = n.bytes().map(|b| u32::from(b - b'0')).collect();
    let sum: u32 = d[..9].iter().zip((2..=10).rev()).map(|(a, w)| a * w).sum();
    match 11 - sum % 11 {
        11 => d[9] == 0,
        10 => false,
        check => d[9] == check,
    }
}

const NHS_WORDS: &[&str] = &["nhs", "nhs number", "nhs no"];

fn nhs(text: &str, findings: &mut Findings) {
    for c in NHS.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let n = format!("{}{}{}", &c[1], &c[3], &c[5]);
        let written = !c[2].is_empty() && c[2] == c[4];
        if nhs_valid(&n) && (written || word_near(text, whole.start(), whole.end(), NHS_WORDS)) {
            findings.insert(n);
        }
    }
}

static UTR: LazyLock<Regex> = LazyLock::new(|| re(r"\b\d{5} ?\d{5}\b"));

const UTR_WORDS: &[&str] = &[
    "utr",
    "unique taxpayer reference",
    "tax reference",
    "self assessment",
];

fn utr(text: &str, findings: &mut Findings) {
    for m in UTR.find_iter(text) {
        if word_near(text, m.start(), m.end(), UTR_WORDS) {
            findings.insert(m.as_str().replace(' ', ""));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mailflow::detectors::by_id;

    fn count(id: &str, text: &str) -> usize {
        by_id(id).unwrap().count(text)
    }

    #[test]
    fn national_insurance() {
        assert_eq!(count("uk-nino", "NI: AB 12 34 56 C, ce123456d"), 2);
        // Letters never used, pairs never allocated, a suffix past D
        for bad in [
            "QQ123456C",
            "AO123456C",
            "GB123456A",
            "AB123456E",
            "DA123456A",
        ] {
            assert_eq!(count("uk-nino", bad), 0, "{bad}");
        }
    }

    #[test]
    fn nhs_numbers() {
        // The NHS's own example
        assert_eq!(count("uk-nhs", "943 476 5919"), 1);
        assert_eq!(count("uk-nhs", "943 476 5918"), 0);
        assert_eq!(count("uk-nhs", "order 9434765919"), 0);
        assert_eq!(count("uk-nhs", "NHS number 9434765919"), 1);
    }

    #[test]
    fn utr() {
        assert_eq!(count("uk-utr", "UTR 12345 67890"), 1);
        assert_eq!(count("uk-utr", "order 1234567890"), 0);
    }
}
