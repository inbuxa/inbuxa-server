/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! United States identifiers (§2.3), each from its issuer's published rules:
//! the SSA (SSN), the IRS (ITIN, EIN), the ABA (routing numbers), CMS (MBI,
//! NPI) and the DEA.

use super::{Detector, Findings, Region, Strength, checks, digits, stands_alone, word_near};
use regex::Regex;
use std::sync::LazyLock;

pub static DETECTORS: &[Detector] = &[
    Detector::new(
        "us-ssn",
        "US Social Security number",
        Region::Us,
        Strength::Checked,
        ssn,
    ),
    Detector::new("us-itin", "US ITIN", Region::Us, Strength::Checked, itin),
    Detector::new("us-ein", "US EIN", Region::Us, Strength::NeedsWord, ein),
    Detector::new(
        "us-aba-routing",
        "US bank routing number",
        Region::Us,
        Strength::NeedsWord,
        aba_routing,
    ),
    Detector::new(
        "us-drivers-license",
        "US driver's license",
        Region::Us,
        Strength::NeedsWord,
        drivers_license,
    ),
    Detector::new(
        "us-mbi",
        "US Medicare Beneficiary Identifier",
        Region::Us,
        Strength::Checked,
        mbi,
    ),
    Detector::new(
        "us-npi",
        "US National Provider Identifier",
        Region::Us,
        Strength::NeedsWord,
        npi,
    ),
    Detector::new(
        "us-dea",
        "US DEA registration number",
        Region::Us,
        Strength::Checked,
        dea,
    ),
];

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("detector pattern")
}

/// `AAA-GG-SSSS` (dashes or spaces), or nine bare digits.
static NINE: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{3})([ -]?)(\d{2})([ -]?)(\d{4})\b"));

/// Numbers the SSA has published as never valid: widely printed examples.
const SSN_EXAMPLES: &[&str] = &["078051120", "219099999"];

fn ssn_rules(area: u32, group: u32, serial: u32) -> bool {
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

const SSN_WORDS: &[&str] = &["ssn", "social security", "soc sec", "ss#", "ss no"];

fn ssn(text: &str, findings: &mut Findings) {
    for c in NINE.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let (area, group, serial) = (num(&c[1]), num(&c[3]), num(&c[5]));
        let number = format!("{}{}{}", &c[1], &c[3], &c[5]);
        // Written form (with both separators, the same one) stands alone;
        // nine bare digits need a word
        let written = !c[2].is_empty() && c[2] == c[4];
        if ssn_rules(area, group, serial)
            && !SSN_EXAMPLES.contains(&number.as_str())
            && (written || word_near(text, whole.start(), whole.end(), SSN_WORDS))
        {
            findings.insert(number);
        }
    }
}

/// ITINs: 9XX, then a group in the IRS's ranges.
fn itin_group(group: u32) -> bool {
    matches!(group, 50..=65 | 70..=88 | 90..=92 | 94..=99)
}

const ITIN_WORDS: &[&str] = &["itin", "taxpayer identification", "tax id"];

fn itin(text: &str, findings: &mut Findings) {
    for c in NINE.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let written = !c[2].is_empty() && c[2] == c[4];
        if c[1].starts_with('9')
            && itin_group(num(&c[3]))
            && (written || word_near(text, whole.start(), whole.end(), ITIN_WORDS))
        {
            findings.insert(format!("{}{}{}", &c[1], &c[3], &c[5]));
        }
    }
}

static EIN: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{2})-?(\d{7})\b"));

/// The prefixes the IRS assigns to its campuses and internet EINs.
fn ein_prefix(prefix: u32) -> bool {
    matches!(prefix, 1..=6 | 10..=16 | 20..=27 | 30..=48 | 50..=68 | 71..=77 | 80..=88 | 90..=95 | 98 | 99)
}

const EIN_WORDS: &[&str] = &[
    "ein",
    "fein",
    "employer identification",
    "tax id",
    "tin",
    "federal tax",
];

fn ein(text: &str, findings: &mut Findings) {
    for c in EIN.captures_iter(text) {
        let whole = c.get(0).unwrap();
        if ein_prefix(num(&c[1])) && word_near(text, whole.start(), whole.end(), EIN_WORDS) {
            findings.insert(format!("{}{}", &c[1], &c[2]));
        }
    }
}

static ROUTING: LazyLock<Regex> = LazyLock::new(|| re(r"\b\d{9}\b"));

/// The ABA check: 3, 7 and 1 weights, mod 10; and a Federal Reserve prefix.
pub fn aba_valid(n: &str) -> bool {
    let d: Vec<u32> = n.bytes().map(|b| u32::from(b - b'0')).collect();
    let prefix = d[0] * 10 + d[1];
    matches!(prefix, 0..=12 | 21..=32 | 61..=72 | 80)
        && (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]))
            .is_multiple_of(10)
}

const ROUTING_WORDS: &[&str] = &["routing", "aba", "rtn", "routing number", "transit"];

fn aba_routing(text: &str, findings: &mut Findings) {
    for m in ROUTING.find_iter(text) {
        // One random number in ten passes the check: always needs a word
        if aba_valid(m.as_str()) && word_near(text, m.start(), m.end(), ROUTING_WORDS) {
            findings.insert(m.as_str());
        }
    }
}

/// The shapes states issue: up to two letters, then 5–14 digits, dashes
/// allowed (Florida and Illinois print them).
static LICENSE: LazyLock<Regex> = LazyLock::new(|| re(r"\b[A-Z]{0,2}\d[\d-]{3,16}\d\b"));

const LICENSE_WORDS: &[&str] = &[
    "driver's license",
    "drivers license",
    "driver license",
    "driver's licence",
    "dl",
    "dl#",
    "license number",
    "lic no",
    "dmv",
];

fn drivers_license(text: &str, findings: &mut Findings) {
    for m in LICENSE.find_iter(text) {
        let n = digits(m.as_str());
        if (5..=14).contains(&n.len()) && word_near(text, m.start(), m.end(), LICENSE_WORDS) {
            findings.insert(m.as_str().replace('-', ""));
        }
    }
}

/// CMS's MBI: 11 characters in a fixed pattern of digits, letters and
/// either, the letters S, L, O, I, B and Z never used; dashes may follow the
/// 4th and 7th.
static MBI: LazyLock<Regex> = LazyLock::new(|| {
    let c = "[AC-HJKMNP-RT-Y]";
    let an = "[AC-HJKMNP-RT-Y0-9]";
    re(&format!(
        r"\b[1-9]{c}{an}[0-9]-?{c}{an}[0-9]-?{c}{c}[0-9][0-9]\b"
    ))
});

fn mbi(text: &str, findings: &mut Findings) {
    for m in MBI.find_iter(text) {
        findings.insert(m.as_str().replace('-', ""));
    }
}

static TEN: LazyLock<Regex> = LazyLock::new(|| re(r"\b[12]\d{9}\b"));

const NPI_WORDS: &[&str] = &["npi", "national provider", "provider id", "provider number"];

/// NPI: Luhn over the ISO card-issuer prefix 80840 and the number.
fn npi(text: &str, findings: &mut Findings) {
    for m in TEN.find_iter(text) {
        if checks::luhn(&format!("80840{}", m.as_str()))
            && word_near(text, m.start(), m.end(), NPI_WORDS)
        {
            findings.insert(m.as_str());
        }
    }
}

static DEA: LazyLock<Regex> = LazyLock::new(|| re(r"\b([ABCDEFGHJKLMPRSTUX][A-Z9])(\d{7})\b"));

/// DEA: (1st + 3rd + 5th) + 2 × (2nd + 4th + 6th) ends in the 7th digit.
fn dea(text: &str, findings: &mut Findings) {
    for c in DEA.captures_iter(text) {
        let d: Vec<u32> = c[2].bytes().map(|b| u32::from(b - b'0')).collect();
        if ((d[0] + d[2] + d[4]) + 2 * (d[1] + d[3] + d[5])) % 10 == d[6] {
            let whole = c.get(0).unwrap();
            if stands_alone(text, whole.start(), whole.end()) {
                findings.insert(whole.as_str());
            }
        }
    }
}

fn num(s: &str) -> u32 {
    s.parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use crate::mailflow::detectors::by_id;

    fn count(id: &str, text: &str) -> usize {
        by_id(id).unwrap().count(text)
    }

    #[test]
    fn ssn() {
        assert_eq!(count("us-ssn", "SSN 536-22-1234, also 536 22 1235"), 2);
        // Bare digits: only with a word
        assert_eq!(count("us-ssn", "ref 536221234"), 0);
        assert_eq!(count("us-ssn", "social security: 536221234"), 1);
        // Never issued, the SSA's printed examples, mixed separators
        for bad in [
            "000-12-3456",
            "666-12-3456",
            "912-12-3456",
            "123-00-4567",
            "123-45-0000",
            "078-05-1120",
            "536-22 1234",
        ] {
            assert_eq!(count("us-ssn", bad), 0, "{bad}");
        }
    }

    #[test]
    fn itin_and_ein() {
        assert_eq!(count("us-itin", "912-70-1234"), 1);
        assert_eq!(count("us-itin", "912-69-1234"), 0);
        assert_eq!(count("us-ssn", "912-70-1234"), 0);
        assert_eq!(count("us-ein", "EIN: 12-3456789"), 1);
        assert_eq!(count("us-ein", "part 12-3456789"), 0);
        assert_eq!(count("us-ein", "EIN 07-3456789"), 0);
    }

    #[test]
    fn routing_needs_a_word() {
        assert_eq!(count("us-aba-routing", "Routing number 011000015"), 1);
        assert_eq!(count("us-aba-routing", "ABA 021000021"), 1);
        assert_eq!(count("us-aba-routing", "invoice 011000015"), 0);
        assert_eq!(count("us-aba-routing", "routing 011000016"), 0);
    }

    #[test]
    fn licenses() {
        assert_eq!(count("us-drivers-license", "Driver's license: D1234567"), 1);
        assert_eq!(count("us-drivers-license", "DL# S123-456-78-901-0"), 1);
        assert_eq!(count("us-drivers-license", "Order D1234567"), 0);
    }

    #[test]
    fn health_identifiers() {
        // CMS's own MBI example
        assert_eq!(count("us-mbi", "Medicare 1EG4-TE5-MK73"), 1);
        assert_eq!(count("us-mbi", "1EG4TE5MK73"), 1);
        assert_eq!(count("us-mbi", "1EG4-TE5-MK7S"), 0);
        // CMS's NPI example
        assert_eq!(count("us-npi", "NPI 1234567893"), 1);
        assert_eq!(count("us-npi", "NPI 1234567894"), 0);
        assert_eq!(count("us-npi", "call 1234567893"), 0);
        assert_eq!(count("us-dea", "DEA AB1234563"), 1);
        assert_eq!(count("us-dea", "AB1234564"), 0);
    }
}
