/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Asian identifiers (§2.3): India's Aadhaar and PAN, China's resident ID,
//! Japan's My Number, Singapore's NRIC and FIN, and South Korea's resident
//! registration number.

use super::{
    Detector, Findings, Region, Strength, digit_values, valid_date, valid_short_date, word_near,
};
use regex::Regex;
use std::sync::LazyLock;

pub static DETECTORS: &[Detector] = &[
    Detector::new(
        "in-aadhaar",
        "India: Aadhaar",
        Region::Asia,
        Strength::Checked,
        in_aadhaar,
    ),
    Detector::new(
        "in-pan",
        "India: PAN",
        Region::Asia,
        Strength::NeedsWord,
        in_pan,
    ),
    Detector::new(
        "cn-resident-id",
        "China: resident ID",
        Region::Asia,
        Strength::Checked,
        cn_resident_id,
    ),
    Detector::new(
        "jp-my-number",
        "Japan: My Number",
        Region::Asia,
        Strength::Checked,
        jp_my_number,
    ),
    Detector::new(
        "sg-nric",
        "Singapore: NRIC and FIN",
        Region::Asia,
        Strength::Checked,
        sg_nric,
    ),
    Detector::new(
        "kr-rrn",
        "South Korea: resident registration number",
        Region::Asia,
        Strength::NeedsWord,
        kr_rrn,
    ),
];

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("detector pattern")
}

/// Twelve digits written in fours, or bare.
static TWELVE: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{4})( ?)(\d{4})( ?)(\d{4})\b"));

const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// The Verhoeff check (dihedral group D5).
pub fn verhoeff(n: &str) -> bool {
    let mut c = 0u8;
    for (i, b) in n.bytes().rev().enumerate() {
        c = VERHOEFF_D[c as usize][VERHOEFF_P[i % 8][(b - b'0') as usize] as usize];
    }
    c == 0
}

const AADHAAR_WORDS: &[&str] = &["aadhaar", "aadhar", "uidai", "uid"];

fn in_aadhaar(text: &str, findings: &mut Findings) {
    for c in TWELVE.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let n = format!("{}{}{}", &c[1], &c[3], &c[5]);
        let written = &c[2] == " " && &c[4] == " ";
        // Never starts with 0 or 1
        if !n.starts_with(['0', '1'])
            && verhoeff(&n)
            && (written || word_near(text, whole.start(), whole.end(), AADHAAR_WORDS))
        {
            findings.insert(n);
        }
    }
}

/// Five letters (the fourth names the holder's type), four digits, a letter.
static PAN: LazyLock<Regex> = LazyLock::new(|| re(r"\b[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]\b"));

const PAN_WORDS: &[&str] = &["pan", "pan card", "permanent account number", "income tax"];

fn in_pan(text: &str, findings: &mut Findings) {
    for m in PAN.find_iter(text) {
        if word_near(text, m.start(), m.end(), PAN_WORDS) {
            findings.insert(m.as_str());
        }
    }
}

/// Region, birth date `YYYYMMDD`, sequence, then the ISO 7064 MOD 11-2
/// check (0–9 or X).
static CN_ID: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b[1-8]\d{5}(\d{4})(\d{2})(\d{2})\d{3}[\dX]\b"));

pub fn cn_id_valid(id: &str) -> bool {
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECKS: &[u8] = b"10X98765432";
    let sum: u32 = digit_values(&id[..17])
        .iter()
        .zip(WEIGHTS)
        .map(|(a, w)| a * w)
        .sum();
    CHECKS[(sum % 11) as usize] == id.as_bytes()[17].to_ascii_uppercase()
}

fn cn_resident_id(text: &str, findings: &mut Findings) {
    for c in CN_ID.captures_iter(text) {
        let id = c[0].to_ascii_uppercase();
        let (y, m, d) = (num(&c[1]), num(&c[2]), num(&c[3]));
        if valid_date(y, m, d) && cn_id_valid(&id) {
            findings.insert(id);
        }
    }
}

/// My Number: weights 2–7 then 2–6 from the right; a remainder of 0 or 1
/// gives 0, else 11 minus it.
pub fn my_number_valid(n: &str) -> bool {
    let d = digit_values(n);
    let sum: u32 = (1..=11)
        .map(|i| d[11 - i] * if i <= 6 { i as u32 + 1 } else { i as u32 - 5 })
        .sum();
    let check = match sum % 11 {
        0 | 1 => 0,
        r => 11 - r,
    };
    check == d[11]
}

const MY_NUMBER_WORDS: &[&str] = &[
    "my number",
    "mynumber",
    "マイナンバー",
    "個人番号",
    "kojin bango",
];

fn jp_my_number(text: &str, findings: &mut Findings) {
    for c in TWELVE.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let n = format!("{}{}{}", &c[1], &c[3], &c[5]);
        let written = &c[2] == " " && &c[4] == " ";
        if my_number_valid(&n)
            && (written || word_near(text, whole.start(), whole.end(), MY_NUMBER_WORDS))
        {
            findings.insert(n);
        }
    }
}

static NRIC: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b([STFGM])(\d{7})([A-Z])\b"));

/// Weights 2, 7, 6, 5, 4, 3, 2; T and G add 4, M adds 3; each series has its
/// own table of check letters.
fn nric_valid(prefix: u8, digits: &str, check: u8) -> bool {
    let sum: u32 = digit_values(digits)
        .iter()
        .zip([2, 7, 6, 5, 4, 3, 2])
        .map(|(a, w)| a * w)
        .sum::<u32>()
        + match prefix {
            b'T' | b'G' => 4,
            b'M' => 3,
            _ => 0,
        };
    let table: &[u8] = match prefix {
        b'S' | b'T' => b"JZIHGFEDCBA",
        b'F' | b'G' => b"XWUTRQPNMLK",
        _ => b"KLJNPQRTUWX",
    };
    table[(sum % 11) as usize] == check
}

fn sg_nric(text: &str, findings: &mut Findings) {
    for c in NRIC.captures_iter(text) {
        let id = c[0].to_ascii_uppercase();
        let bytes = id.as_bytes();
        if nric_valid(bytes[0], &c[2], bytes[8]) {
            findings.insert(id);
        }
    }
}

/// `YYMMDD-GNNNNNN`, the seventh digit giving sex and century.
static RRN: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{2})(\d{2})(\d{2})-?([1-8])\d{6}\b"));

const RRN_WORDS: &[&str] = &["주민등록번호", "주민번호", "resident registration", "rrn"];

fn kr_rrn(text: &str, findings: &mut Findings) {
    for c in RRN.captures_iter(text) {
        let whole = c.get(0).unwrap();
        if valid_short_date(num(&c[1]), num(&c[2]), num(&c[3]))
            && word_near(text, whole.start(), whole.end(), RRN_WORDS)
        {
            findings.insert(whole.as_str().replace('-', ""));
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
    fn india() {
        assert_eq!(count("in-aadhaar", "2345 6789 0124"), 1);
        assert_eq!(count("in-aadhaar", "2345 6789 0125"), 0);
        assert_eq!(count("in-aadhaar", "order 234567890124"), 0);
        assert_eq!(count("in-aadhaar", "Aadhaar 234567890124"), 1);
        assert_eq!(count("in-pan", "PAN: ABCPE1234F"), 1);
        assert_eq!(count("in-pan", "ABCPE1234F"), 0);
    }

    #[test]
    fn china_japan() {
        assert_eq!(count("cn-resident-id", "11010519491231002X"), 1);
        assert_eq!(count("cn-resident-id", "110105194912310021"), 0);
        assert_eq!(count("cn-resident-id", "11010519491331002X"), 0);
        assert_eq!(count("jp-my-number", "1234 5678 9018"), 1);
        assert_eq!(count("jp-my-number", "1234 5678 9017"), 0);
        assert_eq!(count("jp-my-number", "マイナンバー 123456789018"), 1);
    }

    #[test]
    fn singapore_korea() {
        assert_eq!(count("sg-nric", "S1234567D and T1234567J"), 2);
        assert_eq!(count("sg-nric", "S1234567E"), 0);
        assert_eq!(count("kr-rrn", "주민등록번호 800101-1234567"), 1);
        assert_eq!(count("kr-rrn", "800101-1234567"), 0);
        assert_eq!(count("kr-rrn", "RRN 801301-1234567"), 0);
    }
}
