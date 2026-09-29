/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Australian identifiers (§2.3): the ATO's Tax File Number and the Medicare
//! card number.

use super::{Detector, Findings, Region, Strength, word_near};
use regex::Regex;
use std::sync::LazyLock;

pub static DETECTORS: &[Detector] = &[
    Detector::new(
        "au-tfn",
        "Australian Tax File Number",
        Region::Australia,
        Strength::Checked,
        tfn,
    ),
    Detector::new(
        "au-medicare",
        "Australian Medicare number",
        Region::Australia,
        Strength::Checked,
        medicare,
    ),
];

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("detector pattern")
}

/// `NNN NNN NNN` stands alone; bare digits (eight or nine) need a word.
static TFN: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{3})( ?)(\d{3})( ?)(\d{2,3})\b"));

/// Weighted sum mod 11, with the ATO's weights for 9- and 8-digit numbers.
pub fn tfn_valid(n: &str) -> bool {
    let weights: &[u32] = match n.len() {
        9 => &[1, 4, 3, 7, 5, 8, 6, 9, 10],
        8 => &[10, 7, 8, 4, 6, 3, 5, 1],
        _ => return false,
    };
    n.bytes()
        .zip(weights)
        .map(|(b, w)| u32::from(b - b'0') * w)
        .sum::<u32>()
        % 11
        == 0
}

const TFN_WORDS: &[&str] = &["tfn", "tax file number", "tax file no"];

fn tfn(text: &str, findings: &mut Findings) {
    for c in TFN.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let n = format!("{}{}{}", &c[1], &c[3], &c[5]);
        let written = n.len() == 9 && c[2] == *" " && c[4] == *" ";
        if tfn_valid(&n) && (written || word_near(text, whole.start(), whole.end(), TFN_WORDS)) {
            findings.insert(n);
        }
    }
}

/// `NNNN NNNNN N` (and an optional issue number) stands alone; bare digits
/// need a word.
static MEDICARE: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b([2-6]\d{3})( ?)(\d{5})( ?)(\d)(?:[ -]?\d)?\b"));

/// The ninth digit is the weighted sum (1, 3, 7, 9, 1, 3, 7, 9) of the first
/// eight, mod 10.
pub fn medicare_valid(n: &str) -> bool {
    let d: Vec<u32> = n.bytes().map(|b| u32::from(b - b'0')).collect();
    d.len() >= 9
        && d[..8]
            .iter()
            .zip([1, 3, 7, 9, 1, 3, 7, 9])
            .map(|(a, w)| a * w)
            .sum::<u32>()
            % 10
            == d[8]
}

const MEDICARE_WORDS: &[&str] = &[
    "medicare",
    "medicare card",
    "medicare no",
    "medicare number",
];

fn medicare(text: &str, findings: &mut Findings) {
    for c in MEDICARE.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let n = format!("{}{}{}", &c[1], &c[3], &c[5]);
        let written = c[2] == *" " && c[4] == *" ";
        if medicare_valid(&n)
            && (written || word_near(text, whole.start(), whole.end(), MEDICARE_WORDS))
        {
            findings.insert(n);
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
    fn tax_file_numbers() {
        assert_eq!(count("au-tfn", "TFN 123 456 782"), 1);
        assert_eq!(count("au-tfn", "123 456 789"), 0);
        assert_eq!(count("au-tfn", "order 123456782"), 0);
        assert_eq!(count("au-tfn", "tax file number 123456782"), 1);
    }

    #[test]
    fn medicare_numbers() {
        assert_eq!(count("au-medicare", "2123 45670 1"), 1);
        assert_eq!(count("au-medicare", "2123 45671 1"), 0);
        assert_eq!(count("au-medicare", "ref 2123456701"), 0);
        assert_eq!(count("au-medicare", "Medicare 2123456701"), 1);
    }
}
