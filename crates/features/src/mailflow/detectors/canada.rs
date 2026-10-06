/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Canadian identifiers (§2.3): the Social Insurance Number.

use super::{Detector, Findings, Region, Strength, checks, word_near};
use regex::Regex;
use std::sync::LazyLock;

pub static DETECTORS: &[Detector] = &[Detector::new(
    "ca-sin",
    "Canadian Social Insurance Number",
    Region::Canada,
    Strength::Checked,
    sin,
)];

/// `NNN NNN NNN` or `NNN-NNN-NNN` stands alone; nine bare digits need a word.
static SIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{3})([ -]?)(\d{3})([ -]?)(\d{3})\b").expect("detector pattern")
});

const SIN_WORDS: &[&str] = &[
    "sin",
    "social insurance",
    "nas",
    "numéro d'assurance sociale",
    "assurance sociale",
];

fn sin(text: &str, findings: &mut Findings) {
    for c in SIN.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let n = format!("{}{}{}", &c[1], &c[3], &c[5]);
        let written = !c[2].is_empty() && c[2] == c[4];
        // 0 and 8 are never issued as a first digit
        if !n.starts_with(['0', '8'])
            && checks::luhn(&n)
            && (written || word_near(text, whole.start(), whole.end(), SIN_WORDS))
        {
            findings.insert(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mailflow::detectors::by_id;

    fn count(text: &str) -> usize {
        by_id("ca-sin").unwrap().count(text)
    }

    #[test]
    fn social_insurance_numbers() {
        assert_eq!(count("130 692 544 and 193-456-787"), 2);
        assert_eq!(count("130 692 545"), 0);
        // The government's printed example starts with 0, never issued
        assert_eq!(count("046 454 286"), 0);
        assert_eq!(count("order 130692544"), 0);
        assert_eq!(count("SIN: 130692544"), 1);
    }
}
