/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! African identifiers (§2.3): South Africa's ID number.

use super::{Detector, Findings, Region, Strength, checks, valid_short_date};
use regex::Regex;
use std::sync::LazyLock;

pub static DETECTORS: &[Detector] = &[Detector::new(
    "za-id",
    "South Africa: ID number",
    Region::Africa,
    Strength::Checked,
    za_id,
)];

/// Birth date `YYMMDD`, four digits, citizenship (0, 1 or 2), 8 or 9, a Luhn
/// check digit. The date and the two fixed digits make it strong enough to
/// count alone.
static ZA_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{2})(\d{2})(\d{2})\d{4}[012][89]\d\b").expect("detector pattern")
});

fn za_id(text: &str, findings: &mut Findings) {
    for c in ZA_ID.captures_iter(text) {
        let n = &c[0];
        let num = |s: &str| s.parse::<u32>().unwrap_or(0);
        if valid_short_date(num(&c[1]), num(&c[2]), num(&c[3])) && checks::luhn(n) {
            findings.insert(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mailflow::detectors::by_id;

    #[test]
    fn south_africa() {
        let detector = by_id("za-id").unwrap();
        assert_eq!(detector.count("ID 8001015009087"), 1);
        assert_eq!(detector.count("8001015009088"), 0);
        assert_eq!(detector.count("8013015009087"), 0);
    }
}
