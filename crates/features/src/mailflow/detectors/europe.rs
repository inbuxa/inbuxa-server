/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! European identifiers outside the EU (§2.3): Norway's national identity
//! number and Switzerland's AHV number.

use super::{Detector, Findings, Region, Strength, digit_values, valid_short_date};
use regex::Regex;
use std::sync::LazyLock;

pub static DETECTORS: &[Detector] = &[
    Detector::new(
        "no-fnr",
        "Norway: national identity number",
        Region::Europe,
        Strength::Checked,
        no_fnr,
    ),
    Detector::new(
        "ch-ahv",
        "Switzerland: AHV number",
        Region::Europe,
        Strength::Checked,
        ch_ahv,
    ),
];

static ELEVEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{6} ?\d{5}\b").expect("detector pattern"));

/// Two mod 11 check digits over a birth date (D-numbers add 40 to the day,
/// H-numbers 40 to the month): strong enough to count alone.
pub fn fnr_valid(n: &str) -> bool {
    let d = digit_values(n);
    if d.len() != 11 {
        return false;
    }
    let check =
        |weights: &[u32]| match 11 - d.iter().zip(weights).map(|(a, w)| a * w).sum::<u32>() % 11 {
            11 => Some(0),
            10 => None,
            c => Some(c),
        };
    let day = d[0] * 10 + d[1];
    let month = d[2] * 10 + d[3];
    let day = if day > 40 { day - 40 } else { day };
    let month = if month > 40 { month - 40 } else { month };
    valid_short_date(d[4] * 10 + d[5], month, day)
        && check(&[3, 7, 6, 1, 8, 9, 4, 5, 2]) == Some(d[9])
        && check(&[5, 4, 3, 2, 7, 6, 5, 4, 3, 2]) == Some(d[10])
}

fn no_fnr(text: &str, findings: &mut Findings) {
    for m in ELEVEN.find_iter(text) {
        let n = m.as_str().replace(' ', "");
        if fnr_valid(&n) {
            findings.insert(n);
        }
    }
}

/// `756.1234.5678.97`: the country prefix, then an EAN-13 check digit.
static AHV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b756[. ]?\d{4}[. ]?\d{4}[. ]?\d{2}\b").expect("detector pattern")
});

pub fn ean13_valid(n: &str) -> bool {
    let d = digit_values(n);
    if d.len() != 13 {
        return false;
    }
    let sum: u32 = d[..12]
        .iter()
        .enumerate()
        .map(|(i, x)| if i % 2 == 0 { *x } else { x * 3 })
        .sum();
    (10 - sum % 10) % 10 == d[12]
}

fn ch_ahv(text: &str, findings: &mut Findings) {
    for m in AHV.find_iter(text) {
        let n: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
        if ean13_valid(&n) {
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
    fn norway() {
        assert_eq!(count("no-fnr", "01019000083"), 1);
        assert_eq!(count("no-fnr", "010190 00083"), 1);
        assert_eq!(count("no-fnr", "01019000084"), 0);
        // Not a date
        assert_eq!(count("no-fnr", "32019000083"), 0);
    }

    #[test]
    fn switzerland() {
        // The federal example
        assert_eq!(count("ch-ahv", "AHV 756.9217.0769.85"), 1);
        assert_eq!(count("ch-ahv", "7569217076985"), 1);
        assert_eq!(count("ch-ahv", "756.9217.0769.86"), 0);
    }
}
