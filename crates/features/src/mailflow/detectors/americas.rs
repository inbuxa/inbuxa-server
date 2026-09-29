/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Identifiers from the Americas outside the US and Canada (§2.3): Brazil's
//! CPF and CNPJ, and Mexico's CURP.

use super::{Detector, Findings, Region, Strength, digit_values, valid_short_date, word_near};
use regex::Regex;
use std::sync::LazyLock;

pub static DETECTORS: &[Detector] = &[
    Detector::new(
        "br-cpf",
        "Brazil: CPF",
        Region::Americas,
        Strength::Checked,
        br_cpf,
    ),
    Detector::new(
        "br-cnpj",
        "Brazil: CNPJ",
        Region::Americas,
        Strength::Checked,
        br_cnpj,
    ),
    Detector::new(
        "mx-curp",
        "Mexico: CURP",
        Region::Americas,
        Strength::Checked,
        mx_curp,
    ),
];

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("detector pattern")
}

/// Brazil's mod 11 check digit over `digits` with `weights`.
fn br_check(digits: &[u32], weights: &[u32]) -> u32 {
    match digits.iter().zip(weights).map(|(a, w)| a * w).sum::<u32>() % 11 {
        0 | 1 => 0,
        r => 11 - r,
    }
}

/// `111.444.777-35`, or eleven bare digits.
static CPF: LazyLock<Regex> = LazyLock::new(|| re(r"\b\d{3}(\.?)\d{3}(\.?)\d{3}(-?)\d{2}\b"));

pub fn cpf_valid(n: &str) -> bool {
    let d = digit_values(n);
    // A run of one digit passes the arithmetic but is never issued
    d.len() == 11
        && d.iter().any(|x| *x != d[0])
        && br_check(&d[..9], &[10, 9, 8, 7, 6, 5, 4, 3, 2]) == d[9]
        && br_check(&d[..10], &[11, 10, 9, 8, 7, 6, 5, 4, 3, 2]) == d[10]
}

const CPF_WORDS: &[&str] = &[
    "cpf",
    "cadastro de pessoas físicas",
    "cadastro de pessoa física",
];

fn br_cpf(text: &str, findings: &mut Findings) {
    for c in CPF.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let written = &c[1] == "." && &c[2] == "." && &c[3] == "-";
        let n: String = whole
            .as_str()
            .chars()
            .filter(char::is_ascii_digit)
            .collect();
        if cpf_valid(&n) && (written || word_near(text, whole.start(), whole.end(), CPF_WORDS)) {
            findings.insert(n);
        }
    }
}

/// `11.222.333/0001-81`, or fourteen bare digits.
static CNPJ: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b\d{2}(\.?)\d{3}(\.?)\d{3}(/?)\d{4}(-?)\d{2}\b"));

pub fn cnpj_valid(n: &str) -> bool {
    let d = digit_values(n);
    d.len() == 14
        && d.iter().any(|x| *x != d[0])
        && br_check(&d[..12], &[5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == d[12]
        && br_check(&d[..13], &[6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == d[13]
}

const CNPJ_WORDS: &[&str] = &["cnpj", "cadastro nacional da pessoa jurídica"];

fn br_cnpj(text: &str, findings: &mut Findings) {
    for c in CNPJ.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let written = &c[1] == "." && &c[2] == "." && &c[3] == "/" && &c[4] == "-";
        let n: String = whole
            .as_str()
            .chars()
            .filter(char::is_ascii_digit)
            .collect();
        if cnpj_valid(&n) && (written || word_near(text, whole.start(), whole.end(), CNPJ_WORDS)) {
            findings.insert(n);
        }
    }
}

/// Four letters, the birth date, sex (H, M or X), the state, three
/// consonants, a character that tells the century apart, the check digit.
static CURP: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\b[A-Z]{4}(\d{2})(\d{2})(\d{2})[HMX][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d\b")
});

/// RENAPO's check: each character's place in `0-9 A-N Ñ O-Z`, weighted 18
/// down to 2; the digit is 10 minus the sum mod 10 (10 becomes 0).
pub fn curp_valid(curp: &str) -> bool {
    const ALPHABET: &str = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ";
    let mut sum = 0u32;
    for (i, c) in curp.chars().take(17).enumerate() {
        let Some(value) = ALPHABET.chars().position(|a| a == c) else {
            return false;
        };
        sum += value as u32 * (18 - i as u32);
    }
    curp.chars().nth(17).and_then(|c| c.to_digit(10)) == Some((10 - sum % 10) % 10)
}

fn mx_curp(text: &str, findings: &mut Findings) {
    for c in CURP.captures_iter(text) {
        let curp = c[0].to_ascii_uppercase();
        if valid_short_date(num(&c[1]), num(&c[2]), num(&c[3])) && curp_valid(&curp) {
            findings.insert(curp);
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
    fn brazil() {
        assert_eq!(count("br-cpf", "CPF 111.444.777-35"), 1);
        assert_eq!(count("br-cpf", "111.444.777-36"), 0);
        assert_eq!(count("br-cpf", "pedido 11144477735"), 0);
        assert_eq!(count("br-cpf", "cpf: 11144477735"), 1);
        assert_eq!(count("br-cpf", "CPF 111.111.111-11"), 0);
        assert_eq!(count("br-cnpj", "11.222.333/0001-81"), 1);
        assert_eq!(count("br-cnpj", "11.222.333/0001-82"), 0);
        assert_eq!(count("br-cnpj", "CNPJ 11222333000181"), 1);
    }

    #[test]
    fn mexico() {
        // python-stdnum's documented example
        assert_eq!(count("mx-curp", "CURP BOXW310820HNERXN09"), 1);
        assert_eq!(count("mx-curp", "BOXW310820HNERXN08"), 0);
        assert_eq!(count("mx-curp", "BOXW311320HNERXN09"), 0);
    }
}
