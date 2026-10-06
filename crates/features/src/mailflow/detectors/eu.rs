/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! European Union national identifiers (§2.3), each from its issuer's
//! published rules. An identifier that is only digits and whose check a
//! random number passes often (mod 10, mod 11) counts alone only in its
//! written form, and as bare digits only beside a word.

use super::{
    Detector, Findings, Region, Strength, checks, digit_values, stands_alone, valid_short_date,
    word_near,
};
use regex::Regex;
use std::sync::LazyLock;

pub static DETECTORS: &[Detector] = &[
    Detector::new(
        "de-tax-id",
        "Germany: tax ID (Steuer-ID)",
        Region::Eu,
        Strength::Checked,
        de_tax_id,
    ),
    Detector::new(
        "de-id-card",
        "Germany: ID card number",
        Region::Eu,
        Strength::Checked,
        de_id_card,
    ),
    Detector::new(
        "fr-nir",
        "France: social security number (NIR)",
        Region::Eu,
        Strength::Checked,
        fr_nir,
    ),
    Detector::new(
        "es-dni-nie",
        "Spain: DNI and NIE",
        Region::Eu,
        Strength::Checked,
        es_dni_nie,
    ),
    Detector::new(
        "it-codice-fiscale",
        "Italy: codice fiscale",
        Region::Eu,
        Strength::Checked,
        it_codice_fiscale,
    ),
    Detector::new(
        "nl-bsn",
        "Netherlands: BSN",
        Region::Eu,
        Strength::Checked,
        nl_bsn,
    ),
    Detector::new(
        "be-national-number",
        "Belgium: national number",
        Region::Eu,
        Strength::Checked,
        be_national_number,
    ),
    Detector::new(
        "pl-pesel",
        "Poland: PESEL",
        Region::Eu,
        Strength::Checked,
        pl_pesel,
    ),
    Detector::new(
        "se-personnummer",
        "Sweden: personnummer",
        Region::Eu,
        Strength::Checked,
        se_personnummer,
    ),
    Detector::new(
        "dk-cpr",
        "Denmark: CPR number",
        Region::Eu,
        Strength::NeedsWord,
        dk_cpr,
    ),
    Detector::new(
        "fi-hetu",
        "Finland: personal identity code",
        Region::Eu,
        Strength::Checked,
        fi_hetu,
    ),
    Detector::new(
        "ie-pps",
        "Ireland: PPS number",
        Region::Eu,
        Strength::Checked,
        ie_pps,
    ),
    Detector::new(
        "pt-nif",
        "Portugal: NIF",
        Region::Eu,
        Strength::Checked,
        pt_nif,
    ),
    Detector::new(
        "at-svnr",
        "Austria: social insurance number",
        Region::Eu,
        Strength::Checked,
        at_svnr,
    ),
];

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("detector pattern")
}

fn num(s: &str) -> u32 {
    s.parse().unwrap_or(0)
}

// --- Germany --------------------------------------------------------------

/// Eleven digits, written `86 095 742 719` on the BZSt's letters.
static DE_TAX: LazyLock<Regex> = LazyLock::new(|| re(r"\b\d{2}( ?)\d{3}( ?)\d{3}( ?)\d{3}\b"));

/// ISO 7064 MOD 11,10; no leading zero; in the first ten digits one digit
/// appears two or three times and every other at most once.
pub fn de_tax_id_valid(n: &str) -> bool {
    let d = digit_values(n);
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    let mut counts = [0u8; 10];
    for &x in &d[..10] {
        counts[x as usize] += 1;
    }
    let repeated = counts.iter().filter(|&&c| c >= 2).count();
    if repeated != 1 || counts.iter().any(|&c| c > 3) {
        return false;
    }
    let mut product = 10;
    for &x in &d[..10] {
        let mut sum = (x + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (2 * sum) % 11;
    }
    let check = match 11 - product {
        10 => 0,
        c => c,
    };
    check == d[10]
}

const DE_TAX_WORDS: &[&str] = &[
    "steuer-id",
    "steueridentifikationsnummer",
    "steuerliche identifikationsnummer",
    "idnr",
    "identifikationsnummer",
    "tax id",
];

fn de_tax_id(text: &str, findings: &mut Findings) {
    for c in DE_TAX.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let written = [&c[1], &c[2], &c[3]].iter().all(|s| *s == " ");
        let n: String = whole.as_str().replace(' ', "");
        if de_tax_id_valid(&n)
            && (written || word_near(text, whole.start(), whole.end(), DE_TAX_WORDS))
        {
            findings.insert(n);
        }
    }
}

/// The ID card's document number: a letter from the card's alphabet, eight
/// more characters from it, then the check digit.
static DE_ID: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{8}\d\b"));

/// ICAO 9303 check digit: weights 7, 3, 1; letters A=10 … Z=35.
pub fn icao_check(chars: &str, check: u32) -> bool {
    let value = |c: char| c.to_digit(10).unwrap_or_else(|| c as u32 - 'A' as u32 + 10);
    let sum: u32 = chars
        .chars()
        .zip([7, 3, 1].iter().cycle())
        .map(|(c, w)| value(c) * w)
        .sum();
    sum % 10 == check
}

fn de_id_card(text: &str, findings: &mut Findings) {
    for m in DE_ID.find_iter(text) {
        let s = m.as_str();
        if icao_check(&s[..9], num(&s[9..])) {
            findings.insert(s);
        }
    }
}

// --- France ---------------------------------------------------------------

/// Sex, year, month, department (with Corsica's 2A and 2B), commune, order,
/// then the two-digit key, spaces allowed between groups.
static FR_NIR: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\b([1-478]) ?(\d{2}) ?(\d{2}) ?(\d{2}|2[AB]) ?(\d{3}) ?(\d{3}) ?(\d{2})\b")
});

fn fr_nir(text: &str, findings: &mut Findings) {
    for c in FR_NIR.captures_iter(text) {
        let month = num(&c[3]);
        if !(matches!(month, 1..=12 | 20..=42 | 50..=99)) {
            continue;
        }
        let department = match &c[4] {
            "2A" => "19",
            "2B" => "18",
            d => d,
        };
        let body = format!(
            "{}{}{}{}{}{}",
            &c[1], &c[2], &c[3], department, &c[5], &c[6]
        );
        let Ok(value) = body.parse::<u64>() else {
            continue;
        };
        if 97 - value % 97 == u64::from(num(&c[7])) {
            findings.insert(format!(
                "{}{}{}{}{}{}{}",
                &c[1], &c[2], &c[3], &c[4], &c[5], &c[6], &c[7]
            ));
        }
    }
}

// --- Spain ----------------------------------------------------------------

static ES_ID: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b([XYZ]?)[ -]?(\d{7,8})[ -]?([A-Z])\b"));

const DNI_LETTERS: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";

fn es_dni_nie(text: &str, findings: &mut Findings) {
    for c in ES_ID.captures_iter(text) {
        let prefix = c[1].to_ascii_uppercase();
        let digits = &c[2];
        // DNI: eight digits; NIE: X, Y or Z and seven digits
        let number = match (prefix.as_str(), digits.len()) {
            ("", 8) => digits.to_string(),
            ("X", 7) => format!("0{digits}"),
            ("Y", 7) => format!("1{digits}"),
            ("Z", 7) => format!("2{digits}"),
            _ => continue,
        };
        let letter = c[3].to_ascii_uppercase();
        if DNI_LETTERS[(num(&number) % 23) as usize] == letter.as_bytes()[0] {
            findings.insert(format!("{prefix}{digits}{letter}"));
        }
    }
}

// --- Italy ----------------------------------------------------------------

/// Surname and name letters, year, month letter, day, place code, check
/// letter; digits may be replaced by letters (omocodia).
static IT_CF: LazyLock<Regex> = LazyLock::new(|| {
    let d = "[0-9LMNPQRSTUV]";
    re(&format!(
        r"(?i)\b[A-Z]{{6}}{d}{{2}}[ABCDEHLMPRST]{d}{{2}}[A-Z]{d}{{3}}[A-Z]\b"
    ))
});

/// The Ministry's odd-position values for 0–9 and A–Z.
const CF_ODD: [u32; 36] = [
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, // 0-9
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24,
    23, // A-Z
];

pub fn codice_fiscale_valid(cf: &str) -> bool {
    let index = |c: u8| {
        if c.is_ascii_digit() {
            (c - b'0') as usize
        } else {
            (c - b'A') as usize + 10
        }
    };
    let even = |c: u8| {
        if c.is_ascii_digit() {
            u32::from(c - b'0')
        } else {
            u32::from(c - b'A')
        }
    };
    let bytes = cf.as_bytes();
    let sum: u32 = bytes[..15]
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            if i % 2 == 0 {
                CF_ODD[index(c)]
            } else {
                even(c)
            }
        })
        .sum();
    u32::from(bytes[15] - b'A') == sum % 26
}

fn it_codice_fiscale(text: &str, findings: &mut Findings) {
    for m in IT_CF.find_iter(text) {
        let cf = m.as_str().to_ascii_uppercase();
        if codice_fiscale_valid(&cf) {
            findings.insert(cf);
        }
    }
}

// --- Netherlands ----------------------------------------------------------

/// Nine digits, sometimes written `1112.22.333`.
static NL_BSN: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{4})(\.?)(\d{2})(\.?)(\d{3})\b"));

/// The eleven test: weights 9 down to 2, and −1 for the last digit.
pub fn bsn_valid(n: &str) -> bool {
    let d = digit_values(n);
    let sum: i64 = d[..8]
        .iter()
        .zip((2..=9).rev())
        .map(|(a, w)| i64::from(a * w))
        .sum::<i64>()
        - i64::from(d[8]);
    sum != 0 && sum % 11 == 0
}

const BSN_WORDS: &[&str] = &[
    "bsn",
    "burgerservicenummer",
    "sofinummer",
    "sofi-nummer",
    "citizen service number",
];

fn nl_bsn(text: &str, findings: &mut Findings) {
    for c in NL_BSN.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let n = format!("{}{}{}", &c[1], &c[3], &c[5]);
        let written = &c[2] == "." && &c[4] == ".";
        if bsn_valid(&n) && (written || word_near(text, whole.start(), whole.end(), BSN_WORDS)) {
            findings.insert(n);
        }
    }
}

// --- Belgium --------------------------------------------------------------

/// `YY.MM.DD-XXX.CC` or eleven digits.
static BE_NN: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b(\d{2})\.?(\d{2})\.?(\d{2})-?(\d{3})\.?(\d{2})\b"));

fn be_national_number(text: &str, findings: &mut Findings) {
    for c in BE_NN.captures_iter(text) {
        let (month, day) = (num(&c[2]), num(&c[3]));
        // Month 0 and day 0 mean unknown; bis numbers add 20 or 40 to the month
        if !(month <= 12 || (20..=32).contains(&month) || (40..=52).contains(&month)) || day > 31 {
            continue;
        }
        let body = format!("{}{}{}{}", &c[1], &c[2], &c[3], &c[4]);
        let check = u64::from(num(&c[5]));
        let before_2000 = 97 - body.parse::<u64>().unwrap_or(0) % 97;
        let since_2000 = 97 - format!("2{body}").parse::<u64>().unwrap_or(0) % 97;
        if check == before_2000 || check == since_2000 {
            findings.insert(format!("{body}{}", &c[5]));
        }
    }
}

// --- Poland ---------------------------------------------------------------

static ELEVEN: LazyLock<Regex> = LazyLock::new(|| re(r"\b\d{11}\b"));

/// Weights 1, 3, 7, 9 repeating; the birth date encodes the century in the
/// month (+80 for the 1800s, +20 for the 2000s, and so on).
pub fn pesel_valid(n: &str) -> bool {
    let d = digit_values(n);
    let sum: u32 = d[..10]
        .iter()
        .zip([1, 3, 7, 9].iter().cycle())
        .map(|(a, w)| a * w)
        .sum();
    let month = d[2] * 10 + d[3];
    let (century, month) = match month {
        81..=92 => (1800, month - 80),
        1..=12 => (1900, month),
        21..=32 => (2000, month - 20),
        41..=52 => (2100, month - 40),
        _ => return false,
    };
    let year = century + d[0] * 10 + d[1];
    (10 - sum % 10) % 10 == d[10] && (1..=super::days_in(year, month)).contains(&(d[4] * 10 + d[5]))
}

const PESEL_WORDS: &[&str] = &["pesel", "numer pesel", "nr pesel"];

fn pl_pesel(text: &str, findings: &mut Findings) {
    for m in ELEVEN.find_iter(text) {
        if pesel_valid(m.as_str()) && word_near(text, m.start(), m.end(), PESEL_WORDS) {
            findings.insert(m.as_str());
        }
    }
}

// --- Sweden ---------------------------------------------------------------

/// `YYMMDD-NNNN`, `YYYYMMDD-NNNN` (`+` after 100), or the bare digits.
static SE_PNR: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b(?:\d{2})?(\d{2})(\d{2})(\d{2})([-+]?)(\d{4})\b"));

const SE_WORDS: &[&str] = &[
    "personnummer",
    "personnr",
    "person nr",
    "samordningsnummer",
    "pnr",
];

fn se_personnummer(text: &str, findings: &mut Findings) {
    for c in SE_PNR.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let (yy, month, day) = (num(&c[1]), num(&c[2]), num(&c[3]));
        // Coordination numbers add 60 to the day
        let day = if day > 60 { day - 60 } else { day };
        let ten = format!("{}{}{}{}", &c[1], &c[2], &c[3], &c[5]);
        let written = !c[4].is_empty();
        if valid_short_date(yy, month, day)
            && checks::luhn(&ten)
            && (written || word_near(text, whole.start(), whole.end(), SE_WORDS))
        {
            findings.insert(ten);
        }
    }
}

// --- Denmark --------------------------------------------------------------

static DK_CPR: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{2})(\d{2})(\d{2})-?(\d{4})\b"));

const CPR_WORDS: &[&str] = &["cpr", "cpr-nr", "cpr nr", "cpr-nummer", "personnummer"];

fn dk_cpr(text: &str, findings: &mut Findings) {
    for c in DK_CPR.captures_iter(text) {
        let whole = c.get(0).unwrap();
        if valid_short_date(num(&c[3]), num(&c[2]), num(&c[1]))
            && word_near(text, whole.start(), whole.end(), CPR_WORDS)
        {
            findings.insert(whole.as_str().replace('-', ""));
        }
    }
}

// --- Finland --------------------------------------------------------------

static FI_HETU: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b(\d{2})(\d{2})(\d{2})[-+ABCDEFYXWVU](\d{3})([0-9A-Y])\b"));

const HETU_CHECK: &[u8] = b"0123456789ABCDEFHJKLMNPRSTUVWXY";

fn fi_hetu(text: &str, findings: &mut Findings) {
    for c in FI_HETU.captures_iter(text) {
        let (day, month, yy) = (num(&c[1]), num(&c[2]), num(&c[3]));
        let n: u64 = format!("{}{}{}{}", &c[1], &c[2], &c[3], &c[4])
            .parse()
            .unwrap_or(0);
        let check = c[5].to_ascii_uppercase().as_bytes()[0];
        if valid_short_date(yy, month, day) && HETU_CHECK[(n % 31) as usize] == check {
            findings.insert(c[0].to_ascii_uppercase());
        }
    }
}

// --- Ireland --------------------------------------------------------------

static IE_PPS: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b(\d{7})([A-W])([ABHW]?)\b"));

const PPS_CHECK: &[u8] = b"WABCDEFGHIJKLMNOPQRSTUV";

fn ie_pps(text: &str, findings: &mut Findings) {
    for c in IE_PPS.captures_iter(text) {
        let mut sum: u32 = digit_values(&c[1])
            .iter()
            .zip((2..=8).rev())
            .map(|(a, w)| a * w)
            .sum();
        // The second letter counts, times 9; W (the old form) counts as 0
        let second = c[3].to_ascii_uppercase();
        if let Some(&letter) = second.as_bytes().first()
            && letter != b'W'
        {
            sum += u32::from(letter - b'A' + 1) * 9;
        }
        let check = c[2].to_ascii_uppercase().as_bytes()[0];
        if PPS_CHECK[(sum % 23) as usize] == check {
            findings.insert(c[0].to_ascii_uppercase());
        }
    }
}

// --- Portugal -------------------------------------------------------------

static NINE: LazyLock<Regex> = LazyLock::new(|| re(r"\b\d{9}\b"));

/// Mod 11 over weights 9 down to 2; a check of 10 or 11 becomes 0.
pub fn nif_valid(n: &str) -> bool {
    let d = digit_values(n);
    let sum: u32 = d[..8].iter().zip((2..=9).rev()).map(|(a, w)| a * w).sum();
    let check = match 11 - sum % 11 {
        10 | 11 => 0,
        c => c,
    };
    matches!(d[0], 1 | 2 | 3 | 5 | 6 | 8 | 9) && check == d[8]
}

const NIF_WORDS: &[&str] = &[
    "nif",
    "contribuinte",
    "número de identificação fiscal",
    "numero de contribuinte",
];

fn pt_nif(text: &str, findings: &mut Findings) {
    for m in NINE.find_iter(text) {
        if nif_valid(m.as_str()) && word_near(text, m.start(), m.end(), NIF_WORDS) {
            findings.insert(m.as_str());
        }
    }
}

// --- Austria --------------------------------------------------------------

/// A serial and check digit, then the birth date: `1237 010180`.
static AT_SVNR: LazyLock<Regex> = LazyLock::new(|| re(r"\b(\d{3})(\d)( ?)(\d{2})(\d{2})(\d{2})\b"));

const SVNR_WORDS: &[&str] = &[
    "sozialversicherungsnummer",
    "svnr",
    "sv-nr",
    "sv-nummer",
    "versicherungsnummer",
];

fn at_svnr(text: &str, findings: &mut Findings) {
    for c in AT_SVNR.captures_iter(text) {
        let whole = c.get(0).unwrap();
        let n = format!("{}{}{}{}{}", &c[1], &c[2], &c[4], &c[5], &c[6]);
        let d = digit_values(&n);
        let sum: u32 = d
            .iter()
            .zip([3, 7, 9, 0, 5, 8, 4, 2, 1, 6])
            .map(|(a, w)| a * w)
            .sum();
        let written = &c[3] == " ";
        if d[0] != 0
            && sum % 11 == d[3]
            && valid_short_date(num(&c[6]), num(&c[5]), num(&c[4]))
            && (written || word_near(text, whole.start(), whole.end(), SVNR_WORDS))
            && stands_alone(text, whole.start(), whole.end())
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
    fn germany() {
        assert_eq!(count("de-tax-id", "86 095 742 719"), 1);
        assert_eq!(count("de-tax-id", "Steuer-ID: 86095742719"), 1);
        assert_eq!(count("de-tax-id", "Rechnung 86095742719"), 0);
        assert_eq!(count("de-tax-id", "86 095 742 718"), 0);
        // ICAO 9303's German specimen card
        assert_eq!(count("de-id-card", "Ausweis T220001293"), 1);
        assert_eq!(count("de-id-card", "T220001294"), 0);
    }

    #[test]
    fn france_spain_italy() {
        assert_eq!(count("fr-nir", "2 55 08 14 168 025 38"), 1);
        assert_eq!(count("fr-nir", "255081416802539"), 0);
        assert_eq!(count("es-dni-nie", "DNI 12345678Z, NIE X-1234567-L"), 2);
        assert_eq!(count("es-dni-nie", "12345678A"), 0);
        assert_eq!(count("it-codice-fiscale", "CF: RSSMRA85T10A562S"), 1);
        assert_eq!(count("it-codice-fiscale", "RSSMRA85T10A562T"), 0);
    }

    #[test]
    fn benelux() {
        assert_eq!(count("nl-bsn", "1112.22.333"), 1);
        assert_eq!(count("nl-bsn", "BSN 111222333"), 1);
        assert_eq!(count("nl-bsn", "order 111222333"), 0);
        assert_eq!(count("nl-bsn", "BSN 111222334"), 0);
        assert_eq!(count("be-national-number", "85.07.30-033.28"), 1);
        assert_eq!(count("be-national-number", "85073003329"), 0);
    }

    #[test]
    fn nordics() {
        assert_eq!(count("se-personnummer", "811218-9876"), 1);
        assert_eq!(count("se-personnummer", "811218-9875"), 0);
        assert_eq!(count("se-personnummer", "order 8112189876"), 0);
        assert_eq!(count("se-personnummer", "personnummer 198112189876"), 1);
        assert_eq!(count("dk-cpr", "CPR-nr: 010170-1234"), 1);
        assert_eq!(count("dk-cpr", "010170-1234"), 0);
        assert_eq!(count("dk-cpr", "CPR 320170-1234"), 0);
        assert_eq!(count("fi-hetu", "131052-308T"), 1);
        assert_eq!(count("fi-hetu", "131052-308U"), 0);
    }

    #[test]
    fn poland_ireland_portugal_austria() {
        assert_eq!(count("pl-pesel", "PESEL 44051401359, pesel 02070803628"), 2);
        assert_eq!(count("pl-pesel", "PESEL 44051401358"), 0);
        assert_eq!(count("pl-pesel", "44051401359"), 0);
        assert_eq!(count("ie-pps", "PPS 1234567T and 1234567FA"), 2);
        assert_eq!(count("ie-pps", "1234567U"), 0);
        assert_eq!(count("pt-nif", "NIF 123456789"), 1);
        assert_eq!(count("pt-nif", "NIF 123456788"), 0);
        assert_eq!(count("at-svnr", "1237 010180"), 1);
        assert_eq!(count("at-svnr", "SVNR 1237010180"), 1);
        assert_eq!(count("at-svnr", "1238 010180"), 0);
    }
}
