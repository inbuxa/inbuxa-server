/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Check-digit algorithms, each from its public definition.

/// The Luhn check (ISO/IEC 7812-1, Annex B) over a string of ASCII digits.
pub fn luhn(digits: &str) -> bool {
    if digits.len() < 2 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let sum: u32 = digits
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let d = u32::from(b - b'0');
            if i % 2 == 1 {
                let d = d * 2;
                if d > 9 { d - 9 } else { d }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// ISO 13616 IBAN lengths, by country, from the IBAN registry.
const IBAN_LENGTHS: &[(&str, usize)] = &[
    ("AD", 24),
    ("AE", 23),
    ("AL", 28),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BI", 27),
    ("BR", 29),
    ("BY", 28),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DJ", 27),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FK", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HN", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IQ", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LC", 32),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("LY", 25),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MN", 20),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NI", 28),
    ("NL", 18),
    ("NO", 15),
    ("OM", 23),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("RU", 33),
    ("SA", 24),
    ("SC", 31),
    ("SD", 18),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("SO", 23),
    ("ST", 25),
    ("SV", 28),
    ("TL", 23),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VA", 22),
    ("VG", 24),
    ("XK", 20),
    ("YE", 30),
];

/// The IBAN length for a country code, if the country uses IBANs.
pub fn iban_length(country: &str) -> Option<usize> {
    IBAN_LENGTHS
        .iter()
        .find(|(code, _)| *code == country)
        .map(|(_, len)| *len)
}

/// ISO 13616 / ISO 7064 MOD 97-10 over an IBAN with no spaces, upper case:
/// move the first four characters to the end, turn letters into 10–35, and
/// the number mod 97 must be 1. Also checks the country's length.
pub fn iban(iban: &str) -> bool {
    if iban.len() < 5
        || !iban
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return false;
    }
    if iban_length(&iban[..2]) != Some(iban.len())
        || !iban[2..4].bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let mut remainder: u32 = 0;
    for b in iban[4..].bytes().chain(iban[..4].bytes()) {
        let value = if b.is_ascii_digit() {
            u32::from(b - b'0')
        } else {
            u32::from(b - b'A') + 10
        };
        remainder = if value >= 10 {
            (remainder * 100 + value) % 97
        } else {
            (remainder * 10 + value) % 97
        };
    }
    remainder == 1
}

/// ISO 3166-1 alpha-2 country codes, for SWIFT/BIC positions 5–6.
const COUNTRIES: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ \
BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ \
DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT \
GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY \
KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX \
MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS \
RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN \
TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW";

pub fn is_country(code: &str) -> bool {
    code.len() == 2 && COUNTRIES.split(' ').any(|c| c == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_known_numbers() {
        // Published test card numbers
        for good in [
            "4242424242424242",
            "5555555555554444",
            "378282246310005",
            "79927398713",
        ] {
            assert!(luhn(good), "{good}");
        }
        for bad in ["4242424242424241", "79927398710", "1", "12a4"] {
            assert!(!luhn(bad), "{bad}");
        }
    }

    #[test]
    fn iban_registry_examples() {
        // The IBAN registry's own examples
        for good in [
            "GB29NWBK60161331926819",
            "DE89370400440532013000",
            "FR1420041010050500013M02606",
            "NL91ABNA0417164300",
            "BE68539007547034",
            "NO9386011117947",
            "CH9300762011623852957",
        ] {
            assert!(iban(good), "{good}");
        }
        for bad in [
            "GB29NWBK60161331926818", // check fails
            "GB29NWBK6016133192681",  // too short for GB
            "ZZ29NWBK60161331926819", // no such country
            "DE8937040044053201300A", // letters where DE has none still fail mod 97
        ] {
            assert!(!iban(bad), "{bad}");
        }
    }

    #[test]
    fn countries() {
        assert!(is_country("DE") && is_country("US") && is_country("XK"));
        assert!(!is_country("ZZ") && !is_country("D"));
    }
}
