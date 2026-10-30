/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! JMAP `UTCDate` (RFC 8620 §1.4) to and from Unix seconds, without a date
//! library: the relay needs nothing more.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Parses `YYYY-MM-DDTHH:MM:SSZ`, with optional fractional seconds, which
/// are dropped. Anything else is `None`.
pub fn parse_utc_date(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' {
        return None;
    }
    if b[16] != b':' || *b.last()? != b'Z' {
        return None;
    }
    if b.len() > 20
        && (b[19] != b'.' || b.len() == 21 || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u64> {
        let s = text.get(r)?;
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = days_from_civil(y as i64, mo as u32, d as u32);
    if days < 0 || civil_from_days(days) != (y as i64, mo as u32, d as u32) {
        return None;
    }
    Some(days as u64 * 86_400 + h * 3600 + mi * 60 + s)
}

// Howard Hinnant's civil-date algorithms, proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for secs in [0, 951_782_400, 1_793_275_200, 4_102_444_799] {
            assert_eq!(parse_utc_date(&utc_date(secs)), Some(secs));
        }
        assert_eq!(utc_date(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_date(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn parses_fractions_and_rejects_junk() {
        assert_eq!(
            parse_utc_date("2026-10-29T12:00:00.250Z"),
            Some(1_793_275_200)
        );
        for bad in [
            "2026-10-29 12:00:00Z",
            "2026-10-29T12:00:00",
            "2026-02-30T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-29T12:00:00.Z",
            "+026-10-29T12:00:00Z",
        ] {
            assert_eq!(parse_utc_date(bad), None, "{bad}");
        }
    }
}
