/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Limits on creating masks (ME-14, ME-15).

use std::sync::OnceLock;

/// The in-memory store prefix for the create-rate counters. Upstream's
/// prefixes are small numbers counting up from 0; the fork's start at 0xE0.
pub const KV_CREATE_RATE: u8 = 0xE0;

/// Creates allowed per account per hour when nothing else is configured
/// (ME-15).
pub const DEFAULT_CREATES_PER_HOUR: u64 = 50;

/// The environment variable that sets the create rate, until the fork has a
/// settings object of its own. 0 means no limit.
pub const CREATE_RATE_VAR: &str = "INBUXA_MASKED_EMAIL_CREATE_RATE";

/// Creates allowed per account per hour, `None` for no limit. Read once.
pub fn creates_per_hour() -> Option<u64> {
    static RATE: OnceLock<Option<u64>> = OnceLock::new();
    *RATE.get_or_init(|| parse_rate(std::env::var(CREATE_RATE_VAR).ok().as_deref()))
}

fn parse_rate(value: Option<&str>) -> Option<u64> {
    match value.map(str::trim).map(str::parse::<u64>) {
        None => Some(DEFAULT_CREATES_PER_HOUR),
        Some(Ok(0)) => None,
        Some(Ok(rate)) => Some(rate),
        Some(Err(_)) => {
            trc::event!(
                Server(trc::ServerEvent::Startup),
                Details = concat!(
                    "INBUXA_MASKED_EMAIL_CREATE_RATE isn't a whole number; ",
                    "using the default of 50 an hour"
                ),
            );
            Some(DEFAULT_CREATES_PER_HOUR)
        }
    }
}

/// Whether an account may create another mask, given its limit (`u32::MAX`
/// or none for unlimited) and how many live masks it has. 0 turns creation
/// off (ME-14).
pub fn within_limit(limit: u32, live: u64) -> bool {
    limit == u32::MAX || live < limit as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_setting() {
        assert_eq!(parse_rate(None), Some(50));
        assert_eq!(parse_rate(Some("0")), None);
        assert_eq!(parse_rate(Some(" 10 ")), Some(10));
        assert_eq!(parse_rate(Some("lots")), Some(50));
    }

    #[test]
    fn limits() {
        // Acceptance test 9: a limit of 2 refuses the third, 0 refuses any
        assert!(within_limit(2, 1));
        assert!(!within_limit(2, 2));
        assert!(!within_limit(0, 0));
        assert!(within_limit(u32::MAX, 1_000_000));
    }
}
