/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa's version as people see it, worked out from the Cargo one.
//!
//! Cargo needs three numbers (`27.1.0`, `27.1.0-rc.1`); tags, images and
//! `--version` name a series without its `.0` (`27.1`, `27.1-rc.1`).
//! tools/release/version.py does the same mapping for the release workflows,
//! and its tests use the same cases as the ones here.

/// `27.1.0` -> `27.1`, `27.1.3` -> `27.1.3`, `27.1.0-rc.1` -> `27.1-rc.1`.
/// Anything else is refused, so a version nobody planned for fails the build
/// rather than reaching a tag.
pub fn display(cargo: &str) -> Result<String, String> {
    let (core, pre) = match cargo.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (cargo, None),
    };
    let parts = core.split('.').collect::<Vec<_>>();
    let is_number = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'))
    };
    if parts.len() != 3 || !parts.iter().all(|part| is_number(part)) {
        return Err(format!("{cargo:?} is not YY.M.N"));
    }
    // A two-digit year and a month: 2026.10.28 is the old dated scheme.
    let (year, month) = (parts[0].parse::<u32>(), parts[1].parse::<u32>());
    if !matches!((year, month), (Ok(10..=99), Ok(1..=12))) {
        return Err(format!(
            "{cargo:?}: the series is a two-digit year and a month, as in 27.1"
        ));
    }
    let series = format!("{}.{}", parts[0], parts[1]);
    match pre {
        None if parts[2] == "0" => Ok(series),
        None => Ok(format!("{series}.{}", parts[2])),
        Some(pre)
            if parts[2] == "0"
                && pre
                    .strip_prefix("rc.")
                    .is_some_and(|n| is_number(n) && n != "0") =>
        {
            Ok(format!("{series}-{pre}"))
        }
        Some(_) => Err(format!(
            "{cargo:?}: the only pre-release is a series' rc.N, as in 27.1.0-rc.1"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::display;

    #[test]
    fn display_versions() {
        for (cargo, shown) in [
            ("27.1.0", "27.1"),
            ("27.1.3", "27.1.3"),
            ("27.1.0-rc.1", "27.1-rc.1"),
            ("27.7.0-rc.12", "27.7-rc.12"),
            ("28.1.10", "28.1.10"),
        ] {
            assert_eq!(display(cargo).as_deref(), Ok(shown), "{cargo}");
        }
        for cargo in [
            "27.1",
            "27.1.0.1",
            "27.1.1-rc.1",
            "27.1.0-rc.0",
            "27.1.0-beta.1",
            "27.01.0",
            "2026.10.28.1",
            "2026.11.2",
            "27.13.0",
            "",
        ] {
            assert!(display(cargo).is_err(), "{cargo}");
        }
    }
}
