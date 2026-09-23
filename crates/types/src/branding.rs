/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The product's name, in one place.
//!
//! Every name the server shows people (protocol greetings, the HTTP sign-in
//! realm, the startup banner, calendar product ids, the name mail clients see
//! during setup) comes from here. That keeps the rebrand to a single file when
//! merging upstream releases, instead of a scattering of string edits.
//!
//! These are macros, not constants, so they can be joined into other string
//! literals at compile time with `concat!`.

/// The product name: `INBUXA`.
#[macro_export]
macro_rules! brand {
    () => {
        "inbuxa"
    };
}

/// The server's full name: `INBUXA Server`.
#[macro_export]
macro_rules! brand_server {
    () => {
        concat!($crate::brand!(), " Server")
    };
}

/// The iCalendar and vCard `PRODID`.
#[macro_export]
macro_rules! brand_prodid {
    () => {
        concat!("-//", $crate::brand!(), "//", $crate::brand_server!(), "//EN")
    };
}

/// The project's website, given to clients as the support URL (IMAP `ID`).
#[macro_export]
macro_rules! brand_url {
    () => {
        "https://inbuxa.org"
    };
}

/// Reads one of the server's environment variables by its unprefixed name,
/// such as `RECOVERY_ADMIN`, from `INBUXA_<name>`.
///
/// The upstream prefix isn't read (SPEC §2.4). An install moved over from
/// upstream that still sets it stops here with the variable to rename, rather
/// than starting on defaults the operator didn't choose.
pub fn env_var(name: &str) -> Result<String, std::env::VarError> {
    let found = std::env::var(format!("INBUXA_{name}"));
    if matches!(found, Err(std::env::VarError::NotPresent))
        && let Some(legacy) = legacy_setting(name, |var| std::env::var_os(var).is_some())
    {
        eprintln!(
            "Error: {legacy} is set, but inbuxa reads INBUXA_{name}. Rename it and start again \
             (https://docs.inbuxa.org/install/migrating/)."
        );
        std::process::exit(1);
    }
    found
}

/// The environment prefix upstream reads. Only ever used to refuse it.
const LEGACY_ENV_PREFIX: &str = "STALWART";

/// The upstream-prefixed variable for `name`, if it's set.
fn legacy_setting(name: &str, is_set: impl Fn(&str) -> bool) -> Option<String> {
    let legacy = format!("{LEGACY_ENV_PREFIX}_{name}");
    is_set(&legacy).then_some(legacy)
}

/// INBUXA's own version, dated like the rest of its family: `YYYY.M.D`, with
/// a letter or `.N` suffix for a second release on one day. It's set here and
/// not in Cargo.toml, so upstream's version bumps merge without conflicts.
#[macro_export]
macro_rules! brand_version {
    () => {
        "2026.9.24.2"
    };
}

/// The version with the Stalwart release it's built on, e.g.
/// `2026.9.20 (Stalwart 0.16.22)`. The base comes from Cargo, which follows
/// upstream, so it's always the base actually compiled in. It matters because
/// Stalwart's data upgrades are one-way. Once INBUXA stops tracking upstream,
/// this becomes just the version.
#[macro_export]
macro_rules! brand_version_full {
    // The upstream crate version, without naming the upstream project: this
    // string is user-visible (--version, the startup banner, the console,
    // telemetry and the JMAP session's "implementation" field), and the name
    // belongs only in copyright notices and the lineage line.
    () => {
        concat!($crate::brand_version!(), " (upstream ", env!("CARGO_PKG_VERSION"), ")")
    };
}

#[cfg(test)]
mod tests {
    use super::{LEGACY_ENV_PREFIX, legacy_setting};

    #[test]
    fn an_upstream_setting_is_named_for_renaming() {
        let old = format!("{LEGACY_ENV_PREFIX}_RECOVERY_ADMIN");
        let set = |var: &str| var == old;
        assert_eq!(legacy_setting("RECOVERY_ADMIN", set), Some(old.clone()));
        assert_eq!(legacy_setting("HOSTNAME", set), None);
    }
}
