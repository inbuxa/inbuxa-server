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
        "INBUXA"
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
/// such as `RECOVERY_ADMIN`.
///
/// `INBUXA_<name>` wins. `STALWART_<name>` is still read when the new name
/// isn't set, so an existing Stalwart install moves over without editing its
/// environment, and a warning says which variable to rename.
pub fn env_var(name: &str) -> Result<String, std::env::VarError> {
    match std::env::var(format!("INBUXA_{name}")) {
        Err(std::env::VarError::NotPresent) => {
            let legacy = std::env::var(format!("STALWART_{name}"));
            if legacy.is_ok() {
                eprintln!("Warning: STALWART_{name} is deprecated; set INBUXA_{name} instead.");
            }
            legacy
        }
        found => found,
    }
}

/// INBUXA's own version, dated like the rest of its family: `YYYY.M.D`, with
/// a letter or `.N` suffix for a second release on one day. It's set here and
/// not in Cargo.toml, so upstream's version bumps merge without conflicts.
#[macro_export]
macro_rules! brand_version {
    () => {
        "2026.9.23"
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
