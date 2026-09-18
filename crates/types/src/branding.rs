/*
 * SPDX-FileCopyrightText: 2026 John Coffey
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
