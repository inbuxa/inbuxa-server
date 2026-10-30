/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Key pins (RL-6, RL-7): the SHA-256 of a SubjectPublicKeyInfo. The pin is
//! the identity on the link; names in link certificates are never checked.

use aws_lc_rs::digest;

/// A pin: SHA-256 over a DER SubjectPublicKeyInfo.
pub type Pin = [u8; 32];

pub fn spki_pin(spki_der: &[u8]) -> Pin {
    let digest = digest::digest(&digest::SHA256, spki_der);
    let mut pin = [0u8; 32];
    pin.copy_from_slice(digest.as_ref());
    pin
}

/// Compares two pins in constant time.
pub fn pins_match(a: &Pin, b: &Pin) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}
