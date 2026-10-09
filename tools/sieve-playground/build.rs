/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::fs;

fn main() {
    // The vendored crate the server builds, so the playground names the
    // interpreter version the server runs.
    println!("cargo:rerun-if-changed=../../vendor/sieve-rs/Cargo.toml");
    let manifest = fs::read_to_string("../../vendor/sieve-rs/Cargo.toml").unwrap_or_default();
    let mut version = "unknown".to_string();
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package
            && line.starts_with("version")
            && let Some(value) = line.split('=').nth(1)
        {
            version = value.trim().trim_matches('"').to_string();
            break;
        }
    }
    println!("cargo:rustc-env=SIEVE_VERSION={version}");
}
