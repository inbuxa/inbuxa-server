/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

#![warn(clippy::large_futures)]

pub mod jmap;
pub mod pickle;
pub mod schema;
pub mod types;
pub mod utils;

#[cfg(test)]
mod inbuxa_tests;
