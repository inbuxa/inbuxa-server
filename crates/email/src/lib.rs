/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// inbuxa: composite stores (sharded members, read replicas) nest store
// futures deeply enough to pass rustc's default query depth
#![recursion_limit = "512"]

#![warn(clippy::large_futures)]

pub mod cache;
pub mod identity;
pub mod mailbox;
pub mod message;
pub mod push;
pub mod sieve;
pub mod submission;
