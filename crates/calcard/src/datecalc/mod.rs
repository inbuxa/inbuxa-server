/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

//! Recurrence rule expansion.
//!
//! The engine in [`recurrence`] is a port of the one in
//! [`bttf`](https://github.com/BurntSushi/bttf) by Andrew Gallant; see that
//! module for what was changed. [`rrule`] adapts a parsed `RRULE` property
//! onto it.

pub mod error;
pub mod recurrence;
pub mod rrule;
mod weekdate;

pub use recurrence::{MAX_ITER_LOOP, MAX_UNPRODUCTIVE_WORK, RecurrenceIter};
pub use rrule::RRule;
