/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The audit log (audit-hold-lock spec, AU-1 to AU-11): a permanent record
//! of what administrators and the server itself did to the control plane,
//! kept in the fork's own subspace as one hash chain per node.
//!
//! - `record`: what one entry says.
//! - `log`: appending to the chain, reading, querying, purging, verifying.
//! - `scope`: who is acting, carried with the task, so a registry write the
//!   server makes on its own is told apart from one a request made.
//! - `diff`: what changed in a registry object, with secrets redacted.

pub mod diff;
pub mod log;
pub mod record;
pub mod scope;

pub use log::{AuditLog, EntryId};
pub use record::{Action, Actor, Change, Outcome, Record, Target, Via};
