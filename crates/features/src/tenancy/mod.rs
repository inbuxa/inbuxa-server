/*
 * SPDX-FileCopyrightText: 2026 John Coffey
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Multi-tenancy, built from `docs/spec/features/multi-tenancy.md`.
//!
//! A tenant is a separate organization on one server. Its people reach only
//! its own objects, hold at most the permissions it allows, and create only
//! as much as its limits let them. The requirement each piece serves is named
//! as `MT-n`, after the spec.

pub mod ceiling;
pub mod domain_move;
pub mod links;
pub mod logo;
pub mod members;
pub mod queue;
pub mod quota;
pub mod reach;
pub mod writes;
