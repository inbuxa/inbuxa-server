/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Masked email, built from `docs/spec/features/masked-email.md`.
//!
//! A masked address is a disposable address that delivers to one account.
//! Upstream's `x:MaskedEmail` record stays exactly as upstream writes it. What
//! the fork adds (the one state both APIs share, when mail last arrived, the
//! address index delivery uses, tombstones and the change log) lives beside
//! it in the fork's own subspace (`data`). Requirements are named `ME-n`,
//! after the spec.

pub mod address;
pub mod data;
pub mod ops;
pub mod policy;
pub mod state;

pub use state::State;
