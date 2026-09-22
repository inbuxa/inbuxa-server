/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Security hardening INBUXA adds of its own.
//!
//! Unlike the rest of this crate, these are not rebuilds of anything upstream
//! ships. The legacy-protocols switch is INBUXA's own design, specified in
//! `legacy-protocols.md`.

pub mod legacy_use;
pub mod listeners;
pub mod protocol_policy;
pub mod tenant_protocol_policy;
