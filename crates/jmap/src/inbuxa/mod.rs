/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! JMAP glue for INBUXA's rebuilt features. The features' rules live in
//! `crates/features`; this module only speaks JMAP for them.

pub mod access;
pub mod ai_limits;
pub mod deleted_account;
pub mod fastmail;
pub mod masked_email;
pub mod telemetry;
pub mod undelete;
