/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! INBUXA's rebuilt features.
//!
//! Upstream ships these only in its Enterprise Edition. INBUXA rebuilds each
//! one clean-room from a written spec under `docs/spec/features/`, one module
//! per feature, and ships it to everybody (docs/spec/SPEC.md §2.3, §3).
//!
//! Upstream files change only by small hooks that call in here, each marked
//! with an `inbuxa:` comment naming the requirement it serves. That keeps
//! every upstream merge's conflicts few and predictable.
//!
//! This crate sits below `common`, so hooks anywhere in the server can call
//! it. It works on registry objects and the store directly, never on
//! `common::Server`.

pub mod ai;
pub mod audit;
pub mod branding;
pub mod lock;
pub mod masked_email;
pub mod security;
pub mod tenancy;
pub mod undelete;
