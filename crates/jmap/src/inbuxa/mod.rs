/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! JMAP glue for INBUXA's rebuilt features. The features' rules live in
//! `crates/features`; this module only speaks JMAP for them.

pub mod access;
pub mod account_lock;
pub mod legal_hold;
pub mod mail_rule;
pub mod security_acceptance;
pub mod deliverability; // inbuxa: the deliverability check
pub mod journal;
pub mod journal_entry;
pub mod held_message;
pub mod dlp_settings;
pub mod hold_export;
pub mod hold_export_api;
pub mod audit;
pub mod audit_log;
pub mod ai_limits;
pub mod log_settings;
pub mod data_inventory;
pub mod directory_test;
pub mod webhook_test;
pub mod explanation;
pub mod protocol_policy;
pub mod tenant_protocol_policy;
pub mod sharing_policy;
pub mod deleted_account;
pub mod fastmail;
pub mod masked_email;
pub mod telemetry;
pub mod undelete;
