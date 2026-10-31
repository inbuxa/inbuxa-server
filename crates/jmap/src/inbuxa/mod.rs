/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! JMAP glue for INBUXA's rebuilt features. The features' rules live in
//! `crates/features`; this module only speaks JMAP for them.

pub mod access;
pub mod account_lock;
pub mod ai_limits;
pub mod audit;
pub mod audit_log;
pub mod data_inventory;
pub mod deleted_account;
pub mod deliverability; // inbuxa: the deliverability check
pub mod directory_test;
pub mod dlp_settings;
pub mod explanation;
pub mod fastmail;
pub mod front_ends;
pub mod held_message;
pub mod hold_export;
pub mod hold_export_api;
pub mod journal;
pub mod journal_entry;
pub mod legal_hold;
pub mod log_settings;
pub mod mail_rule;
pub mod masked_email;
pub mod masked_secrets; // inbuxa: "****" is never saved as a secret
pub mod migration; // inbuxa: migrations into this server
pub mod oidc_directory; // inbuxa: http-directory-services-13
pub mod protocol_policy;
pub mod relay; // inbuxa: inbuxa Relay
pub mod relay_message; // inbuxa: a relay's queues
pub mod scheduled_reports; // inbuxa: scheduled reports and the weekly digest
pub mod security_acceptance;
pub mod sharing_policy;
pub mod telemetry;
pub mod tenant_protocol_policy;
pub mod undelete;
pub mod webhook_test;
