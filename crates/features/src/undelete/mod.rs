/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Undelete, built from `docs/spec/features/undelete.md`.
//!
//! With `x:DataRetention.archiveDeletedItemsFor` set, a permanently deleted
//! item is kept for that long and can be restored. Upstream's `x:ArchivedItem`
//! record and the kept copy (a blob held by a temporary link until
//! `archivedUntil`) stay exactly as upstream writes them. What restore needs
//! beyond them, and the fork's bookkeeping, live in the fork's own subspace
//! (`data`). Requirements are named `UD-n`, after the spec.

pub mod accounts;
pub mod data;
pub mod email;
pub mod groupware;
pub mod records;
pub mod settings;
