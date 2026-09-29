/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Data loss prevention and mail flow rules (dlp-and-mail-flow-rules spec).
//!
//! Pure functions over text and attachment bytes, so everything here is
//! unit-tested without a server:
//!
//! - [`detectors`]: find identifiers in text (payment cards, IBANs,
//!   national ID numbers, keys), each by its published format and check
//!   (§2.3);
//! - [`words`]: an organization's own word lists and patterns;
//! - [`extract`]: the text of an attachment, or why it can't be read.
//!
//! Nothing here writes what it finds anywhere: callers get counts, and the
//! matched text never leaves the evaluation (§2.7).

pub mod detectors;
pub mod extract;
pub mod words;
