/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod analyze;
pub mod dmarc;
pub mod reschedule; // inbuxa: report reschedules and unreadable queue rows
pub mod scheduler;
pub mod tls;
