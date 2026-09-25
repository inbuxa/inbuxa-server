/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod broadcast;
pub mod live_roles; // inbuxa: role edits apply without a restart
#[cfg(feature = "nats")]
pub mod coordinator; // inbuxa: coordinator reconnects
pub mod stress;
pub mod task_roles; // inbuxa: task types follow cluster roles
