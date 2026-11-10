/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod dane;
pub mod extensions;
pub mod fallback_relay;
pub mod ip_lookup;
pub mod lmtp;
pub mod mta_sts;
pub mod per_sender_tls;
pub mod smtp;
pub mod throttle;
pub mod tls;
