/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod lookup;

#[derive(Debug)]
pub enum Error {
    Dns(mail_auth::Error),
    Http(reqwest::Error),
    InvalidPolicy(String),
}
