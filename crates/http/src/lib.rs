/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

pub mod api;
pub mod auth;
pub mod branding; // inbuxa: branding
pub mod form;
pub mod live; // inbuxa: monitoring (MON-20 to MON-24)
pub mod request;
pub mod scim; // inbuxa: SCIM 2.0 provisioning

use common::Inner;
use std::sync::Arc;

#[derive(Clone)]
pub struct HttpSessionManager {
    pub inner: Arc<Inner>,
}

impl HttpSessionManager {
    pub fn new(inner: Arc<Inner>) -> Self {
        Self { inner }
    }
}
