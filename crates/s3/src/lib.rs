/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod client;
pub mod credentials;
pub mod delete;
pub mod endpoint;
pub mod error;
pub mod retry;
pub mod signer;

pub use client::{Bucket, BucketConfig};
pub use credentials::Credentials;
pub use delete::DeleteBatch;
pub use endpoint::{Endpoint, Scheme, UrlStyle};
pub use error::{Error, Result};
pub use retry::RetryPolicy;
