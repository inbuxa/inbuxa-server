/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod discovery;
pub mod integration;
pub mod ldap;
pub mod oidc; // inbuxa: rebuilt from the per-domain directories spec
#[cfg(feature = "sqlite")]
pub mod per_domain; // inbuxa: per-domain directories
#[cfg(feature = "sqlite")]
pub mod sql;
pub mod synchronization;
pub mod unavailable;
// inbuxa: upstream's issuer.rs (since v0.16.23) is left out. It tests routing a
// token that names no address by its issuer, which upstream ships in
// Enterprise; here such a token gets the server's default directory (DIR-2).

#[tokio::test(flavor = "multi_thread")]
pub async fn directory_tests() {
    ldap::test().await;
    oidc::test().await;
    unavailable::test().await;
    discovery::test().await;
    #[cfg(feature = "sqlite")]
    sql::test().await;
    synchronization::test().await;
    integration::test().await;
}
