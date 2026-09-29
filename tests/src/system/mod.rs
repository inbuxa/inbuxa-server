/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod antispam;
pub mod authentication;
pub mod ai;
pub mod ai_calibration;
pub mod ai_explain;
pub mod account_lock; // inbuxa: account lock with delegation
pub mod legal_hold; // inbuxa: legal hold
pub mod compliance; // inbuxa: the compliance roles
pub mod mail_rules; // inbuxa: DLP and mail flow rules
pub mod audit; // inbuxa: the audit log
pub mod authorization;
pub mod auto_reload; // inbuxa: registry writes apply at once
pub mod branding;
pub mod crypto;
pub mod delivery;
pub mod directory;
pub mod masked_email;
pub mod monitoring;
pub mod oidc;
pub mod purge;
pub mod quota;
pub mod reload; // inbuxa: reloads and build errors
pub mod security;
pub mod task;
pub mod tracer_reload; // inbuxa: tracers start over when their settings change
pub mod tenant;
pub mod undelete;

use crate::utils::server::TestServerBuilder;
use registry::schema::structs::{Expression, Imap, MtaStageAuth};

#[tokio::test(flavor = "multi_thread")]
pub async fn system_tests() {
    let mut test = TestServerBuilder::new("system_tests")
        .await
        .with_default_listeners()
        .await
        .with_object(Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
        .await
        .with_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;

    // Create admin account
    let admin = test
        .create_user_account(
            "admin",
            "admin@example.org",
            "these_pretzels_are_making_me_thirsty",
            &[],
            "Admin",
        )
        .await;
    test.account("admin")
        .assign_roles_to_account(admin.id(), &["user", "system"])
        .await;
    test.insert_account(admin);

    directory::test(&test).await;
    authentication::test(&test).await;
    oidc::test(&mut test).await;
    authorization::test(&mut test).await;
    tenant::test(&mut test).await;
    masked_email::test(&mut test).await;
    security::test(&mut test).await;
    quota::test(&mut test).await;
    purge::test(&mut test).await;
    delivery::test(&mut test).await;
    crypto::test(&mut test).await;
    antispam::test(&mut test).await;
    undelete::test(&mut test).await;
    task::test(&mut test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}
