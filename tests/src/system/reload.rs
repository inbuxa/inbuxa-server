/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// inbuxa: a settings reload isn't held back by a DNS lookup, or by objects
// that already failed when the running settings were built; an error in an
// object that built then still refuses it, and says which object.

use crate::utils::server::{TestServer, TestServerBuilder};
use common::{BuildServer, config::mailstore::spamfilter::PyzorConfig, ipc::RegistryChange};
use registry::schema::{
    enums::TracingLevel,
    prelude::{ObjectType, Property},
    structs::{Action, Expression, MtaStageAuth, SpamPyzor, Tracer, TracerStdout},
};

#[tokio::test(flavor = "multi_thread")]
pub async fn reload_tests() {
    let mut test = TestServerBuilder::new("reload_tests")
        .await
        .with_default_listeners()
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

    test_unresolvable_pyzor(&test).await;
    test_build_errors(&test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

async fn test_unresolvable_pyzor(test: &TestServer) {
    println!("Running reload with an unresolvable Pyzor host...");
    let admin = test.account("admin@example.org");

    // Upstream resolved the host while building the settings and refused the
    // reload when that failed.
    admin
        .registry_update_setting(
            SpamPyzor {
                enable: true,
                host: "pyzor.invalid".into(),
                port: 24441,
                ..Default::default()
            },
            &[Property::Enable, Property::Host, Property::Port],
        )
        .await;
    admin.reload_settings().await;

    let pyzor = running_pyzor(test);
    assert_eq!(pyzor.host, "pyzor.invalid");
    assert_eq!(pyzor.port, 24441);
    assert!(pyzor.address().await.is_err());

    // An IP address needs no lookup
    admin
        .registry_update_setting(
            SpamPyzor {
                host: "192.0.2.1".into(),
                ..Default::default()
            },
            &[Property::Host],
        )
        .await;
    admin.reload_settings().await;
    assert_eq!(
        running_pyzor(test).address().await.unwrap().to_string(),
        "192.0.2.1:24441"
    );
}

async fn test_build_errors(test: &TestServer) {
    println!("Running reload with build errors...");
    let admin = test.account("admin@example.org");
    let pyzor_ratio = running_pyzor(test).ratio;
    assert_ne!(pyzor_ratio, 0.25);

    // Two console tracers: only one is allowed, so the build of one of them
    // fails. Neither existed when the running settings were built.
    let mut tracer_ids = Vec::new();
    for _ in 0..2 {
        tracer_ids.push(
            admin
                .registry_create_object(Tracer::Stdout(TracerStdout {
                    enable: true,
                    level: TracingLevel::Error,
                    ..Default::default()
                }))
                .await,
        );
    }
    admin
        .registry_update_setting(
            SpamPyzor {
                ratio: 0.25.into(),
                ..Default::default()
            },
            &[Property::Ratio],
        )
        .await;

    // A new error refuses the reload and names the object
    let err = admin
        .registry_create_object_expect_err(Action::ReloadSettings)
        .await;
    let description = err.description.clone().unwrap_or_default();
    assert!(
        description.starts_with("Settings were not reloaded. ")
            && description.contains("Tracer")
            && description.contains("Only one console tracer is allowed"),
        "{err:?}"
    );
    assert_eq!(running_pyzor(test).ratio, pyzor_ratio);

    // Had the running settings been built with that tracer failing, as a
    // restart now would, the same error doesn't hold the reload back.
    let result = Box::pin(
        test.server
            .reload_registry(RegistryChange::Reload(ObjectType::DataStore)),
    )
    .await
    .unwrap();
    assert!(!result.replaced_core);
    assert_eq!(result.errors.len(), 1, "{:?}", result.errors);
    test.server.record_build_errors(&result.errors);

    admin.reload_settings().await;
    assert_eq!(running_pyzor(test).ratio, 0.25);
    let result = Box::pin(
        test.server
            .reload_registry(RegistryChange::Reload(ObjectType::DataStore)),
    )
    .await
    .unwrap();
    assert!(result.replaced_core);
    assert!(result.errors.is_empty());
    assert_eq!(result.known_errors.len(), 1);

    // Once fixed, the object is no longer known to fail, so a new error
    // there refuses the reload again.
    admin
        .registry_destroy(ObjectType::Tracer, tracer_ids.iter())
        .await
        .assert_destroyed(&tracer_ids);
    admin.reload_settings().await;
    let result = Box::pin(
        test.server
            .reload_registry(RegistryChange::Reload(ObjectType::DataStore)),
    )
    .await
    .unwrap();
    assert!(result.replaced_core);
    assert!(result.errors.is_empty() && result.known_errors.is_empty());

    for _ in 0..2 {
        tracer_ids.push(
            admin
                .registry_create_object(Tracer::Stdout(TracerStdout {
                    enable: true,
                    level: TracingLevel::Error,
                    ..Default::default()
                }))
                .await,
        );
    }
    admin
        .registry_create_object_expect_err(Action::ReloadSettings)
        .await;
    let tracer_ids = tracer_ids.split_off(2);
    admin
        .registry_destroy(ObjectType::Tracer, tracer_ids.iter())
        .await
        .assert_destroyed(&tracer_ids);
    admin.reload_settings().await;
}

fn running_pyzor(test: &TestServer) -> PyzorConfig {
    test.server
        .inner
        .build_server()
        .core
        .spam
        .pyzor
        .clone()
        .expect("Pyzor enabled")
}
