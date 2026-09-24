/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// inbuxa: a registry write to an object the running settings are built from
// applies without an x:Action ReloadSettings, and the set response says so.

use crate::utils::{
    jmap::JmapResponse,
    server::{TestServer, TestServerBuilder},
};
use common::BuildServer;
use registry::schema::{
    enums::TracingLevel,
    prelude::ObjectType,
    structs::{
        CertificateManagement, DkimManagement, DnsManagement, Domain, Expression,
        MtaDeliverySchedule, MtaStageAuth, MtaVirtualQueue, Tracer, TracerStdout,
    },
};
use serde_json::Value;

#[tokio::test(flavor = "multi_thread")]
pub async fn settings_reload_tests() {
    let mut test = TestServerBuilder::new("settings_reload_tests")
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

    test_write_applies(&test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

async fn test_write_applies(test: &TestServer) {
    println!("Running settings reload after registry writes...");
    let admin = test.account("admin@example.org");

    // A delivery schedule is in use as soon as it is saved
    let response = admin
        .registry_create([MtaVirtualQueue {
            name: "autorld".into(),
            threads_per_node: 2,
            description: None,
        }])
        .await;
    assert_applied(&response);
    let queue_id = response.created_id(0);
    assert!(!has_schedule(test, "autoreload-schedule"));
    let response = admin
        .registry_create([MtaDeliverySchedule {
            name: "autoreload-schedule".into(),
            queue_id,
            ..Default::default()
        }])
        .await;
    assert_applied(&response);
    assert!(has_schedule(test, "autoreload-schedule"));

    // Destroyed, it's gone at once too
    let schedule_id = response.created_id(0);
    let response = admin
        .registry_destroy(ObjectType::MtaDeliverySchedule, [schedule_id])
        .await;
    assert_applied(&response);
    assert!(!has_schedule(test, "autoreload-schedule"));

    // Concurrent writes all end up in the running settings
    let names = (0..8)
        .map(|i| format!("autoreload-{i}"))
        .collect::<Vec<_>>();
    let mut writes = Vec::new();
    for name in &names {
        writes.push(admin.registry_create([MtaDeliverySchedule {
            name: name.clone(),
            queue_id,
            ..Default::default()
        }]));
    }
    let mut schedule_ids = Vec::new();
    for response in futures::future::join_all(writes).await {
        assert_applied(&response);
        schedule_ids.push(response.created_id(0));
    }
    for name in &names {
        assert!(has_schedule(test, name), "{name} missing");
    }
    // Several objects in one request: one reload
    let response = admin
        .registry_destroy(ObjectType::MtaDeliverySchedule, schedule_ids.iter())
        .await;
    assert_applied(&response);
    for name in &names {
        assert!(!has_schedule(test, name), "{name} still present");
    }

    // A write whose reload fails is stored, and the response says the
    // settings weren't reloaded: only one console tracer is allowed.
    let response = admin
        .registry_create([
            Tracer::Stdout(TracerStdout {
                enable: true,
                level: TracingLevel::Error,
                ..Default::default()
            }),
            Tracer::Stdout(TracerStdout {
                enable: true,
                level: TracingLevel::Error,
                ..Default::default()
            }),
        ])
        .await;
    let reload = settings_reload(&response).expect("x:settingsReload missing");
    assert_eq!(reload["applied"], Value::Bool(false), "{response:?}");
    let description = reload["description"].as_str().unwrap_or_default();
    assert!(
        description.starts_with("Saved, but the running settings were not reloaded. ")
            && description.contains("Only one console tracer is allowed"),
        "{description}"
    );
    let tracer_ids = [response.created_id(0), response.created_id(1)];
    let response = admin
        .registry_destroy(ObjectType::Tracer, tracer_ids.iter())
        .await;
    assert_applied(&response);

    // Data that isn't part of the running settings doesn't reload them
    let response = admin
        .registry_create([Domain {
            name: "autoreload.example.org".into(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        }])
        .await;
    assert!(settings_reload(&response).is_none(), "{response:?}");
}

fn settings_reload(response: &JmapResponse) -> Option<&Value> {
    response.pointer("/methodResponses/0/1/x:settingsReload")
}

fn assert_applied(response: &JmapResponse) {
    assert_eq!(
        settings_reload(response),
        Some(&serde_json::json!({"applied": true})),
        "{response:?}"
    );
}

fn has_schedule(test: &TestServer, name: &str) -> bool {
    test.server
        .inner
        .build_server()
        .core
        .smtp
        .queue
        .queue_strategy
        .contains_key(name)
}
