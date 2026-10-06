/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
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
use registry::{
    schema::{
        enums::TracingLevel,
        prelude::ObjectType,
        structs::{
            AllowedIp, CertificateManagement, DkimManagement, DnsManagement, Domain, Expression,
            MtaDeliverySchedule, MtaStageAuth, MtaVirtualQueue, Tracer, TracerStdout,
        },
    },
    types::ipmask::IpAddrOrMask,
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
    // A burst of separate requests shares a reload or two: each arrives
    // tens of milliseconds after the last, so none overlaps a running
    // reload, and the reload waits for writes to settle instead
    let reloads = test.server.inner.data.settings_reload.reloads();
    let started = std::time::Instant::now();
    let burst = (0..10)
        .map(|i| format!("autoreload-burst-{i}"))
        .collect::<Vec<_>>();
    let mut writes = Vec::new();
    for name in &burst {
        writes.push(admin.registry_create([MtaDeliverySchedule {
            name: name.clone(),
            queue_id,
            ..Default::default()
        }]));
    }
    for response in futures::future::join_all(writes).await {
        assert_applied(&response);
        schedule_ids.push(response.created_id(0));
    }
    let burst_reloads = test.server.inner.data.settings_reload.reloads() - reloads;
    println!(
        "10 concurrent writes: {burst_reloads} reload(s), {} ms",
        started.elapsed().as_millis()
    );
    assert!(
        (1..=2).contains(&burst_reloads),
        "{burst_reloads} reloads for 10 concurrent writes"
    );
    for name in &burst {
        assert!(has_schedule(test, name), "{name} missing");
    }

    // A single write still reloads promptly
    let reloads = test.server.inner.data.settings_reload.reloads();
    let started = std::time::Instant::now();
    let response = admin
        .registry_create([MtaDeliverySchedule {
            name: "autoreload-single".into(),
            queue_id,
            ..Default::default()
        }])
        .await;
    assert_applied(&response);
    schedule_ids.push(response.created_id(0));
    println!("1 write: {} ms", started.elapsed().as_millis());
    assert_eq!(
        test.server.inner.data.settings_reload.reloads() - reloads,
        1
    );
    assert!(has_schedule(test, "autoreload-single"));

    // Several objects in one request: one reload
    let response = admin
        .registry_destroy(ObjectType::MtaDeliverySchedule, schedule_ids.iter())
        .await;
    assert_applied(&response);
    for name in names.iter().chain(&burst) {
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

    // An allowed IP is live as soon as it is saved, and gone once
    // destroyed. It lives in the core's security settings, which the
    // blocked-IP reload it used to get doesn't rebuild.
    let ip: std::net::IpAddr = "198.51.100.7".parse().unwrap();
    assert!(!is_allowed(test, ip));
    let response = admin
        .registry_create([AllowedIp {
            address: IpAddrOrMask::from_ip(ip),
            reason: Some("autoreload".into()),
            ..Default::default()
        }])
        .await;
    assert_applied(&response);
    assert!(
        is_allowed(test, ip),
        "allowed IP not in the running settings"
    );
    let allowed_id = response.created_id(0);
    let response = admin
        .registry_destroy(ObjectType::AllowedIp, [allowed_id])
        .await;
    assert_applied(&response);
    assert!(!is_allowed(test, ip), "destroyed allowed IP still live");

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

fn is_allowed(test: &TestServer, ip: std::net::IpAddr) -> bool {
    test.server.inner.build_server().is_ip_allowed(ip)
}
