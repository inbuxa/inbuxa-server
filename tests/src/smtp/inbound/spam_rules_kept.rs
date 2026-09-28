/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A spam rules update brings unedited rules up to date and leaves an admin's
//! edits alone (common::manager::spam_rules), including on an install whose
//! rules were loaded before updates fingerprinted what they wrote. Each
//! update records what it replaced and what it kept in one audit record
//! (AU-1.10).

use crate::utils::server::{TestServer, TestServerBuilder};
use registry::{
    schema::{
        enums::TaskSpamFilterMaintenanceType,
        prelude::ObjectType,
        structs::{SpamRule, SpamSettings, Task, TaskSpamFilterMaintenance, TaskStatus},
    },
    types::ObjectImpl,
};
use serde_json::{Value, json};
use std::fs;

const USING: &[&str] = &["urn:ietf:params:jmap:core", "urn:inbuxa:jmap"];

#[tokio::test(flavor = "multi_thread")]
async fn spam_rules_keep_admin_edits() {
    let test = TestServerBuilder::new("spam_rules_kept_test")
        .await
        .with_http_listener(19059)
        .await
        .build()
        .await;
    let admin = test.account("admin");
    let rules_path = test.temp_dir.path.join("spam-filter-rules.json");
    admin
        .registry_create_object(SpamSettings {
            spam_filter_rules_url: format!("file://{}", rules_path.display()).into(),
            ..Default::default()
        })
        .await;

    // Two rules an admin made before any update ran: one exactly as the
    // release has it, as an install from before fingerprints would, and one
    // different from it, as an edited one would be.
    admin.registry_create_object(rule("INBX_PRESET", 500)).await;
    admin
        .registry_create_object(rule("INBX_PRESET_EDITED", 300))
        .await;
    admin.reload_settings().await;

    update_rules(&test, &release(500)).await;
    assert_eq!(priority(&test, "INBX_UNTOUCHED").await, 500);
    assert_eq!(priority(&test, "INBX_PRESET_EDITED").await, 300);

    // An admin edits one rule the update wrote, and switches another off.
    let edited = id_of(&test, "INBX_EDITED").await;
    admin
        .registry_update_object(ObjectType::SpamRule, edited, json!({"priority": 300}))
        .await;
    let switched_off = id_of(&test, "INBX_SWITCHED_OFF").await;
    admin
        .registry_update_object(ObjectType::SpamRule, switched_off, json!({"enable": false}))
        .await;

    for run in 0..2 {
        update_rules(&test, &release(400)).await;

        for (name, expected) in [
            ("INBX_UNTOUCHED", 400),
            ("INBX_SWITCHED_OFF", 400),
            ("INBX_PRESET", 400),
            ("INBX_EDITED", 300),
            ("INBX_PRESET_EDITED", 300),
        ] {
            assert_eq!(priority(&test, name).await, expected, "{name}, run {run}");
        }
        assert!(
            !stored(&test, "INBX_SWITCHED_OFF").await.enable(),
            "run {run}: switching a rule off was undone"
        );
    }

    // Two updates changed something: the first and the first of release 400.
    // The second run of 400 changed nothing, so it isn't recorded.
    let records = audit(&test, json!({"targetKind": "x:SpamRule"})).await;
    let details = records
        .iter()
        .filter_map(|record| record["details"].as_str())
        .filter(|details| details.starts_with("Rules update"))
        .collect::<Vec<_>>();
    assert_eq!(details.len(), 2, "{details:?}");
    assert!(
        details[0].contains("replaced 3 SpamRule")
            && details[0].contains("kept as edited locally 2 SpamRule"),
        "{}",
        details[0]
    );
    assert!(details[1].contains("added 3 SpamRule"), "{}", details[1]);
}

fn rule(name: &str, priority: i64) -> SpamRule {
    serde_json::from_value(rule_json(name, priority)).unwrap()
}

fn rule_json(name: &str, priority: i64) -> Value {
    json!({
        "@type": "Any",
        "name": name,
        "enable": true,
        "priority": priority,
        "condition": {"else": "false", "match": {"0": {"if": "$MISSING_ESSENTIAL_HEADERS && $SINGLE_SHORT_PART", "then": "'SHORT_PART_BAD_HEADERS'"}}}
    })
}

fn release(priority: i64) -> Value {
    let rules = [
        "INBX_UNTOUCHED",
        "INBX_EDITED",
        "INBX_SWITCHED_OFF",
        "INBX_PRESET",
        "INBX_PRESET_EDITED",
    ]
    .into_iter()
    .map(|name| rule_json(name, priority))
    .collect::<Vec<_>>();
    json!({ "SpamRule": rules })
}

async fn update_rules(test: &TestServer, rules: &Value) {
    fs::write(
        test.temp_dir.path.join("spam-filter-rules.json"),
        rules.to_string(),
    )
    .unwrap();
    test.account("admin")
        .registry_create_object(Task::SpamFilterMaintenance(TaskSpamFilterMaintenance {
            maintenance_type: TaskSpamFilterMaintenanceType::UpdateRules,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
}

async fn stored(test: &TestServer, name: &str) -> SpamRule {
    test.server
        .registry()
        .list::<SpamRule>()
        .await
        .unwrap()
        .into_iter()
        .find(|item| object_json(&item.object)["name"] == name)
        .unwrap_or_else(|| panic!("no rule {name}"))
        .object
}

async fn id_of(test: &TestServer, name: &str) -> types::id::Id {
    test.server
        .registry()
        .list::<SpamRule>()
        .await
        .unwrap()
        .into_iter()
        .find(|item| object_json(&item.object)["name"] == name)
        .unwrap_or_else(|| panic!("no rule {name}"))
        .id
        .id()
}

async fn priority(test: &TestServer, name: &str) -> i64 {
    object_json(&stored(test, name).await)["priority"]
        .as_i64()
        .unwrap()
}

fn object_json<T: ObjectImpl>(object: &T) -> Value {
    serde_json::to_value(object).unwrap()
}

/// Audit records matching `filter`, newest first.
async fn audit(test: &TestServer, filter: Value) -> Vec<Value> {
    let admin = test.account("admin");
    let response = admin
        .jmap_request(
            USING,
            json!([
                ["inbuxa:AuditEvent/query", {
                    "accountId": admin.id_string(), "filter": filter, "limit": 100
                }, "q"],
                ["inbuxa:AuditEvent/get", {
                    "accountId": admin.id_string(),
                    "#ids": {"resultOf": "q", "name": "inbuxa:AuditEvent/query", "path": "/ids"}
                }, "g"]
            ]),
        )
        .await;
    response
        .0
        .pointer("/methodResponses/1/1/list")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| panic!("audit query failed: {}", response.0))
}
