/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Legal holds, the object itself (audit-hold-lock spec, LH-1, LH-3, LH-13,
//! AU-12): placing, widening and releasing a hold, and who may. What a hold
//! keeps is tested with the undelete hooks.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant, UserRoles},
};
use serde_json::{Value, json};

const USING: &[&str] = &["urn:ietf:params:jmap:core", "urn:inbuxa:jmap"];

impl Account {
    async fn hold_call(&self, method: &str, mut arguments: Value) -> (String, Value) {
        arguments["accountId"] = self.id_string().into();
        let response = self.jmap_request(USING, json!([[method, arguments, "0"]])).await;
        let call = response
            .0
            .pointer("/methodResponses/0")
            .cloned()
            .unwrap_or_else(|| panic!("{method}: {}", response.0));
        (call[0].as_str().unwrap_or_default().to_string(), call[1].clone())
    }

    async fn hold_set(&self, arguments: Value) -> Value {
        let (name, response) = self.hold_call("inbuxa:LegalHold/set", arguments).await;
        assert_eq!(name, "inbuxa:LegalHold/set", "{response}");
        response
    }

    async fn hold_get(&self, id: &str) -> Value {
        let (name, response) = self
            .hold_call("inbuxa:LegalHold/get", json!({"ids": [id]}))
            .await;
        assert_eq!(name, "inbuxa:LegalHold/get", "{response}");
        response["list"][0].clone()
    }
}

pub async fn test(test: &mut TestServer) {
    println!("Running legal hold tests...");
    let admin = test.account("admin@example.com");
    let custodian = admin
        .create_user_account("custodian@example.com", "custodian-secret-2201", "Custodian", &[], vec![])
        .await;
    let other = admin
        .create_user_account("other@example.com", "other-secret-7310", "Other", &[], vec![])
        .await;
    let custodian_id = custodian.id_string().to_string();
    let other_id = other.id_string().to_string();

    // AU-12: no hold without a reason; LH-1: nor without a name or a scope
    let response = admin
        .hold_set(json!({"create": {"h": {"name": "Matter 4411",
            "scope": {"accounts": [custodian_id]}}}}))
        .await;
    assert_eq!(response["notCreated"]["h"]["type"], "invalidProperties", "AU-12: {response}");
    let response = admin
        .hold_set(json!({"reason": "Counsel's letter", "create": {"h": {
            "scope": {"accounts": [custodian_id]}}}}))
        .await;
    assert_eq!(response["notCreated"]["h"]["type"], "invalidProperties", "LH-1 name: {response}");
    let response = admin
        .hold_set(json!({"reason": "Counsel's letter", "create": {"h": {
            "name": "Matter 4411", "scope": {}}}}))
        .await;
    assert_eq!(response["notCreated"]["h"]["type"], "invalidProperties", "LH-1 scope: {response}");
    let response = admin
        .hold_set(json!({"reason": "Counsel's letter", "create": {"h": {
            "name": "Matter 4411", "scope": {"accounts": ["zzzzzz"]}}}}))
        .await;
    assert_eq!(
        response["notCreated"]["h"]["type"], "invalidProperties",
        "LH-1 unknown account: {response}"
    );
    let response = admin
        .hold_set(json!({"reason": "Counsel's letter", "create": {"h": {
            "name": "Matter 4411",
            "from": "2026-06-30T00:00:00Z", "to": "2026-01-01T00:00:00Z",
            "scope": {"accounts": [custodian_id]}}}}))
        .await;
    assert_eq!(response["notCreated"]["h"]["type"], "invalidProperties", "LH-3 backwards: {response}");

    // LH-1: placed, with a reference and a range
    let response = admin
        .hold_set(json!({"create": {"h": {
            "name": "Matter 4411", "reference": "4411-A", "reason": "Counsel's letter",
            "from": "2026-01-01T00:00:00Z", "to": "2026-06-30T23:59:59Z",
            "scope": {"accounts": [custodian_id]}}}}))
        .await;
    let hold_id = response["created"]["h"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("LH-1: not placed: {response}"))
        .to_string();
    let hold = admin.hold_get(&hold_id).await;
    assert_eq!(hold["name"], "Matter 4411", "{hold}");
    assert_eq!(hold["reference"], "4411-A", "{hold}");
    assert_eq!(hold["scope"]["accounts"], json!([custodian_id]), "{hold}");
    assert_eq!(hold["from"], "2026-01-01T00:00:00Z", "{hold}");
    assert_eq!(hold["released"], false, "{hold}");
    assert!(hold["placedBy"].as_str().is_some_and(|by| by.contains("admin")), "{hold}");

    // AU-12: every later change needs a reason too
    let response = admin
        .hold_set(json!({"update": {hold_id.as_str(): {"name": "Renamed"}}}))
        .await;
    assert_eq!(
        response["notUpdated"][hold_id.as_str()]["type"], "invalidProperties",
        "AU-12: {response}"
    );

    // LH-3: narrowing is refused, widening is allowed
    let response = admin
        .hold_set(json!({"reason": "Narrow it", "update": {hold_id.as_str(): {
            "from": "2026-03-01T00:00:00Z"}}}))
        .await;
    assert_eq!(
        response["notUpdated"][hold_id.as_str()]["type"], "invalidProperties",
        "LH-3 narrowed: {response}"
    );
    let response = admin
        .hold_set(json!({"reason": "Counsel widened the matter", "update": {hold_id.as_str(): {
            "from": "2025-01-01T00:00:00Z", "to": null}}}))
        .await;
    assert!(response["updated"].get(hold_id.as_str()).is_some(), "LH-3 widened: {response}");
    let hold = admin.hold_get(&hold_id).await;
    assert_eq!(hold["from"], "2025-01-01T00:00:00Z", "{hold}");
    assert_eq!(hold["to"], Value::Null, "LH-3: an open end catches mail to come: {hold}");

    // The scope grows, and never shrinks
    let response = admin
        .hold_set(json!({"reason": "Second custodian", "update": {hold_id.as_str(): {
            "scope": {"accounts": [custodian_id, other_id]}}}}))
        .await;
    assert!(response["updated"].get(hold_id.as_str()).is_some(), "scope grown: {response}");
    let response = admin
        .hold_set(json!({"reason": "Drop one", "update": {hold_id.as_str(): {
            "scope": {"accounts": [other_id]}}}}))
        .await;
    assert_eq!(
        response["notUpdated"][hold_id.as_str()]["type"], "invalidProperties",
        "scope shrunk: {response}"
    );

    // LH-13: a hold is never deleted
    let response = admin
        .hold_set(json!({"reason": "Delete it", "destroy": [hold_id]}))
        .await;
    assert_eq!(
        response["notDestroyed"][hold_id.as_str()]["type"], "forbidden",
        "LH-13: {response}"
    );

    // LH-13: only server-level administrators see holds, never a plain user
    let (name, response) = custodian
        .hold_call("inbuxa:LegalHold/get", json!({"ids": null}))
        .await;
    assert_eq!(name, "error", "LH-13: a user read holds: {response}");

    // ... and never a tenant administrator, whatever its role says: a hold
    // may concern the tenant's own administrator
    let tenant = admin
        .registry_create_object(Tenant {
            name: "Hold tenant".to_string(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Domain {
            name: "tenant-hold.example.org".to_string(),
            is_enabled: true,
            member_tenant_id: Some(tenant),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    let t_admin = admin
        .create_user_account(
            "tadmin@tenant-hold.example.org",
            "tenant-admin-secret-6604",
            "Tenant admin",
            &[],
            vec![],
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            t_admin.id(),
            json!({Property::Roles: UserRoles::Admin}),
        )
        .await;
    let (name, response) = t_admin
        .hold_call("inbuxa:LegalHold/get", json!({"ids": null}))
        .await;
    assert_eq!(name, "error", "LH-13: a tenant administrator read holds: {response}");
    let (name, response) = t_admin
        .hold_call(
            "inbuxa:LegalHold/set",
            json!({"reason": "Mine", "create": {"h": {"name": "Tenant matter",
                "scope": {"accounts": [t_admin.id_string()]}}}}),
        )
        .await;
    assert_eq!(name, "error", "LH-13: a tenant administrator placed a hold: {response}");

    // Test 7, LH-2: a hold on a domain reaches an account created there
    // later, and keeps it by name when it moves to another domain
    let held_domain = admin
        .registry_create_object(Domain {
            name: "held.example.net".to_string(),
            is_enabled: true,
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    let elsewhere = admin
        .registry_create_object(Domain {
            name: "elsewhere.example.net".to_string(),
            is_enabled: true,
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    let response = admin
        .hold_set(json!({"reason": "Whole division", "create": {"d": {
            "name": "Matter 5120", "scope": {"domains": [held_domain.to_string()]}}}}))
        .await;
    let domain_hold = response["created"]["d"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("LH-1 domain hold: {response}"))
        .to_string();
    let mover = admin
        .create_user_account("mover@held.example.net", "mover-secret-8812", "Mover", &[], vec![])
        .await;
    assert_eq!(
        admin.hold_get(&domain_hold).await["scope"]["accounts"],
        json!([]),
        "LH-2: covered through the domain, not named yet"
    );
    admin
        .registry_update_object(
            ObjectType::Account,
            mover.id(),
            json!({Property::DomainId: elsewhere.to_string()}),
        )
        .await;
    assert_eq!(
        admin.hold_get(&domain_hold).await["scope"]["accounts"],
        json!([mover.id_string()]),
        "test 7, LH-2: the moved account escaped the hold"
    );

    // LH-10: release needs a reason, and a released hold stays, read-only
    let response = admin
        .hold_set(json!({"update": {hold_id.as_str(): {"released": true}}}))
        .await;
    assert_eq!(
        response["notUpdated"][hold_id.as_str()]["type"], "invalidProperties",
        "AU-12 release: {response}"
    );
    let response = admin
        .hold_set(json!({"reason": "Matter settled", "update": {hold_id.as_str(): {"released": true}}}))
        .await;
    assert!(response["updated"].get(hold_id.as_str()).is_some(), "LH-10: {response}");
    let hold = admin.hold_get(&hold_id).await;
    assert_eq!(hold["released"], true, "{hold}");
    assert_eq!(hold["releaseReason"], "Matter settled", "{hold}");
    assert!(hold["releasedAt"].is_string(), "{hold}");
    let response = admin
        .hold_set(json!({"reason": "Rename", "update": {hold_id.as_str(): {"name": "After"}}}))
        .await;
    assert_eq!(
        response["notUpdated"][hold_id.as_str()]["type"], "invalidProperties",
        "LH-1: a released hold changed: {response}"
    );
    let response = admin
        .hold_set(json!({"reason": "Undo", "update": {hold_id.as_str(): {"released": false}}}))
        .await;
    assert_eq!(
        response["notUpdated"][hold_id.as_str()]["type"], "invalidProperties",
        "LH-10: a released hold came back: {response}"
    );

    // AU-12: placing, widening and releasing are recorded with their reasons
    let (_, query) = admin
        .hold_call(
            "inbuxa:AuditEvent/query",
            json!({"filter": {"targetKind": "inbuxa:LegalHold"}}),
        )
        .await;
    let ids = query["ids"].clone();
    let (_, records) = admin
        .hold_call("inbuxa:AuditEvent/get", json!({"ids": ids}))
        .await;
    let reasons = records["list"]
        .as_array()
        .unwrap_or_else(|| panic!("AU-12: no records: {records}"))
        .iter()
        .filter_map(|r| r["reason"].as_str())
        .collect::<Vec<_>>();
    for reason in ["Counsel's letter", "Counsel widened the matter", "Matter settled"] {
        assert!(reasons.contains(&reason), "AU-12: {reason:?} not recorded: {reasons:?}");
    }
}

/// Runs these tests alone: `cargo test -p tests legal_hold_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn legal_hold_tests() {
    let mut test = TestServerBuilder::new("legal_hold_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.com").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
