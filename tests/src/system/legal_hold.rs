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
    structs::{
        CertificateManagement, DataRetention, DkimManagement, DnsManagement, Domain, Tenant,
        UserRoles,
    },
};
use serde_json::{Value, json};
use types::id::Id;

const INBOX_ID: u32 = 0;

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:mail",
    "urn:ietf:params:jmap:contacts",
    "urn:inbuxa:jmap",
];

impl Account {
    async fn hold_call(&self, method: &str, mut arguments: Value) -> (String, Value) {
        if arguments.get("accountId").is_none() {
            arguments["accountId"] = self.id_string().into();
        }
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

    async fn archived_items(&self) -> Vec<Value> {
        let (_, response) = self
            .hold_call("x:ArchivedItem/get", json!({"ids": null}))
            .await;
        response["list"].as_array().cloned().unwrap_or_default()
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

    // Test 6, LH-4: what a hold keeps, with undelete switched off, so only
    // the hold can be keeping anything
    admin
        .registry_update_setting(
            DataRetention {
                archive_deleted_items_for: None,
                ..Default::default()
            },
            &[Property::ArchiveDeletedItemsFor],
        )
        .await;
    let held = admin
        .create_user_account("held@example.com", "held-secret-4419", "Held", &[], vec![])
        .await;
    let ranged = admin
        .create_user_account("ranged@example.com", "ranged-secret-5530", "Ranged", &[], vec![])
        .await;
    let response = admin
        .hold_set(json!({"reason": "Preserve everything", "create": {
            "w": {"name": "Matter 6001", "scope": {"accounts": [held.id_string()]}},
            "r": {"name": "Matter 6002", "from": "2020-01-01T00:00:00Z", "to": "2020-12-31T23:59:59Z",
                  "scope": {"accounts": [ranged.id_string()]}}}}))
        .await;
    let whole_hold = response["created"]["w"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("LH-1: {response}"))
        .to_string();
    assert!(response["created"]["r"]["id"].is_string(), "LH-1: {response}");

    let held_client = held.jmap_client().await;
    let ranged_client = ranged.jmap_client().await;
    let whole = import(&held_client, "Held whole", None).await;
    held_client.email_destroy(&whole).await.unwrap();
    // 2020-03-15: inside the range; now: outside it
    let inside = import(&ranged_client, "Inside the range", Some(1_584_230_400)).await;
    let outside = import(&ranged_client, "Outside the range", None).await;
    ranged_client.email_destroy(&inside).await.unwrap();
    ranged_client.email_destroy(&outside).await.unwrap();

    // LH-3: a contact is held whole, whatever the range
    let (_, books) = ranged
        .hold_call("AddressBook/get", json!({"ids": null}))
        .await;
    let book = books["list"][0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no address book: {books}"))
        .to_string();
    {
        let (_, created) = ranged
            .hold_call(
                "ContactCard/set",
                json!({"create": {"c": {"addressBookIds": {book: true},
                    "name": {"full": "Kept Contact"}}}}),
            )
            .await;
        let card = created["created"]["c"]["id"].as_str().unwrap_or_default().to_string();
        let (_, destroyed) = ranged
            .hold_call("ContactCard/set", json!({"destroy": [card]}))
            .await;
        assert!(destroyed["destroyed"][0].is_string(), "{destroyed}");
    }
    test.wait_for_tasks().await;

    let is_held = |item: &Value| item["archivedUntil"].as_str().is_some_and(|u| u.starts_with("9999-"));
    let kept = held.archived_items().await;
    assert!(
        kept.iter().any(|i| i["subject"] == "Held whole" && is_held(i)),
        "test 6, LH-4: a held account's mail wasn't kept: {kept:?}"
    );
    let kept = ranged.archived_items().await;
    assert!(
        kept.iter().any(|i| i["subject"] == "Inside the range" && is_held(i)),
        "LH-3: mail inside the range wasn't kept: {kept:?}"
    );
    assert!(
        !kept.iter().any(|i| i["subject"] == "Outside the range"),
        "LH-3: mail outside the range was kept, with undelete off: {kept:?}"
    );
    assert!(
        kept.iter().any(|i| i["name"] == "Kept Contact" && is_held(i)),
        "LH-3: a contact wasn't kept whole: {kept:?}"
    );

    // LH-6: placing a hold freezes what's already archived; LH-7: frozen
    // items can't be destroyed; LH-11: releasing one hold of two frees
    // nothing; LH-10: releasing the last gives a real deadline back
    admin
        .registry_update_setting(
            DataRetention {
                archive_deleted_items_for: Some(registry::schema::prelude::Duration(
                    std::time::Duration::from_secs(30 * 86_400),
                )),
                ..Default::default()
            },
            &[Property::ArchiveDeletedItemsFor],
        )
        .await;
    let frozen = admin
        .create_user_account("frozen@example.com", "frozen-secret-9031", "Frozen", &[], vec![])
        .await;
    let frozen_client = frozen.jmap_client().await;
    let doomed = import(&frozen_client, "Deleted before the hold", None).await;
    frozen_client.email_destroy(&doomed).await.unwrap();
    test.wait_for_tasks().await;
    let archived = |items: Vec<Value>| {
        items
            .into_iter()
            .find(|i| i["subject"] == "Deleted before the hold")
            .unwrap_or_else(|| panic!("not archived"))
    };
    let item = archived(frozen.archived_items().await);
    assert!(!is_held(&item), "undelete's 30 days first: {item}");
    let item_id = item["id"].as_str().unwrap().to_string();

    let response = admin
        .hold_set(json!({"reason": "First matter", "create": {
            "a": {"name": "Matter 7001", "scope": {"accounts": [frozen.id_string()]}},
            "b": {"name": "Matter 7002", "scope": {"accounts": [frozen.id_string()]}}}}))
        .await;
    let first = response["created"]["a"]["id"].as_str().unwrap().to_string();
    let second = response["created"]["b"]["id"].as_str().unwrap().to_string();
    assert!(
        is_held(&archived(frozen.archived_items().await)),
        "test 6, LH-6: the archived item wasn't frozen"
    );
    // LH-9: what the hold keeps, for the console
    let (_, response) = admin
        .hold_call(
            "inbuxa:LegalHold/get",
            json!({"ids": [first], "properties": ["accountsCovered", "itemsHeld", "sizeHeld"]}),
        )
        .await;
    let summary = &response["list"][0];
    assert_eq!(summary["accountsCovered"], 1, "LH-9: {response}");
    assert_eq!(summary["itemsHeld"], 1, "LH-9: {response}");
    assert!(summary["sizeHeld"].as_u64().is_some_and(|s| s > 0), "LH-9: {response}");
    // LH-14: the holds on one account, for the console's Held badge
    let (_, response) = admin
        .hold_call(
            "inbuxa:LegalHold/get",
            json!({"coveringAccount": frozen.id_string(), "properties": ["name"]}),
        )
        .await;
    let mut names = response["list"]
        .as_array()
        .map(|l| l.iter().filter_map(|h| h["name"].as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    names.sort_unstable();
    assert_eq!(names, vec!["Matter 7001", "Matter 7002"], "LH-14: {response}");

    let (_, response) = frozen
        .hold_call("x:ArchivedItem/set", json!({"destroy": [item_id]}))
        .await;
    assert_eq!(
        response["notDestroyed"][item_id.as_str()]["type"], "forbidden",
        "test 6, LH-7: the owner destroyed a held item: {response}"
    );
    assert!(
        !response.to_string().contains("Matter 70"),
        "LH-7: the hold was named to someone who can't see holds: {response}"
    );
    let (_, response) = admin
        .hold_call(
            "x:ArchivedItem/set",
            json!({"accountId": frozen.id_string(), "destroy": [item_id]}),
        )
        .await;
    assert!(
        response.to_string().contains("Matter 7001"),
        "LH-7: the administrator isn't told which hold: {response}"
    );

    admin
        .hold_set(json!({"reason": "First settled", "update": {first.as_str(): {"released": true}}}))
        .await;
    assert!(
        is_held(&archived(frozen.archived_items().await)),
        "test 9, LH-11: releasing one hold of two freed the item"
    );
    admin
        .hold_set(json!({"reason": "Second settled", "update": {second.as_str(): {"released": true}}}))
        .await;
    let item = archived(frozen.archived_items().await);
    assert!(!is_held(&item), "LH-10: the last release left it held: {item}");
    let until = item["archivedUntil"].as_str().unwrap_or_default().to_string();
    let grace = chrono::Utc::now() + chrono::Duration::days(29);
    assert!(
        until > grace.format("%Y-%m-%dT%H:%M:%S").to_string(),
        "test 8, LH-10: under 30 days of grace after release: {until}"
    );

    // Test 8, LH-8: a held account destroyed as a login is kept, data and
    // all, with no expiry, although undelete keeps no accounts here
    let held_id = held.id_string().to_string();
    admin.destroy_account(held).await;
    let kept = |list: Value| {
        list["list"]
            .as_array()
            .and_then(|l| l.iter().find(|a| a["id"] == held_id.as_str()).cloned())
    };
    let (_, list) = admin
        .hold_call("inbuxa:DeletedAccount/get", json!({"ids": null}))
        .await;
    let entry = kept(list.clone()).unwrap_or_else(|| panic!("test 8, LH-8: not kept: {list}"));
    assert!(
        entry["keptUntil"].as_str().is_some_and(|u| u.starts_with("9999-")),
        "test 8, LH-8: kept with an expiry: {entry}"
    );
    let (_, response) = admin
        .hold_call("inbuxa:DeletedAccount/set", json!({"destroy": [held_id]}))
        .await;
    assert_eq!(
        response["notDestroyed"][held_id.as_str()]["type"], "forbidden",
        "test 8, LH-8: destroy-now wasn't refused: {response}"
    );
    // Its hold names it now, so no domain or tenant move can drop it
    assert!(
        admin.hold_get(&whole_hold).await["scope"]["accounts"]
            .as_array()
            .is_some_and(|a| a.iter().any(|id| id == held_id.as_str())),
        "LH-8: the hold doesn't name the deleted account"
    );
    // Release: the data is destroyed 30 days later, not before
    admin
        .hold_set(json!({"reason": "Matter closed", "update": {whole_hold.as_str(): {"released": true}}}))
        .await;
    let (_, list) = admin
        .hold_call("inbuxa:DeletedAccount/get", json!({"ids": null}))
        .await;
    let entry = kept(list.clone()).unwrap_or_else(|| panic!("test 8, LH-10: gone at release: {list}"));
    let until = entry["keptUntil"].as_str().unwrap_or_default().to_string();
    let grace = chrono::Utc::now() + chrono::Duration::days(29);
    assert!(
        !until.starts_with("9999-") && until > grace.format("%Y-%m-%dT%H:%M:%S").to_string(),
        "test 8, LH-10: after release, not 30 days of grace: {until}"
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

async fn import(
    client: &jmap_client::client::Client,
    subject: &str,
    received_at: Option<i64>,
) -> String {
    client
        .email_import(
            format!("From: a@example.org\r\nSubject: {subject}\r\n\r\nBody.\r\n").into_bytes(),
            [Id::from(INBOX_ID).to_string()],
            None::<Vec<&str>>,
            received_at,
        )
        .await
        .unwrap()
        .take_id()
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
