/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The compliance roles (personal-data catalog spec, §7): each made once,
//! the officer reads the audit log and places holds but changes no setting,
//! and the tenant officer reaches no holds.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{
        CertificateManagement, CustomRoles, DkimManagement, DnsManagement, Domain, Role, Tenant,
        UserRoles,
    },
};
use registry::types::map::Map;
use serde_json::{Value, json};
use types::id::Id;

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:inbuxa:jmap",
    "urn:inbuxa:jmap:registry",
];

async fn call(account: &Account, method: &str, mut arguments: Value) -> (String, Value) {
    if arguments.get("accountId").is_none() {
        arguments["accountId"] = account.id_string().into();
    }
    let response = account.jmap_request(USING, json!([[method, arguments, "0"]])).await;
    let call = response
        .0
        .pointer("/methodResponses/0")
        .cloned()
        .unwrap_or_else(|| panic!("{method}: {}", response.0));
    (call[0].as_str().unwrap_or_default().to_string(), call[1].clone())
}

/// The ids of the roles with this name and tenant, as an administrator sees them.
async fn roles_named(admin: &Account, description: &str, tenant: Option<Id>) -> Vec<Id> {
    let mut found = Vec::new();
    for id in admin
        .registry_query_ids(ObjectType::Role, Vec::<(&str, &str)>::new(), Vec::<&str>::new())
        .await
    {
        let role = admin.registry_get::<Role>(id).await;
        if role.description == description && role.member_tenant_id == tenant {
            found.push(id);
        }
    }
    found
}

pub async fn test(test: &mut TestServer) {
    println!("Running compliance role tests...");
    let admin = test.account("admin@example.com");

    // The server's officer role exists, once
    let officer_role = roles_named(&admin, "Compliance Officer", None).await;
    let user_role = roles_named(&admin, "User", None).await;
    assert_eq!(officer_role.len(), 1, "one server-level Compliance Officer role");
    assert_eq!(user_role.len(), 1);

    // A compliance officer: the role carries a user's own permissions too
    let officer = admin
        .create_user_account("officer@example.com", "officer-secret-4410", "Officer", &[], vec![])
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            officer.id(),
            json!({Property::Roles: UserRoles::Custom(CustomRoles {
                role_ids: Map::new(vec![officer_role[0]]),
            })}),
        )
        .await;

    // Reads and exports the audit log
    let (name, response) = call(&officer, "inbuxa:AuditEvent/query", json!({})).await;
    assert_eq!(name, "inbuxa:AuditEvent/query", "the officer reads the audit log: {response}");

    // Places and releases a hold: that is the role
    let (name, response) = call(
        &officer,
        "inbuxa:LegalHold/set",
        json!({"reason": "Regulator's request", "create": {"h": {"name": "Matter 9001",
            "scope": {"accounts": [officer.id_string()]}}}}),
    )
    .await;
    let hold = response["created"]["h"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the officer places a hold: {name} {response}"))
        .to_string();
    let (_, response) = call(
        &officer,
        "inbuxa:LegalHold/set",
        json!({"reason": "Closed", "update": {hold.as_str(): {"released": true}}}),
    )
    .await;
    assert!(
        response["updated"].get(hold.as_str()).is_some(),
        "the officer releases a hold: {response}"
    );

    // Changes no server setting and creates no account
    let (name, response) = call(
        &officer,
        "x:DataRetention/set",
        json!({"update": {"singleton": {"holdTracesFor": 86400000}}}),
    )
    .await;
    assert!(
        name == "error" || response["notUpdated"].get("singleton").is_some(),
        "the officer changed a setting: {name} {response}"
    );
    let (name, response) = call(
        &officer,
        "x:Account/set",
        json!({"create": {"a": {"@type": "User", "name": "nobody"}}}),
    )
    .await;
    assert!(
        name == "error" || response["notCreated"].get("a").is_some(),
        "the officer created an account: {name} {response}"
    );
    let (name, response) = call(
        &officer,
        "inbuxa:AuditSettings/set",
        json!({"update": {"singleton": {"keepForDays": 90}}}),
    )
    .await;
    assert!(
        name == "error" || response["notUpdated"].get("singleton").is_some(),
        "the officer shortened audit retention: {name} {response}"
    );

    // A tenant compliance officer reads its tenant's audit log, and no holds
    let tenant = admin
        .registry_create_object(Tenant {
            name: "compliance-tenant".to_string(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Domain {
            name: "tenant-compliance.example.org".to_string(),
            is_enabled: true,
            member_tenant_id: Some(tenant),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    // A new tenant gets its own Compliance Officer role (MT-3: a tenant's
    // accounts hold only its own roles)
    let tenant_role = roles_named(&admin, "Compliance Officer", Some(tenant)).await;
    assert_eq!(tenant_role.len(), 1, "the tenant's Compliance Officer role");
    let t_officer = admin
        .create_user_account(
            "officer@tenant-compliance.example.org",
            "tenant-officer-secret-7715",
            "Tenant officer",
            &[],
            vec![],
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            t_officer.id(),
            json!({Property::Roles: UserRoles::Custom(CustomRoles {
                role_ids: Map::new(vec![tenant_role[0]]),
            })}),
        )
        .await;
    let (name, response) = call(&t_officer, "inbuxa:AuditEvent/query", json!({})).await;
    assert_eq!(name, "inbuxa:AuditEvent/query", "the tenant officer reads the audit log: {response}");
    let (name, response) = call(&t_officer, "inbuxa:LegalHold/get", json!({"ids": null})).await;
    assert_eq!(name, "error", "LH-13: the tenant officer read holds: {response}");

    // The data inventory (§6): the officer reads it, facts not verdicts
    let (name, response) = call(&officer, "inbuxa:DataInventory/get", json!({"ids": null})).await;
    assert_eq!(name, "inbuxa:DataInventory/get", "{response}");
    let inventory = response["list"][0].clone();
    let ids: Vec<&str> = inventory["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["id"].as_str())
        .collect();
    assert!(ids.contains(&"x:UserAccount") && ids.contains(&"log-file"), "{ids:?}");
    assert!(inventory["summary"]["collected"].as_u64().unwrap_or(0) > 0);
    assert!(!inventory.to_string().to_lowercase().contains("complian"), "facts only");

    // Somebody without the permission is refused
    let plain = admin
        .create_user_account("plain@example.com", "plain-secret-1182", "Plain", &[], vec![])
        .await;
    let (name, _) = call(&plain, "inbuxa:DataInventory/get", json!({"ids": null})).await;
    assert_eq!(name, "error", "a user without sysComplianceGet read the inventory");

    // A tenant's officer sees the tenant's slice, and no processors
    let (_, response) = call(&t_officer, "inbuxa:DataInventory/get", json!({"ids": null})).await;
    let slice = &response["list"][0];
    assert!(
        slice["items"].as_array().is_some_and(|items| !items.is_empty()
            && items.iter().all(|i| i["scope"] == "tenant")),
        "{slice}"
    );
    assert_eq!(slice["processors"], json!([]));

    // A webhook to another host makes it a candidate processor, and the
    // change is in the inventory's history
    let (_, response) = call(
        &admin,
        "x:WebHook/set",
        json!({"create": {"w": {"url": "https://hooks.example.net/in", "enable": true}}}),
    )
    .await;
    assert!(response["created"].get("w").is_some(), "{response}");
    let (_, response) = call(&officer, "inbuxa:DataInventory/get", json!({"ids": null})).await;
    let inventory = &response["list"][0];
    assert!(
        inventory["processors"]
            .as_array()
            .is_some_and(|p| p.iter().any(|p| p["host"] == "hooks.example.net")),
        "{inventory}"
    );
    let webhooks = inventory["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == "webhooks")
        .unwrap();
    assert_eq!(webhooks["collected"], json!(true));
    assert_eq!(webhooks["leavesHost"], json!(true));
    let (_, response) = call(
        &officer,
        "inbuxa:InventorySnapshot/get",
        json!({"ids": null, "properties": ["id", "takenAt", "trigger", "summary"]}),
    )
    .await;
    let snapshots = response["list"].as_array().cloned().unwrap_or_default();
    assert!(
        snapshots
            .iter()
            .any(|s| s["trigger"]["kind"] == "settingChanged" && s["trigger"]["setting"] == "x:WebHook"),
        "the webhook's snapshot: {snapshots:?}"
    );
    assert!(snapshots.iter().all(|s| s.get("inventory").is_none()), "left out when not asked");

    // A retention change reads through
    let (_, response) = call(
        &admin,
        "x:DataRetention/set",
        json!({"update": {"singleton": {"holdTracesFor": 604800000}}}),
    )
    .await;
    assert!(response["updated"].get("singleton").is_some(), "{response}");
    let (_, response) = call(&officer, "inbuxa:DataInventory/get", json!({"ids": null})).await;
    let trace = response["list"][0]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == "x:Trace")
        .cloned()
        .unwrap();
    assert_eq!(trace["retention"]["days"], json!(7), "{trace}");

    // D5: a new install's first rules leave the hashed-address blocklist
    // off, once; an existing server (no note) keeps it as it is
    let (_, response) = call(
        &admin,
        "x:SpamDnsblServer/set",
        json!({"create": {"m": {"@type": "Email", "name": "STWT_MSBL_EBL_EMAIL", "enable": true,
            "zone": {"else": "hash(email, 'sha1') + '.ebl.msbl.org'", "match": {}},
            "tag": {"else": "'MSBL_EBL'", "match": {}}}}}),
    )
    .await;
    let msbl = response["created"]["m"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"))
        .to_string();
    let registry = test.server.registry();
    let store = test.server.store();
    assert!(
        !common::manager::spam_rules::apply_new_install(registry, store).await.unwrap(),
        "no note, no change"
    );
    let enabled = |response: &Value| response["list"][0]["enable"].clone();
    let (_, response) = call(&admin, "x:SpamDnsblServer/get", json!({"ids": [msbl]})).await;
    assert_eq!(enabled(&response), json!(true));
    let (_, response) = call(&officer, "inbuxa:DataInventory/get", json!({"ids": null})).await;
    assert!(
        response["list"][0]["processors"]
            .as_array()
            .is_some_and(|p| p.iter().any(|p| p["host"] == "ebl.msbl.org")),
        "the zone, not the hash: {response}"
    );
    common::manager::spam_rules::mark_new_install(store).await.unwrap();
    assert!(common::manager::spam_rules::apply_new_install(registry, store).await.unwrap());
    let (_, response) = call(&admin, "x:SpamDnsblServer/get", json!({"ids": [msbl]})).await;
    assert_eq!(enabled(&response), json!(false), "{response}");
    assert!(
        !common::manager::spam_rules::apply_new_install(registry, store).await.unwrap(),
        "the note works once"
    );

    // A tenant can still be deleted: its unused role goes with it
    let spare = admin
        .registry_create_object(Tenant {
            name: "spare-tenant".to_string(),
            ..Default::default()
        })
        .await;
    assert_eq!(roles_named(&admin, "Compliance Officer", Some(spare)).await.len(), 1);
    let (name, response) = call(&admin, "x:Tenant/set", json!({"destroy": [spare.to_string()]})).await;
    assert!(
        response["destroyed"].as_array().is_some_and(|d| d.iter().any(|i| i == &json!(spare.to_string()))),
        "the tenant was deleted: {name} {response}"
    );
    assert!(roles_named(&admin, "Compliance Officer", Some(spare)).await.is_empty());
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn compliance_tests() {
    let mut test = TestServerBuilder::new("compliance_tests")
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
