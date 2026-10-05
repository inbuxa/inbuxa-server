/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Audit log acceptance tests, from `inbuxa-drafts/specs/audit-hold-lock.md`
//! (AU-1 to AU-11, and tests 1 to 5 of its list). Each check names the
//! requirement or test number.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use inbuxa_features::audit::{EntryId, log};
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{
            BlockedIp, CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant,
            UserRoles,
        },
    },
    types::ipmask::IpAddrOrMask,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use store::{Deserialize, registry::write::RegistryWrite, write::BatchBuilder};
use types::id::Id;

const USING: &[&str] = &["urn:ietf:params:jmap:core", "urn:inbuxa:jmap"];

struct Bytes(Vec<u8>);

impl Deserialize for Bytes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Bytes(bytes.to_vec()))
    }
}

impl Account {
    /// Records matching `filter`, newest first.
    async fn audit(&self, filter: Value) -> Vec<Value> {
        let response = self
            .jmap_request(
                USING,
                json!([
                    ["inbuxa:AuditEvent/query", {
                        "accountId": self.id_string(), "filter": filter, "limit": 100
                    }, "q"],
                    ["inbuxa:AuditEvent/get", {
                        "accountId": self.id_string(),
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

    /// One method's response: its name and arguments.
    async fn audit_call(&self, method: &str, arguments: Value) -> (String, Value) {
        let response = self
            .jmap_request(USING, json!([[method, arguments, "0"]]))
            .await;
        let call = response
            .0
            .pointer("/methodResponses/0")
            .cloned()
            .unwrap_or_else(|| panic!("{method}: {}", response.0));
        (
            call[0].as_str().unwrap_or_default().to_string(),
            call[1].clone(),
        )
    }

    async fn audit_verify(&self) -> Value {
        let (_, response) = self
            .audit_call(
                "inbuxa:AuditVerification/set",
                json!({"accountId": self.id_string(), "create": {"v": {}}}),
            )
            .await;
        response["created"]["v"].clone()
    }

    async fn create_audit_domain(&self, name: &str, tenant: Option<Id>) -> Id {
        self.registry_create_object(Domain {
            name: name.to_string(),
            is_enabled: true,
            member_tenant_id: tenant,
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await
    }
}

fn changed(record: &Value, field: &str) -> Option<(Value, Value)> {
    record["changes"]
        .as_array()?
        .iter()
        .find(|change| change["field"] == field)
        .map(|change| (change["before"].clone(), change["after"].clone()))
}

pub async fn test(test: &mut TestServer) {
    println!("Running audit log tests...");
    let admin = test.account("admin@example.org");
    let admin_id = admin.id_string().to_string();

    // AU-1.4, AU-5: the administrator's sign-in, by password
    admin.jmap_session_object().await;
    let signins = admin
        .audit(json!({"action": "signIn", "actorId": admin_id}))
        .await;
    assert!(!signins.is_empty(), "AU-1.4: no sign-in recorded");
    assert_eq!(
        signins[0]["via"]["kind"], "password",
        "AU-5: {}",
        signins[0]
    );
    assert!(signins[0]["remoteIp"].is_string(), "AU-4");

    // Test 1: a change, with its field's before and after
    let domain = admin.create_audit_domain("audit.example.org", None).await;
    let created = admin
        .audit(json!({"action": "create", "targetKind": "x:Domain"}))
        .await;
    let record = created
        .iter()
        .find(|r| r["outcome"]["createdId"] == domain.to_string())
        .unwrap_or_else(|| panic!("test 1: no create record in {created:?}"));
    assert_eq!(record["outcome"]["status"], "success", "test 1");
    assert_eq!(record["target"]["name"], "audit.example.org", "test 1");
    assert_eq!(record["actor"]["name"], "admin@example.org", "test 1");

    admin
        .registry_update_object(
            ObjectType::Domain,
            domain,
            json!({Property::IsEnabled: false}),
        )
        .await;
    let updated = admin
        .audit(json!({"action": "update", "targetId": domain.to_string()}))
        .await;
    assert_eq!(updated.len(), 1, "test 1: {updated:?}");
    assert_eq!(
        changed(&updated[0], "isEnabled"),
        Some((json!(true), json!(false))),
        "test 1: {}",
        updated[0]
    );
    assert_eq!(updated[0]["target"]["name"], "audit.example.org", "test 1");
    let update_id = updated[0]["id"].as_str().unwrap().to_string();

    // Test 1: a secret is recorded as changed, never with its value
    let secret = "a-very-secret-password-0192";
    let user = admin
        .create_user_account("audituser@example.org", secret, "Audit user", &[], vec![])
        .await;
    let accounts = admin
        .audit(json!({"action": "create", "targetKind": "x:Account"}))
        .await;
    assert!(!accounts.is_empty(), "test 1: account create");
    for record in &accounts {
        assert!(
            !record.to_string().contains(secret),
            "test 1: secret kept: {record}"
        );
    }

    // AU-1.10: a registry write outside any request is the server's own
    let blocked = IpAddrOrMask::from_ip("192.0.2.99".parse().unwrap());
    test.server
        .registry()
        .write(RegistryWrite::insert(
            &BlockedIp {
                address: blocked,
                ..Default::default()
            }
            .into(),
        ))
        .await
        .unwrap();
    let system = admin.audit(json!({"targetKind": "x:BlockedIp"})).await;
    assert_eq!(system.len(), 1, "AU-1.10: {system:?}");
    assert_eq!(system[0]["actor"]["name"], "system:server", "AU-1.10");
    assert!(system[0]["actor"]["accountId"].is_null(), "AU-1.10");

    // Test 3, AU-1.6: impersonated access, once an hour
    for _ in 0..2 {
        let response = admin
            .jmap_request(
                &["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                json!([["Mailbox/get", {"accountId": user.id_string(), "ids": null}, "0"]]),
            )
            .await;
        assert_eq!(
            response.0.pointer("/methodResponses/0/0"),
            Some(&json!("Mailbox/get")),
            "test 3: {}",
            response.0
        );
    }
    let access = admin
        .audit(json!({"action": "accountAccess", "accountId": user.id_string()}))
        .await;
    assert_eq!(access.len(), 1, "test 3: {access:?}");
    assert_eq!(
        access[0]["target"]["name"], "audituser@example.org",
        "test 3"
    );

    // AU-9: a plain user can't read the audit log
    let plain = Account::new(
        "audituser@example.org",
        "a-very-secret-password-0192",
        &[],
        "",
        user.id(),
    );
    let (name, response) = plain
        .audit_call(
            "inbuxa:AuditEvent/query",
            json!({"accountId": user.id_string(), "filter": {}}),
        )
        .await;
    assert_eq!(name, "error", "AU-9: a user read the audit log: {response}");
    assert_eq!(response["type"], "forbidden", "AU-9");

    // AU-1.4: a failed password sign-in to an administrator's account
    let wrong = Account::new(
        "admin@example.org",
        "not-the-password",
        &[],
        "Admin",
        admin.id(),
    );
    let failed = wrong.jmap_session_object().await;
    assert!(
        failed.0.pointer("/accounts").is_none(),
        "wrong password worked"
    );
    let failures = admin
        .audit(json!({"action": "signInFailed", "actorId": admin_id}))
        .await;
    assert_eq!(failures.len(), 1, "AU-1.4: {failures:?}");
    assert_eq!(failures[0]["outcome"]["status"], "refused", "AU-1.4");
    // A user that isn't an administrator isn't recorded
    let wrong_user = Account::new(
        "audituser@example.org",
        "not-the-password",
        &[],
        "",
        user.id(),
    );
    wrong_user.jmap_session_object().await;
    assert!(
        admin
            .audit(json!({"action": "signInFailed", "actorId": user.id_string()}))
            .await
            .is_empty(),
        "AU-1.4: a plain user's failure recorded"
    );

    // Test 5, AU-9: a tenant administrator sees its tenant only
    let tenant = admin
        .registry_create_object(Tenant {
            name: "Audit tenant".to_string(),
            ..Default::default()
        })
        .await;
    let tenant_domain = admin
        .create_audit_domain("tenant-audit.example.org", Some(tenant))
        .await;
    let t_admin = admin
        .create_user_account(
            "tadmin@tenant-audit.example.org",
            "tenant-admin-secret-3391",
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
    let seen = t_admin.audit(json!({})).await;
    assert!(!seen.is_empty(), "test 5: nothing seen");
    let tenant_str = tenant.to_string();
    for record in &seen {
        assert!(
            record["actor"]["tenantId"] == tenant_str.as_str()
                || record["target"]["tenantId"] == tenant_str.as_str(),
            "test 5: outside the tenant: {record}"
        );
    }
    // The server administrator's change to the tenant's domain is included
    assert!(
        seen.iter()
            .any(|r| r["outcome"]["createdId"] == tenant_domain.to_string()),
        "test 5: the server admin's create is missing"
    );
    assert!(
        t_admin
            .audit(json!({"targetId": domain.to_string()}))
            .await
            .is_empty(),
        "test 5: another domain's records seen"
    );
    let (name, _) = t_admin
        .audit_call(
            "inbuxa:AuditSettings/set",
            json!({"accountId": t_admin.id_string(),
                "update": {"singleton": {"keepForDays": 400}}}),
        )
        .await;
    assert_eq!(name, "error", "AU-9: a tenant admin changed retention");
    let (name, _) = t_admin
        .audit_call(
            "inbuxa:AuditVerification/set",
            json!({"accountId": t_admin.id_string(), "create": {"v": {}}}),
        )
        .await;
    assert_eq!(name, "error", "AU-9: a tenant admin verified");

    // AU-7: retention
    let (_, response) = admin
        .audit_call(
            "inbuxa:AuditSettings/set",
            json!({"accountId": admin_id, "update": {"singleton": {"keepForDays": 30}}}),
        )
        .await;
    assert_eq!(
        response["notUpdated"]["singleton"]["type"], "invalidProperties",
        "AU-7: {response}"
    );
    let (_, response) = admin
        .audit_call(
            "inbuxa:AuditSettings/set",
            json!({"accountId": admin_id, "update": {"singleton": {"keepForDays": 365}}}),
        )
        .await;
    assert!(
        response["updated"]["singleton"].is_null(),
        "AU-7: {response}"
    );
    let (_, response) = admin
        .audit_call(
            "inbuxa:AuditSettings/get",
            json!({"accountId": admin_id, "ids": null}),
        )
        .await;
    assert_eq!(response["list"][0]["keepForDays"], 365, "AU-7");
    let settings_changes = admin
        .audit(json!({"targetKind": "inbuxa:AuditSettings"}))
        .await;
    assert_eq!(
        changed(&settings_changes[0], "keepForDays"),
        Some((json!(730), json!(365))),
        "AU-7: the retention change is recorded with what it replaced"
    );

    // AU-11: an export, recorded, with its hash
    let (_, response) = admin
        .audit_call(
            "inbuxa:AuditExport/set",
            json!({"accountId": admin_id, "create": {"x": {
                "format": "jsonl",
                "filter": {"targetId": domain.to_string()},
                "reason": "Test export"
            }}}),
        )
        .await;
    let export = response["created"]["x"].clone();
    assert!(export["blobId"].is_string(), "AU-11: {response}");
    assert!(export["count"].as_u64().unwrap() >= 2, "AU-11: {export}");
    let file = admin
        .http_get_raw(
            &format!(
                "{}/jmap/download/{}/{}/audit.jsonl",
                admin.base_url(),
                admin_id,
                export["blobId"].as_str().unwrap()
            ),
            None,
        )
        .await;
    assert_eq!(file.status, 200, "AU-11: download");
    let sha: String = Sha256::digest(&file.body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(export["sha256"], sha.as_str(), "AU-11: file hash");
    let text = String::from_utf8(file.body).unwrap();
    let manifest: Value = serde_json::from_str(text.trim_end().lines().last().unwrap()).unwrap();
    assert_eq!(manifest["manifest"]["count"], export["count"], "AU-11");
    assert!(text.contains("\"hash\""), "AU-11: lines carry hashes");
    let exports = admin.audit(json!({"action": "export"})).await;
    assert_eq!(exports.len(), 1, "AU-1.9: {exports:?}");
    assert_eq!(exports[0]["reason"], "Test export", "AU-1.9");
    assert_eq!(exports[0]["outcome"]["status"], "success", "AU-1.9");

    // Test 4, AU-6: verification passes, then catches an edited entry
    let report = admin.audit_verify().await;
    assert_eq!(report["verified"], true, "test 4: {report}");

    let store = test.server.store();
    let tampered = EntryId::from_u64(Id::from_str(&update_id).unwrap().id());
    let key = log::entry_key(tampered);
    let original = store
        .get_value::<Bytes>(key.clone())
        .await
        .unwrap()
        .unwrap()
        .0;
    let edited = String::from_utf8(original.clone()).unwrap().replacen(
        "\"after\":false",
        "\"after\":true",
        1,
    );
    assert_ne!(
        edited.as_bytes(),
        original.as_slice(),
        "test 4: nothing to edit"
    );
    let write = |bytes: Vec<u8>| {
        let key = key.clone();
        async move {
            let mut batch = BatchBuilder::new();
            batch.set(key.class, bytes);
            store.write(batch.build_all()).await.unwrap();
        }
    };
    write(edited.into_bytes()).await;
    let report = admin.audit_verify().await;
    assert_eq!(report["verified"], false, "test 4: {report}");
    let broken = report["chains"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|chain| chain["brokenAt"].as_str())
        .unwrap_or_else(|| panic!("test 4: no break named: {report}"))
        .to_string();
    assert_eq!(
        broken,
        EntryId {
            node: tampered.node,
            seq: tampered.seq + 1
        }
        .to_string(),
        "test 4: the break is found at the entry after the edited one"
    );
    write(original).await;
    assert_eq!(
        admin.audit_verify().await["verified"],
        true,
        "test 4: restored"
    );

    // Test 2, AU-3: no change without its record
    let head = log::head_key(tampered.node);
    let head_bytes = store
        .get_value::<Bytes>(head.clone())
        .await
        .unwrap()
        .unwrap()
        .0;
    let mut batch = BatchBuilder::new();
    batch.set(head.class.clone(), b"bad".to_vec());
    store.write(batch.build_all()).await.unwrap();
    let (name, response) = admin
        .audit_call(
            "x:Domain/set",
            json!({"accountId": admin_id, "create": {"d": {
                "name": "refused.example.org",
                "isEnabled": true,
                "certificateManagement": {"@type": "Manual"},
                "dnsManagement": {"@type": "Manual"},
                "dkimManagement": {"@type": "Manual"}
            }}}),
        )
        .await;
    assert_eq!(name, "error", "test 2: the change went ahead: {response}");
    let mut batch = BatchBuilder::new();
    batch.set(head.class, head_bytes);
    store.write(batch.build_all()).await.unwrap();
    assert!(
        admin
            .registry_query_ids(
                ObjectType::Domain,
                [(Property::Name, "refused.example.org")],
                Vec::<&str>::new(),
            )
            .await
            .is_empty(),
        "test 2: the domain exists"
    );

    // AU-7: purging leaves a chain that verifies and carries on
    let removed = log::purge(store, u64::MAX, |_| false).await.unwrap();
    assert!(removed > 0, "AU-7: nothing purged");
    assert_eq!(
        admin.audit_verify().await["verified"],
        true,
        "AU-7: after purge"
    );
    admin
        .registry_update_object(
            ObjectType::Domain,
            domain,
            json!({Property::IsEnabled: true}),
        )
        .await;
    assert_eq!(
        admin
            .audit(json!({"targetId": domain.to_string()}))
            .await
            .len(),
        1,
        "AU-7: only the change after the purge"
    );
    assert_eq!(
        admin.audit_verify().await["verified"],
        true,
        "AU-7: continued"
    );

    // MA-D0a: a group member sending as the group is named in the log; the
    // same person sending as themselves isn't recorded
    let group = admin
        .create_group_account("helpdesk@send-as.example.org", "Help desk", &[])
        .await;
    let agent = admin
        .create_user_account(
            "agent@send-as.example.org",
            "agent-secret-for-send-as",
            "Agent",
            &[],
            vec![],
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            agent.id(),
            json!({"memberGroupIds": {group.id_string(): true}}),
        )
        .await;
    agent.send_as("helpdesk@send-as.example.org").await;
    agent.send_as("agent@send-as.example.org").await;
    let sends = admin
        .audit(json!({
            "targetKind": "EmailSubmission",
            "actorId": agent.id_string(),
        }))
        .await;
    assert_eq!(sends.len(), 1, "MA-D0a: {sends:?}");
    assert_eq!(sends[0]["target"]["name"], "helpdesk@send-as.example.org");
    assert_eq!(
        sends[0]["target"]["accountId"],
        group.id_string(),
        "MA-D0a: {}",
        sends[0]
    );
    assert_eq!(
        sends[0]["details"],
        "Sent as helpdesk@send-as.example.org, from agent@send-as.example.org"
    );

    // Clean up what later suites could trip over
    admin.registry_destroy_all(ObjectType::BlockedIp).await;
}

impl Account {
    /// Sends one message to itself from its own account, as `from`.
    async fn send_as(&self, from: &str) {
        const USING: &[&str] = &[
            "urn:ietf:params:jmap:core",
            "urn:ietf:params:jmap:mail",
            "urn:ietf:params:jmap:submission",
        ];
        let account_id = self.id_string();
        let response = self
            .jmap_request(
                USING,
                json!([
                    ["Identity/get", {"accountId": account_id}, "i"],
                    ["Mailbox/get", {"accountId": account_id, "properties": ["role"]}, "m"]
                ]),
            )
            .await;
        let identity = response
            .0
            .pointer("/methodResponses/0/1/list")
            .and_then(Value::as_array)
            .and_then(|list| list.iter().find(|identity| identity["email"] == from))
            .unwrap_or_else(|| panic!("no identity for {from}: {}", response.0))["id"]
            .clone();
        let drafts = response
            .0
            .pointer("/methodResponses/1/1/list")
            .and_then(Value::as_array)
            .and_then(|list| list.iter().find(|mailbox| mailbox["role"] == "drafts"))
            .unwrap_or_else(|| panic!("no drafts: {}", response.0))["id"]
            .clone();
        let response = self
            .jmap_request(
                USING,
                json!([
                    ["Email/set", {"accountId": account_id, "create": {"m": {
                        "mailboxIds": {drafts.as_str().unwrap(): true},
                        "from": [{"email": from}],
                        "to": [{"email": self.name()}],
                        "subject": format!("Sent as {from}"),
                        "bodyValues": {"t": {"value": "MA-D0a"}},
                        "textBody": [{"partId": "t", "type": "text/plain"}]
                    }}}, "e"],
                    ["EmailSubmission/set", {"accountId": account_id, "create": {"s": {
                        "identityId": identity, "emailId": "#m"
                    }}}, "s"]
                ]),
            )
            .await;
        assert!(
            response.0.pointer("/methodResponses/1/1/created/s").is_some(),
            "send as {from}: {}",
            response.0
        );
    }
}

/// Runs these tests alone: `cargo test -p tests audit_log_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn audit_log_tests() {
    let mut test = TestServerBuilder::new("audit_log_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
