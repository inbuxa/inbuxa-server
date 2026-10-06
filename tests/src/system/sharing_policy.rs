/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Who may share mail (multi-account spec, MA-C): the server's switch and a
//! tenant's, which can only be stricter. Off refuses new shares and stops
//! honoring old ones, which come back when it's on again; locks and shared
//! mailboxes are never affected.

use crate::utils::{account::Account, server::TestServerBuilder};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant, UserRoles},
};
use serde_json::{Value, json};

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:mail",
    "urn:inbuxa:jmap",
];

impl Account {
    async fn one(&self, method: &str, arguments: Value) -> Value {
        let response = self.jmap_request(USING, json!([[method, arguments, "0"]])).await;
        response
            .0
            .pointer("/methodResponses/0")
            .cloned()
            .unwrap_or_else(|| panic!("{method}: {}", response.0))
    }

    async fn policy(&self, update: Value) -> Value {
        self.one(
            "inbuxa:SharingPolicy/set",
            json!({"accountId": self.id_string(), "update": update}),
        )
        .await[1]
            .clone()
    }

    async fn inbox(&self) -> String {
        let response = self
            .one(
                "Mailbox/get",
                json!({"accountId": self.id_string(), "ids": null, "properties": ["role"]}),
            )
            .await;
        response[1]["list"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["role"] == "inbox")
            .unwrap_or_else(|| panic!("no Inbox: {response}"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Shares the Inbox with `with` (read), or stops with `None` rights.
    async fn share_inbox(&self, with: &Account, read: bool) -> Value {
        let inbox = self.inbox().await;
        let rights = if read { json!({"mayReadItems": true}) } else { Value::Null };
        self.one(
            "Mailbox/set",
            json!({"accountId": self.id_string(),
                "update": {inbox: {format!("shareWith/{}", with.id_string()): rights}}}),
        )
        .await[1]
            .clone()
    }

    async fn sees(&self, other: &Account) -> bool {
        self.jmap_session_object().await.0["accounts"]
            .get(other.id_string())
            .is_some()
    }

    async fn mail_sharing(&self) -> Value {
        self.jmap_session_object().await.0["accounts"][self.id_string()]["accountCapabilities"]
            ["urn:inbuxa:jmap"]["mailSharing"]
            .clone()
    }
}

/// Runs these tests alone: `cargo test -p tests sharing_policy_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn sharing_policy_tests() {
    let mut test = TestServerBuilder::new("sharing_policy_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    println!("Running sharing policy tests...");

    let tenant = admin
        .registry_create_object(Tenant {
            name: "School".to_string(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Domain {
            name: "school.example.org".to_string(),
            is_enabled: true,
            member_tenant_id: Some(tenant),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    let ann = admin
        .create_user_account("ann@school.example.org", "ann-secret-6610", "Ann", &[], vec![])
        .await;
    let ben = admin
        .create_user_account("ben@school.example.org", "ben-secret-6611", "Ben", &[], vec![])
        .await;
    let head = admin
        .create_user_account("head@school.example.org", "head-secret-6612", "Head", &[], vec![])
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            head.id(),
            json!({Property::Roles: UserRoles::Admin}),
        )
        .await;
    let carl = admin
        .create_user_account("carl@example.org", "carl-secret-6613", "Carl", &[], vec![])
        .await;
    // Shares never cross tenants (MT-3), so Carl's neighbour is outside too
    let dan = admin
        .create_user_account("dan@example.org", "dan-secret-6614", "Dan", &[], vec![])
        .await;
    let tenant_id = tenant.to_string();

    // MA-10: on by default
    assert_eq!(ann.mail_sharing().await, true, "MA-10");
    let response = ann.share_inbox(&ben, true).await;
    assert!(response["updated"].is_object(), "MA-10: {response}");
    assert!(ben.sees(&ann).await, "MA-10: the share gives nothing");

    // The school turns mail sharing off, as its own administrator
    let response = head
        .policy(json!({tenant_id.as_str(): {"mailSharing": "disabled"}}))
        .await;
    assert!(response["updated"].is_object(), "MA-13: {response}");
    // ...but can't touch the server's
    let response = head
        .policy(json!({"singleton": {"mailSharing": "disabled"}}))
        .await;
    assert_eq!(response["notUpdated"]["singleton"]["type"], "forbidden", "MA-13: {response}");

    // MA-11: what was shared gives nothing now, and nothing new is shared
    assert_eq!(ann.mail_sharing().await, false, "MA-11");
    assert!(!ben.sees(&ann).await, "MA-11: an old share still honored");
    let response = ann.share_inbox(&head, true).await;
    assert_eq!(
        response["notUpdated"].as_object().and_then(|o| o.values().next()).map(|e| e["type"].clone()),
        Some(json!("forbidden")),
        "MA-11: {response}"
    );
    // MA-12: a shared mailbox isn't anyone's share, and keeps working
    let office = admin
        .create_user_account("office@school.example.org", "office-secret-6615", "Office", &[], vec![])
        .await;
    let response = admin
        .one(
            "inbuxa:AccountLock/set",
            json!({"accountId": admin.id_string(), "create": {"o": {"accountId": office.id_string(),
                "kind": "sharedMailbox",
                "delegates": [{"accountId": ben.id_string(), "access": "organize"}]}}}),
        )
        .await;
    assert!(response[1]["created"]["o"].is_object(), "MA-12: {response}");
    assert!(ben.sees(&office).await, "MA-12: the switch reached a shared mailbox");

    // Outside the school nothing changed
    let response = carl.share_inbox(&dan, true).await;
    assert!(response["updated"].is_object(), "MA-C: another tenant's switch reached Carl: {response}");
    assert!(dan.sees(&carl).await, "MA-C");

    // A tenant can only be stricter than the server
    let response = admin
        .policy(json!({"singleton": {"mailSharing": "disabled"}}))
        .await;
    assert!(response["updated"].is_object(), "MA-C: {response}");
    let response = head
        .policy(json!({tenant_id.as_str(): {"mailSharing": "enabled"}}))
        .await;
    assert_eq!(
        response["notUpdated"][tenant_id.as_str()]["type"],
        "forbidden",
        "MA-C: {response}"
    );
    assert!(!dan.sees(&carl).await, "MA-C: the server's switch didn't reach Carl's share");

    // Turned back on, the old shares are honored again
    admin
        .policy(json!({"singleton": {"mailSharing": null}}))
        .await;
    head.policy(json!({tenant_id.as_str(): {"mailSharing": null}}))
        .await;
    assert!(ben.sees(&ann).await, "MA-C: an old share didn't come back");
    assert!(dan.sees(&carl).await, "MA-C");

    // Ending a share is always allowed, even while sharing is off
    head.policy(json!({tenant_id.as_str(): {"mailSharing": "disabled"}}))
        .await;
    let response = ann.share_inbox(&ben, false).await;
    assert!(response["updated"].is_object(), "MA-11: ending a share refused: {response}");
    head.policy(json!({tenant_id.as_str(): {"mailSharing": null}}))
        .await;
    assert!(!ben.sees(&ann).await, "MA-11: the ended share came back");

    // MA-14: every change is in the audit log
    let query = admin
        .one(
            "inbuxa:AuditEvent/query",
            json!({"accountId": admin.id_string(), "filter": {"targetKind": "inbuxa:SharingPolicy"}}),
        )
        .await;
    assert!(
        query[1]["ids"].as_array().is_some_and(|ids| ids.len() >= 5),
        "MA-14: {query}"
    );

    if test.is_reset() {
        test.temp_dir.delete();
    }
}
