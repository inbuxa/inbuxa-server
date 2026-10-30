/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Relay` (docs/spec/features/relay.md, "Registry objects"): a
//! create returns a join token once, every relay is pinned to the one link
//! CA, settings change one at a time, a private key reads back as `****`
//! and is kept when written back that way, a rejoin issues a new token,
//! nobody in a tenant reaches relays, and the audit log never holds the
//! key or a token.

use crate::utils::{
    account::Account,
    server::{TestServer, TestServerBuilder},
};
use inbuxa_relay_proto::{time, token::JoinToken};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant, UserRoles},
};
use serde_json::{Value, json};
use std::str::FromStr;

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:inbuxa:jmap",
    "urn:inbuxa:jmap:registry",
];

const KEY_PEM: &str =
    "-----BEGIN PRIVATE KEY-----\nTUFSS0VSLXJlbGF5LXByaXZhdGUta2V5\n-----END PRIVATE KEY-----\n";
const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

async fn call(account: &Account, method: &str, mut arguments: Value) -> (String, Value) {
    if arguments.get("accountId").is_none() {
        arguments["accountId"] = account.id_string().into();
    }
    let response = account
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

fn relay(name: &str) -> Value {
    json!({
        "name": name,
        "address": "relay1.example.net",
        "settings": {"hostname": "mx1.example.com"}
    })
}

async fn get(account: &Account, id: &str) -> Value {
    let (name, response) = call(account, "inbuxa:Relay/get", json!({"ids": [id]})).await;
    assert_eq!(name, "inbuxa:Relay/get", "{response}");
    response["list"][0].clone()
}

pub async fn test(test: &mut TestServer) {
    println!("Running inbuxa Relay tests...");
    let admin = test.account("admin@example.com");
    let now = time::now();

    // Created with a join token, shown once, for the shared link CA
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"create": {"a": relay("Edge one"), "b": relay("Edge two")}}),
    )
    .await;
    let id = response["created"]["a"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("relay created: {response}"))
        .to_string();
    let token = response["created"]["a"]["joinToken"]
        .as_str()
        .unwrap()
        .to_string();
    let first = JoinToken::decode(&token, now).expect("a join token");
    let second =
        JoinToken::decode(response["created"]["b"]["joinToken"].as_str().unwrap(), now).unwrap();
    assert_eq!(first.relay_id, id);
    assert_eq!(first.ca_spki, second.ca_spki, "one link CA for every relay");
    assert_ne!(first.secret, second.secret);
    let other = response["created"]["b"]["id"].as_str().unwrap().to_string();

    let relay_a = get(admin, &id).await;
    assert_eq!(relay_a["joinState"], "waiting", "{relay_a}");
    assert_eq!(relay_a["linkPort"], 443);
    assert_eq!(relay_a["enabled"], true);
    assert_eq!(relay_a["settings"]["heldMaxAge"], 30);
    assert_eq!(relay_a["settings"]["hostname"], "mx1.example.com");
    assert!(relay_a["settings"].get("sealingKey").is_none(), "{relay_a}");
    assert!(
        relay_a["settings"].get("recipientKey").is_none(),
        "{relay_a}"
    );
    assert_eq!(relay_a["smtpPrivateKey"], Value::Null);
    assert_eq!(relay_a["createdBy"], "admin@example.com");
    assert!(relay_a.get("joinToken").is_none(), "{relay_a}");
    let (_, response) = call(
        admin,
        "inbuxa:Relay/get",
        json!({"ids": [&id], "properties": ["joinToken"]}),
    )
    .await;
    assert_eq!(response["list"][0]["joinToken"], Value::Null, "{response}");

    // Checked when written
    let mut no_hostname = relay("x");
    no_hostname["settings"] = json!({});
    let mut unknown_setting = relay("x");
    unknown_setting["settings"]["noSuchSetting"] = 1.into();
    let mut server_set = relay("x");
    server_set["joinState"] = "joined".into();
    let mut rejoin = relay("x");
    rejoin["rejoin"] = true.into();
    let mut masked = relay("x");
    masked["smtpCertificate"] = CERT_PEM.into();
    masked["smtpPrivateKey"] = "****".into();
    let mut keys = relay("x");
    keys["settings"]["sealingKey"] = "AAAA".into();
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"create": {
            "a": no_hostname, "b": unknown_setting, "c": server_set,
            "d": rejoin, "e": masked, "f": keys
        }}),
    )
    .await;
    for (client_id, property) in [
        ("a", "settings"),
        ("b", "settings"),
        ("c", "joinState"),
        ("d", "rejoin"),
        ("e", "smtpPrivateKey"),
        ("f", "settings"),
    ] {
        assert_eq!(
            response["notCreated"][client_id]["properties"][0], property,
            "{client_id}: {response}"
        );
    }
    assert!(
        response["notCreated"]["b"]["description"]
            .as_str()
            .is_some_and(|d| d.contains("noSuchSetting")),
        "{response}"
    );

    // One setting at a time; the rest stay as they were
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {
            "settings/heldMaxAge": 10,
            "settings/maxRecipients": 20,
            "name": "Edge north",
            "smtpCertificate": CERT_PEM,
            "smtpPrivateKey": KEY_PEM
        }}}),
    )
    .await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    let relay_a = get(admin, &id).await;
    assert_eq!(relay_a["name"], "Edge north");
    assert_eq!(relay_a["settings"]["heldMaxAge"], 10);
    assert_eq!(relay_a["settings"]["maxRecipients"], 20);
    assert_eq!(relay_a["settings"]["hostname"], "mx1.example.com");
    assert_eq!(relay_a["smtpPrivateKey"], "****", "{relay_a}");
    assert_eq!(relay_a["smtpCertificate"], CERT_PEM);

    // A setting put back to its default, and the key written back masked
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {"settings/heldMaxAge": null, "smtpPrivateKey": "****"}}}),
    )
    .await;
    assert!(response["updated"].get(&id).is_some(), "{response}");
    assert_eq!(get(admin, &id).await["settings"]["heldMaxAge"], 30);
    let stored = inbuxa_features::relay::get(
        test.server.store(),
        u32::try_from(types::id::Id::from_str(&id).unwrap().id()).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        stored.smtp_private_key.as_deref(),
        Some(KEY_PEM),
        "key kept"
    );

    // A change made from a stale read is refused, so a join being recorded
    // and an administrator's edit can't overwrite each other
    let (mut stored, version) =
        inbuxa_features::relay::get_versioned(test.server.store(), stored.id)
            .await
            .unwrap()
            .unwrap();
    stored.description = "changed".into();
    assert!(
        !inbuxa_features::relay::replace(test.server.store(), &stored, version ^ 1)
            .await
            .unwrap()
    );
    assert!(
        inbuxa_features::relay::replace(test.server.store(), &stored, version)
            .await
            .unwrap()
    );
    assert_eq!(get(admin, &id).await["description"], "changed");

    // Out of range, a bad setting name, and a server property: refused
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {
            &id: {"settings/heldMaxAge": 91},
            &other: {"settings/nope": 1}
        }}),
    )
    .await;
    assert_eq!(response["notUpdated"][&id]["properties"][0], "settings");
    assert_eq!(response["notUpdated"][&other]["properties"][0], "settings");
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {"linkKeyPin": "AAAA"}}}),
    )
    .await;
    assert_eq!(
        response["notUpdated"][&id]["properties"][0], "linkKeyPin",
        "{response}"
    );

    // A rejoin issues a new token for the same relay
    let (_, response) = call(
        admin,
        "inbuxa:Relay/set",
        json!({"update": {&id: {"rejoin": true}}}),
    )
    .await;
    let again = JoinToken::decode(
        response["updated"][&id]["joinToken"]
            .as_str()
            .unwrap_or_else(|| panic!("rejoin token: {response}")),
        now,
    )
    .unwrap();
    assert_eq!(again.relay_id, id);
    assert_eq!(again.ca_spki, first.ca_spki);
    assert_ne!(again.secret, first.secret);
    assert_eq!(get(admin, &id).await["joinState"], "waiting");

    // Nobody in a tenant reaches relays
    let tenant = admin
        .registry_create_object(Tenant {
            name: "Relay tenant".to_string(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Domain {
            name: "relays.example.org".to_string(),
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
            "tadmin@relays.example.org",
            "tenant-admin-secret-8841",
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
    for (method, arguments) in [
        ("inbuxa:Relay/get", json!({"ids": null})),
        (
            "inbuxa:Relay/set",
            json!({"create": {"x": relay("Tenant's own")}}),
        ),
    ] {
        let (name, response) = call(&t_admin, method, arguments).await;
        assert_eq!(name, "error", "{method} by a tenant: {response}");
    }

    // Destroyed
    let (_, response) = call(admin, "inbuxa:Relay/set", json!({"destroy": [&other]})).await;
    assert_eq!(response["destroyed"][0], other.as_str(), "{response}");
    let (_, response) = call(admin, "inbuxa:Relay/get", json!({"ids": [&other]})).await;
    assert_eq!(response["notFound"][0], other.as_str(), "{response}");

    // Every change audited, with neither the key nor a token in it
    let (_, response) = call(
        admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:Relay"}}),
    )
    .await;
    let ids = response["ids"].clone();
    assert!(
        ids.as_array().is_some_and(|ids| ids.len() >= 6),
        "creates, updates, rejoin and destroy audited: {response}"
    );
    let (_, response) = call(admin, "inbuxa:AuditEvent/get", json!({"ids": ids})).await;
    let text = response.to_string();
    assert!(!text.contains("TUFSS0VS"), "the private key was audited");
    assert!(!text.contains(&token), "a join token was audited");
    assert!(!text.contains(&again.encode()), "a join token was audited");

    call(admin, "inbuxa:Relay/set", json!({"destroy": [&id]})).await;
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn relay_tests() {
    let mut test = TestServerBuilder::new("relay_tests")
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
