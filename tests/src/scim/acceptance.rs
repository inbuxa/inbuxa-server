/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! SCIM acceptance tests, from `docs/spec/features/scim.md`. Each check
//! names its test number or requirement.

use crate::{
    scim::{
        PRINCIPAL_SECRET, SCIM_DOMAIN, ScimClient, ScimTest, api_key, api_key_with_id,
        create_principal, full_permissions, group_body, patch_body, query, user_body,
    },
    utils::{account::Account, server::TestServer, smtp::SmtpConnection},
};
use registry::{
    schema::{
        enums::{Permission, TenantStorageQuota},
        prelude::{ObjectType, Property},
        structs::{
            self, Action, CertificateManagement, DataRetention, DkimManagement, DnsManagement,
            Domain, PasswordCredential, Permissions, PermissionsList, Tenant, UserAccount,
        },
    },
    types::{duration::Duration, list::List, map::Map},
};
use scim_proto::{
    MESSAGE_BULK_REQUEST, MESSAGE_SEARCH_REQUEST, SCHEMA_ENTERPRISE_USER, SCHEMA_USER,
};
use serde_json::json;
use std::str::FromStr;
use trc::{Collector, MetricType};
use types::id::Id;
use utils::map::vec_map::VecMap;

const CLOSED: &str = "closed.example.com";
const USER_SECRET: &str = "scim acceptance user passphrase";

pub async fn test(test: &TestServer, scim: &ScimTest) {
    println!("Running SCIM acceptance tests...");
    let admin = test.account("admin");
    let closed_id = admin
        .registry_create_object(Domain {
            is_enabled: true,
            name: CLOSED.to_string(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    admin.registry_create_object(Action::InvalidateCaches).await;

    discovery(scim).await;
    authentication(test, scim).await;
    domains(test, scim, closed_id).await;
    users(test, scim).await;
    groups(scim).await;
    patching(scim).await;
    conditional(scim).await;
    queries(scim).await;
    bulk(scim).await;
    suspension(test, scim).await;
    deletion(test, scim).await;
    adoption(test, scim).await;
    tenants(test, scim).await;
    authority(test, scim, closed_id).await;
    rate_limits(test, scim).await;

    admin
        .registry_destroy(ObjectType::Domain, [closed_id])
        .await;
}

/// Test 10 (SCIM-2 to SCIM-6).
async fn discovery(scim: &ScimTest) {
    let anonymous = ScimClient::anonymous();
    let config = anonymous.get("/ServiceProviderConfig").await;
    config.assert_status(200);
    assert_eq!(
        config.header("content-type").as_deref(),
        Some("application/scim+json")
    );
    assert_eq!(config.json["bulk"]["maxOperations"], json!(1000), "SCIM-4");
    assert_eq!(
        config.json["bulk"]["maxPayloadSize"],
        json!(1048576),
        "SCIM-4"
    );
    assert_eq!(config.json["filter"]["maxResults"], json!(200), "SCIM-4");
    assert_eq!(
        config.json["changePassword"]["supported"],
        json!(false),
        "SCIM-4"
    );
    assert_eq!(
        config.json["pagination"]["cursorTimeout"],
        json!(3600),
        "SCIM-4"
    );
    assert_eq!(
        config.json["interopProfileConformant"],
        json!(false),
        "SCIM-4"
    );
    assert!(
        !config.body.contains("stalw"),
        "SCIM-4: documentation is INBUXA's own"
    );

    let types = anonymous.get("/ResourceTypes").await;
    types.assert_status(200);
    assert_eq!(types.total_results(), 2, "SCIM-5");
    assert!(!types.body.contains("schemaExtensions\":[{"), "SCIM-5");
    anonymous
        .get("/ResourceTypes/User")
        .await
        .assert_status(200);

    let schemas = anonymous.get("/Schemas").await;
    schemas.assert_status(200);
    assert!(!schemas.body.contains("\"password\""), "SCIM-6");
    anonymous
        .get(&format!("/Schemas/{SCHEMA_USER}"))
        .await
        .assert_status(200);

    anonymous
        .get("/Schemas?filter=id%20eq%20%22x%22")
        .await
        .assert_error(403, None);
    anonymous.get("/Nothing").await.assert_error(404, None);
    let wrong = anonymous
        .request(reqwest::Method::DELETE, "/ServiceProviderConfig", None, &[])
        .await;
    wrong.assert_error(405, None);
    assert!(wrong.header("allow").is_some(), "SCIM-2: Allow");
    let options = anonymous
        .request(reqwest::Method::OPTIONS, "/Users", None, &[])
        .await;
    assert_eq!(options.status, 204, "SCIM-2");
    anonymous.get("/Me").await.assert_error(501, None);
    scim.client.get("/Me").await.assert_error(501, None);
}

/// Tests 6, 7, 8 (SCIM-7, SCIM-9, SCIM-11, SCIM-13, SCIM-52).
async fn authentication(test: &TestServer, scim: &ScimTest) {
    let admin = test.account("admin");

    // Test 6: missing, Basic, a bearer that isn't an API key
    for client in [
        ScimClient::anonymous(),
        ScimClient::with_authorization(Some(format!(
            "Basic {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("scim-svc@{SCIM_DOMAIN}:{PRINCIPAL_SECRET}")
            )
        ))),
        ScimClient::bearer("not-an-api-key"),
        ScimClient::bearer("API_bm90IGEgcmVhbCBrZXk"),
    ] {
        let reply = client.get("/Users").await;
        reply.assert_error(401, None);
        assert!(
            reply
                .header("www-authenticate")
                .is_some_and(|h| h.starts_with("Bearer")),
            "test 6: {}",
            reply.body
        );
    }
    let basic = ScimClient::with_authorization(Some("Basic eDp5".into()))
        .get("/Users")
        .await;
    basic.assert_detail_contains("Bearer");

    // A key from a disallowed address, and a deleted key
    let principal = Account::new(
        "scim-svc@scim.example.com",
        PRINCIPAL_SECRET,
        &[],
        "",
        scim.principal_id,
    );
    let (fenced_id, fenced) = api_key_with_id(&principal, json!({"@type": "Inherit"})).await;
    principal
        .jmap_update(
            "x:ApiKey",
            [(
                fenced_id.to_string(),
                json!({"allowedIps": {"10.9.9.9": true}}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    ScimClient::bearer(&fenced)
        .get("/Users")
        .await
        .assert_error(401, None);
    let (doomed_id, doomed) = api_key_with_id(&principal, json!({"@type": "Inherit"})).await;
    ScimClient::bearer(&doomed)
        .get("/Users")
        .await
        .assert_status(200);
    principal
        .registry_destroy(ObjectType::ApiKey, [doomed_id])
        .await;
    ScimClient::bearer(&doomed)
        .get("/Users")
        .await
        .assert_error(401, None);

    // A Replace key without scimAccess: 403 naming it
    let narrow = api_key(
        admin,
        &principal,
        json!({"@type": "Replace", "permissions": {"authenticate": true, "sysAccountGet": true}}),
    )
    .await;
    ScimClient::bearer(&narrow)
        .get("/Users")
        .await
        .assert_error(403, None)
        .assert_detail_contains("scimAccess");

    // Test 7: no sysAccountDestroy: DELETE refused, suspension works
    let no_destroy = api_key(
        admin,
        &principal,
        json!({"@type": "Disable", "permissions": {"sysAccountDestroy": true}}),
    )
    .await;
    let limited = ScimClient::bearer(&no_destroy);
    let id = scim.create_user(&format!("leaver@{SCIM_DOMAIN}")).await;
    limited
        .delete(&format!("/Users/{id}"))
        .await
        .assert_error(403, None)
        .assert_detail_contains("sysAccountDestroy");
    let patched = limited
        .patch(
            &format!("/Users/{id}"),
            patch_body(json!([{"op": "replace", "path": "active", "value": false}])),
        )
        .await;
    patched.assert_status(200);
    assert_eq!(patched.json["active"], json!(false), "test 7");
    scim.destroy(&format!("/Users/{id}")).await;

    // Test 8: the principal can't deactivate, rename or delete itself
    let me = format!("/Users/{}", scim.principal_id);
    let before = scim.client.get(&me).await;
    before.assert_status(200);
    for body in [
        patch_body(json!([{"op": "replace", "path": "active", "value": false}])),
        patch_body(
            json!([{"op": "replace", "path": "userName", "value": format!("other@{SCIM_DOMAIN}")}]),
        ),
    ] {
        scim.client.patch(&me, body).await.assert_error(403, None);
    }
    scim.client.delete(&me).await.assert_error(403, None);
    let after = scim.client.get(&me).await;
    assert_eq!(after.etag(), before.etag(), "test 8: unchanged");
}

/// Tests 11, 12, 13 (SCIM-15, SCIM-16, SCIM-18).
async fn domains(test: &TestServer, scim: &ScimTest, closed_id: Id) {
    let admin = test.account("admin");

    // Test 11
    scim.client
        .post("/Users", user_body(&format!("nobody@{CLOSED}")))
        .await
        .assert_error(400, Some("invalidValue"))
        .assert_detail_contains(CLOSED);
    scim.client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": format!("half@{SCIM_DOMAIN}"),
                "emails": [{"value": format!("half@{CLOSED}")}],
            }),
        )
        .await
        .assert_error(400, Some("invalidValue"));
    scim.client
        .get(&query(
            "/Users",
            &format!("userName eq \"half@{SCIM_DOMAIN}\""),
        ))
        .await
        .assert_status(200);
    scim.client
        .post("/Users", user_body("not an address"))
        .await
        .assert_error(400, Some("invalidValue"))
        .assert_detail_contains("is not a valid email address");

    // Test 12: an account on a closed domain isn't listed
    let hidden = admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: "hidden".to_string(),
            domain_id: closed_id,
            ..Default::default()
        }))
        .await;
    scim.client
        .get("/Users?count=200")
        .await
        .assert_status(200)
        .assert_lacks_id(&hidden.to_string());
    scim.client
        .get(&format!("/Users/{hidden}"))
        .await
        .assert_error(404, None);

    // Test 13: a principal on a closed domain can't create groups
    let outsider_id =
        create_principal(admin, "outside-svc", closed_id, None, full_permissions()).await;
    let outsider = Account::new(
        "outside-svc@closed.example.com",
        PRINCIPAL_SECRET,
        &[],
        "",
        outsider_id,
    );
    let token = api_key(admin, &outsider, json!({"@type": "Inherit"})).await;
    let client = ScimClient::bearer(&token);
    client
        .post("/Groups", group_body("Closed Team"))
        .await
        .assert_error(400, Some("invalidValue"))
        .assert_detail_contains(CLOSED);
    let id = client
        .post("/Users", user_body(&format!("managed@{SCIM_DOMAIN}")))
        .await
        .assert_status(201)
        .id();
    scim.destroy(&format!("/Users/{id}")).await;

    admin
        .registry_destroy(ObjectType::Account, [hidden, outsider_id])
        .await;
}

/// Tests 15 to 20 (SCIM-21 to SCIM-29).
async fn users(test: &TestServer, scim: &ScimTest) {
    let admin = test.account("admin");

    // Test 16: a duplicate address is 409 and changes nothing
    let first = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": format!("Jane.Doe@{SCIM_DOMAIN}"),
                "displayName": "Jane Doe",
                "emails": [
                    {"value": format!("jane.doe@{SCIM_DOMAIN}"), "primary": true, "type": "work"},
                    {"value": format!("jd@{SCIM_DOMAIN}")},
                    {"value": format!("JD@{SCIM_DOMAIN}"), "type": "home"},
                ],
            }),
        )
        .await;
    first.assert_status(201);
    let jane = first.id();
    assert_eq!(
        first.json["userName"],
        json!(format!("jane.doe@{SCIM_DOMAIN}")),
        "SCIM-22"
    );
    assert!(
        first.header("location").is_some_and(|l| l.ends_with(&jane)),
        "SCIM-39"
    );
    assert!(
        first.etag().is_some_and(|e| e.starts_with("W/\"")),
        "SCIM-44"
    );
    assert!(first.json["meta"].get("lastModified").is_none(), "SCIM-30");
    // Test 17: primary first, read-only; the duplicate alias skipped
    assert_eq!(
        first.json["emails"],
        json!([
            {"value": format!("jane.doe@{SCIM_DOMAIN}"), "type": "work", "primary": true},
            {"value": format!("jd@{SCIM_DOMAIN}"), "primary": false},
        ]),
        "test 17"
    );
    scim.client
        .post("/Users", user_body(&format!("JANE.DOE@{SCIM_DOMAIN}")))
        .await
        .assert_error(409, Some("uniqueness"));
    scim.client
        .post("/Users", user_body(&format!("jd@{SCIM_DOMAIN}")))
        .await
        .assert_error(409, Some("uniqueness"));
    let unchanged = scim.client.get(&format!("/Users/{jane}")).await;
    assert_eq!(unchanged.etag(), first.etag(), "test 16");

    // Test 17: the primary through emails is 400 mutability; an alias
    // another account holds is 409; PATCH remove drops an alias
    scim.client
        .patch(
            &format!("/Users/{jane}"),
            patch_body(json!([{
                "op": "remove",
                "path": format!("emails[value eq \"jane.doe@{SCIM_DOMAIN}\"]"),
            }])),
        )
        .await
        .assert_error(400, Some("mutability"))
        .assert_detail_contains("userName");
    let other = scim.create_user(&format!("other@{SCIM_DOMAIN}")).await;
    scim.client
        .patch(
            &format!("/Users/{other}"),
            patch_body(json!([{"op": "add", "path": "emails", "value": [{"value": format!("jd@{SCIM_DOMAIN}")}]}])),
        )
        .await
        .assert_error(409, Some("uniqueness"));
    let dropped = scim
        .client
        .patch(
            &format!("/Users/{jane}"),
            patch_body(
                json!([{"op": "remove", "path": format!("emails[value eq \"jd@{SCIM_DOMAIN}\"]")}]),
            ),
        )
        .await;
    dropped.assert_status(200);
    assert_eq!(
        dropped.json["emails"].as_array().unwrap().len(),
        1,
        "test 17"
    );

    // Test 15: a rename moves the account; the old address is released
    let renamed = scim
        .client
        .patch(
            &format!("/Users/{jane}"),
            patch_body(json!([{"op": "replace", "path": "userName", "value": format!("jane.smith@{SCIM_DOMAIN}")}])),
        )
        .await;
    renamed.assert_status(200);
    assert_eq!(renamed.json["id"], json!(jane), "SCIM-21");
    assert_eq!(
        renamed.json["emails"].as_array().unwrap().len(),
        1,
        "SCIM-23"
    );
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.mail_from("sender@remote.example.org", 2).await;
    lmtp.rcpt_to(&format!("jane.doe@{SCIM_DOMAIN}"), 5).await;
    lmtp.rcpt_to(&format!("jane.smith@{SCIM_DOMAIN}"), 2).await;
    lmtp.quit().await;

    // Test 18: locales and time zones
    for (sent, stored) in [
        (json!({"locale": "EN-us"}), "en-US"),
        (json!({"locale": "ca-ES@valencia"}), "ca-ES-valencia"),
        (json!({"preferredLanguage": "fr-FR"}), "fr-FR"),
        (
            json!({"locale": "de-DE", "preferredLanguage": "fr-FR"}),
            "de-DE",
        ),
    ] {
        let mut body = user_body(&format!("jane.smith@{SCIM_DOMAIN}"));
        body.as_object_mut()
            .unwrap()
            .extend(sent.as_object().unwrap().clone());
        let reply = scim.client.put(&format!("/Users/{jane}"), body).await;
        reply.assert_status(200);
        assert_eq!(reply.json["locale"], json!(stored), "test 18 {sent}");
        assert_eq!(
            reply.json["preferredLanguage"],
            json!(stored),
            "test 18 {sent}"
        );
    }
    for bad in [
        json!({"locale": "xx-YY"}),
        json!({"timezone": "Mars/Olympus"}),
    ] {
        let mut body = user_body(&format!("jane.smith@{SCIM_DOMAIN}"));
        body.as_object_mut()
            .unwrap()
            .extend(bad.as_object().unwrap().clone());
        scim.client
            .put(&format!("/Users/{jane}"), body)
            .await
            .assert_error(400, Some("invalidValue"));
    }
    let mut body = user_body(&format!("jane.smith@{SCIM_DOMAIN}"));
    body["timezone"] = json!("europe/madrid");
    let reply = scim.client.put(&format!("/Users/{jane}"), body).await;
    assert_eq!(reply.json["timezone"], json!("Europe/Madrid"), "test 18");

    // SCIM-24: the display name by precedence, and returned twice
    let reply = scim
        .client
        .put(
            &format!("/Users/{jane}"),
            json!({
                "schemas": [SCHEMA_USER],
                "userName": format!("jane.smith@{SCIM_DOMAIN}"),
                "name": {"givenName": "Jane", "familyName": "Smith"},
            }),
        )
        .await;
    assert_eq!(reply.json["displayName"], json!("Jane Smith"), "SCIM-24");
    assert_eq!(
        reply.json["name"]["formatted"],
        json!("Jane Smith"),
        "SCIM-24"
    );

    // SCIM-33: ignored attributes, never echoed; unknown ones refused
    let reply = scim
        .client
        .put(
            &format!("/Users/{jane}"),
            json!({
                "schemas": [SCHEMA_USER, SCHEMA_ENTERPRISE_USER],
                "userName": format!("jane.smith@{SCIM_DOMAIN}"),
                "password": "not stored anywhere",
                "title": "Engineer",
                "phoneNumbers": [{"value": "555-0100"}],
                SCHEMA_ENTERPRISE_USER: {"department": "Sales"},
            }),
        )
        .await;
    reply.assert_status(200);
    assert!(!reply.body.contains("not stored anywhere"), "SCIM-33");
    assert!(!reply.body.contains("Engineer"), "SCIM-33");
    for bad in [
        json!({"schemas": [SCHEMA_USER], "userName": format!("jane.smith@{SCIM_DOMAIN}"), "dispalyName": "x"}),
        json!({"schemas": ["urn:example:unknown"], "userName": format!("jane.smith@{SCIM_DOMAIN}")}),
        json!({"userName": format!("jane.smith@{SCIM_DOMAIN}")}),
    ] {
        scim.client
            .put(&format!("/Users/{jane}"), bad)
            .await
            .assert_error(400, Some("invalidSyntax"));
    }

    // Test 19: active on an Inherit account leaves exactly Inherit
    let id = Id::from_str(&jane).unwrap();
    for active in [false, true] {
        scim.client
            .patch(
                &format!("/Users/{jane}"),
                patch_body(json!([{"op": "Replace", "value": {"active": if active { "True" } else { "False" }}}])),
            )
            .await
            .assert_status(200);
        let account = admin.registry_get::<structs::Account>(id).await;
        let structs::Account::User(user) = account else {
            panic!()
        };
        if active {
            assert_eq!(user.permissions, Permissions::Inherit, "test 19");
        } else {
            assert_ne!(user.permissions, Permissions::Inherit, "test 19");
        }
    }
    // ... and custom permissions come back as they were
    let custom = Permissions::Merge(PermissionsList {
        enabled_permissions: Map::new(vec![Permission::JmapEmailGet]),
        disabled_permissions: Map::new(vec![Permission::JmapEmailQuery]),
    });
    admin
        .registry_update_object(
            ObjectType::Account,
            id,
            json!({ Property::Permissions: custom }),
        )
        .await;
    for active in [false, true] {
        scim.client
            .patch(
                &format!("/Users/{jane}"),
                patch_body(json!([{"op": "replace", "path": "active", "value": active}])),
            )
            .await
            .assert_status(200);
    }
    let structs::Account::User(user) = admin.registry_get::<structs::Account>(id).await else {
        panic!()
    };
    assert_eq!(user.permissions, custom, "test 19");

    // Test 20: externalId unique in a tenant, matched case-exactly
    scim.client
        .patch(
            &format!("/Users/{jane}"),
            patch_body(json!([{"op": "add", "path": "externalId", "value": "EXT-1"}])),
        )
        .await
        .assert_status(200);
    scim.client
        .patch(
            &format!("/Users/{other}"),
            patch_body(json!([{"op": "add", "path": "externalId", "value": "EXT-1"}])),
        )
        .await
        .assert_error(409, Some("uniqueness"));
    let found = scim
        .client
        .get(&query("/Users", "externalId eq \"EXT-1\""))
        .await;
    assert_eq!(found.total_results(), 1, "test 20");
    let found = scim
        .client
        .get(&query("/Users", "externalId eq \"ext-1\""))
        .await;
    assert_eq!(found.total_results(), 0, "test 20: case-exact");
    scim.client
        .patch(
            &format!("/Users/{other}"),
            patch_body(json!([{"op": "add", "path": "externalId", "value": ""}])),
        )
        .await
        .assert_error(400, Some("invalidValue"));

    // SCIM-28: groups is read-only
    scim.client
        .patch(
            &format!("/Users/{jane}"),
            patch_body(json!([{"op": "add", "path": "groups", "value": [{"value": "x"}]}])),
        )
        .await
        .assert_error(400, Some("mutability"));

    scim.destroy(&format!("/Users/{jane}")).await;
    scim.destroy(&format!("/Users/{other}")).await;
}

/// Test 21 (SCIM-34 to SCIM-38).
async fn groups(scim: &ScimTest) {
    let sales = scim.client.post("/Groups", group_body("Sales EMEA")).await;
    sales.assert_status(201);
    let sales_id = sales.id();
    scim.client
        .post("/Groups", group_body("sales emea"))
        .await
        .assert_error(409, Some("uniqueness"));

    // SCIM-35: the address, and a second group taking the suffix
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.mail_from("sender@remote.example.org", 2).await;
    lmtp.rcpt_to(&format!("sales-emea@{SCIM_DOMAIN}"), 2).await;
    lmtp.quit().await;
    let renamed = scim
        .client
        .patch(
            &format!("/Groups/{sales_id}"),
            patch_body(json!([{"op": "replace", "path": "displayName", "value": "Sales Europe"}])),
        )
        .await;
    renamed.assert_status(200);
    let second = scim.create_group("Sales-EMEA").await;
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.mail_from("sender@remote.example.org", 2).await;
    lmtp.rcpt_to(&format!("sales-emea-2@{SCIM_DOMAIN}"), 2)
        .await;
    lmtp.quit().await;

    // A group as member, an unknown member: 400
    for member in [second.clone(), "zzzzzzzz".to_string()] {
        scim.client
            .patch(
                &format!("/Groups/{sales_id}"),
                patch_body(json!([{"op": "add", "path": "members", "value": [{"value": member}]}])),
            )
            .await
            .assert_error(400, Some("invalidValue"));
    }

    // SCIM-38: the version changes when a member is added
    let user = scim.create_user(&format!("member@{SCIM_DOMAIN}")).await;
    let before = scim.client.get(&format!("/Groups/{sales_id}")).await;
    let after = scim
        .client
        .patch(
            &format!("/Groups/{sales_id}"),
            patch_body(json!([{"op": "add", "path": "members", "value": [{"value": user}]}])),
        )
        .await;
    after.assert_status(200);
    assert_ne!(after.etag(), before.etag(), "SCIM-38");
    assert_eq!(after.json["members"][0]["value"], json!(user), "SCIM-36");
    assert_eq!(after.json["members"][0]["type"], json!("User"), "SCIM-36");
    let member = scim.client.get(&format!("/Users/{user}")).await;
    assert_eq!(
        member.json["groups"][0]["value"],
        json!(sales_id),
        "SCIM-28"
    );
    assert_eq!(
        member.json["groups"][0]["display"],
        json!("Sales Europe"),
        "SCIM-28"
    );

    // Test 22: removing a non-member succeeds
    scim.client
        .patch(
            &format!("/Groups/{sales_id}"),
            patch_body(json!([{"op": "remove", "path": "members[value eq \"zzzzzzzz\"]"}])),
        )
        .await
        .assert_status(200);
    // SCIM-36: remove without a filter empties the group
    let emptied = scim
        .client
        .patch(
            &format!("/Groups/{sales_id}"),
            patch_body(json!([{"op": "remove", "path": "members"}])),
        )
        .await;
    assert_eq!(emptied.json["members"], json!([]), "SCIM-36");

    // SCIM-37: over 200 members needs excludedAttributes=members
    let mut members = Vec::new();
    let mut operations = Vec::new();
    for n in 0..201 {
        operations.push(json!({
            "method": "POST",
            "path": "/Users",
            "bulkId": format!("m{n}"),
            "data": user_body(&format!("crowd{n}@{SCIM_DOMAIN}")),
        }));
    }
    let created = scim
        .client
        .post(
            "/Bulk",
            json!({"schemas": [MESSAGE_BULK_REQUEST], "Operations": operations}),
        )
        .await;
    created.assert_status(200);
    for result in created.json["Operations"].as_array().unwrap() {
        assert_eq!(result["status"], json!("201"), "{result}");
        let id = result["location"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        members.push(json!({"value": id}));
    }
    scim.client
        .patch(
            &format!("/Groups/{sales_id}"),
            patch_body(json!([{"op": "add", "path": "members", "value": members}])),
        )
        .await
        .assert_status(200);
    scim.client
        .get(&format!("/Groups/{sales_id}"))
        .await
        .assert_error(400, Some("tooMany"));
    scim.client
        .get(&format!("/Groups/{sales_id}?excludedAttributes=members"))
        .await
        .assert_status(200);

    // Test 25: count is capped at 200; count=0 gives totals only
    let page = scim.client.get("/Users?count=500").await;
    assert_eq!(page.json["itemsPerPage"], json!(200), "test 25");
    assert!(page.total_results() > 200, "test 25");
    let totals = scim.client.get("/Users?count=0").await;
    assert!(totals.json.get("Resources").is_none(), "test 25");
    assert_eq!(totals.total_results(), page.total_results(), "test 25");
    let a = scim.client.get("/Users?startIndex=11&count=10").await;
    let b = scim.client.get("/Users?startIndex=11&count=10").await;
    assert_eq!(a.resource_ids(), b.resource_ids(), "test 25: stable");
    let mut ids = page.resource_ids();
    let sorted = {
        let mut s = ids.clone();
        s.sort_by_key(|id| Id::from_str(id).unwrap().id());
        s
    };
    assert_eq!(ids, sorted, "SCIM-47");
    let descending = scim
        .client
        .get("/Users?count=200&sortBy=userName&sortOrder=descending")
        .await;
    descending.assert_status(200);
    scim.client
        .get("/Users?sortBy=title")
        .await
        .assert_error(400, Some("invalidValue"));

    // Test 26: a cursor walk, and cursors that don't match
    let mut seen = Vec::new();
    let mut cursor = String::new();
    loop {
        let page = scim
            .client
            .get(&format!("/Users?count=100&cursor={cursor}"))
            .await;
        page.assert_status(200);
        seen.extend(page.resource_ids());
        match page.json["nextCursor"].as_str() {
            Some(next) => cursor = next.to_string(),
            None => break,
        }
    }
    ids.sort();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len() as u64, page.total_results(), "test 26");
    let first = scim.client.get("/Users?count=100&cursor=").await;
    let next = first.json["nextCursor"].as_str().unwrap().to_string();
    scim.client
        .get(&format!("/Users?count=50&cursor={next}"))
        .await
        .assert_error(400, Some("invalidCount"));
    scim.client
        .get(&format!(
            "{}&count=100&cursor={next}",
            query("/Users", "externalId eq \"nobody\"")
        ))
        .await
        .assert_error(400, Some("invalidCursor"));
    let mut tampered = next.clone().into_bytes();
    tampered[4] = if tampered[4] == b'A' { b'B' } else { b'A' };
    scim.client
        .get(&format!(
            "/Users?count=100&cursor={}",
            String::from_utf8(tampered).unwrap()
        ))
        .await
        .assert_error(400, Some("invalidCursor"));
    scim.client
        .get("/Users?cursor=&startIndex=1")
        .await
        .assert_error(400, Some("invalidValue"));

    // Test 24: an unindexed filter over 200 candidates
    scim.client
        .get(&query("/Users", "active eq false"))
        .await
        .assert_error(400, Some("tooMany"));

    // Clean up
    let mut operations = vec![];
    for member in &members {
        operations.push(json!({
            "method": "DELETE",
            "path": format!("/Users/{}", member["value"].as_str().unwrap()),
        }));
    }
    scim.client
        .post(
            "/Bulk",
            json!({"schemas": [MESSAGE_BULK_REQUEST], "Operations": operations}),
        )
        .await
        .assert_status(200);
    scim.destroy(&format!("/Groups/{sales_id}")).await;
    scim.destroy(&format!("/Groups/{second}")).await;
    scim.destroy(&format!("/Users/{user}")).await;
}

/// Test 22 (SCIM-42).
async fn patching(scim: &ScimTest) {
    let id = scim.create_user(&format!("patchy@{SCIM_DOMAIN}")).await;
    let before = scim.client.get(&format!("/Users/{id}")).await;
    scim.client
        .patch(
            &format!("/Users/{id}"),
            patch_body(json!([
                {"op": "replace", "path": "displayName", "value": "Changed"},
                {"op": "replace", "path": "nothing.here", "value": "x"},
            ])),
        )
        .await
        .assert_error(400, Some("invalidPath"));
    let after = scim.client.get(&format!("/Users/{id}")).await;
    assert_eq!(after.etag(), before.etag(), "test 22: nothing changed");
    // Entra's shape: Replace, a sub-attribute, an extension path
    let reply = scim
        .client
        .patch(
            &format!("/Users/{id}"),
            patch_body(json!([
                {"op": "Replace", "path": "name.givenName", "value": "Pat"},
                {"op": "Replace", "path": "displayName", "value": "Pat Chy"},
                {"op": "Add", "path": format!("{SCHEMA_ENTERPRISE_USER}:department"), "value": "Ops"},
            ])),
        )
        .await;
    reply.assert_status(200);
    assert_eq!(reply.json["displayName"], json!("Pat Chy"), "SCIM-42");
    scim.client
        .patch(
            &format!("/Users/{id}"),
            patch_body(json!([{"op": "remove"}])),
        )
        .await
        .assert_error(400, None);
    scim.destroy(&format!("/Users/{id}")).await;
}

/// Test 23 (SCIM-44).
async fn conditional(scim: &ScimTest) {
    let id = scim.create_user(&format!("etag@{SCIM_DOMAIN}")).await;
    let path = format!("/Users/{id}");
    let current = scim.client.get(&path).await;
    let etag = current.etag().unwrap();
    let not_modified = scim
        .client
        .request(
            reqwest::Method::GET,
            &path,
            None,
            &[("if-none-match", &etag)],
        )
        .await;
    assert_eq!(not_modified.status, 304, "test 23");
    scim.client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "displayName", "value": "Moved on"}])),
        )
        .await
        .assert_status(200);
    for (method, body) in [
        (
            reqwest::Method::PUT,
            Some(user_body(&format!("etag@{SCIM_DOMAIN}"))),
        ),
        (
            reqwest::Method::PATCH,
            Some(patch_body(
                json!([{"op": "replace", "path": "displayName", "value": "x"}]),
            )),
        ),
        (reqwest::Method::DELETE, None),
    ] {
        scim.client
            .request(method, &path, body, &[("if-match", &etag)])
            .await
            .assert_error(412, None);
    }
    scim.destroy(&path).await;
}

/// Test 24 (SCIM-45, SCIM-46, SCIM-50).
async fn queries(scim: &ScimTest) {
    let id = scim
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": format!("findme@{SCIM_DOMAIN}"),
                "displayName": "Find Me",
                "externalId": "FIND-1",
                "emails": [{"value": format!("found@{SCIM_DOMAIN}")}],
            }),
        )
        .await
        .assert_status(201)
        .id();
    let group = scim
        .client
        .post(
            "/Groups",
            json!({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Finders", "members": [{"value": id}]}),
        )
        .await
        .assert_status(201)
        .id();
    for filter in [
        format!("id eq \"{id}\""),
        "externalId eq \"FIND-1\"".to_string(),
        format!("userName eq \"FINDME@{SCIM_DOMAIN}\""),
        format!("emails eq \"found@{SCIM_DOMAIN}\""),
        format!("emails.value eq \"findme@{SCIM_DOMAIN}\""),
        format!("groups eq \"{group}\""),
        format!("groups.value eq \"{group}\" and displayName eq \"find me\""),
        format!("userName eq \"findme@{SCIM_DOMAIN}\" and active eq true"),
        format!("userName eq \"findme@{SCIM_DOMAIN}\" and name.formatted eq \"Find Me\""),
    ] {
        let reply = scim.client.get(&query("/Users", &filter)).await;
        reply.assert_status(200);
        assert_eq!(reply.total_results(), 1, "{filter}: {}", reply.body);
        reply.assert_contains_id(&id);
    }
    for filter in [
        format!("members eq \"{id}\""),
        "displayName eq \"finders\"".to_string(),
    ] {
        let reply = scim.client.get(&query("/Groups", &filter)).await;
        assert_eq!(reply.total_results(), 1, "{filter}: {}", reply.body);
    }
    let empty = scim
        .client
        .get(&query("/Users", "userName eq \"no@one.example\""))
        .await;
    empty.assert_status(200);
    assert_eq!(empty.total_results(), 0, "SCIM-45: an empty ListResponse");
    for filter in [
        "userName co \"find\"",
        "userName eq \"a\" or userName eq \"b\"",
        "title pr",
        "emails[type eq \"work\"]",
        "title eq \"x\"",
    ] {
        scim.client
            .get(&query("/Users", filter))
            .await
            .assert_error(400, Some("invalidFilter"));
    }
    let searched = scim
        .client
        .post(
            "/Users/.search",
            json!({"schemas": [MESSAGE_SEARCH_REQUEST], "filter": "externalId eq \"FIND-1\"", "attributes": ["userName"]}),
        )
        .await;
    assert_eq!(searched.total_results(), 1, "SCIM-50");
    assert!(
        searched.json["Resources"][0].get("displayName").is_none(),
        "SCIM-40"
    );
    let both = scim
        .client
        .post(
            "/.search",
            json!({"schemas": [MESSAGE_SEARCH_REQUEST], "count": 200}),
        )
        .await;
    both.assert_status(200);
    let kinds = both.json["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["schemas"][0].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let first_group = kinds.iter().position(|k| k.ends_with("Group")).unwrap();
    assert!(
        kinds[first_group..].iter().all(|k| k.ends_with("Group")),
        "SCIM-50: users first"
    );

    scim.destroy(&format!("/Groups/{group}")).await;
    scim.destroy(&format!("/Users/{id}")).await;
}

/// Test 27 (SCIM-51).
async fn bulk(scim: &ScimTest) {
    let reply = scim
        .client
        .post(
            "/Bulk",
            json!({
                "schemas": [MESSAGE_BULK_REQUEST],
                "Operations": [
                    {"method": "POST", "path": "/Users", "bulkId": "u1", "data": user_body(&format!("bulk1@{SCIM_DOMAIN}"))},
                    {"method": "POST", "path": "/Groups", "bulkId": "g1", "data": {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                        "displayName": "Bulk Team",
                        "members": [{"value": "bulkId:u1"}],
                    }},
                    {"method": "PATCH", "path": "/Users/bulkId:u1", "data": patch_body(json!([{"op": "replace", "path": "displayName", "value": "Bulk One"}]))},
                    {"method": "DELETE", "path": "/Users/bulkId:nope"},
                ],
            }),
        )
        .await;
    reply.assert_status(200);
    let results = reply.json["Operations"].as_array().unwrap();
    assert_eq!(results[0]["status"], json!("201"), "{results:?}");
    assert_eq!(results[1]["status"], json!("201"), "{results:?}");
    assert_eq!(results[2]["status"], json!("200"), "{results:?}");
    assert_eq!(results[3]["status"], json!("409"), "{results:?}");
    assert!(results[0]["version"].is_string(), "SCIM-51");
    let user = results[0]["location"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let group = results[1]["location"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    let member = scim.client.get(&format!("/Users/{user}")).await;
    assert_eq!(member.json["groups"][0]["value"], json!(group), "SCIM-51");
    assert_eq!(member.json["displayName"], json!("Bulk One"), "SCIM-51");

    // failOnErrors stops after the first failure
    let reply = scim
        .client
        .post(
            "/Bulk",
            json!({
                "schemas": [MESSAGE_BULK_REQUEST],
                "failOnErrors": 1,
                "Operations": [
                    {"method": "POST", "path": "/Users", "bulkId": "x", "data": user_body("bad address")},
                    {"method": "POST", "path": "/Users", "bulkId": "y", "data": user_body(&format!("never@{SCIM_DOMAIN}"))},
                ],
            }),
        )
        .await;
    assert_eq!(
        reply.json["Operations"].as_array().unwrap().len(),
        1,
        "test 27"
    );

    // 1001 operations: 413
    let operations = (0..1001)
        .map(|_| json!({"method": "DELETE", "path": "/Users/x"}))
        .collect::<Vec<_>>();
    let reply = scim
        .client
        .post(
            "/Bulk",
            json!({"schemas": [MESSAGE_BULK_REQUEST], "Operations": operations}),
        )
        .await;
    assert_eq!(reply.status, 413, "test 27");

    scim.destroy(&format!("/Groups/{group}")).await;
    scim.destroy(&format!("/Users/{user}")).await;
}

/// An account made by an administrator, with a password.
async fn manual_user(test: &TestServer, scim: &ScimTest, name: &str) -> Id {
    test.account("admin")
        .registry_create_object(structs::Account::User(UserAccount {
            name: name.to_string(),
            domain_id: scim.domain_id,
            credentials: List::from_iter([structs::Credential::Password(PasswordCredential {
                secret: USER_SECRET.to_string(),
                ..Default::default()
            })]),
            ..Default::default()
        }))
        .await
}

/// Whether an IMAP LOGIN is accepted. A refusal may be a tagged `NO` or
/// the server closing the connection.
async fn imap_login(address: &str, ok: bool) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stream = tokio::net::TcpStream::connect("127.0.0.1:9991")
        .await
        .unwrap();
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    let greeting = lines.next_line().await.unwrap().unwrap_or_default();
    assert!(greeting.starts_with("* OK"), "{greeting}");
    writer
        .write_all(format!("a LOGIN \"{address}\" \"{USER_SECRET}\"\r\n").as_bytes())
        .await
        .unwrap();
    let mut accepted = false;
    while let Ok(Ok(Some(line))) =
        tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line()).await
    {
        if let Some(status) = line.strip_prefix("a ") {
            accepted = status.starts_with("OK");
            break;
        }
    }
    assert_eq!(accepted, ok, "IMAP login of {address}");
}

type IdleLines = tokio::io::Lines<tokio::io::BufReader<tokio::io::ReadHalf<tokio::net::TcpStream>>>;

/// An IMAP session in IDLE.
async fn idle_session(address: &str) -> (IdleLines, tokio::io::WriteHalf<tokio::net::TcpStream>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stream = tokio::net::TcpStream::connect("127.0.0.1:9991")
        .await
        .unwrap();
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    lines.next_line().await.unwrap();
    for (tag, command) in [
        ("a", format!("LOGIN \"{address}\" \"{USER_SECRET}\"")),
        ("b", "SELECT INBOX".to_string()),
    ] {
        writer
            .write_all(format!("{tag} {command}\r\n").as_bytes())
            .await
            .unwrap();
        loop {
            let line = lines.next_line().await.unwrap().unwrap();
            if let Some(status) = line.strip_prefix(&format!("{tag} ")) {
                assert!(status.starts_with("OK"), "{command}: {line}");
                break;
            }
        }
    }
    writer.write_all(b"c IDLE\r\n").await.unwrap();
    let line = lines.next_line().await.unwrap().unwrap();
    assert!(line.starts_with('+'), "IDLE: {line}");
    (lines, writer)
}

/// Whether the server ends an IDLE session within ten seconds.
async fn idle_ends(idle: &mut (IdleLines, tokio::io::WriteHalf<tokio::net::TcpStream>)) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(deadline, idle.0.next_line()).await {
            Ok(Ok(Some(line))) if line.starts_with("* BYE") => return true,
            Ok(Ok(Some(_))) => continue,
            Ok(Ok(None)) | Ok(Err(_)) => return true,
            Err(_) => return false,
        }
    }
}

/// Test 28 (SCIM-52): suspension stops sign-in, not mail.
async fn suspension(test: &TestServer, scim: &ScimTest) {
    let address = format!("suspended@{SCIM_DOMAIN}");
    let id = manual_user(test, scim, "suspended").await;
    imap_login(&address, true).await;

    // Credentials used, and cached, before the suspension
    let user = Account::new("suspended@scim.example.com", USER_SECRET, &[], "", id);
    let (_, user_key) = api_key_with_id(&user, json!({"@type": "Inherit"})).await;
    let basic = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{address}:{USER_SECRET}")
        )
    );
    let bearer = format!("Bearer {user_key}");
    for authorization in [&basic, &bearer] {
        assert_eq!(
            crate::scim::jmap_session_status(authorization).await,
            200,
            "test 28"
        );
    }
    let mut idle = idle_session(&address).await;

    scim.client
        .patch(
            &format!("/Users/{id}"),
            patch_body(json!([{"op": "replace", "path": "active", "value": false}])),
        )
        .await
        .assert_status(200);
    imap_login(&address, false).await;
    assert!(idle_ends(&mut idle).await, "test 28: an open IDLE is ended");
    for authorization in [&basic, &bearer] {
        let status = crate::scim::jmap_session_status(authorization).await;
        assert!(matches!(status, 401 | 403), "test 28: {status}");
    }
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "sender@remote.example.org",
        &[&address],
        "From: sender@remote.example.org\r\nSubject: still arrives\r\n\r\nHello\r\n",
    )
    .await;
    scim.client
        .patch(
            &format!("/Users/{id}"),
            patch_body(json!([{"op": "replace", "path": "active", "value": true}])),
        )
        .await
        .assert_status(200);
    imap_login(&address, true).await;
    scim.destroy(&format!("/Users/{id}")).await;
}

/// Test 29 (SCIM-52): deletion, and a held address.
async fn deletion(test: &TestServer, scim: &ScimTest) {
    let admin = test.account("admin");
    let address = format!("gone@{SCIM_DOMAIN}");
    let id = scim.create_user(&address).await;
    scim.client
        .delete(&format!("/Users/{id}"))
        .await
        .assert_status(204);
    scim.client
        .get(&format!("/Users/{id}"))
        .await
        .assert_error(404, None);
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.mail_from("sender@remote.example.org", 2).await;
    lmtp.rcpt_to(&address, 5).await;
    lmtp.quit().await;

    // With accounts held after deletion, the address stays reserved
    admin
        .registry_update_setting(
            DataRetention {
                archive_deleted_accounts_for: Some(Duration::from_millis(86_400_000)),
                ..Default::default()
            },
            &[Property::ArchiveDeletedAccountsFor],
        )
        .await;
    let held = format!("held@{SCIM_DOMAIN}");
    let id = scim.create_user(&held).await;
    scim.client
        .delete(&format!("/Users/{id}"))
        .await
        .assert_status(204);
    scim.client
        .post("/Users", user_body(&held))
        .await
        .assert_error(409, Some("uniqueness"));
    admin
        .registry_update_setting(
            DataRetention {
                archive_deleted_accounts_for: None,
                ..Default::default()
            },
            &[Property::ArchiveDeletedAccountsFor],
        )
        .await;
}

/// Test 30 (SCIM-32, SCIM-55, SCIM-56): an administrator's account is
/// found, adopted, and keeps its local settings.
async fn adoption(test: &TestServer, scim: &ScimTest) {
    let admin = test.account("admin");
    let id = manual_user(test, scim, "handmade").await;
    admin
        .registry_update_object(
            ObjectType::Account,
            id,
            json!({ Property::Roles: {"@type": "Admin"} }),
        )
        .await;
    let found = scim
        .client
        .get(&query(
            "/Users",
            &format!("userName eq \"handmade@{SCIM_DOMAIN}\""),
        ))
        .await;
    assert_eq!(found.total_results(), 1, "test 30");
    scim.client
        .post("/Users", user_body(&format!("handmade@{SCIM_DOMAIN}")))
        .await
        .assert_error(409, Some("uniqueness"));
    scim.client
        .patch(
            &format!("/Users/{id}"),
            patch_body(json!([{"op": "add", "path": "externalId", "value": "IDP-9"}])),
        )
        .await
        .assert_status(200);
    let structs::Account::User(user) = admin.registry_get::<structs::Account>(id).await else {
        panic!()
    };
    assert_eq!(user.external_id.as_deref(), Some("IDP-9"), "test 30");
    assert_eq!(user.roles, structs::UserRoles::Admin, "SCIM-32");
    assert_eq!(user.credentials.len(), 1, "SCIM-32");
    imap_login(&format!("handmade@{SCIM_DOMAIN}"), true).await;
    scim.destroy(&format!("/Users/{id}")).await;
}

/// Tests 9 and 14 (SCIM-12, SCIM-20).
async fn tenants(test: &TestServer, scim: &ScimTest) {
    let admin = test.account("admin");
    let _ = scim;
    for (name, allows_scim) in [("nosync", false), ("capped", true)] {
        let tenant = admin
            .registry_create_object(Tenant {
                name: name.to_string(),
                permissions: Permissions::Merge(PermissionsList {
                    disabled_permissions: if allows_scim {
                        Default::default()
                    } else {
                        Map::new(vec![Permission::ScimAccess])
                    },
                    enabled_permissions: if allows_scim {
                        Map::new(vec![Permission::ScimAccess, Permission::UnlimitedRequests])
                    } else {
                        Default::default()
                    },
                }),
                ..Default::default()
            })
            .await;
        let domain_name = format!("{name}.example.com");
        let domain = admin
            .registry_create_object(Domain {
                is_enabled: true,
                name: domain_name.clone(),
                certificate_management: CertificateManagement::Manual,
                dns_management: DnsManagement::Manual,
                dkim_management: DkimManagement::Manual,
                member_tenant_id: Some(tenant),
                allow_scim_provisioning: true,
                ..Default::default()
            })
            .await;
        let principal_id =
            create_principal(admin, "svc", domain, Some(tenant), full_permissions()).await;
        admin.registry_create_object(Action::InvalidateCaches).await;
        let principal = Account::new(
            Box::leak(format!("svc@{domain_name}").into_boxed_str()),
            PRINCIPAL_SECRET,
            &[],
            "",
            principal_id,
        );
        let client =
            ScimClient::bearer(&api_key(admin, &principal, json!({"@type": "Inherit"})).await);

        if !allows_scim {
            // Test 9: the tenant's ceiling wins
            client
                .get("/Users")
                .await
                .assert_error(403, None)
                .assert_detail_contains("scimAccess");
        } else {
            // Test 14: maxAccounts reached
            admin
                .registry_update_object(
                    ObjectType::Tenant,
                    tenant,
                    json!({ Property::Quotas: VecMap::from_iter([(TenantStorageQuota::MaxAccounts, 1u64)]) }),
                )
                .await;
            let events = Collector::read_metric(MetricType::LimitTenantQuota);
            client
                .post("/Users", user_body(&format!("extra@{domain_name}")))
                .await
                .assert_error(403, None)
                .assert_detail_contains("maxAccounts");
            assert!(
                Collector::read_metric(MetricType::LimitTenantQuota) > events,
                "test 14: limit.tenant-quota"
            );
        }

        admin
            .registry_destroy(ObjectType::Account, [principal_id])
            .await;
        admin.registry_destroy(ObjectType::Domain, [domain]).await;
        admin.registry_destroy(ObjectType::Tenant, [tenant]).await;
    }
    admin.registry_create_object(Action::InvalidateCaches).await;
}

/// SCIM-58 to SCIM-60, through just-in-time sync itself (acceptance test
/// 5 does the same over OIDC once per-domain directories exist).
async fn authority(test: &TestServer, scim: &ScimTest, closed_id: Id) {
    let admin = test.account("admin");
    let sync = |email: &str, name: &str, groups: Vec<String>| directory::Account {
        email: email.to_string(),
        email_aliases: vec![],
        secret: None,
        groups: Some(groups),
        description: Some(name.to_string()),
    };

    // An unprovisioned person on a SCIM domain: refused, nothing created
    assert!(
        test.server
            .synchronize_account(sync(&format!("jit@{SCIM_DOMAIN}"), "JIT", vec![]))
            .await
            .is_err(),
        "SCIM-58"
    );
    scim.client
        .get(&query(
            "/Users",
            &format!("userName eq \"jit@{SCIM_DOMAIN}\""),
        ))
        .await
        .assert_status(200);
    assert_eq!(
        scim.client
            .get(&query(
                "/Users",
                &format!("userName eq \"jit@{SCIM_DOMAIN}\"")
            ))
            .await
            .total_results(),
        0,
        "SCIM-58: no account"
    );

    // A provisioned one: sign-in changes nothing, creates no group
    let id = scim
        .client
        .post(
            "/Users",
            json!({"schemas": [SCHEMA_USER], "userName": format!("synced@{SCIM_DOMAIN}"), "displayName": "From SCIM"}),
        )
        .await
        .assert_status(201)
        .id();
    let before = scim.client.get(&format!("/Users/{id}")).await;
    for _ in 0..2 {
        test.server
            .synchronize_account(sync(
                &format!("synced@{SCIM_DOMAIN}"),
                "From the directory",
                vec![format!("claimed@{SCIM_DOMAIN}")],
            ))
            .await
            .unwrap();
    }
    let after = scim.client.get(&format!("/Users/{id}")).await;
    assert_eq!(after.json["displayName"], json!("From SCIM"), "SCIM-58");
    assert_eq!(after.etag(), before.etag(), "SCIM-58: version unchanged");
    assert_eq!(
        scim.client
            .get(&query("/Groups", "displayName eq \"claimed\""))
            .await
            .total_results(),
        0,
        "SCIM-58: no group from the claim"
    );

    // SCIM-59: without the flag, sync works as it always has
    let made = test
        .server
        .synchronize_account(sync(&format!("jit@{CLOSED}"), "JIT", vec![]))
        .await
        .unwrap();
    admin
        .registry_destroy(ObjectType::Account, [Id::from(made.id)])
        .await;

    // SCIM-60: turning the flag off hands the account back to sync
    admin
        .registry_update_object(
            ObjectType::Domain,
            scim.domain_id,
            json!({ Property::AllowScimProvisioning: false }),
        )
        .await;
    test.server
        .synchronize_account(sync(
            &format!("synced@{SCIM_DOMAIN}"),
            "From the directory",
            vec![],
        ))
        .await
        .unwrap();
    let structs::Account::User(user) = admin
        .registry_get::<structs::Account>(Id::from_str(&id).unwrap())
        .await
    else {
        panic!()
    };
    assert_eq!(
        user.description.as_deref(),
        Some("From the directory"),
        "SCIM-60"
    );
    scim.client
        .get(&format!("/Users/{id}"))
        .await
        .assert_error(404, None);
    admin
        .registry_update_object(
            ObjectType::Domain,
            scim.domain_id,
            json!({ Property::AllowScimProvisioning: true }),
        )
        .await;
    scim.destroy(&format!("/Users/{id}")).await;
    let _ = closed_id;
}

/// SCIM-14: the authenticated rate limit, per principal, with
/// `unlimitedRequests` exempt.
async fn rate_limits(test: &TestServer, scim: &ScimTest) {
    let admin = test.account("admin");
    admin
        .registry_update_setting(
            structs::Http {
                rate_limit_authenticated: Some(structs::Rate {
                    count: 2,
                    period: Duration::from_millis(60_000),
                }),
                ..Default::default()
            },
            &[Property::RateLimitAuthenticated],
        )
        .await;
    admin.reload_settings().await;

    let principal = Account::new(
        "scim-svc@scim.example.com",
        PRINCIPAL_SECRET,
        &[],
        "",
        scim.principal_id,
    );
    let limited = ScimClient::bearer(
        &api_key(
            admin,
            &principal,
            json!({"@type": "Disable", "permissions": {"unlimitedRequests": true}}),
        )
        .await,
    );
    let mut refused = None;
    for _ in 0..6 {
        let reply = limited.get("/Users?count=1").await;
        if reply.status == 429 {
            refused = Some(reply);
            break;
        }
        reply.assert_status(200);
    }
    let refused = refused.expect("SCIM-14: never rate limited");
    refused.assert_error(429, None);
    assert!(
        refused.header("retry-after").is_some(),
        "SCIM-14: Retry-After"
    );
    scim.client.get("/Users?count=1").await.assert_status(200);

    admin
        .registry_update_setting(
            structs::Http {
                rate_limit_authenticated: None,
                ..Default::default()
            },
            &[Property::RateLimitAuthenticated],
        )
        .await;
    admin.reload_settings().await;
}
