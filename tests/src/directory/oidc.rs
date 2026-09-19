/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The OIDC directory as a domain's own directory, from
//! `docs/spec/features/per-domain-directories.md`, against the Keycloak
//! realm in `tests/docker/keycloak`. Replaces the removed `oidc.rs`, and
//! runs from `directory_tests`. Each check names its test number or
//! requirement.

use crate::utils::{server::TestServerBuilder, smtp::SmtpConnection};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{BuildServer, auth::AuthRequest};
use directory::Credentials;
use registry::{
    schema::{
        enums::TenantStorageQuota,
        prelude::{ObjectType, Property},
        structs::{
            self, CertificateManagement, DkimManagement, DnsManagement, Domain, Expression,
            MtaStageRcpt, OidcDirectory, Tenant, UserAccount,
        },
    },
    types::map::Map,
};
use serde_json::json;
use std::net::IpAddr;
use trc::{Collector, MetricType};
use types::id::Id;
use utils::map::vec_map::VecMap;

const PASSWORD: &str = "this is an OIDC password";
const JOHN: &str = "john.doe@example.org";
const JANE: &str = "jane.smith@example.org";
const BILL: &str = "bill.foobar@example.org";

fn directory(tenant: Option<Id>) -> structs::Directory {
    structs::Directory::Oidc(OidcDirectory {
        description: "Keycloak".to_string(),
        issuer_url: "http://localhost:9080/realms/stalwart".to_string(),
        claim_username: "email".to_string(),
        claim_name: Some("name".to_string()),
        claim_groups: Some("groups".to_string()),
        username_domain: None,
        require_audience: Some("stalwart".to_string()),
        require_scopes: Map::new(vec![
            "email".to_string(),
            "profile".to_string(),
            "openid".to_string(),
        ]),
        member_tenant_id: tenant,
    })
}

async fn token(client: &str, secret: &str, username: &str, scope: &str) -> Option<String> {
    let body = reqwest::Client::new()
        .post("http://localhost:9080/realms/stalwart/protocol/openid-connect/token")
        .form(&[
            ("grant_type", "password"),
            ("client_id", client),
            ("client_secret", secret),
            ("username", username),
            ("password", PASSWORD),
            ("scope", scope),
        ])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|json| json["access_token"].as_str().map(str::to_string))
}

async fn john_token(username: &str) -> String {
    token(
        "stalwart",
        "stalwart-secret",
        username,
        "openid email profile",
    )
    .await
    .expect("a Keycloak token")
}

fn server(test: &crate::utils::server::TestServer) -> common::Server {
    test.server.inner.build_server()
}

async fn bearer(
    test: &crate::utils::server::TestServer,
    username: Option<&str>,
    token: &str,
) -> trc::Result<u32> {
    server(test)
        .authenticate(&AuthRequest::from_credentials(
            Credentials::Bearer {
                username: username.map(str::to_string),
                token: token.to_string(),
            },
            0,
            IpAddr::from([127, 0, 0, 1]),
        ))
        .await
        .map(|token| token.account_id())
}

/// A JWT with a new header and payload but the original signature.
fn forged(
    token: &str,
    header: serde_json::Value,
    edit: impl FnOnce(&mut serde_json::Value),
) -> String {
    let mut parts = token.split('.');
    let _ = parts.next();
    let mut payload = serde_json::from_slice::<serde_json::Value>(
        &URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap(),
    )
    .unwrap();
    edit(&mut payload);
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string()),
        parts.next().unwrap()
    )
}

async fn rcpt(address: &str) -> char {
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.mail_from("sender@remote.example", 2).await;
    lmtp.send(&format!("RCPT TO:<{address}>")).await;
    let reply = lmtp.read(1, u8::MAX).await;
    lmtp.quit().await;
    reply
        .last()
        .and_then(|line| line.chars().next())
        .unwrap_or('?')
}

pub async fn test() {
    println!("Running OIDC directory tests...");
    crate::utils::containers::ensure_keycloak().await;
    let test = TestServerBuilder::new("oidc_directory_test")
        .await
        .with_default_listeners()
        .await
        .with_object(MtaStageRcpt {
            wait_on_fail: Expression {
                else_: "1ms".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;
    let admin = test.account("admin");
    admin.mta_no_auth().await;
    admin.reload_settings().await;

    // example.org signs in against Keycloak; there is no server default
    let keycloak = admin.registry_create_object(directory(None)).await;
    let domain = admin.find_or_create_domain("example.org").await;
    admin
        .registry_update_object(
            ObjectType::Domain,
            domain,
            json!({ Property::DirectoryId: keycloak.to_string() }),
        )
        .await;

    // Test 14: an account that already exists is the one sign-in finds
    // (DIR-18)
    let existing = admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: "jane.smith".to_string(),
            domain_id: domain,
            ..Default::default()
        }))
        .await;

    // Test 12: the first sign-in creates the account, with its name and
    // groups (DIR-14)
    let john = bearer(&test, None, &john_token(JOHN).await)
        .await
        .expect("test 12: first sign-in");
    let account = admin
        .registry_get::<structs::Account>(Id::from(john))
        .await
        .into_user()
        .unwrap();
    assert_eq!(account.name, "john.doe", "test 12");
    assert!(account.description.is_some(), "test 12: the name claim");
    assert_eq!(
        account.member_group_ids.len(),
        1,
        "test 12: the groups claim"
    );
    let jane = bearer(&test, None, &john_token(JANE).await)
        .await
        .expect("test 14");
    assert_eq!(Id::from(jane), existing, "test 14: DIR-18");

    // Test 5: a token for one user named as another is refused (DIR-7)
    let john_token = john_token(JOHN).await;
    assert!(
        bearer(&test, Some(JANE), &john_token).await.is_err(),
        "test 5"
    );
    assert_eq!(
        bearer(&test, Some(JOHN), &john_token).await.unwrap(),
        john,
        "test 5: the named user"
    );

    // Test 17: no password sign-in on an OIDC domain (DIR-29)
    assert!(
        server(&test)
            .authenticate(&AuthRequest::from_plain(
                JOHN,
                PASSWORD,
                0,
                IpAddr::from([127, 0, 0, 1]),
            ))
            .await
            .is_err(),
        "test 17: DIR-29"
    );
    assert!(bearer(&test, None, "not a token").await.is_err(), "test 17");

    // Test 16: JWTs the directory must refuse (DIR-26)
    let header = |alg: &str, kid: Option<&str>| {
        let mut header = json!({"alg": alg, "typ": "JWT"});
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        }
        header
    };
    for (what, forged) in [
        ("HS256", forged(&john_token, header("HS256", None), |_| {})),
        (
            "unknown kid",
            forged(&john_token, header("RS256", Some("no-such-key")), |_| {}),
        ),
        (
            "another issuer",
            forged(&john_token, header("RS256", None), |p| {
                p["iss"] = json!("http://localhost:9080/realms/other")
            }),
        ),
        (
            "expired",
            forged(&john_token, header("RS256", None), |p| p["exp"] = json!(1)),
        ),
    ] {
        assert!(
            bearer(&test, None, &forged).await.is_err(),
            "test 16: {what}"
        );
    }
    // Keycloak adds its default scopes to every token, so only a token that
    // really lacks one of the required scopes is checked
    if let Some(narrow) = token("stalwart", "stalwart-secret", JOHN, "openid").await {
        let payload = serde_json::from_slice::<serde_json::Value>(
            &URL_SAFE_NO_PAD
                .decode(narrow.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        let scopes = payload["scope"].as_str().unwrap_or_default().to_string();
        let lacks = ["openid", "email", "profile"]
            .iter()
            .any(|s| !scopes.split(' ').any(|t| t == *s));
        if lacks {
            assert!(
                bearer(&test, None, &narrow).await.is_err(),
                "test 16: a required scope missing ({scopes})"
            );
        } else {
            println!(
                "  Keycloak granted every required scope ({scopes}); scope check not exercised"
            );
        }
    }

    // Test 8: an OIDC domain has no recipient lookup (DIR-10)
    assert_eq!(rcpt(BILL).await, '5', "test 8: never signed in");
    admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: "bill.foobar".to_string(),
            domain_id: domain,
            ..Default::default()
        }))
        .await;
    assert_eq!(rcpt(BILL).await, '2', "test 8: created by an administrator");

    // Test 13: sign-in can't pass a tenant's limit (DIR-15)
    let tenant = admin
        .registry_create_object(Tenant {
            name: "oidc-tenant".into(),
            quotas: VecMap::from_iter([(TenantStorageQuota::MaxAccounts, 0u64)]),
            ..Default::default()
        })
        .await;
    let tenant_directory = admin.registry_create_object(directory(Some(tenant))).await;
    let tenant_domain = admin
        .registry_create_object(Domain {
            is_enabled: true,
            name: "tenant.example.org".to_string(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            member_tenant_id: Some(tenant),
            directory_id: Some(tenant_directory),
            ..Default::default()
        })
        .await;
    let events = Collector::read_metric(MetricType::LimitTenantQuota);
    // Keycloak's users are on example.org, not on the tenant's domain, so
    // DIR-6 refuses them first; the limit is checked through sync itself
    let refused = server(&test)
        .synchronize_account(directory::Account {
            email: "new.person@tenant.example.org".to_string(),
            ..Default::default()
        })
        .await;
    assert!(refused.is_err(), "test 13");
    assert!(
        Collector::read_metric(MetricType::LimitTenantQuota) > events,
        "test 13: limit.tenant-quota"
    );

    let _ = tenant_domain;
    test.temp_dir.delete();
}
