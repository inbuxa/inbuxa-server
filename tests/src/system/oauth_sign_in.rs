/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Who an OAuth sign-in may be for. A client a tenant registered signs in,
//! approves devices for and gets tokens for that tenant's accounts only, and
//! can't take one of the server's own client ids.

use crate::utils::{account::Account, registry::UnwrapRegistryId, server::TestServer};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jmap_proto::error::set::SetErrorType;
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{Http, OAuthClient, OidcProvider, Rate},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use store::registry::write::RegistryWrite;
use types::id::Id;

const BASE: &str = "https://127.0.0.1:8899";
const VERIFIER: &str = "an-oauth-sign-in-test-code-verifier-of-43-or-more-chars";
const T_ADMIN_SECRET: &str = "oauth tenant t administrator passphrase";
const T_USER_SECRET: &str = "oauth tenant t ordinary user passphrase";
const U_USER_SECRET: &str = "oauth tenant u ordinary user passphrase";
const TENANT_APP: &str = "oauth-sign-in-tenant-app";
const TENANT_APP_REDIRECT: &str = "https://app.oauth-t.example.org/cb";
const MOVED_APP: &str = "oauth-sign-in-moved-app";
const MOVED_APP_REDIRECT: &str = "https://app.oauth-moved.example.org/cb";
const CONSOLE: &str = "https://console.oauth-sign-in.example.org";

pub async fn test(test: &mut TestServer) {
    println!("Running OAuth sign-in tests...");
    let admin = test.account("admin@example.org");

    // Registration required, as in production, and room for the requests
    // below on top of the OIDC tests' within the minute
    admin
        .registry_update_setting(
            OidcProvider {
                require_client_registration: true,
                ..Default::default()
            },
            &[Property::RequireClientRegistration],
        )
        .await;
    set_anonymous_rate(admin, 1000, 61_000).await;

    tenant_clients(test).await;

    set_anonymous_rate(admin, 100, 60_000).await;
}

/// A client a tenant registered serves that tenant's accounts only.
async fn tenant_clients(test: &TestServer) {
    let admin = test.account("admin@example.org");

    // Two tenants: T with an administrator and a user, U with a user
    let t_id = admin.create_tenant("OAuth tenant T").await;
    let u_id = admin.create_tenant("OAuth tenant U").await;
    let t_domain = admin
        .create_tenant_domain("oauth-t.example.org", Some(t_id))
        .await;
    let u_domain = admin
        .create_tenant_domain("oauth-u.example.org", Some(u_id))
        .await;
    let t_admin = admin
        .create_user_account(
            "tadmin@oauth-t.example.org",
            T_ADMIN_SECRET,
            "T admin",
            &[],
            vec![],
        )
        .await;
    admin.make_tenant_admin(t_admin.id()).await;
    let t_user = admin
        .create_user_account(
            "tuser@oauth-t.example.org",
            T_USER_SECRET,
            "T user",
            &[],
            vec![],
        )
        .await;
    let u_user = admin
        .create_user_account(
            "uuser@oauth-u.example.org",
            U_USER_SECRET,
            "U user",
            &[],
            vec![],
        )
        .await;

    // The tenant administrator registers a client; it is the tenant's
    let tenant_app = t_admin
        .registry_create_object(OAuthClient {
            client_id: TENANT_APP.to_string(),
            redirect_uris: vec![TENANT_APP_REDIRECT.to_string()].into(),
            ..Default::default()
        })
        .await;
    assert_eq!(
        admin.client_tenant(tenant_app).await,
        Some(t_id),
        "the tenant's client is in the tenant"
    );

    let mut failed = Vec::new();

    // Code flow: no code for another tenant's account or the server's
    // administrator, a code for the tenant's own
    for (who, name, secret) in [
        ("tenant U's user", u_user.name(), U_USER_SECRET),
        ("the server administrator", admin.name(), admin.secret()),
    ] {
        let response = auth_code(name, secret, TENANT_APP, TENANT_APP_REDIRECT).await;
        if response.code().is_some() {
            failed.push(format!(
                "code flow: tenant T's client got a code for {who}: {response:?}"
            ));
        }
    }
    match auth_code(
        t_user.name(),
        T_USER_SECRET,
        TENANT_APP,
        TENANT_APP_REDIRECT,
    )
    .await
    .code()
    {
        Some(code) => {
            let granted = redeem_code(&code, TENANT_APP, TENANT_APP_REDIRECT).await;
            if !granted["access_token"].is_string() {
                failed.push(format!(
                    "code flow: tenant T's user got no token: {granted}"
                ));
            }
        }
        None => failed.push("code flow: tenant T's user got no code".to_string()),
    }

    // Device flow: another tenant's account or the server's administrator
    // can't approve the tenant client's device; the tenant's own can
    let device = device_code(TENANT_APP).await;
    for (who, name, secret) in [
        ("tenant U's user", u_user.name(), U_USER_SECRET),
        ("the server administrator", admin.name(), admin.secret()),
    ] {
        let response = approve_device(name, secret, &device.1).await;
        if response["type"] != "failure" {
            failed.push(format!(
                "device flow: {who} approved tenant T's client: {response}"
            ));
        }
    }
    let redeemed = redeem_device(&device.0, TENANT_APP).await;
    if redeemed["error"] != "authorization_pending" {
        failed.push(format!(
            "device flow: refused approvals left the device code {redeemed}"
        ));
    }
    let response = approve_device(t_user.name(), T_USER_SECRET, &device.1).await;
    if response["type"] != "verified" {
        failed.push(format!(
            "device flow: tenant T's user couldn't approve: {response}"
        ));
    } else {
        let granted = redeem_device(&device.0, TENANT_APP).await;
        if !granted["access_token"].is_string() {
            failed.push(format!(
                "device flow: tenant T's user got no token: {granted}"
            ));
        }
    }

    // Token endpoint: a code, an approved device and a refresh token, all
    // for tenant U's user while the client was the server's, are refused
    // once the client is moved into tenant T
    let moved_app = admin
        .registry_create_object(OAuthClient {
            client_id: MOVED_APP.to_string(),
            redirect_uris: vec![MOVED_APP_REDIRECT.to_string()].into(),
            ..Default::default()
        })
        .await;
    let code = auth_code(u_user.name(), U_USER_SECRET, MOVED_APP, MOVED_APP_REDIRECT)
        .await
        .code()
        .expect("a code for the server's client");
    let refresh = redeem_code(
        &auth_code(u_user.name(), U_USER_SECRET, MOVED_APP, MOVED_APP_REDIRECT)
            .await
            .code()
            .expect("a code for the server's client"),
        MOVED_APP,
        MOVED_APP_REDIRECT,
    )
    .await["refresh_token"]
        .as_str()
        .expect("a refresh token for the server's client")
        .to_string();
    let device = device_code(MOVED_APP).await;
    assert_eq!(
        approve_device(u_user.name(), U_USER_SECRET, &device.1).await["type"],
        "verified",
        "the server's client's device"
    );
    admin
        .registry_update_object(
            ObjectType::OAuthClient,
            moved_app,
            json!({ Property::MemberTenantId: t_id }),
        )
        .await;
    assert_eq!(admin.client_tenant(moved_app).await, Some(t_id));
    let granted = redeem_code(&code, MOVED_APP, MOVED_APP_REDIRECT).await;
    if granted["access_token"].is_string() {
        failed.push(format!(
            "token endpoint: a code for tenant U's user redeemed by tenant T's client: {granted}"
        ));
    }
    let granted = redeem_device(&device.0, MOVED_APP).await;
    if granted["access_token"].is_string() {
        failed.push(format!(
            "token endpoint: a device code for tenant U's user redeemed by tenant T's client: {granted}"
        ));
    }
    let granted = token(&[
        ("grant_type", "refresh_token"),
        ("client_id", MOVED_APP),
        ("refresh_token", &refresh),
    ])
    .await;
    if granted["access_token"].is_string() {
        failed.push(format!(
            "token endpoint: a refresh token for tenant U's user refreshed by tenant T's client: {granted}"
        ));
    }

    // The server's own client ids are refused to a tenant, created or
    // renamed to
    for reserved in ["inbuxa-admin", "inbuxa-webui", "ihasmail-inbuxa"] {
        let response = t_admin
            .registry_create([OAuthClient {
                client_id: reserved.to_string(),
                redirect_uris: vec![TENANT_APP_REDIRECT.to_string()].into(),
                ..Default::default()
            }])
            .await;
        let refused = response
            .0
            .pointer("/methodResponses/0/1/notCreated/i0/type")
            .and_then(Value::as_str)
            == Some(SetErrorType::Forbidden.as_str());
        if !refused {
            failed.push(format!(
                "tenant T's administrator created a client named {reserved}: {response:?}"
            ));
            if let Some(id) = response
                .0
                .pointer("/methodResponses/0/1/created/i0/id")
                .and_then(Value::as_str)
            {
                admin
                    .registry_destroy(ObjectType::OAuthClient, [id.to_string()])
                    .await;
            }
        }
    }
    let response = t_admin
        .registry_update(
            ObjectType::OAuthClient,
            [(tenant_app, json!({ Property::ClientId: "inbuxa-admin" }))],
        )
        .await;
    if response
        .0
        .pointer(&format!("/methodResponses/0/1/notUpdated/{tenant_app}"))
        .is_none()
    {
        failed.push(format!(
            "tenant T's administrator renamed a client to inbuxa-admin: {response:?}"
        ));
        t_admin
            .registry_update(
                ObjectType::OAuthClient,
                [(tenant_app, json!({ Property::ClientId: TENANT_APP }))],
            )
            .await;
    }

    // A tenant's client that already holds a first-party id, from before
    // they were reserved, isn't taken over at start-up: the console's
    // address doesn't become one of its redirects
    for (id, client) in admin.registry_get_all::<OAuthClient>().await {
        if client.client_id == "inbuxa-admin" {
            admin.registry_destroy(ObjectType::OAuthClient, [id]).await;
        }
    }
    let squatted = test
        .server
        .registry()
        .write(RegistryWrite::insert(
            &OAuthClient {
                client_id: "inbuxa-admin".to_string(),
                member_tenant_id: Some(t_id),
                redirect_uris: vec![TENANT_APP_REDIRECT.to_string()].into(),
                ..Default::default()
            }
            .into(),
        ))
        .await
        .unwrap()
        .unwrap_id(trc::location!());
    let response = admin.set_console_url(Some(CONSOLE)).await;
    assert!(
        response["updated"].is_object(),
        "inbuxa:FrontEnds/set: {response}"
    );
    let squatter = admin
        .registry_get_all::<OAuthClient>()
        .await
        .into_iter()
        .find(|(id, _)| *id == squatted)
        .map(|(_, client)| client)
        .expect("the tenant's inbuxa-admin client");
    if squatter
        .redirect_uris
        .iter()
        .any(|uri| uri.starts_with(CONSOLE))
        || squatter.member_tenant_id != Some(t_id)
    {
        failed.push(format!(
            "start-up took over tenant T's inbuxa-admin client: {squatter:?}"
        ));
    }
    admin.set_console_url(None).await;

    // Clean up
    admin
        .registry_destroy(ObjectType::OAuthClient, [tenant_app, moved_app, squatted])
        .await;
    for account in [t_admin, t_user, u_user] {
        admin.destroy_account(account).await;
    }
    for domain in [t_domain, u_domain] {
        admin
            .registry_destroy(ObjectType::Domain, [domain])
            .await
            .assert_destroyed(&[domain]);
    }
    for tenant in [t_id, u_id] {
        admin
            .registry_destroy(ObjectType::Tenant, [tenant])
            .await
            .assert_destroyed(&[tenant]);
    }

    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

impl Account {
    async fn client_tenant(&self, client: Id) -> Option<Id> {
        self.registry_get_all::<OAuthClient>()
            .await
            .into_iter()
            .find(|(id, _)| *id == client)
            .and_then(|(_, client)| client.member_tenant_id)
    }

    /// Sets INBUXA Admin's address (`inbuxa:FrontEnds`), which registers
    /// its first-party client at once, as a start does.
    async fn set_console_url(&self, url: Option<&str>) -> Value {
        let response = self
            .jmap_request(
                &["urn:ietf:params:jmap:core", "urn:inbuxa:jmap"],
                json!([[
                    "inbuxa:FrontEnds/set",
                    {"accountId": self.id_string(), "update": {"singleton": {"adminUrl": url}}},
                    "0"
                ]]),
            )
            .await;
        response
            .0
            .pointer("/methodResponses/0/1")
            .cloned()
            .unwrap_or_else(|| panic!("inbuxa:FrontEnds/set: {}", response.0))
    }
}

trait LoginCode {
    fn code(&self) -> Option<String>;
}

impl LoginCode for Value {
    fn code(&self) -> Option<String> {
        (self["type"] == "authenticated")
            .then(|| {
                ["clientCode", "client_code"]
                    .iter()
                    .find_map(|key| self[*key].as_str())
                    .map(str::to_string)
            })
            .flatten()
    }
}

/// The sign-in page's request for an authorization code.
async fn auth_code(name: &str, secret: &str, client_id: &str, redirect_uri: &str) -> Value {
    login(json!({
        "type": "authCode",
        "accountName": name,
        "accountSecret": secret,
        "clientId": client_id,
        "redirectUri": redirect_uri,
        "codeChallenge": URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
        "codeChallengeMethod": "S256",
    }))
    .await
}

/// The device page's approval of a user code.
async fn approve_device(name: &str, secret: &str, user_code: &str) -> Value {
    login(json!({
        "type": "authDevice",
        "accountName": name,
        "accountSecret": secret,
        "code": user_code,
    }))
    .await
}

async fn login(body: Value) -> Value {
    let response = http()
        .post(format!("{BASE}/api/auth"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.bytes().await.unwrap();
    serde_json::from_slice(&body)
        .unwrap_or_else(|_| json!({"status": status, "body": String::from_utf8_lossy(&body)}))
}

/// A device code and its user code, for `client_id`.
async fn device_code(client_id: &str) -> (String, String) {
    let response: Value = http()
        .post(format!("{BASE}/auth/device"))
        .form(&[("client_id", client_id)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        response["device_code"]
            .as_str()
            .unwrap_or_else(|| panic!("no device code: {response}"))
            .to_string(),
        response["user_code"].as_str().unwrap().to_string(),
    )
}

async fn redeem_code(code: &str, client_id: &str, redirect_uri: &str) -> Value {
    token(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_verifier", VERIFIER),
    ])
    .await
}

async fn redeem_device(device_code: &str, client_id: &str) -> Value {
    token(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device_code),
        ("client_id", client_id),
    ])
    .await
}

async fn token(form: &[(&str, &str)]) -> Value {
    http()
        .post(format!("{BASE}/auth/token"))
        .form(form)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn set_anonymous_rate(admin: &Account, count: u64, period_ms: u64) {
    admin
        .registry_update_setting(
            Http {
                rate_limit_anonymous: Some(Rate {
                    count,
                    period: registry::schema::prelude::Duration::from_millis(period_ms),
                }),
                ..Default::default()
            },
            &[Property::RateLimitAnonymous],
        )
        .await;
    admin.reload_settings().await;
}

/// A longer timeout than the OIDC tests' helpers: each sign-in hashes a
/// password, and the suite runs under load.
fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}
