/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Where the front ends are (contract C-4): `inbuxa:FrontEnds` registers the
//! console's and the webmail's OAuth clients and puts their origins on the
//! cross-origin allowlist, at once and without touching the server's
//! environment. That is what the installer's `inbuxa join` relies on.

use crate::utils::{account::Account, server::TestServerBuilder};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use registry::schema::structs::OAuthClient;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

const USING: &[&str] = &["urn:ietf:params:jmap:core", "urn:inbuxa:jmap"];
const ADMIN: &str = "https://admin.joined.example";
const WEBMAIL: &str = "https://webmail.joined.example";
const SECRET: &str = "a-webmail-secret-of-more-than-thirty-two-characters";
const VERIFIER: &str = "a-pkce-code-verifier-of-forty-three-or-more-characters";

impl Account {
    async fn front_ends_call(&self, method: &str, arguments: Value) -> Value {
        let response = self
            .jmap_request(USING, json!([[method, arguments, "0"]]))
            .await;
        response
            .0
            .pointer("/methodResponses/0/1")
            .cloned()
            .unwrap_or_else(|| panic!("{method}: {}", response.0))
    }

    async fn front_ends(&self) -> Value {
        self.front_ends_call(
            "inbuxa:FrontEnds/get",
            json!({"accountId": self.id_string()}),
        )
        .await["list"][0]
            .clone()
    }

    async fn set_front_ends(&self, update: Value) -> Value {
        self.front_ends_call(
            "inbuxa:FrontEnds/set",
            json!({"accountId": self.id_string(), "update": {"singleton": update}}),
        )
        .await
    }

    /// The `Access-Control-Allow-Origin` a browser at `origin` gets on the
    /// preflight it sends before an authorized JMAP request, if any.
    async fn allowed_origin(&self, origin: &str) -> Option<String> {
        let response = http()
            .request(
                reqwest::Method::OPTIONS,
                format!("{}/jmap/session", self.base_url()),
            )
            .header("origin", origin)
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "authorization")
            .send()
            .await
            .unwrap();
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    /// An authorization code for this account, for the webmail at WEBMAIL,
    /// the way the server's own sign-in page gets one.
    async fn webmail_code(&self) -> String {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
        let response: Value = http()
            .post(format!("{}/api/auth", self.base_url()))
            .json(&json!({
                "type": "authCode",
                "accountName": self.name(),
                "accountSecret": self.secret(),
                "clientId": "ihasmail-inbuxa",
                "redirectUri": format!("{WEBMAIL}/api/auth/callback"),
                "codeChallenge": challenge,
                "codeChallengeMethod": "S256",
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        ["clientCode", "client_code", "code"]
            .iter()
            .find_map(|k| response.get(*k).and_then(Value::as_str))
            .unwrap_or_else(|| panic!("C-6: no code for the webmail: {response}"))
            .to_string()
    }

    /// Exchanges a code at the token endpoint as the webmail, with `secret`.
    async fn exchange(&self, code: &str, secret: &str) -> Value {
        http()
            .post(format!("{}/auth/token", self.base_url()))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &format!("{WEBMAIL}/api/auth/callback")),
                ("client_id", "ihasmail-inbuxa"),
                ("client_secret", secret),
                ("code_verifier", VERIFIER),
            ])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn client(&self, client_id: &str) -> Option<OAuthClient> {
        self.registry_get_all::<OAuthClient>()
            .await
            .into_iter()
            .map(|(_, client)| client)
            .find(|client| client.client_id == client_id)
    }
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn updated(response: &Value) -> bool {
    response["updated"]["singleton"].is_null() && response["updated"].is_object()
}

fn refusal(response: &Value) -> String {
    response["notUpdated"]["singleton"]["type"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Runs these tests alone: `cargo test -p tests front_ends_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn front_ends_tests() {
    let test = TestServerBuilder::new("front_ends_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    let ann = admin
        .create_user_account("ann@example.org", "ann-secret-7710", "Ann", &[], vec![])
        .await;
    println!("Running front ends tests...");

    // Unset, it says so, and changes nothing
    let current = admin.front_ends().await;
    assert_eq!(current["id"], "singleton", "{current}");
    assert!(current["adminUrl"].is_null(), "{current}");
    assert_eq!(current["webmailClientSecretSet"], false, "{current}");
    assert_eq!(
        current["environmentWebmailClientSecret"], false,
        "{current}"
    );
    assert_eq!(
        admin.allowed_origin(ADMIN).await,
        None,
        "C-14: allowed before it was set"
    );

    // Someone who isn't a server administrator can't change it
    let response = ann.set_front_ends(json!({"adminUrl": ADMIN})).await;
    assert!(
        !updated(&response),
        "C-4: an ordinary account changed the front ends: {response}"
    );

    // What isn't a front end's address is refused, with the property named
    for (property, value) in [
        ("adminUrl", json!("admin.joined.example")),
        ("webmailUrl", json!("ftp://webmail.joined.example")),
        ("webmailClientSecret", json!("short")),
        ("extraOrigins", json!(["not an origin"])),
        ("webmailClientSecretSet", json!(true)),
        ("environmentAdminUrl", json!(ADMIN)),
    ] {
        let response = admin.set_front_ends(json!({property: value})).await;
        assert_eq!(
            refusal(&response),
            "invalidProperties",
            "{property}: {response}"
        );
    }
    // A webmail's address without its secret would register nothing
    let response = admin.set_front_ends(json!({"webmailUrl": WEBMAIL})).await;
    assert_eq!(refusal(&response), "invalidProperties", "{response}");
    // A singleton: never created or destroyed
    let response = admin
        .front_ends_call(
            "inbuxa:FrontEnds/set",
            json!({"accountId": admin.id_string(), "create": {"x": {}}, "destroy": ["singleton"]}),
        )
        .await;
    assert_eq!(
        response["notCreated"]["x"]["type"], "forbidden",
        "{response}"
    );
    assert_eq!(
        response["notDestroyed"]["singleton"]["type"], "forbidden",
        "{response}"
    );

    // Set: the clients are registered and the origins allowed at once
    let response = admin
        .set_front_ends(json!({
            "adminUrl": format!("{ADMIN}/"),
            "webmailUrl": WEBMAIL,
            "webmailClientSecret": SECRET,
            "extraOrigins": ["http://localhost:5173/some/path"],
        }))
        .await;
    assert!(updated(&response), "C-4: {response}");

    let current = admin.front_ends().await;
    assert_eq!(current["adminUrl"], ADMIN, "trailing slash kept: {current}");
    assert_eq!(current["webmailUrl"], WEBMAIL, "{current}");
    assert!(
        current["webmailClientSecret"].is_null(),
        "the secret was read back: {current}"
    );
    assert_eq!(current["webmailClientSecretSet"], true, "{current}");
    assert_eq!(
        current["extraOrigins"],
        json!(["http://localhost:5173"]),
        "{current}"
    );
    assert!(current["changedAt"].is_number(), "{current}");

    let console = admin
        .client("inbuxa-admin")
        .await
        .expect("C-6: no inbuxa-admin client");
    assert!(
        console
            .redirect_uris
            .iter()
            .any(|uri| uri == &format!("{ADMIN}/oauth/callback")),
        "C-6: {:?}",
        console.redirect_uris
    );
    let webmail = admin
        .client("ihasmail-inbuxa")
        .await
        .expect("C-6: no ihasmail-inbuxa client");
    assert!(
        webmail
            .redirect_uris
            .iter()
            .any(|uri| uri == &format!("{WEBMAIL}/api/auth/callback")),
        "C-6: {:?}",
        webmail.redirect_uris
    );
    // The secret is read back redacted, as it should be, so it's proved the
    // way the webmail uses it: a code for Ann, exchanged as the webmail.
    let code = ann.webmail_code().await;
    assert_eq!(
        ann.exchange(&code, "not-the-secret").await["error"],
        "invalid_client",
        "C-6: a wrong webmail secret was taken"
    );
    let granted = ann.exchange(&code, SECRET).await;
    assert!(
        granted["access_token"].is_string(),
        "C-6: the webmail's secret was refused: {granted}"
    );

    assert_eq!(
        admin.allowed_origin(ADMIN).await.as_deref(),
        Some(ADMIN),
        "C-14"
    );
    assert_eq!(
        admin.allowed_origin(WEBMAIL).await.as_deref(),
        Some(WEBMAIL),
        "C-14"
    );
    assert_eq!(
        admin
            .allowed_origin("http://localhost:5173")
            .await
            .as_deref(),
        Some("http://localhost:5173"),
        "C-14: extra origin"
    );
    assert_eq!(
        admin.allowed_origin("https://evil.example").await,
        None,
        "C-14"
    );

    // Setting it again with the same values changes nothing, secret aside
    let response = admin.set_front_ends(json!({"adminUrl": ADMIN})).await;
    assert!(updated(&response), "{response}");

    // Cleared, the console's origin is no longer allowed
    let response = admin
        .set_front_ends(json!({"adminUrl": null, "extraOrigins": null}))
        .await;
    assert!(updated(&response), "{response}");
    assert_eq!(
        admin.allowed_origin(ADMIN).await,
        None,
        "C-14: still allowed after clearing"
    );
    assert_eq!(
        admin.allowed_origin(WEBMAIL).await.as_deref(),
        Some(WEBMAIL),
        "C-14"
    );

    // AU-1.2: every change is in the audit log
    let query = admin
        .front_ends_call(
            "inbuxa:AuditEvent/query",
            json!({"accountId": admin.id_string(), "filter": {"targetKind": "inbuxa:FrontEnds"}}),
        )
        .await;
    assert!(
        query["ids"].as_array().is_some_and(|ids| ids.len() >= 2),
        "AU-1.2: {query}"
    );

    if test.is_reset() {
        test.temp_dir.delete();
    }
}
