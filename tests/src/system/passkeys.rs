/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Passkeys (passkeys spec): `inbuxa:Passkey` management (PK-5, PK-14 to
//! PK-17): starting a registration, the limit per account, renaming,
//! removing, who reaches whose passkeys, and the audit log. Registration on
//! the server's page (PK-6 to PK-8) and sign-in (PK-9 to PK-12), with a
//! software authenticator.

use crate::utils::{
    account::Account,
    http::HttpRequest,
    server::{TestServer, TestServerBuilder},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::manager::defaults::BootstrapDefaults;
use registry::{
    schema::{
        enums::Permission,
        prelude::{ObjectType, Property},
        structs::{Authentication, Role},
    },
    types::EnumImpl,
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use store::{
    SUBSPACE_INBUXA,
    registry::bootstrap::Bootstrap,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use types::id::Id;

/// The page's origin: the test server's public URL.
const ORIGIN: &str = "https://localhost:8899";
const RP_ID: &str = "localhost";

const USING: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:inbuxa:jmap",
    "urn:inbuxa:jmap:registry",
];

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

/// PK-19: the session's flag for the signed-in account.
async fn session_allows(account: &Account) -> Value {
    let session = account.jmap_session_object().await;
    session.0["accounts"][account.id_string()]["accountCapabilities"]["urn:inbuxa:jmap"].clone()
}

async fn list(account: &Account, of: &Account) -> Vec<Value> {
    let (name, response) = call(
        account,
        "inbuxa:Passkey/get",
        json!({"accountId": of.id_string(), "ids": null}),
    )
    .await;
    assert_eq!(name, "inbuxa:Passkey/get", "{response}");
    response["list"].as_array().unwrap().clone()
}

pub async fn test(test: &mut TestServer) {
    println!("Running passkey tests...");
    let admin = test.account("admin@example.com");
    let user = admin
        .create_user_account(
            "passkey-user@example.com",
            "passkey-secret-5521",
            "Passkey user",
            &[],
            vec![],
        )
        .await;
    let other = admin
        .create_user_account(
            "passkey-other@example.com",
            "passkey-other-6634",
            "Other user",
            &[],
            vec![],
        )
        .await;

    // PK-5: creating starts a registration: a pending passkey and the page
    // that finishes it
    let (_, response) = call(
        &user,
        "inbuxa:Passkey/set",
        json!({"create": {"phone": {"name": "  Phone  "}}}),
    )
    .await;
    let created = &response["created"]["phone"];
    let phone_id = created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("not created: {response}"))
        .to_string();
    assert_eq!(created["state"], "pending", "{response}");
    let url = created["registrationUrl"].as_str().unwrap_or_default();
    assert!(
        url.starts_with("https://") && url.contains("/passkey/register?ticket="),
        "{response}"
    );

    let mine = list(&user, &user).await;
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert_eq!(mine[0]["name"], "Phone");
    assert_eq!(mine[0]["state"], "pending");
    assert_eq!(mine[0]["usable"], false);
    assert_eq!(mine[0]["accountId"], user.id_string());
    // The ticket is shown once, when the registration starts
    assert_eq!(mine[0]["registrationUrl"], Value::Null, "{mine:?}");

    // A name is required, and what the server sets can't be sent
    let (_, response) = call(
        &user,
        "inbuxa:Passkey/set",
        json!({"create": {
            "blank": {"name": "   "},
            "none": {},
            "state": {"name": "Key", "state": "active"}
        }}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["blank"]["properties"][0], "name",
        "{response}"
    );
    assert_eq!(
        response["notCreated"]["none"]["properties"][0], "name",
        "{response}"
    );
    assert_eq!(
        response["notCreated"]["state"]["properties"][0], "state",
        "{response}"
    );

    // PK-14: only the name changes
    let (_, response) = call(
        &user,
        "inbuxa:Passkey/set",
        json!({"update": {
            phone_id.as_str(): {"name": "Work phone"}
        }}),
    )
    .await;
    assert!(
        response["updated"].get(phone_id.as_str()).is_some(),
        "{response}"
    );
    let (_, response) = call(
        &user,
        "inbuxa:Passkey/set",
        json!({"update": {phone_id.as_str(): {"rpId": "example.com"}}}),
    )
    .await;
    assert_eq!(
        response["notUpdated"][phone_id.as_str()]["properties"][0],
        "rpId",
        "{response}"
    );
    assert_eq!(list(&user, &user).await[0]["name"], "Work phone");

    // PK-5: ten per account, pending ones included
    let mut create = serde_json::Map::new();
    for n in 0..10 {
        create.insert(format!("k{n}"), json!({"name": format!("Key {n}")}));
    }
    let (_, response) = call(&user, "inbuxa:Passkey/set", json!({"create": create})).await;
    let made = response["created"].as_object().map_or(0, |m| m.len());
    assert_eq!(made, 9, "{response}");
    let over = response["notCreated"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(over["type"], "overQuota", "{response}");
    assert_eq!(list(&user, &user).await.len(), 10);

    // Someone else's passkeys are out of reach for an ordinary account
    let (name, response) = call(
        &other,
        "inbuxa:Passkey/get",
        json!({"accountId": user.id_string(), "ids": null}),
    )
    .await;
    assert_eq!(name, "error", "another user read passkeys: {response}");
    let (_, response) = call(
        &other,
        "inbuxa:Passkey/set",
        json!({"accountId": user.id_string(), "destroy": [phone_id]}),
    )
    .await;
    assert!(
        response["destroyed"]
            .as_array()
            .is_none_or(|d| d.is_empty()),
        "another user removed a passkey: {response}"
    );
    assert!(list(&other, &other).await.is_empty());

    // PK-16: an administrator sees and removes them
    let seen = list(&admin, &user).await;
    assert_eq!(seen.len(), 10, "{seen:?}");
    let all_ids = seen
        .iter()
        .map(|p| p["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let (_, response) = call(
        &admin,
        "inbuxa:Passkey/set",
        json!({"accountId": user.id_string(), "destroy": all_ids}),
    )
    .await;
    assert_eq!(
        response["destroyed"].as_array().map_or(0, |d| d.len()),
        10,
        "{response}"
    );
    assert!(list(&user, &user).await.is_empty());

    // PK-17: made and removed are in the audit log, by name
    let (_, response) = call(
        &admin,
        "inbuxa:AuditEvent/query",
        json!({"filter": {"targetKind": "inbuxa:Passkey"}}),
    )
    .await;
    let ids = response["ids"].clone();
    let (_, response) = call(&admin, "inbuxa:AuditEvent/get", json!({"ids": ids})).await;
    let events = response["list"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "create" && e["outcome"]["status"] == "success"),
        "{response}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "destroy" && e["target"]["name"] == "Work phone"),
        "no removal recorded by name: {response}"
    );

    let key = registration(&user).await;
    let client_id = sign_in(&user, &key).await;
    policy(&admin, &user, &key, &client_id).await;
}

/// A software authenticator: one P-256 key, user verification always done.
pub struct SoftKey {
    pub key: EcdsaKeyPair,
    pub credential_id: Vec<u8>,
    /// The account's user handle, as registration gave it (base64url).
    pub user_handle: std::sync::Mutex<String>,
}

impl SoftKey {
    pub fn new(credential_id: &[u8]) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        SoftKey {
            key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
            credential_id: credential_id.to_vec(),
            user_handle: Default::default(),
        }
    }

    /// What `navigator.credentials.get` hands the page for a sign-in
    /// challenge, with the given counter and origin.
    pub fn get(&self, challenge: &Value, counter: u32, origin: &str) -> Value {
        let client_data = json!({
            "type": "webauthn.get",
            "challenge": challenge["options"]["publicKey"]["challenge"],
            "origin": origin,
            "crossOrigin": false
        })
        .to_string();
        let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        // UP, UV, backup eligible, backed up
        auth_data.push(0x01 | 0x04 | 0x08 | 0x10);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
        let signature = self.key.sign(&SystemRandom::new(), &signed).unwrap();
        let id = URL_SAFE_NO_PAD.encode(&self.credential_id);
        json!({
            "challengeId": challenge["challengeId"],
            "credential": {
                "id": id,
                "rawId": id,
                "type": "public-key",
                "response": {
                    "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
                    "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
                    "signature": URL_SAFE_NO_PAD.encode(signature.as_ref()),
                    "userHandle": self.user_handle.lock().unwrap().clone()
                },
                "extensions": {}
            }
        })
    }

    /// What `navigator.credentials.create` hands the page, for `options`.
    pub fn create(&self, options: &Value) -> Value {
        if let Some(handle) = options["publicKey"]["user"]["id"].as_str() {
            *self.user_handle.lock().unwrap() = handle.to_string();
        }
        let challenge = options["publicKey"]["challenge"].as_str().unwrap();
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": ORIGIN,
            "crossOrigin": false
        })
        .to_string();

        // COSE EC2 key: kty 2, alg -7 (ES256), crv 1 (P-256), x, y
        let point = self.key.public_key().as_ref();
        let mut cose = Vec::new();
        cbor_head(&mut cose, 5, 5);
        cbor_int(&mut cose, 1);
        cbor_int(&mut cose, 2);
        cbor_int(&mut cose, 3);
        cbor_int(&mut cose, -7);
        cbor_int(&mut cose, -1);
        cbor_int(&mut cose, 1);
        cbor_int(&mut cose, -2);
        cbor_bytes(&mut cose, &point[1..33]);
        cbor_int(&mut cose, -3);
        cbor_bytes(&mut cose, &point[33..65]);

        let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        // UP, UV, backup eligible, backed up, attested credential data
        auth_data.push(0x01 | 0x04 | 0x08 | 0x10 | 0x40);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend_from_slice(&cose);

        // Attestation `none` (PK-1)
        let mut attestation = Vec::new();
        cbor_head(&mut attestation, 5, 3);
        cbor_text(&mut attestation, "fmt");
        cbor_text(&mut attestation, "none");
        cbor_text(&mut attestation, "attStmt");
        cbor_head(&mut attestation, 5, 0);
        cbor_text(&mut attestation, "authData");
        cbor_bytes(&mut attestation, &auth_data);

        let id = URL_SAFE_NO_PAD.encode(&self.credential_id);
        json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode(&attestation),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
                "transports": ["internal"]
            },
            "extensions": {}
        })
    }
}

fn cbor_head(out: &mut Vec<u8>, major: u8, len: u64) {
    let major = major << 5;
    match len {
        0..=23 => out.push(major | len as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, len as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(major | 26);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
}

fn cbor_int(out: &mut Vec<u8>, n: i64) {
    if n >= 0 {
        cbor_head(out, 0, n as u64);
    } else {
        cbor_head(out, 1, (-1 - n) as u64);
    }
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

async fn register(body: Value) -> Value {
    HttpRequest::new()
        .post::<Value>("/api/passkey/register", &body)
        .await
        .unwrap_or_else(|err| panic!("{body}: {err}"))
}

/// Starts a registration through JMAP and returns its id and ticket.
async fn start_registration(user: &Account, name: &str) -> (String, String) {
    let (_, response) = call(
        user,
        "inbuxa:Passkey/set",
        json!({"create": {"k": {"name": name}}}),
    )
    .await;
    let created = &response["created"]["k"];
    let url = created["registrationUrl"]
        .as_str()
        .unwrap_or_else(|| panic!("{response}"));
    assert!(url.starts_with(ORIGIN), "{url}");
    (
        created["id"].as_str().unwrap().to_string(),
        url.split_once("ticket=").unwrap().1.to_string(),
    )
}

/// PK-6 to PK-8: the registration page's two steps.
async fn registration(user: &Account) -> SoftKey {
    let (laptop_id, ticket) = start_registration(user, "Laptop").await;

    // The server serves the page itself
    let page = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!(
            "https://127.0.0.1:8899/passkey/register?ticket={ticket}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    assert!(page.text().await.unwrap().contains("/api/passkey/register"));

    // PK-8: nothing without the password
    let response = register(json!({
        "step": "start", "ticket": ticket, "password": "wrong-password"
    }))
    .await;
    assert_eq!(response["type"], "failure", "{response}");
    let key = SoftKey::new(b"soft-key-laptop-0001");
    let response = register(json!({
        "step": "finish", "ticket": ticket, "credential": key.create(&json!({
            "publicKey": {"challenge": URL_SAFE_NO_PAD.encode(b"made-up")}
        }))
    }))
    .await;
    assert_eq!(response["type"], "expired", "{response}");
    let response = register(json!({
        "step": "start", "ticket": "not-a-ticket", "password": "passkey-secret-5521"
    }))
    .await;
    assert_eq!(response["type"], "expired", "{response}");

    // PK-1: discoverable, user verification, attestation none
    let response = register(json!({
        "step": "start", "ticket": ticket, "password": "passkey-secret-5521"
    }))
    .await;
    assert_eq!(response["type"], "options", "{response}");
    assert_eq!(response["name"], "Laptop");
    assert_eq!(response["accountName"], "passkey-user@example.com");
    let options = &response["options"];
    let selection = &options["publicKey"]["authenticatorSelection"];
    assert_eq!(selection["residentKey"], "required", "{options}");
    assert_eq!(selection["userVerification"], "required", "{options}");
    assert_eq!(options["publicKey"]["rp"]["id"], RP_ID, "{options}");
    assert_eq!(options["publicKey"]["attestation"], "none", "{options}");

    // A wrong origin is refused, and the step is used up
    let mut forged = key.create(options);
    forged["response"]["clientDataJSON"] = URL_SAFE_NO_PAD
        .encode(
            json!({
                "type": "webauthn.create",
                "challenge": options["publicKey"]["challenge"],
                "origin": "https://evil.example",
                "crossOrigin": false
            })
            .to_string(),
        )
        .into();
    let response =
        register(json!({"step": "finish", "ticket": ticket, "credential": forged})).await;
    assert_eq!(response["type"], "refused", "{response}");
    assert_eq!(list(user, user).await[0]["state"], "pending");

    // PK-7: done, the passkey is active
    let response = register(json!({
        "step": "start", "ticket": ticket, "password": "passkey-secret-5521"
    }))
    .await;
    let response = register(json!({
        "step": "finish", "ticket": ticket, "credential": key.create(&response["options"])
    }))
    .await;
    assert_eq!(response["type"], "registered", "{response}");
    assert_eq!(response["name"], "Laptop");
    let mine = list(user, user).await;
    let laptop = mine.iter().find(|p| p["id"] == laptop_id.as_str()).unwrap();
    assert_eq!(laptop["state"], "active", "{laptop}");
    assert_eq!(laptop["usable"], true, "{laptop}");
    assert_eq!(laptop["rpId"], RP_ID, "{laptop}");
    assert_eq!(laptop["backedUp"], true, "{laptop}");
    assert_eq!(laptop["transports"], json!(["internal"]), "{laptop}");

    // The ticket is good once
    let response = register(json!({
        "step": "start", "ticket": ticket, "password": "passkey-secret-5521"
    }))
    .await;
    assert_eq!(response["type"], "expired", "{response}");

    // PK-7: a credential id already registered is refused; the browser is
    // told which ones the account has
    let (_, ticket) = start_registration(user, "Again").await;
    let response = register(json!({
        "step": "start", "ticket": ticket, "password": "passkey-secret-5521"
    }))
    .await;
    let excluded = &response["options"]["publicKey"]["excludeCredentials"];
    assert_eq!(
        excluded[0]["id"],
        URL_SAFE_NO_PAD.encode(b"soft-key-laptop-0001"),
        "{response}"
    );
    let response = register(json!({
        "step": "finish", "ticket": ticket, "credential": key.create(&response["options"])
    }))
    .await;
    assert_eq!(response["type"], "refused", "{response}");
    key
}

async fn new_challenge() -> Value {
    let challenge = register_at("/api/auth/passkey", json!({})).await;
    assert_eq!(
        challenge["options"]["publicKey"]["rpId"], RP_ID,
        "{challenge}"
    );
    assert_eq!(
        challenge["options"]["publicKey"]["userVerification"], "required",
        "{challenge}"
    );
    challenge
}

async fn register_at(path: &str, body: Value) -> Value {
    HttpRequest::new()
        .post::<Value>(path, &body)
        .await
        .unwrap_or_else(|err| panic!("{path} {body}: {err}"))
}

const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "com.example.app:/cb";

async fn login(client_id: &str, assertion: Value) -> Value {
    register_at(
        "/api/auth",
        json!({
            "type": "authCode",
            "clientId": client_id,
            "redirectUri": REDIRECT,
            "codeChallenge": PKCE_CHALLENGE,
            "codeChallengeMethod": "S256",
            "passkey": assertion
        }),
    )
    .await
}

/// PK-9 to PK-12: sign-in in the authorization-code flow.
async fn sign_in(user: &Account, key: &SoftKey) -> String {
    let client = HttpRequest::with_credentials(
        8899,
        "admin@example.com",
        "these_pretzels_are_making_me_thirsty",
    )
    .post::<Value>("/auth/register", &json!({"redirect_uris": [REDIRECT]}))
    .await
    .unwrap();
    let client_id = client["client_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{client}"))
        .to_string();

    // A passkey signs in on its own and the code works
    let challenge = new_challenge().await;
    let assertion = key.get(&challenge, 5, ORIGIN);
    let response = login(&client_id, assertion.clone()).await;
    assert_eq!(response["type"], "authenticated", "{response}");
    let code = response["client_code"].as_str().unwrap().to_string();
    let token = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post("https://127.0.0.1:8899/auth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_verifier", PKCE_VERIFIER),
        ])
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(token["access_token"].is_string(), "{token}");
    let laptop = list(user, user)
        .await
        .into_iter()
        .find(|p| p["name"] == "Laptop")
        .unwrap();
    assert!(laptop["lastUsedAt"].is_string(), "{laptop}");

    // PK-10: a challenge is good once
    let response = login(&client_id, assertion).await;
    assert_eq!(response["type"], "failure", "{response}");

    // PK-11: a counter that didn't go up fails
    let challenge = new_challenge().await;
    let response = login(&client_id, key.get(&challenge, 5, ORIGIN)).await;
    assert_eq!(response["type"], "failure", "{response}");

    // PK-2: another origin fails
    let challenge = new_challenge().await;
    let response = login(&client_id, key.get(&challenge, 9, "https://evil.example")).await;
    assert_eq!(response["type"], "failure", "{response}");

    // An unknown passkey fails
    let stranger = SoftKey::new(b"soft-key-stranger-01");
    *stranger.user_handle.lock().unwrap() = key.user_handle.lock().unwrap().clone();
    let challenge = new_challenge().await;
    let response = login(&client_id, stranger.get(&challenge, 1, ORIGIN)).await;
    assert_eq!(response["type"], "failure", "{response}");

    // Still signs in with a higher counter
    let challenge = new_challenge().await;
    let response = login(&client_id, key.get(&challenge, 6, ORIGIN)).await;
    assert_eq!(response["type"], "authenticated", "{response}");

    // PK-8: the registration page takes the account's passkey instead of
    // the password, and not someone else's
    let (_, ticket) = start_registration(user, "Second").await;
    let challenge = new_challenge().await;
    let response = register(json!({
        "step": "start", "ticket": ticket, "passkey": key.get(&challenge, 7, ORIGIN)
    }))
    .await;
    assert_eq!(response["type"], "options", "{response}");
    client_id
}

/// The device flow, the settings and the off switches (PK-3, PK-5, PK-9,
/// PK-12).
async fn policy(admin: &Account, user: &Account, key: &SoftKey, client_id: &str) {
    // PK-9: the device flow takes a passkey too
    let device = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .post("https://127.0.0.1:8899/auth/device")
        .form(&[("client_id", client_id)])
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let user_code = device["user_code"]
        .as_str()
        .unwrap_or_else(|| panic!("{device}"));
    let challenge = new_challenge().await;
    let response = register_at(
        "/api/auth",
        json!({"type": "authDevice", "code": user_code, "passkey": key.get(&challenge, 8, ORIGIN)}),
    )
    .await;
    assert_eq!(response["type"], "verified", "{response}");

    // PK-5: maxPasskeys; the account has one passkey and two pending
    admin
        .registry_update_setting(
            Authentication {
                max_passkeys: 3,
                ..Default::default()
            },
            &[Property::MaxPasskeys],
        )
        .await;
    let (_, response) = call(
        user,
        "inbuxa:Passkey/set",
        json!({"create": {"k": {"name": "Fourth"}}}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["k"]["type"], "overQuota",
        "{response}"
    );
    admin
        .registry_update_setting(
            Authentication {
                max_passkeys: 10,
                ..Default::default()
            },
            &[Property::MaxPasskeys],
        )
        .await;

    // PK-19: the session says adding would work
    let caps = session_allows(user).await;
    assert_eq!(caps["passkeysAllowed"], true, "{caps}");
    assert_eq!(caps["maxPasskeys"], 10, "{caps}");

    // PK-12: the domain's off switch stops adding and signing in
    let domain_id = admin.find_or_create_domain("example.com").await;
    admin
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({"passkeysAllowed": false}),
        )
        .await;
    let (_, response) = call(
        user,
        "inbuxa:Passkey/set",
        json!({"create": {"k": {"name": "Off"}}}),
    )
    .await;
    assert_eq!(
        response["notCreated"]["k"]["type"], "forbidden",
        "{response}"
    );
    // PK-19: and the session says so up front
    let caps = session_allows(user).await;
    assert_eq!(caps["passkeysAllowed"], false, "{caps}");
    let challenge = new_challenge().await;
    let response = login(client_id, key.get(&challenge, 9, ORIGIN)).await;
    assert_eq!(response["type"], "failure", "{response}");
    admin
        .registry_update_object(
            ObjectType::Domain,
            domain_id,
            json!({"passkeysAllowed": true}),
        )
        .await;
    let challenge = new_challenge().await;
    let response = login(client_id, key.get(&challenge, 10, ORIGIN)).await;
    assert_eq!(response["type"], "authenticated", "{response}");

    // PK-9: off server-wide, the login page isn't offered a challenge
    admin
        .registry_update_setting(
            Authentication {
                passkeys_allowed: false,
                ..Default::default()
            },
            &[Property::PasskeysAllowed],
        )
        .await;
    let refused = HttpRequest::new()
        .post::<Value>("/api/auth/passkey", &json!({}))
        .await;
    assert!(
        refused
            .as_ref()
            .map_or(true, |response| response["challengeId"].is_null()),
        "{refused:?}"
    );
    admin
        .registry_update_setting(
            Authentication {
                passkeys_allowed: true,
                ..Default::default()
            },
            &[Property::PasskeysAllowed],
        )
        .await;

    // PK-3: the relying-party id must fit the public URL
    for bad in ["com", "example.com", "co.uk"] {
        let (_, response) = call(
            admin,
            "x:Authentication/set",
            json!({"update": {"singleton": {"passkeyRpId": bad}}}),
        )
        .await;
        assert_eq!(
            response["notUpdated"]["singleton"]["properties"][0], "passkeyRpId",
            "{bad}: {response}"
        );
    }
    let (_, response) = call(
        admin,
        "x:Authentication/set",
        json!({"update": {"singleton": {"passkeyRpId": RP_ID}}}),
    )
    .await;
    assert!(response["updated"].get("singleton").is_some(), "{response}");
    let challenge = new_challenge().await;
    let response = login(client_id, key.get(&challenge, 11, ORIGIN)).await;
    assert_eq!(response["type"], "authenticated", "{response}");
}

const PASSKEY_PERMISSIONS: [Permission; 4] = [
    Permission::SysPasskeyGet,
    Permission::SysPasskeyCreate,
    Permission::SysPasskeyUpdate,
    Permission::SysPasskeyDestroy,
];

/// #478: an install from before passkeys stored its default roles without
/// the passkey permissions. Start-up adds them once to the user, tenant
/// administrator and administrator roles, and never to the group role.
async fn upgraded_install(test: &TestServer, admin: &Account) {
    let auth = admin.registry_get::<Authentication>(Id::singleton()).await;
    let roles = [
        ("user", auth.default_user_role_ids.as_slice()[0], "Pguser:"),
        (
            "tenant",
            auth.default_tenant_role_ids.as_slice()[0],
            "Pgtenant:",
        ),
        ("admin", auth.default_admin_role_ids.as_slice()[0], "Pg"),
    ];
    let group_role = auth.default_group_role_ids.as_slice()[0];
    let held = |role_id: Id| async move {
        let role = admin.registry_get::<Role>(role_id).await;
        PASSKEY_PERMISSIONS
            .iter()
            .filter(|p| role.enabled_permissions.as_slice().contains(p))
            .count()
    };
    for (name, role_id, _) in roles {
        assert_eq!(
            held(role_id).await,
            4,
            "a new install's {name} role has them"
        );
    }

    // Back to how a pre-passkey install stored them
    let mut batch = BatchBuilder::new();
    for (_, role_id, prefix) in roles {
        let others: serde_json::Map<String, Value> = admin
            .registry_get::<Role>(role_id)
            .await
            .enabled_permissions
            .as_slice()
            .iter()
            .filter(|p| !PASSKEY_PERMISSIONS.contains(p))
            .map(|p| (p.as_str().to_string(), Value::Bool(true)))
            .collect();
        admin
            .registry_update_object(
                ObjectType::Role,
                role_id,
                json!({Property::EnabledPermissions: others}),
            )
            .await;
        for permission in PASSKEY_PERMISSIONS {
            batch.clear(ValueClass::Any(AnyClass {
                subspace: SUBSPACE_INBUXA,
                key: format!("{prefix}{}", permission.as_str()).into_bytes(),
            }));
        }
    }
    let mut bp = Bootstrap::new_uninitialized(test.server.registry().clone());
    bp.data_store.write(batch.build_all()).await.unwrap();
    for (name, role_id, _) in roles {
        assert_eq!(held(role_id).await, 0, "{name} role stripped");
    }
    let before = admin
        .create_user_account(
            "passkey-before@example.com",
            "passkey-before-7712",
            "Before the upgrade",
            &[],
            vec![],
        )
        .await;
    let (name, response) = call(&before, "inbuxa:Passkey/get", json!({"ids": null})).await;
    assert_eq!(name, "error", "refused before the upgrade: {response}");

    // The upgrade: start-up grants them once
    bp.insert_safe_defaults().await;
    assert!(bp.errors.is_empty(), "{:?}", bp.errors);
    for (name, role_id, _) in roles {
        assert_eq!(held(role_id).await, 4, "{name} role granted on upgrade");
    }
    assert_eq!(held(group_role).await, 0, "never the group role");
    // Start-up grants before anything is cached; here the server is already
    // running, so drop its caches as a restart would
    test.server.invalidate_all_local_caches();
    let after = admin
        .create_user_account(
            "passkey-after@example.com",
            "passkey-after-8823",
            "After the upgrade",
            &[],
            vec![],
        )
        .await;
    assert!(list(&after, &after).await.is_empty());

    // An operator who takes them away again keeps them away
    let user_role = roles[0].1;
    let others: serde_json::Map<String, Value> = admin
        .registry_get::<Role>(user_role)
        .await
        .enabled_permissions
        .as_slice()
        .iter()
        .filter(|p| **p != Permission::SysPasskeyCreate)
        .map(|p| (p.as_str().to_string(), Value::Bool(true)))
        .collect();
    admin
        .registry_update_object(
            ObjectType::Role,
            user_role,
            json!({Property::EnabledPermissions: others}),
        )
        .await;
    Bootstrap::new_uninitialized(test.server.registry().clone())
        .insert_safe_defaults()
        .await;
    assert_eq!(held(user_role).await, 3, "not granted twice");
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn passkey_tests() {
    let mut test = TestServerBuilder::new("passkey_tests")
        .await
        .with_public_host("localhost")
        .with_default_listeners()
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.com").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    let admin = test.account("admin@example.com");
    upgraded_install(&test, admin).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
