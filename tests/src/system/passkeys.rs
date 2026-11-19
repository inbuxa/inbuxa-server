/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Passkeys (passkeys spec): `inbuxa:Passkey` management (PK-5, PK-14 to
//! PK-17): starting a registration, the limit per account, renaming,
//! removing, who reaches whose passkeys, and the audit log. Registration on
//! the server's page (PK-6 to PK-8), with a software authenticator.

use crate::utils::{
    account::Account,
    http::HttpRequest,
    server::{TestServer, TestServerBuilder},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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

    registration(&user).await;
}

/// A software authenticator: one P-256 key, user verification always done.
pub struct SoftKey {
    pub key: EcdsaKeyPair,
    pub credential_id: Vec<u8>,
}

impl SoftKey {
    pub fn new(credential_id: &[u8]) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        SoftKey {
            key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
            credential_id: credential_id.to_vec(),
        }
    }

    /// What `navigator.credentials.create` hands the page, for `options`.
    pub fn create(&self, options: &Value) -> Value {
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
async fn registration(user: &Account) {
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
    if test.is_reset() {
        test.temp_dir.delete();
    }
}
