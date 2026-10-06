/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! SCIM 2.0 provisioning (`docs/spec/features/scim.md`). The helpers the
//! surviving suites import, rebuilt from the spec, and the suites' entry
//! points. `scim_tests` runs the acceptance suite, tenant isolation and,
//! with `SCIM_CONFORMANCE=1`, the third-party clients in a container.

pub mod acceptance;
pub mod conformance;
pub mod oidc;
pub mod tenant;

use crate::utils::{account::Account, server::TestServer};
use registry::{
    schema::{
        enums::{Permission, StorageQuota},
        prelude::{ObjectType, Property},
        structs::{
            self, Action, CertificateManagement, DkimManagement, DnsManagement, Domain,
            PasswordCredential, Permissions, PermissionsList, UserAccount,
        },
    },
    types::{EnumImpl, list::List, map::Map},
};
use scim_proto::{MESSAGE_PATCH_OP, SCHEMA_GROUP, SCHEMA_USER};
use serde_json::{Value, json};
use types::id::Id;

/// The server-level domain the main SCIM client provisions into.
pub const SCIM_DOMAIN: &str = "scim.example.com";
/// The test server's HTTP listener.
pub const HTTP_PORT: u16 = 8899;
pub const PRINCIPAL: &str = "scim-svc@scim.example.com";
pub const PRINCIPAL_SECRET: &str = "these_pretzels_are_making_me_thirsty";

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

/// A SCIM client with a fixed `Authorization` header.
#[derive(Clone)]
pub struct ScimClient {
    authorization: Option<String>,
}

/// A SCIM answer, with assertions.
#[derive(Debug, Clone)]
pub struct ScimReply {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: String,
    pub json: Value,
}

impl ScimClient {
    pub fn bearer(token: &str) -> Self {
        ScimClient {
            authorization: Some(format!("Bearer {token}")),
        }
    }

    pub fn with_authorization(authorization: Option<String>) -> Self {
        ScimClient { authorization }
    }

    pub fn anonymous() -> Self {
        ScimClient {
            authorization: None,
        }
    }

    pub async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> ScimReply {
        let url = format!("https://127.0.0.1:{HTTP_PORT}/scim/v2{path}");
        let mut request = http().request(method, url);
        if let Some(authorization) = &self.authorization {
            request = request.header("authorization", authorization);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request
                .header("content-type", "application/scim+json")
                .body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap();
        let json = serde_json::from_str(&body).unwrap_or(Value::Null);
        ScimReply {
            status,
            headers,
            body,
            json,
        }
    }

    pub async fn get(&self, path: &str) -> ScimReply {
        self.request(reqwest::Method::GET, path, None, &[]).await
    }

    pub async fn post(&self, path: &str, body: Value) -> ScimReply {
        self.request(reqwest::Method::POST, path, Some(body), &[])
            .await
    }

    pub async fn put(&self, path: &str, body: Value) -> ScimReply {
        self.request(reqwest::Method::PUT, path, Some(body), &[])
            .await
    }

    pub async fn patch(&self, path: &str, body: Value) -> ScimReply {
        self.request(reqwest::Method::PATCH, path, Some(body), &[])
            .await
    }

    pub async fn delete(&self, path: &str) -> ScimReply {
        self.request(reqwest::Method::DELETE, path, None, &[]).await
    }
}

impl ScimReply {
    pub fn assert_status(&self, status: u16) -> &Self {
        assert_eq!(self.status, status, "Unexpected status: {}", self.body);
        self
    }

    /// A SCIM error document with that status and, if given, `scimType`.
    pub fn assert_error(&self, status: u16, scim_type: Option<&str>) -> &Self {
        assert_eq!(self.status, status, "Unexpected status: {}", self.body);
        assert_eq!(
            self.json["schemas"],
            json!(["urn:ietf:params:scim:api:messages:2.0:Error"]),
            "Not a SCIM error: {}",
            self.body
        );
        assert_eq!(
            self.json["status"],
            json!(status.to_string()),
            "{}",
            self.body
        );
        if let Some(scim_type) = scim_type {
            assert_eq!(self.json["scimType"], json!(scim_type), "{}", self.body);
        }
        assert_eq!(
            self.header("content-type").as_deref(),
            Some("application/scim+json"),
            "{}",
            self.body
        );
        self
    }

    pub fn assert_detail_contains(&self, text: &str) -> &Self {
        let detail = self.json["detail"].as_str().unwrap_or_default();
        assert!(detail.contains(text), "'{detail}' lacks '{text}'");
        self
    }

    pub fn id(&self) -> String {
        self.json["id"]
            .as_str()
            .unwrap_or_else(|| panic!("No id in {}", self.body))
            .to_string()
    }

    pub fn etag(&self) -> Option<String> {
        self.header("etag")
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    pub fn total_results(&self) -> u64 {
        self.json["totalResults"]
            .as_u64()
            .unwrap_or_else(|| panic!("No totalResults in {}", self.body))
    }

    pub fn resource_ids(&self) -> Vec<String> {
        self.json["Resources"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["id"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn assert_contains_id(&self, id: &str) -> &Self {
        assert!(
            self.resource_ids().iter().any(|i| i == id),
            "{id} missing from {}",
            self.body
        );
        self
    }

    pub fn assert_lacks_id(&self, id: &str) -> &Self {
        assert!(
            !self.resource_ids().iter().any(|i| i == id),
            "{id} present in {}",
            self.body
        );
        self
    }
}

pub fn user_body(user_name: &str) -> Value {
    json!({"schemas": [SCHEMA_USER], "userName": user_name})
}

pub fn group_body(display_name: &str) -> Value {
    json!({"schemas": [SCHEMA_GROUP], "displayName": display_name})
}

pub fn patch_body(operations: Value) -> Value {
    json!({"schemas": [MESSAGE_PATCH_OP], "Operations": operations})
}

/// `path?filter=…`, encoded.
pub fn query(path: &str, filter: &str) -> String {
    let encoded =
        http_proto::form_urlencoded::byte_serialize(filter.as_bytes()).collect::<String>();
    format!("{path}?filter={encoded}")
}

/// The status of `GET /jmap/session` with that `Authorization` header.
pub async fn jmap_session_status(authorization: &str) -> u16 {
    http()
        .get(format!("https://127.0.0.1:{HTTP_PORT}/jmap/session"))
        .header("authorization", authorization)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// An API key for `principal`, created over JMAP as the principal itself.
/// Returns the secret.
pub async fn api_key(admin: &Account, principal: &Account, permissions: Value) -> String {
    let _ = admin;
    api_key_with_id(principal, permissions).await.1
}

/// An API key's registry id and secret.
pub async fn api_key_with_id(principal: &Account, permissions: Value) -> (Id, String) {
    let response = principal
        .jmap_create(
            "x:ApiKey",
            [json!({"description": "SCIM", "permissions": permissions})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let created = response.created(0);
    let secret = created["secret"]
        .as_str()
        .unwrap_or_else(|| panic!("No API key secret in {response:?}"))
        .to_string();
    (response.created_id(0), secret)
}

/// A user account with a password and extra permissions, for principals.
pub async fn create_principal(
    admin: &Account,
    name: &str,
    domain_id: Id,
    tenant_id: Option<Id>,
    permissions: Vec<Permission>,
) -> Id {
    let id = admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: name.to_string(),
            domain_id,
            member_tenant_id: tenant_id,
            description: Some("SCIM service principal".to_string()),
            credentials: List::from_iter([structs::Credential::Password(PasswordCredential {
                secret: PRINCIPAL_SECRET.to_string(),
                ..Default::default()
            })]),
            permissions: Permissions::Merge(PermissionsList {
                disabled_permissions: Default::default(),
                enabled_permissions: Map::new(permissions),
            }),
            ..Default::default()
        }))
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            id,
            json!({ Property::Quotas: { StorageQuota::MaxApiKeys.as_str(): 20 } }),
        )
        .await;
    id
}

/// The permissions a full SCIM key needs (spec, "Setting it up").
pub fn full_permissions() -> Vec<Permission> {
    vec![
        Permission::ScimAccess,
        Permission::SysAccountGet,
        Permission::SysAccountCreate,
        Permission::SysAccountUpdate,
        Permission::SysAccountDestroy,
        Permission::UnlimitedRequests,
    ]
}

/// The main SCIM client, a server-level principal on [`SCIM_DOMAIN`].
pub struct ScimTest {
    pub client: ScimClient,
    pub token: String,
    pub domain_id: Id,
    pub principal_id: Id,
}

impl ScimTest {
    pub async fn new(test: &TestServer) -> Self {
        let admin = test.account("admin");
        let domain_id = admin
            .registry_create_object(Domain {
                is_enabled: true,
                name: SCIM_DOMAIN.to_string(),
                certificate_management: CertificateManagement::Manual,
                dns_management: DnsManagement::Manual,
                dkim_management: DkimManagement::Manual,
                allow_scim_provisioning: true,
                ..Default::default()
            })
            .await;
        let principal_id =
            create_principal(admin, "scim-svc", domain_id, None, full_permissions()).await;
        admin.registry_create_object(Action::InvalidateCaches).await;
        let principal = Account::new(PRINCIPAL, PRINCIPAL_SECRET, &[], "", principal_id);
        let token = api_key(admin, &principal, json!({"@type": "Inherit"})).await;
        ScimTest {
            client: ScimClient::bearer(&token),
            token,
            domain_id,
            principal_id,
        }
    }

    /// Creates a user on the SCIM domain; its id.
    pub async fn create_user(&self, user_name: &str) -> String {
        self.client
            .post("/Users", user_body(user_name))
            .await
            .assert_status(201)
            .id()
    }

    /// Creates a group; its id.
    pub async fn create_group(&self, display_name: &str) -> String {
        self.client
            .post("/Groups", group_body(display_name))
            .await
            .assert_status(201)
            .id()
    }

    /// Deletes a resource, whether or not it's still there.
    pub async fn destroy(&self, path: &str) {
        let reply = self.client.delete(path).await;
        assert!(
            matches!(reply.status, 204 | 404),
            "Deleting {path}: {}",
            reply.body
        );
    }
}

/// The SCIM suites that run without containers, and the third-party
/// clients with `SCIM_CONFORMANCE=1`.
/// `cargo test -p tests scim_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn scim_tests() {
    let test = crate::utils::server::TestServerBuilder::new("scim_tests")
        .await
        .with_default_listeners()
        .await
        .with_object(registry::schema::structs::Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
        .await
        .with_object(registry::schema::structs::MtaStageRcpt {
            wait_on_fail: registry::schema::structs::Expression {
                else_: "1ms".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .with_object(registry::schema::structs::MtaStageAuth {
            require: registry::schema::structs::Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;
    let scim = ScimTest::new(&test).await;
    acceptance::test(&test, &scim).await;
    tenant::test(&test, &scim).await;
    if conformance::is_enabled() {
        conformance::test(&scim).await;
    }
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

/// Acceptance test 5: SCIM's authority over sign-in sync, with Keycloak as
/// one domain's own directory (per-domain directories, feature 9).
/// `cargo test -p tests scim_oidc_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn scim_oidc_tests() {
    let test = crate::utils::server::TestServerBuilder::new("scim_oidc_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;
    let scim = ScimTest::new(&test).await;
    oidc::test(&test, &scim).await;
}

/// Acceptance test 31 (compat): on a copy of INBUXA's data, the SCIM
/// fields read back as observed 1: no domain open to SCIM, and no account
/// with an `externalId`. Run with `INBUXA_COMPAT_ADMIN` (`name:password`),
/// `NO_INSERT=1`, and the store's `TMPDIR`/`STORE` pointing at the copy.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn scim_compat() {
    let admin = std::env::var("INBUXA_COMPAT_ADMIN").expect("INBUXA_COMPAT_ADMIN");
    assert!(std::env::var("NO_INSERT").is_ok(), "NO_INSERT must be set");
    let _test = crate::utils::server::TestServerBuilder::new("scim_compat")
        .await
        .with_default_listeners()
        .await
        .build_with_opts(false)
        .await;
    let (name, secret) = admin.split_once(':').expect("name:password");
    let admin = Account::new(
        Box::leak(name.to_string().into_boxed_str()),
        Box::leak(secret.to_string().into_boxed_str()),
        &[],
        "Compat admin",
        Id::from(u32::MAX),
    );

    admin.assert_authenticates("INBUXA_COMPAT_ADMIN").await;
    let domains = admin
        .jmap_method_call("x:Domain/get", json!({"ids": null}))
        .await;
    for domain in domains.list() {
        assert_eq!(
            domain["allowScimProvisioning"],
            json!(false),
            "observed 1: {}",
            domain["name"]
        );
    }
    let accounts = admin
        .jmap_method_call("x:Account/get", json!({"ids": null}))
        .await;
    assert!(!accounts.list().is_empty(), "the copy has accounts");
    for account in accounts.list() {
        assert!(
            account["externalId"].is_null(),
            "observed 1: {}",
            account["name"]
        );
    }
}
