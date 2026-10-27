/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::utils::{
    http::HttpRequest,
    pop3::Pop3Connection,
    server::TestServer,
    smtp::SmtpConnection,
};
use base64::{Engine, engine::general_purpose};
use biscuit::{JWT, SingleOrMultiple, jwk::JWKSet};
use bytes::Bytes;
use common::auth::oauth::{
    introspect::OAuthIntrospect,
    oidc::StandardClaims,
    registration::{
        ClientRegistrationRequest, ClientRegistrationResponse, TokenEndpointAuthMethod,
    },
};
use http::auth::oauth::{
    DeviceAuthResponse, ErrorType, TokenResponse,
    auth::{LoginRequest, LoginResponse},
};
use jmap_client::{
    client::{Client, Credentials},
    mailbox::query::Filter,
};
use registry::schema::{
    enums::{JwtSignatureAlgorithm, OAuthGrantType, OAuthScope},
    prelude::{ObjectType, Property},
    structs::{OAuthClient, OidcProvider, SecretText, SecretTextValue},
};
use serde::{Serialize, de::DeserializeOwned};
use rustls_pki_types::ServerName;
use std::time::{Duration, Instant};
use store::ahash::AHashMap;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;
use utils::tls::build_tls_connector;

#[derive(Debug, serde::Deserialize)]
pub struct OAuthMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    pub authorization_endpoint: String,
    pub device_authorization_endpoint: String,
    pub registration_endpoint: String,
    pub introspection_endpoint: String,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub authorization_response_iss_parameter_supported: bool,
}

#[derive(Debug, serde::Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
}

const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
// inbuxa: 1.0 issues an ID token only when `openid` is granted
const PROFILE_SCOPE: &str = "openid urn:ietf:params:oauth:scope:mail offline_access";
const STATE: &str = "af0ifjsldkj";

#[derive(Debug, serde::Deserialize)]
pub struct OpenIdMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: String,
    pub device_authorization_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub authorization_response_iss_parameter_supported: bool,
}

pub async fn test(test: &mut TestServer) {
    println!("Running OIDC tests...");

    let admin = test.account("admin@example.org");

    // Set test parameters
    // inbuxa: five times upstream's lifetimes. Expiry counts whole seconds, so
    // a 1s token could lapse before a debug build's next request.
    // 1.0 dropped auth_code_max_attempts (a code is consumed on first use),
    // refresh_token_renewal (refresh tokens rotate on every refresh) and
    // require_client_registration (unknown client ids are always refused).
    // 1.0's registry refuses lifetimes under 10 minutes (a day for refresh
    // tokens), on /set and when the setting loads, so the short ones are set
    // on the running core after the reload; the next reload restores the
    // registry's.
    let settings = OidcProvider {
        anonymous_client_registration: true,
        signature_algorithm: JwtSignatureAlgorithm::Rs256,
        signature_key: SecretText::Text(SecretTextValue {
            secret: OIDC_SIGNATURE_KEY_RS256.to_string(),
        }),
        ..Default::default()
    };
    admin
        .registry_update_setting(
            settings,
            &[
                Property::AnonymousClientRegistration,
                Property::SignatureAlgorithm,
                Property::SignatureKey,
            ],
        )
        .await;
    admin.reload_settings().await;
    let inner = &test.server.inner;
    let mut core = inner.shared_core.load_full().as_ref().clone();
    core.oauth.oauth_expiry_token = 5;
    core.oauth.oauth_expiry_auth_code = 5;
    core.oauth.oauth_expiry_user_code = 5;
    core.oauth.oauth_expiry_refresh_token = 15;
    inner.shared_core.store(std::sync::Arc::new(core));

    // Create test account
    let user = test
        .create_user_account(
            "admin@example.org",
            "user@example.org",
            "this is a very strong password",
            &[],
            "user@example.org",
        )
        .await;
    let user_id = user.id();

    // Build API
    let http = HttpRequest::new();

    // Obtain OAuth metadata
    let metadata: OAuthMetadata =
        get("https://127.0.0.1:8899/.well-known/oauth-authorization-server").await;
    let oidc_metadata: OpenIdMetadata =
        get("https://127.0.0.1:8899/.well-known/openid-configuration").await;
    let jwk_set: JWKSet<()> = get(&oidc_metadata.jwks_uri).await;

    // OAuth Public Clients profile: the authorization server metadata must advertise the
    // mandatory properties (RFC 8414 + draft-ietf-mailmaint-oauth-public).
    assert!(
        metadata
            .grant_types_supported
            .iter()
            .any(|g| g == "authorization_code")
    );
    assert!(
        metadata
            .grant_types_supported
            .iter()
            .any(|g| g == "refresh_token")
    );
    assert!(
        metadata
            .response_types_supported
            .iter()
            .any(|r| r == "code")
    );
    assert!(
        metadata
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|m| m == "none")
    );
    assert!(
        metadata
            .code_challenge_methods_supported
            .iter()
            .any(|m| m == "S256")
    );
    assert!(metadata.authorization_response_iss_parameter_supported);
    for scope in [
        "urn:ietf:params:oauth:scope:mail",
        "urn:ietf:params:oauth:scope:contacts",
        "urn:ietf:params:oauth:scope:calendars",
        "offline_access",
    ] {
        assert!(
            metadata.scopes_supported.iter().any(|s| s == scope),
            "missing scope {scope}"
        );
    }
    assert!(
        oidc_metadata
            .grant_types_supported
            .iter()
            .any(|g| g == "refresh_token")
    );
    assert!(
        oidc_metadata
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|m| m == "none")
    );
    assert!(oidc_metadata.authorization_response_iss_parameter_supported);

    // Protected Resource Metadata (RFC 9728)
    let resource_metadata: ProtectedResourceMetadata =
        get("https://127.0.0.1:8899/.well-known/oauth-protected-resource").await;
    assert_eq!(
        resource_metadata.authorization_servers,
        vec![metadata.issuer.clone()]
    );
    assert!(
        resource_metadata
            .bearer_methods_supported
            .iter()
            .any(|m| m == "header")
    );
    assert!(!resource_metadata.resource.is_empty());

    // Dynamic Client Registration: invalid redirect URIs are rejected (RFC 7591 §3.2.2)
    for bad_uri in [
        "http://example.com/cb",
        "http://127.0.0.1/cb#frag",
        "http://127.0.0.1/../cb",
        // inbuxa: 1.0 wants a path on a loopback redirect URI, even "/"
        "http://127.0.0.1",
        "http://127.0.0.1:54321",
        "http://[::1]:8080",
    ] {
        let (status, body) = post_json_raw(
            &metadata.registration_endpoint,
            &ClientRegistrationRequest {
                redirect_uris: vec![bad_uri.to_string()],
                ..Default::default()
            },
        )
        .await;
        assert_eq!(status, 400, "expected rejection for {bad_uri}: {body}");
        assert_eq!(body["error"], "invalid_redirect_uri", "for {bad_uri}");
    }

    // A loopback redirect URI is accepted and registration returns 201 Created,
    // including loopback URIs that specify an ephemeral port (RFC 8252 §7.3).
    for good_uri in [
        "http://127.0.0.1/cb",
        "http://127.0.0.1:54321/cb",
        "http://[::1]:8080/cb",
        "http://127.0.0.1/",
        "http://127.0.0.1:54321/",
        "http://[::1]:8080/",
    ] {
        let (status, body) = post_json_raw(
            &metadata.registration_endpoint,
            &ClientRegistrationRequest {
                redirect_uris: vec![good_uri.to_string()],
                scope: Some(PROFILE_SCOPE.to_string()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(
            status, 201,
            "registration should return 201 for {good_uri}: {body}"
        );
    }

    // Register the client used for the flow with a private-use scheme redirect URI
    let registration: ClientRegistrationResponse = post_json(
        &metadata.registration_endpoint,
        None,
        &ClientRegistrationRequest {
            redirect_uris: vec!["com.example.app:/cb".to_string()],
            scope: Some(PROFILE_SCOPE.to_string()),
            ..Default::default()
        },
    )
    .await;
    let client_id = registration.client_id;

    // Public client ids are stateless (self-describing) and issued deterministically
    assert!(
        client_id.starts_with("swc1."),
        "expected stateless client id, got {client_id}"
    );
    let registration2: ClientRegistrationResponse = post_json(
        &metadata.registration_endpoint,
        None,
        &ClientRegistrationRequest {
            redirect_uris: vec!["com.example.app:/cb".to_string()],
            scope: Some(PROFILE_SCOPE.to_string()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        registration2.client_id, client_id,
        "identical registration must be deterministic"
    );

    /*println!("OAuth metadata: {:#?}", metadata);
    println!("OpenID metadata: {:#?}", oidc_metadata);
    println!("JWKSet: {:#?}", jwk_set);*/

    // ------------------------
    // Authorization code flow
    // ------------------------

    // A redirect URI that does not match the client registration must be rejected
    // and the authorization server must not issue a code (OAuth Public Clients §3.4)
    // inbuxa: 1.0 answers a refused authorization with 200 and an `invalid` or
    // `redirect` login response, so "not authorized" means no code was issued
    let (status, body) = post_login_raw(&auth_code_request(AuthQuery {
        client_id: &client_id,
        redirect_uri: "com.example.app:/evil",
        nonce: None,
        scope: Some(PROFILE_SCOPE),
        code_challenge: Some(PKCE_CHALLENGE),
        code_challenge_method: Some("S256"),
        resources: &[],
    }))
    .await;
    assert_not_authorized(
        status,
        &body,
        "mismatched redirect URI must not be authorized",
    );

    // An unknown resource indicator must be rejected (RFC 8707)
    let (status, body) = post_login_raw(&auth_code_request(AuthQuery {
        client_id: &client_id,
        redirect_uri: "com.example.app:/cb",
        nonce: None,
        scope: Some(PROFILE_SCOPE),
        code_challenge: Some(PKCE_CHALLENGE),
        code_challenge_method: Some("S256"),
        resources: &["https://evil.example.com/jmap"],
    }))
    .await;
    assert_not_authorized(
        status,
        &body,
        "unknown resource indicator must not be authorized",
    );

    // inbuxa: only S256 is accepted. `plain`, named or as RFC 7636's default
    // when no method is given, sends the verifier itself as the challenge.
    for method in [Some("plain"), None] {
        let (status, body) = post_login_raw(&auth_code_request(AuthQuery {
            client_id: &client_id,
            redirect_uri: "com.example.app:/cb",
            nonce: None,
            scope: Some(PROFILE_SCOPE),
            code_challenge: Some(PKCE_VERIFIER),
            code_challenge_method: method,
            resources: &[],
        }))
        .await;
        assert_not_authorized(
            status,
            &body,
            &format!("PKCE method {method:?} must not be authorized"),
        );
    }

    // Authenticate with the correct password, PKCE (S256), scope and a valid resource indicator
    let response = http
        .post::<LoginResponse>(
            "/api/auth",
            &auth_code_request(AuthQuery {
                client_id: &client_id,
                redirect_uri: "com.example.app:/cb",
                nonce: Some("abc1234"),
                scope: Some(PROFILE_SCOPE),
                code_challenge: Some(PKCE_CHALLENGE),
                code_challenge_method: Some("S256"),
                resources: &["https://mail.example.org/jmap/session"],
            }),
        )
        .await
        .unwrap();

    // The issuer returned in the authorization response must match the metadata issuer (RFC 9207)
    // inbuxa: 1.0 returns the redirect location; the issuer rides in its `iss`
    if let LoginResponse::Authenticated { location } = &response {
        assert_eq!(
            location_param(location, "iss").as_deref(),
            Some(metadata.issuer.as_str())
        );
        assert_eq!(location_param(location, "state").as_deref(), Some(STATE));
    } else {
        panic!("Expected an authenticated response, got {response:?}");
    }

    // Both client_id and redirect_uri have to match
    // inbuxa: 1.0 checks the code's own client and redirect URI first, so a
    // mismatch of either is invalid_grant rather than invalid_client
    let mut token_params = AHashMap::from_iter([
        ("client_id".to_string(), "invalid_client".to_string()),
        (
            "redirect_uri".to_string(),
            "com.example.app:/cb".to_string(),
        ),
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), response.unwrap_code()),
        ("code_verifier".to_string(), PKCE_VERIFIER.to_string()),
    ]);
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidGrant
        }
    );
    token_params.insert("client_id".to_string(), client_id.to_string());
    token_params.insert(
        "redirect_uri".to_string(),
        "com.example.app:/other".to_string(),
    );
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidGrant
        }
    );

    // A missing or invalid PKCE verifier must be rejected (RFC 7636)
    token_params.insert(
        "redirect_uri".to_string(),
        "com.example.app:/cb".to_string(),
    );
    token_params.insert(
        "code_verifier".to_string(),
        "the-wrong-verifier".to_string(),
    );
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidGrant
        }
    );

    // Obtain token and verify the granted scope is echoed back
    token_params.insert("code_verifier".to_string(), PKCE_VERIFIER.to_string());
    let granted = post::<TokenResponse>(&metadata.token_endpoint, &token_params).await;
    if let TokenResponse::Granted(response) = &granted {
        assert_eq!(response.scope, PROFILE_SCOPE);
    }
    let (token, refresh_token, id_token) = unwrap_oidc_token_response(granted);

    // Connect to account using token and attempt to search
    let john_client = Client::new()
        .credentials(Credentials::bearer(&token))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(john_client.default_account_id(), user_id.to_string());
    assert!(
        !john_client
            .mailbox_query(None::<Filter>, None::<Vec<_>>)
            .await
            .unwrap()
            .ids()
            .is_empty()
    );

    // Verify ID token using the JWK set
    let id_token = JWT::<StandardClaims, biscuit::Empty>::new_encoded(&id_token)
        .decode_with_jwks(&jwk_set, None)
        .unwrap();
    let claims = id_token.payload().unwrap();
    let registered_claims = &claims.registered;
    let private_claims = &claims.private;
    assert_eq!(registered_claims.issuer, Some(oidc_metadata.issuer));
    assert_eq!(
        registered_claims.subject,
        Some(user_id.document_id().to_string())
    );
    assert_eq!(
        registered_claims.audience,
        Some(SingleOrMultiple::Single(client_id.to_string()))
    );
    assert_eq!(private_claims.nonce, Some("abc1234".into()));
    assert_eq!(
        private_claims.preferred_username,
        Some("user@example.org".into())
    );
    assert_eq!(private_claims.email, Some("user@example.org".into()));

    // Introspect token
    let access_introspect: OAuthIntrospect = post_with_auth::<OAuthIntrospect>(
        &metadata.introspection_endpoint,
        token.as_str().into(),
        &AHashMap::from_iter([("token".to_string(), token.to_string())]),
    )
    .await;
    assert_eq!(access_introspect.username.unwrap(), "user@example.org");
    assert_eq!(access_introspect.token_type.unwrap(), "bearer");
    // inbuxa: 1.0 names the grant's client
    assert_eq!(access_introspect.client_id.as_deref(), Some(client_id.as_str()));
    assert!(access_introspect.active);
    let refresh_introspect = post_with_auth::<OAuthIntrospect>(
        &metadata.introspection_endpoint,
        token.as_str().into(),
        &AHashMap::from_iter([("token".to_string(), refresh_token.unwrap())]),
    )
    .await;
    assert_eq!(refresh_introspect.username.unwrap(), "user@example.org");
    assert_eq!(refresh_introspect.client_id.as_deref(), Some(client_id.as_str()));
    assert!(refresh_introspect.active);
    assert_eq!(
        refresh_introspect.iat.unwrap(),
        access_introspect.iat.unwrap()
    );

    // Try SMTP OAUTHBEARER auth
    let oauth_bearer_invalid_sasl = general_purpose::STANDARD.encode(format!(
        "n,a={},\u{1}auth=Bearer {}\u{1}\u{1}",
        "user@domain", "invalid_token"
    ));
    let oauth_bearer_sasl = general_purpose::STANDARD.encode(format!(
        "n,a={},\u{1}auth=Bearer {}\u{1}\u{1}",
        "user@domain", token
    ));
    // inbuxa: 1.0 takes bearer tokens only over TLS (accepts_bearer_tokens),
    // so in plain text AUTH is refused, and the checks run after STARTTLS
    let mut smtp = SmtpConnection::connect().await;
    smtp.send(&format!("AUTH OAUTHBEARER {oauth_bearer_sasl}",))
        .await;
    smtp.read(1, 5).await;
    let mut smtp = TlsLines::lmtp_starttls().await;
    smtp.send(&format!("AUTH OAUTHBEARER {oauth_bearer_sasl}"))
        .await;
    let reply = smtp.read_smtp().await;
    assert!(reply.starts_with('2'), "SMTP OAUTHBEARER: {reply}");

    // Try IMAP OAUTHBEARER auth
    // inbuxa: over the implicit TLS listener, for the same reason
    let mut imap = TlsLines::connect(
        TcpStream::connect("127.0.0.1:9992").await.unwrap(),
        "imap.example.org",
    )
    .await;
    let greeting = imap.read_until(|line| line.starts_with("* ")).await;
    assert!(greeting.starts_with("* OK"), "IMAP greeting: {greeting}");
    imap.send(&format!("_x AUTHENTICATE OAUTHBEARER {oauth_bearer_sasl}"))
        .await;
    let reply = imap.read_until(|line| line.starts_with("_x ")).await;
    assert!(reply.starts_with("_x OK"), "IMAP OAUTHBEARER: {reply}");

    // Try POP3 OAUTHBEARER auth
    let mut pop3 = Pop3Connection::connect().await;
    pop3.send(&format!("AUTH OAUTHBEARER {oauth_bearer_sasl}"))
        .await;
    pop3.assert_read(crate::utils::pop3::ResponseType::Ok).await;

    // inbuxa: 1.0 answers a refused token with the RFC 7628 error challenge;
    // the client's %x01 ends the exchange with the failure. Checked after the
    // valid token's uses: the failure takes waitOnFail (5s), the token's
    // lifetime here
    let mut smtp = TlsLines::lmtp_starttls().await;
    smtp.send(&format!("AUTH OAUTHBEARER {oauth_bearer_invalid_sasl}"))
        .await;
    let reply = smtp.read_smtp().await;
    let challenge = reply
        .strip_prefix("334 ")
        .and_then(|challenge| general_purpose::STANDARD.decode(challenge).ok())
        .map(|challenge| String::from_utf8_lossy(&challenge).into_owned())
        .unwrap_or_else(|| panic!("SMTP invalid OAUTHBEARER: {reply}"));
    assert!(
        challenge.contains("\"status\":\"invalid_token\""),
        "SMTP invalid OAUTHBEARER challenge: {challenge}"
    );
    smtp.send("AQ==").await;
    let reply = smtp.read_smtp().await;
    assert!(reply.starts_with("535"), "SMTP invalid OAUTHBEARER: {reply}");

    // ------------------------
    // Confidential client with client_secret
    // ------------------------

    // Registering a confidential client requires authentication and returns a
    // generated client_secret exactly once. Web (https) redirect URIs are allowed.
    let confidential_redirect = "https://confidential.example.org/callback";
    let confidential: ClientRegistrationResponse = post_json_basic(
        &metadata.registration_endpoint,
        "admin",
        "popolna_zapora",
        &ClientRegistrationRequest {
            redirect_uris: vec![confidential_redirect.to_string()],
            scope: Some(PROFILE_SCOPE.to_string()),
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::ClientSecretPost),
            ..Default::default()
        },
    )
    .await;
    let confidential_id = confidential.client_id;
    let confidential_secret = confidential
        .client_secret
        .expect("confidential client must receive a client_secret");
    assert!(
        !confidential_id.starts_with("swc1."),
        "confidential client id must be registry-backed, got {confidential_id}"
    );
    assert!(
        confidential_secret.len() >= 40,
        "client secret is too short: {confidential_secret}"
    );

    // Registering a confidential client anonymously must be rejected
    let (status, _) = post_json_raw(
        &metadata.registration_endpoint,
        &ClientRegistrationRequest {
            redirect_uris: vec![confidential_redirect.to_string()],
            token_endpoint_auth_method: Some(TokenEndpointAuthMethod::ClientSecretBasic),
            ..Default::default()
        },
    )
    .await;
    assert_ne!(
        status, 201,
        "anonymous confidential client registration must be rejected"
    );

    let base_params = || {
        AHashMap::from_iter([
            ("client_id".to_string(), confidential_id.to_string()),
            (
                "redirect_uri".to_string(),
                confidential_redirect.to_string(),
            ),
            ("grant_type".to_string(), "authorization_code".to_string()),
        ])
    };

    // A confidential client that omits its secret must be rejected
    let mut params = base_params();
    params.insert(
        "code".to_string(),
        obtain_auth_code(&http, &confidential_id, confidential_redirect).await,
    );
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidClient
        },
        "token request without client_secret must be rejected"
    );

    // A confidential client that presents a wrong secret must be rejected
    let mut params = base_params();
    params.insert(
        "code".to_string(),
        obtain_auth_code(&http, &confidential_id, confidential_redirect).await,
    );
    params.insert("client_secret".to_string(), "not-the-secret".to_string());
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidClient
        },
        "token request with a wrong client_secret must be rejected"
    );

    // The correct secret in the request body (client_secret_post) grants a usable token
    let mut params = base_params();
    params.insert(
        "code".to_string(),
        obtain_auth_code(&http, &confidential_id, confidential_redirect).await,
    );
    params.insert("client_secret".to_string(), confidential_secret.to_string());
    let (token, _, _) = unwrap_token_response(post(&metadata.token_endpoint, &params).await);
    let confidential_client = Client::new()
        .credentials(Credentials::bearer(&token))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(
        confidential_client.default_account_id(),
        user_id.to_string()
    );

    // The correct secret in the Authorization header (client_secret_basic) also works
    let mut params = base_params();
    params.remove("client_id");
    params.insert(
        "code".to_string(),
        obtain_auth_code(&http, &confidential_id, confidential_redirect).await,
    );
    let granted: TokenResponse = post_form_basic(
        &metadata.token_endpoint,
        &confidential_id,
        &confidential_secret,
        &params,
    )
    .await;
    unwrap_token_response(granted);

    // A confidential client created through the management API must have its
    // secret hashed before storage; authenticating with the plaintext secret
    // only succeeds if the stored value is a verifiable hash.
    let managed_secret = "managed-client-secret-abcdefghijklmnopqrstuvwxyz";
    let managed_id = "managed-confidential-client";
    admin
        .registry_create_object(OAuthClient {
            client_id: managed_id.to_string(),
            redirect_uris: vec![confidential_redirect.to_string()].into(),
            secret: Some(managed_secret.to_string()),
            // inbuxa: 1.0 grants a registered client only its listed scopes
            scopes: vec![OAuthScope::Mail].into(),
            ..Default::default()
        })
        .await;

    let managed_params = || {
        AHashMap::from_iter([
            ("client_id".to_string(), managed_id.to_string()),
            (
                "redirect_uri".to_string(),
                confidential_redirect.to_string(),
            ),
            ("grant_type".to_string(), "authorization_code".to_string()),
        ])
    };

    let mut params = managed_params();
    params.insert(
        "code".to_string(),
        obtain_auth_code(&http, managed_id, confidential_redirect).await,
    );
    params.insert("client_secret".to_string(), "wrong-secret".to_string());
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &params).await,
        TokenResponse::Error {
            error: ErrorType::InvalidClient
        },
        "management-api client must reject a wrong secret"
    );

    let mut params = managed_params();
    params.insert(
        "code".to_string(),
        obtain_auth_code(&http, managed_id, confidential_redirect).await,
    );
    params.insert("client_secret".to_string(), managed_secret.to_string());
    unwrap_token_response(post(&metadata.token_endpoint, &params).await);

    // ------------------------
    // Device code flow
    // ------------------------

    // inbuxa: 1.0 keeps the device code grant to registered clients; a
    // stateless (self-describing) client id is refused it
    let device_client_id = "device-public-client";
    admin
        .registry_create_object(OAuthClient {
            client_id: device_client_id.to_string(),
            grant_types: vec![OAuthGrantType::DeviceCode, OAuthGrantType::RefreshToken].into(),
            // inbuxa: 1.0 grants a registered client only its listed scopes
            scopes: vec![OAuthScope::Mail].into(),
            ..Default::default()
        })
        .await;
    let client_id = device_client_id.to_string();

    // Request a device code
    // inbuxa: 1.0 grants only the scopes asked for; without the mail scope
    // the token reaches no account
    let device_code_params = AHashMap::from_iter([
        ("client_id".to_string(), client_id.to_string()),
        (
            "scope".to_string(),
            "urn:ietf:params:oauth:scope:mail offline_access".to_string(),
        ),
    ]);
    let device_response: DeviceAuthResponse =
        post(&metadata.device_authorization_endpoint, &device_code_params).await;
    //println!("Device response: {:#?}", device_response);

    // Status should be pending
    let mut token_params = AHashMap::from_iter([
        ("client_id".to_string(), client_id.to_string()),
        (
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ),
        (
            "device_code".to_string(),
            device_response.device_code.to_string(),
        ),
    ]);
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::AuthorizationPending
        }
    );

    // Let the code expire and make sure it's invalidated
    tokio::time::sleep(Duration::from_secs(6)).await; // inbuxa: past the 5s code
    assert_eq!(
        http.post::<LoginResponse>(
            "/api/auth",
            &LoginRequest::AuthDevice {
                account_name: "user@example.org".to_string(),
                account_secret: "this is a very strong password".to_string(),
                mfa_token: None,
                code: device_response.user_code.clone(),
                consent: Some(true),
            },
        )
        .await
        .unwrap(),
        LoginResponse::Failure
    );
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::ExpiredToken
        }
    );

    // Authenticate account using a valid code
    let device_response: DeviceAuthResponse =
        post(&metadata.device_authorization_endpoint, &device_code_params).await;
    token_params.insert(
        "device_code".to_string(),
        device_response.device_code.to_string(),
    );
    assert_eq!(
        http.post::<LoginResponse>(
            "/api/auth",
            &LoginRequest::AuthDevice {
                account_name: "user@example.org".to_string(),
                account_secret: "this is a very strong password".to_string(),
                mfa_token: None,
                code: device_response.user_code.clone(),
                consent: Some(true),
            },
        )
        .await
        .unwrap(),
        LoginResponse::Verified
    );

    // Obtain token
    let time_first_token = Instant::now();
    let (token, refresh_token, _) =
        unwrap_token_response(post(&metadata.token_endpoint, &token_params).await);
    let refresh_token = refresh_token.unwrap();

    // Authorization codes can only be used once
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &token_params).await,
        TokenResponse::Error {
            error: ErrorType::ExpiredToken
        }
    );

    // Connect to account using token and attempt to search
    let john_client = Client::new()
        .credentials(Credentials::bearer(&token))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(john_client.default_account_id(), user_id.to_string());
    assert!(
        !john_client
            .mailbox_query(None::<Filter>, None::<Vec<_>>)
            .await
            .unwrap()
            .ids()
            .is_empty()
    );

    // Connecting using the refresh token should not work
    assert_unauthorized("https://127.0.0.1:8899", &refresh_token).await;

    // Refreshing a token using the access token should not work
    assert_eq!(
        post::<TokenResponse>(
            &metadata.token_endpoint,
            &AHashMap::from_iter([
                ("client_id".to_string(), client_id.to_string()),
                ("grant_type".to_string(), "refresh_token".to_string()),
                ("refresh_token".to_string(), token),
            ]),
        )
        .await,
        TokenResponse::Error {
            error: ErrorType::InvalidGrant
        }
    );

    // inbuxa: 1.0 rotates the refresh token on every refresh, so refreshing
    // before expiration also returns a new refresh token, and each one
    // expires refresh_token_expiry after it was issued
    let refresh_params = |refresh_token: String| {
        AHashMap::from_iter([
            ("client_id".to_string(), client_id.to_string()),
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token),
        ])
    };
    let time_before_post: Instant = Instant::now();
    let (token, new_refresh_token, _) = unwrap_token_response(
        post(&metadata.token_endpoint, &refresh_params(refresh_token.clone())).await,
    );
    let new_refresh_token = new_refresh_token.unwrap_or_else(|| {
        panic!(
            "No rotated refresh token in {:?}, since start {:?}",
            time_before_post.elapsed(),
            time_first_token.elapsed()
        )
    });
    assert_ne!(new_refresh_token, refresh_token);

    // Wait 1 second and make sure the access token expired
    tokio::time::sleep(Duration::from_secs(6)).await; // inbuxa: past the 5s token
    assert_unauthorized("https://127.0.0.1:8899", &token).await;

    // Wait another second and expect a new refresh token
    tokio::time::sleep(Duration::from_secs(2)).await; // inbuxa: ~8s in
    let (_, new_refresh_token, _) = unwrap_token_response(
        post(&metadata.token_endpoint, &refresh_params(new_refresh_token)).await,
    );
    //println!("New refresh token: {:?}", new_refresh_token);
    let new_refresh_token = new_refresh_token.expect("a rotated refresh token");

    // Wait and make sure the refresh token expired
    tokio::time::sleep(Duration::from_secs(16)).await; // inbuxa: past its 15s
    assert_eq!(
        post::<TokenResponse>(&metadata.token_endpoint, &refresh_params(new_refresh_token))
            .await,
        TokenResponse::Error {
            error: ErrorType::InvalidGrant
        }
    );

    // Clean up
    admin.registry_destroy_all(ObjectType::OAuthClient).await;
    admin.destroy_account(user).await;
    test.cleanup().await;
}

// inbuxa: a line client over TLS, for the bearer checks above (the IMAP
// and SMTP helpers speak plain text only)
struct TlsLines {
    reader: Lines<BufReader<ReadHalf<TlsStream<TcpStream>>>>,
    writer: WriteHalf<TlsStream<TcpStream>>,
}

impl TlsLines {
    async fn connect(stream: TcpStream, name: &'static str) -> Self {
        let (reader, writer) = tokio::io::split(
            build_tls_connector(true)
                .unwrap()
                .connect(ServerName::try_from(name).unwrap().to_owned(), stream)
                .await
                .unwrap(),
        );
        TlsLines {
            reader: BufReader::new(reader).lines(),
            writer,
        }
    }

    async fn lmtp_starttls() -> Self {
        let mut stream = TcpStream::connect("127.0.0.1:11200").await.unwrap();
        let mut plain = BufReader::new(&mut stream);
        for command in [None, Some("LHLO localhost"), Some("STARTTLS")] {
            if let Some(command) = command {
                plain
                    .get_mut()
                    .write_all(format!("{command}\r\n").as_bytes())
                    .await
                    .unwrap();
            }
            loop {
                let mut line = String::new();
                tokio::time::timeout(Duration::from_secs(5), plain.read_line(&mut line))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(line.starts_with('2'), "LMTP {command:?}: {line}");
                if line.as_bytes().get(3) == Some(&b' ') {
                    break;
                }
            }
        }
        drop(plain);
        let mut conn = Self::connect(stream, "lmtp.example.org").await;
        conn.send("LHLO localhost").await;
        conn.read_smtp().await;
        conn
    }

    async fn send(&mut self, line: &str) {
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .unwrap();
    }

    async fn read_until(&mut self, done: impl Fn(&str) -> bool) -> String {
        loop {
            // a failed SMTP AUTH answers after waitOnFail (5s by default)
            let line = tokio::time::timeout(Duration::from_secs(15), self.reader.next_line())
                .await
                .unwrap()
                .unwrap()
                .expect("connection closed");
            if done(&line) {
                return line;
            }
        }
    }

    async fn read_smtp(&mut self) -> String {
        self.read_until(|line| line.as_bytes().get(3) == Some(&b' '))
            .await
    }
}

async fn post_bytes(
    url: &str,
    auth_token: Option<&str>,
    params: &AHashMap<String, String>,
) -> Bytes {
    let mut client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .post(url);

    if let Some(auth_token) = auth_token {
        client = client.bearer_auth(auth_token);
    }

    client
        .form(params)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
}

async fn post_json<D: DeserializeOwned>(
    url: &str,
    auth_token: Option<&str>,
    body: &impl Serialize,
) -> D {
    let mut client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .post(url);

    if let Some(auth_token) = auth_token {
        client = client.bearer_auth(auth_token);
    }

    serde_json::from_slice(
        &client
            .body(serde_json::to_string(body).unwrap().into_bytes())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn post_json_basic<D: DeserializeOwned>(
    url: &str,
    username: &str,
    password: &str,
    body: &impl Serialize,
) -> D {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .post(url)
        .basic_auth(username, Some(password))
        .body(serde_json::to_string(body).unwrap().into_bytes())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    serde_json::from_slice(&response).unwrap()
}

async fn post_form_basic<T: DeserializeOwned>(
    url: &str,
    username: &str,
    password: &str,
    params: &AHashMap<String, String>,
) -> T {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .post(url)
        .basic_auth(username, Some(password))
        .form(params)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    serde_json::from_slice(&response).unwrap()
}

async fn obtain_auth_code(http: &HttpRequest, client_id: &str, redirect_uri: &str) -> String {
    http.post::<LoginResponse>(
        "/api/auth",
        &auth_code_request(AuthQuery {
            client_id,
            redirect_uri,
            nonce: None,
            scope: Some(PROFILE_SCOPE),
            code_challenge: None,
            code_challenge_method: None,
            resources: &[],
        }),
    )
    .await
    .unwrap()
    .unwrap_code()
}

/// inbuxa: 1.0's login request carries the authorization request as the
/// query string the client sent to the authorization endpoint.
struct AuthQuery<'x> {
    client_id: &'x str,
    redirect_uri: &'x str,
    nonce: Option<&'x str>,
    scope: Option<&'x str>,
    code_challenge: Option<&'x str>,
    code_challenge_method: Option<&'x str>,
    resources: &'x [&'x str],
}

fn auth_code_request(query: AuthQuery<'_>) -> LoginRequest {
    let mut params = form_urlencoded::Serializer::new(String::new());
    params
        .append_pair("response_type", "code")
        .append_pair("client_id", query.client_id)
        .append_pair("redirect_uri", query.redirect_uri)
        .append_pair("state", STATE);
    for (name, value) in [
        ("nonce", query.nonce),
        ("scope", query.scope),
        ("code_challenge", query.code_challenge),
        ("code_challenge_method", query.code_challenge_method),
    ] {
        if let Some(value) = value {
            params.append_pair(name, value);
        }
    }
    for resource in query.resources {
        params.append_pair("resource", resource);
    }
    LoginRequest::AuthCode {
        account_name: "user@example.org".to_string(),
        account_secret: "this is a very strong password".to_string(),
        mfa_token: None,
        query: params.finish(),
        consent: Some(true),
    }
}

/// A query parameter of a redirect location.
fn location_param(location: &str, name: &str) -> Option<String> {
    let (_, query) = location.split_once('?')?;
    form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

fn assert_not_authorized(status: u16, body: &serde_json::Value, message: &str) {
    assert!(
        status != 200 || body["type"] != "authenticated",
        "{message}: {status} {body}"
    );
}

async fn post_json_raw(url: &str, body: &impl Serialize) -> (u16, serde_json::Value) {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .post(url)
        .body(serde_json::to_string(body).unwrap().into_bytes())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn post_login_raw(body: &impl Serialize) -> (u16, serde_json::Value) {
    post_json_raw("https://127.0.0.1:8899/api/auth", body).await
}

async fn post<T: DeserializeOwned>(url: &str, params: &AHashMap<String, String>) -> T {
    post_with_auth(url, None, params).await
}
async fn post_with_auth<T: DeserializeOwned>(
    url: &str,
    auth_token: Option<&str>,
    params: &AHashMap<String, String>,
) -> T {
    serde_json::from_slice(&post_bytes(url, auth_token, params).await).unwrap()
}

async fn get_bytes(url: &str) -> Bytes {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
        .get(url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
}

async fn get<T: DeserializeOwned>(url: &str) -> T {
    serde_json::from_slice(&get_bytes(url).await).unwrap()
}

async fn assert_unauthorized(base_url: &str, token: &str) {
    match Client::new()
        .credentials(Credentials::bearer(token))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect(base_url)
        .await
    {
        Ok(_) => panic!("Expected unauthorized access."),
        Err(err) => {
            let err = err.to_string();
            assert!(err.contains("Unauthorized"), "{}", err);
        }
    }
}

fn unwrap_token_response(response: TokenResponse) -> (String, Option<String>, u64) {
    match response {
        TokenResponse::Granted(granted) => {
            assert_eq!(granted.token_type, "bearer");
            (
                granted.access_token,
                granted.refresh_token,
                granted.expires_in,
            )
        }
        TokenResponse::Error { error } => panic!("Expected granted, got {:?}", error),
    }
}

fn unwrap_oidc_token_response(response: TokenResponse) -> (String, Option<String>, String) {
    match response {
        TokenResponse::Granted(granted) => {
            assert_eq!(granted.token_type, "bearer");
            (
                granted.access_token,
                granted.refresh_token,
                granted.id_token.unwrap(),
            )
        }
        TokenResponse::Error { error } => panic!("Expected granted, got {:?}", error),
    }
}

pub trait LoginResponseTest {
    fn unwrap_code(self) -> String;
}

impl LoginResponseTest for LoginResponse {
    fn unwrap_code(self) -> String {
        match self {
            LoginResponse::Authenticated { location } => location_param(&location, "code")
                .unwrap_or_else(|| panic!("No code in {location}")),
            _ => panic!("Expected auth code response, got {:?}", self),
        }
    }
}

const OIDC_SIGNATURE_KEY_RS256: &str = "-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDMXJI1bL3z8gaF
Ze/6493VjL+jHkFMP2Pc7fLwRF1fhkuIdYTp69LabzrSEJCRCz0UI2NHqPOgtOta
+zRHKAMr7c7Z6uKO0K+aXiQYHw4Y70uSG8CnmNl7kb4OM/CAcoO6fePmvBsyESfn
TmkJ5bfHEZQFDQEAoDlDjtjxuwYsAQQVQXuAydi8j8pyTWKAJ1RDgnUT+HbOub7j
JrQ7sPe6MPCjXv5N76v9RMHKktfYwRNMlkLkxImQU55+vlvghNztgFlIlJDFfNiy
UQPV5FTEZJli9BzMoj1JQK3sZyV8WV0W1zN41QQ+glAAC6+K7iTDPRMINBSwbHyn
6Lb9Q6U7AgMBAAECggEAB93qZ5xrhYgEFeoyKO4mUdGsu4qZyJB0zNeWGgdaXCfZ
zC4l8zFM+R6osix0EY6lXRtC95+6h9hfFQNa5FWseupDzmIQiEnim1EowjWef87l
Eayi0nDRB8TjqZKjR/aLOUhzrPlXHKrKEUk/RDkacCiDklwz9S0LIfLOSXlByBDM
/n/eczfX2gUATexMHSeIXs8vN2jpuiVv0r+FPXcRvqdzDZnYSzS8BJ9k6RYXVQ4o
NzCbfqgFIpVryB7nHgSTrNX9G7299If8/dXmesXWSFEJvvDSSpcBoINKbfgSlrxd
6ubjiotcEIBUSlbaanRrydwShhLHnXyupNAb7tlvyQKBgQDsIipSK4+H9FGl1rAk
Gg9DLJ7P/94sidhoq1KYnj/CxwGLoRq22khZEUYZkSvYXDu1Qkj9Avi3TRhw8uol
l2SK1VylL5FQvTLKhWB7b2hjrUd5llMRgS3/NIdLhOgDMB7w3UxJnCA/df/Rj+dM
WhkyS1f0x3t7XPLwWGurW0nJcwKBgQDdjhrNfabrK7OQvDpAvNJizuwZK9WUL7CD
rR0V0MpDGYW12BTEOY6tUK6XZgiRitAXf4EkEI6R0Q0bFzwDDLrg7TvGdTuzNeg/
8vm8IlRlOkrdihtHZI4uRB7Ytmz24vzywEBE0p6enA7v4oniscUks/KKmDGr0V90
yT9gIVrjGQKBgQCjnWC5otlHGLDiOgm+WhgtMWOxN9dYAQNkMyF+Alinu4CEoVKD
VGhA3sk1ufMpbW8pvw4X0dFIITFIQeift3DBCemxw23rBc2FqjkaDi3EszINO22/
eUTHyjvcxfCFFPi7aHsNnhJyJm7lY9Kegudmg/Ij93zGE7d5darVBuHvpQKBgBBY
YovUgFMLR1UfPeD2zUKy52I4BKrJFemxBNtOKw3mPSIcTfPoFymcMTVENs+eARoq
svlZK1uAo8ni3e+Pqd3cQrOyhHQFPxwwrdH+amGJemp7vOV4erDZH7l3Q/S27Fhw
bI1nSIKFGukBupB58wRxLiyha9C0QqmYC0/pRg5JAn8Rbj5tP26oVCXjZEfWJL8J
axxSxsGA4Vol6i6LYnVgZG+1ez2rP8vUORo1lRzmdeP4o1BSJf9TPwXkuppE5J+t
UZVKtYGlEn1RqwGNd8I9TiWvU84rcY9nsxlDR86xwKRWFvYqVOiGYtzRyewYRdjU
rTs9aqB3v1+OVxGxR6Na
-----END PRIVATE KEY-----
";

#[allow(dead_code)]
const OIDC_SIGNATURE_KEY_ES256: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggybcqc86ulFFiOon
WiYrLO4z8/kmkqvA7wGElBok9IqhRANCAAQxZK68FnQtHC0eyh8CA05xRIvxhVHn
0ymka6XBh9aFtW4wfeoKhTkSKjHc/zjh9Rr2dr3kvmYe80fMGhW4ycGA
-----END PRIVATE KEY-----
";
