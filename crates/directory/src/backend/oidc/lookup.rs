/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    Account, Credentials,
    backend::oidc::{CachedKey, Introspection, OidcError, OpaqueTokens, OpenIdDirectory},
};
use ahash::AHashMap;
use jsonwebtoken::{
    Algorithm, DecodingKey, Header, Validation, decode, decode_header,
    jwk::{self, JwkSet},
};
use reqwest::Client;
use serde_json::Value;
use std::time::Instant;
use std::{sync::Arc, time::Duration};
use trc::AuthEvent;

impl OpenIdDirectory {
    pub async fn authenticate(&self, credentials: &Credentials) -> trc::Result<Account> {
        match credentials {
            Credentials::Bearer { token, .. } if token.is_empty() => {
                Err(AuthEvent::Failed.into_err().reason("Empty token rejected"))
            }
            Credentials::Bearer { token, .. } => if let Ok(header) = decode_header(token) {
                self.authenticate_jwt(token, header).await
            } else {
                #[cfg(feature = "test_mode")]
                let token = token.strip_prefix(".").unwrap_or(token);
                self.authenticate_opaque(token).await
            }
            .map_err(|err| match err {
                // inbuxa: DIR-30: a refused token is an authentication
                // failure and counts toward the sign-in ban; a network,
                // provider or configuration fault is an error and doesn't
                OidcError::AuthorizationFailed(reason) | OidcError::TokenValidation(reason) => {
                    AuthEvent::Failed.into_err().reason(reason)
                }
                err => AuthEvent::Error.into_err().reason(err),
            }),
            _ => Err(AuthEvent::Error
                .into_err()
                .reason("Unsupported credentials type for OIDC backend")),
        }
    }

    async fn authenticate_jwt(&self, token: &str, header: Header) -> Result<Account, OidcError> {
        if matches!(
            header.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            return Err(OidcError::TokenValidation(
                "Unsupported algorithm".to_string(),
            ));
        }

        let candidates = self.get_key(header.kid.as_deref()).await?;
        let mut last_err = None;
        for cached in &candidates {
            let dk = &cached.decoding_key;
            let alg = cached.algorithm;
            let mut validation = Validation::new(alg);

            if let Some(aud) = &self.config.require_aud {
                validation.set_audience(&[aud]);
            } else {
                validation.validate_aud = false;
            }

            validation.set_issuer(&[&self.discovery.document.issuer]);
            validation.leeway = 60;

            match decode::<serde_json::Value>(token, dk, &validation) {
                Ok(token_data) => {
                    if self.config.require_aud.is_some() && token_data.claims.get("aud").is_none() {
                        last_err = Some(jsonwebtoken::errors::Error::from(
                            jsonwebtoken::errors::ErrorKind::InvalidAudience,
                        ));
                        continue;
                    }

                    check_token_type(&token_data.claims)?;
                    self.validate_scopes(&token_data.claims)?;

                    return self.account_from_claims(token, token_data.claims).await;
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(OidcError::TokenValidation(format!(
            "JWT validation failed: {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )))
    }

    /// inbuxa: the account a validated token's claims name, with what they
    /// lack taken from the user info endpoint (shared by JWTs and
    /// introspected tokens).
    async fn account_from_claims(
        &self,
        token: &str,
        mut claims: serde_json::Value,
    ) -> Result<Account, OidcError> {
        let missing_username = is_claim_missing(&claims, Some(&self.config.claim_email));
        let jwt_email = self.resolve_email(&claims).ok();
        let missing_profile = is_claim_missing(&claims, self.config.claim_name.as_ref())
            || is_claim_missing(&claims, self.config.claim_groups.as_ref());

        if jwt_email.is_none() || missing_username || missing_profile {
            match self.fetch_userinfo(token).await {
                Ok(userinfo) => {
                    if let (Some(base), Value::Object(extra)) = (claims.as_object_mut(), userinfo) {
                        for (key, value) in extra {
                            if base.get(&key).is_none_or(Value::is_null) {
                                base.insert(key, value);
                            }
                        }
                    }
                }
                Err(err) if jwt_email.is_none() => return Err(err),
                Err(_) => {}
            }
        }

        let email = match jwt_email {
            Some(email) if !missing_username => email,
            _ => self.resolve_email(&claims)?,
        };
        self.build_account(email, &claims)
    }

    async fn authenticate_opaque(&self, token: &str) -> Result<Account, OidcError> {
        // inbuxa: http-directory-services-13: by the directory's policy
        match &self.config.opaque_tokens {
            OpaqueTokens::Reject => Err(OidcError::TokenValidation(
                "This directory accepts only JWT access tokens".to_string(),
            )),
            OpaqueTokens::Userinfo => {
                let claims = self.fetch_userinfo(token).await?;
                self.build_account(self.resolve_email(&claims)?, &claims)
            }
            OpaqueTokens::Introspection(introspection) => {
                let claims = self.introspect(token, introspection).await?;
                check_token_type(&claims)?;
                self.validate_scopes(&claims)?;
                self.account_from_claims(token, claims).await
            }
        }
    }

    /// inbuxa: http-directory-services-13: asks the provider about a token
    /// (RFC 7662), and returns what it says only for an active token it
    /// issued, for the required audience when one is set.
    async fn introspect(
        &self,
        token: &str,
        introspection: &Introspection,
    ) -> Result<serde_json::Value, OidcError> {
        let url = introspection
            .url
            .as_deref()
            .ok_or_else(|| OidcError::Config("No introspection endpoint is known".to_string()))?;
        let resp = self
            .http
            .post(url)
            // RFC 6749, section 2.3.1: both form-encoded first
            .basic_auth(
                form_encode(&introspection.client_id),
                Some(form_encode(&introspection.client_secret)),
            )
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(format!(
                "token={}&token_type_hint=access_token",
                form_encode(token)
            ))
            .send()
            .await
            .map_err(|e| OidcError::Network(format!("Introspection request failed: {e}")))?;

        // A refusal here is of this server's client credentials, not the token
        let status = resp.status();
        if !status.is_success() {
            return Err(OidcError::Provider(format!(
                "Introspection returned HTTP {status}"
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| OidcError::Provider(format!("Introspection HTTP error: {e}")))?;
        let claims = serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|e| OidcError::Provider(format!("Introspection JSON parse error: {e}")))?;

        if claims.get("active") != Some(&Value::Bool(true)) {
            return Err(OidcError::AuthorizationFailed(
                "The provider says the token is not active".to_string(),
            ));
        }
        let issuer = self.discovery.document.issuer.trim_end_matches('/');
        if claims
            .get("iss")
            .and_then(|iss| iss.as_str())
            .is_none_or(|iss| iss.trim_end_matches('/') != issuer)
        {
            return Err(OidcError::TokenValidation(
                "The token was not issued by this directory's provider".to_string(),
            ));
        }
        if let Some(audience) = &self.config.require_aud {
            let found = match claims.get("aud") {
                Some(Value::String(aud)) => aud == audience,
                Some(Value::Array(auds)) => auds.iter().any(|aud| aud.as_str() == Some(audience)),
                _ => false,
            };
            if !found {
                return Err(OidcError::TokenValidation(
                    "The token was not issued for the required audience".to_string(),
                ));
            }
        }
        if let Some(exp) = claims.get("exp").and_then(|exp| exp.as_u64())
            && exp + 60
                < std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |now| now.as_secs())
        {
            return Err(OidcError::TokenValidation(
                "The token has expired".to_string(),
            ));
        }

        Ok(claims)
    }

    async fn get_key(&self, kid: Option<&str>) -> Result<Vec<Arc<CachedKey>>, OidcError> {
        {
            let guard = self.cache.read().await;

            if let Some(kid) = kid {
                if let Some(cached) = guard.keys.get(kid) {
                    return Ok(vec![cached.clone()]);
                }

                if guard.last_updated.elapsed() < Duration::from_secs(300) {
                    return Err(OidcError::TokenValidation("Unknown key id".to_string()));
                }
            } else {
                let all: Vec<_> = guard.keys.values().cloned().collect();
                if !all.is_empty() {
                    return Ok(all);
                }
            }
        }

        let new_keys = fetch_jwks_keys(&self.http, &self.discovery.document.jwks_uri).await?;
        {
            let mut guard = self.cache.write().await;
            guard.keys = new_keys;
            guard.last_updated = Instant::now();
        }

        let guard = self.cache.read().await;
        if let Some(kid) = kid {
            if let Some(cached) = guard.keys.get(kid) {
                Ok(vec![cached.clone()])
            } else {
                Err(OidcError::TokenValidation(
                    "Unknown key id after refresh".to_string(),
                ))
            }
        } else {
            let all: Vec<_> = guard.keys.values().cloned().collect();
            if all.is_empty() {
                Err(OidcError::Provider(
                    "JWKS contains no usable keys".to_string(),
                ))
            } else {
                Ok(all)
            }
        }
    }

    async fn fetch_userinfo(&self, token: &str) -> Result<serde_json::Value, OidcError> {
        let resp = self
            .http
            .get(&self.discovery.document.userinfo_endpoint)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| OidcError::Network(format!("UserInfo request failed: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            let reason = resp.text().await.unwrap_or_default();
            return Err(OidcError::AuthorizationFailed(format!(
                "Token rejected by UserInfo endpoint with status {status}: {reason}"
            )));
        }
        if !status.is_success() {
            return Err(OidcError::Provider(format!(
                "UserInfo returned HTTP {status}"
            )));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| OidcError::Provider(format!("UserInfo HTTP error: {e}")))?;

        serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|e| OidcError::Provider(format!("UserInfo JSON parse error: {e}")))
    }

    fn validate_scopes(&self, claims: &serde_json::Value) -> Result<(), OidcError> {
        if !self.config.require_scopes.is_empty() {
            let token_scopes = extract_scopes(claims);

            for required in &self.config.require_scopes {
                if !token_scopes.iter().any(|s| s == required) {
                    return Err(OidcError::AuthorizationFailed(format!(
                        "Missing required scope '{required}', present scopes: {token_scopes:?}"
                    )));
                }
            }
        }

        Ok(())
    }

    fn build_account(
        &self,
        email: String,
        claims: &serde_json::Value,
    ) -> Result<Account, OidcError> {
        Ok(Account {
            email,
            email_aliases: Vec::new(),
            secret: None,
            groups: self
                .config
                .claim_groups
                .as_ref()
                .and_then(|groups_claim| claims.get(groups_claim))
                .and_then(extract_string_list)
                .map(|groups| {
                    groups
                        .into_iter()
                        .map(|group| match &self.config.default_domain {
                            Some(domain) if !group.contains('@') => format!("{group}@{domain}"),
                            _ => group,
                        })
                        .collect()
                }),
            description: self
                .config
                .claim_name
                .as_ref()
                .and_then(|name_claim| claims.get(name_claim))
                .and_then(|v| v.as_str())
                .filter(|name| !name.is_empty())
                .map(|s| s.to_string()),
        })
    }

    fn resolve_email(&self, claims: &serde_json::Value) -> Result<String, OidcError> {
        if let Some(val) = claims
            .get(&self.config.claim_email)
            .and_then(|v| v.as_str())
        {
            if val.contains('@') {
                return Ok(val.to_string());
            }
            if let Some(domain) = &self.config.default_domain {
                return Ok(format!("{val}@{domain}"));
            }
        }

        if self.config.claim_email != "email"
            && let Some(val) = claims.get("email").and_then(|v| v.as_str())
            && val.contains('@')
        {
            return Ok(val.to_string());
        }

        Err(OidcError::AuthorizationFailed(
            "Could not determine a valid email address for account".to_string(),
        ))
    }
}

pub(super) async fn fetch_jwks_keys(
    http: &Client,
    jwks_uri: &str,
) -> Result<AHashMap<String, Arc<CachedKey>>, OidcError> {
    let jwks_bytes = http
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| OidcError::Network(format!("JWKS fetch failed: {e}")))?
        .error_for_status()
        .map_err(|e| OidcError::Provider(format!("JWKS HTTP error: {e}")))?
        .bytes()
        .await
        .map_err(|e| OidcError::Provider(format!("JWKS HTTP error: {e}")))?;
    let jwks: JwkSet = serde_json::from_slice(&jwks_bytes)
        .map_err(|e| OidcError::Provider(format!("JWKS JSON parse error: {e}")))?;

    let mut map = AHashMap::new();
    let mut synthetic_id: u64 = 0;

    for key in &jwks.keys {
        if let Some(pk_use) = &key.common.public_key_use
            && pk_use != &jwk::PublicKeyUse::Signature
        {
            continue;
        }

        let algorithm = match &key.algorithm {
            jwk::AlgorithmParameters::RSA(_) => match key.common.key_algorithm {
                Some(jwk::KeyAlgorithm::RS256) => Algorithm::RS256,
                Some(jwk::KeyAlgorithm::RS384) => Algorithm::RS384,
                Some(jwk::KeyAlgorithm::RS512) => Algorithm::RS512,
                Some(jwk::KeyAlgorithm::PS256) => Algorithm::PS256,
                Some(jwk::KeyAlgorithm::PS384) => Algorithm::PS384,
                Some(jwk::KeyAlgorithm::PS512) => Algorithm::PS512,
                None => Algorithm::RS256,
                Some(other) => {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = jwks_uri.to_string(),
                        Reason = format!("Unsupported RSA key algorithm {:?}", other)
                    );
                    continue;
                }
            },
            jwk::AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
                jwk::EllipticCurve::P256 => Algorithm::ES256,
                jwk::EllipticCurve::P384 => Algorithm::ES384,
                _ => {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = jwks_uri.to_string(),
                        Reason = format!("Unsupported EC curve {:?}", ec.curve)
                    );
                    continue;
                }
            },
            jwk::AlgorithmParameters::OctetKeyPair(_) => Algorithm::EdDSA,
            jwk::AlgorithmParameters::OctetKey(_) => {
                trc::event!(
                    Auth(AuthEvent::Warning),
                    Url = jwks_uri.to_string(),
                    Reason = format!(
                        "Symmetric (HMAC) key found in JWKS (kid={:?}), skipping — HMAC is not accepted",
                        key.common.key_id
                    )
                );
                continue;
            }
            _ => {
                trc::event!(
                    Auth(AuthEvent::Warning),
                    Url = jwks_uri.to_string(),
                    Reason = format!(
                        "Unrecognised key type in JWKS (kid={:?}), skipping",
                        key.common.key_id
                    )
                );
                continue;
            }
        };

        let decoding_key = match DecodingKey::from_jwk(key) {
            Ok(decoding_key) => decoding_key,
            Err(e) => {
                trc::event!(
                    Auth(AuthEvent::Warning),
                    Url = jwks_uri.to_string(),
                    Reason = format!(
                        "Failed to build DecodingKey from JWK (kid={:?}): {e}",
                        key.common.key_id
                    )
                );
                continue;
            }
        };

        map.insert(
            match &key.common.key_id {
                Some(id) => id.clone(),
                None => {
                    let id = format!("_synthetic_{synthetic_id}");
                    synthetic_id += 1;
                    id
                }
            },
            CachedKey {
                decoding_key,
                algorithm,
            }
            .into(),
        );
    }

    Ok(map)
}

/// inbuxa: application/x-www-form-urlencoded, for the introspection request.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn extract_scopes(claims: &serde_json::Value) -> Vec<String> {
    match claims.get("scope") {
        Some(serde_json::Value::String(s)) => s.split_whitespace().map(|s| s.to_string()).collect(),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

fn extract_string_list(value: &serde_json::Value) -> Option<Vec<String>> {
    match value {
        serde_json::Value::Array(arr) => Some(
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
        ),
        serde_json::Value::String(s) => Some(s.split_whitespace().map(|s| s.to_string()).collect()),
        _ => None,
    }
}

/// inbuxa: only an access token signs in. A token the provider marks as an
/// ID token was minted for whichever client the user signed in to, and a
/// refresh token is never presented as a bearer token. Keycloak marks its
/// tokens with `typ`, Amazon Cognito with `token_use`.
fn check_token_type(claims: &serde_json::Value) -> Result<(), OidcError> {
    let marker = |claim: &str| claims.get(claim).and_then(|v| v.as_str());
    let refused = match (marker("typ"), marker("token_use")) {
        (Some(typ), _)
            if ["id", "refresh", "offline", "logout"]
                .iter()
                .any(|kind| typ.eq_ignore_ascii_case(kind)) =>
        {
            Some(typ)
        }
        (_, Some(token_use))
            if ["id", "refresh"]
                .iter()
                .any(|kind| token_use.eq_ignore_ascii_case(kind)) =>
        {
            Some(token_use)
        }
        _ => None,
    };
    match refused {
        Some(kind) => Err(OidcError::TokenValidation(format!(
            "Not an access token (marked {kind:?})"
        ))),
        None => Ok(()),
    }
}

#[inline(always)]
fn is_claim_missing(claims: &serde_json::Value, claim: Option<&String>) -> bool {
    claim.is_some_and(|claim| claims.get(claim).is_none_or(serde_json::Value::is_null))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // A key for these tests only
    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGtahTxccpNyO2c/+k3fa0Opl10EO4gp0Iw8XAM2hUeL
-----END PRIVATE KEY-----";
    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAXNXjqSjw780GFXxFztdFBUMpxRoFqsYWN55FXnvncCE=
-----END PUBLIC KEY-----";

    fn test_directory() -> OpenIdDirectory {
        test_directory_at("https://idp.example.org")
    }

    /// The test directory, with its endpoints at `base`.
    fn test_directory_at(base: &str) -> OpenIdDirectory {
        test_directory_with(base, None, OpaqueTokens::Reject)
    }

    fn test_directory_with(
        base: &str,
        require_aud: Option<&str>,
        opaque_tokens: OpaqueTokens,
    ) -> OpenIdDirectory {
        let mut keys = AHashMap::new();
        keys.insert(
            "test".to_string(),
            Arc::new(CachedKey {
                decoding_key: DecodingKey::from_ed_pem(TEST_PUBLIC_KEY.as_bytes()).unwrap(),
                algorithm: Algorithm::EdDSA,
            }),
        );
        OpenIdDirectory {
            config: crate::backend::oidc::OidcConfig {
                issue_url: "https://idp.example.org".to_string(),
                require_aud: require_aud.map(str::to_string),
                require_scopes: Vec::new(),
                claim_email: "email".to_string(),
                claim_name: None,
                claim_groups: None,
                default_domain: None,
                opaque_tokens,
            },
            discovery: crate::backend::oidc::OidcDiscovery {
                url: "https://idp.example.org".to_string(),
                document: crate::backend::oidc::DiscoveryDocument {
                    issuer: "https://idp.example.org".to_string(),
                    jwks_uri: format!("{base}/jwks"),
                    userinfo_endpoint: format!("{base}/userinfo"),
                    token_endpoint: format!("{base}/token"),
                    authorization_endpoint: format!("{base}/auth"),
                    end_session_endpoint: None,
                    introspection_endpoint: None,
                    scopes_supported: None,
                    claims_supported: None,
                    code_challenge_methods_supported: None,
                },
            },
            http: Client::new(),
            cache: tokio::sync::RwLock::new(crate::backend::oidc::JwksCache {
                keys,
                last_updated: Instant::now(),
            }),
        }
    }

    fn signed(claims: serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::EdDSA);
        header.kid = Some("test".to_string());
        let mut claims = claims;
        claims["iss"] = json!("https://idp.example.org");
        claims["exp"] = json!(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 300
        );
        claims["email"] = json!("john@example.org");
        jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_ed_pem(TEST_KEY.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// A provider on 127.0.0.1 that answers every request with what
    /// `answer` returns for it (the request line, headers and body).
    async fn provider(answer: impl Fn(&str) -> (u16, String) + Send + Sync + 'static) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let answer = Arc::new(answer);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let answer = answer.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let read = stream.read(&mut buf).await.unwrap_or(0);
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..read]);
                        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&request[..end]).to_lowercase();
                            let length = head
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length:"))
                                .and_then(|value| value.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if request.len() >= end + 4 + length {
                                break;
                            }
                        }
                    }
                    let (status, body) = answer(&String::from_utf8_lossy(&request));
                    // No Content-Length: the body ends when the connection does
                    let head = format!(
                        "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(body.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        base
    }

    async fn sign_in(directory: &OpenIdDirectory, token: String) -> trc::Result<Account> {
        directory
            .authenticate(&Credentials::Bearer {
                username: None,
                token,
            })
            .await
    }

    // inbuxa: a token the provider marks as an ID or refresh token is not an
    // access token: an ID token is minted for whichever client signed in
    #[tokio::test]
    async fn only_access_tokens_sign_in() {
        let directory = test_directory();

        for claims in [
            json!({}),
            json!({"typ": "Bearer"}),
            json!({"token_use": "access"}),
        ] {
            assert_eq!(
                sign_in(&directory, signed(claims.clone()))
                    .await
                    .map(|account| account.email)
                    .ok()
                    .as_deref(),
                Some("john@example.org"),
                "{claims}"
            );
        }
        for claims in [
            json!({"typ": "ID"}),
            json!({"typ": "Refresh"}),
            json!({"typ": "Offline"}),
            json!({"token_use": "id"}),
            json!({"token_use": "refresh"}),
        ] {
            assert!(
                sign_in(&directory, signed(claims.clone())).await.is_err(),
                "{claims} must not sign in"
            );
        }
    }

    // http-directory-services-13: any token the provider issued, to any
    // application, passes its user info endpoint, so a new directory
    // refuses tokens that aren't JWTs
    #[tokio::test]
    async fn new_directories_refuse_opaque_tokens() {
        let base = provider(|_| (200, json!({"email": "john@example.org"}).to_string())).await;
        let directory = test_directory_at(&base);
        assert!(
            sign_in(&directory, "an-opaque-token".to_string())
                .await
                .is_err(),
            "an opaque token signed in through the user info endpoint"
        );

        // ... and a directory saved before the policy keeps doing so
        let directory = test_directory_with(&base, None, OpaqueTokens::Userinfo);
        assert_eq!(
            sign_in(&directory, "an-opaque-token".to_string())
                .await
                .map(|account| account.email)
                .ok()
                .as_deref(),
            Some("john@example.org")
        );
    }

    // http-directory-services-13: introspection signs in only an active
    // token this provider issued for the required audience
    #[tokio::test]
    async fn introspection_checks_what_the_provider_says() {
        let base = provider(|request| {
            let (head, body) = request.split_once("\r\n\r\n").unwrap_or_default();
            // RFC 6749 2.3.1: id and secret form-encoded, then Basic
            let authorized = head.lines().any(|line| {
                line.eq_ignore_ascii_case(&format!(
                    "authorization: Basic {}",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        "inbuxa:se+cret%2F%2B"
                    )
                ))
            });
            if !head.starts_with("POST /introspect ") || !authorized {
                return (401, json!({"error": "invalid_client"}).to_string());
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut claims = json!({
                "active": true,
                "iss": "https://idp.example.org",
                "aud": ["inbuxa", "account"],
                "exp": now + 300,
                "email": "john@example.org",
            });
            match body
                .strip_prefix("token=")
                .and_then(|body| body.split('&').next())
                .unwrap_or_default()
            {
                "good%2Btoken" => {}
                "inactive" => claims = json!({"active": false}),
                "foreign" => claims["iss"] = json!("https://other.example.org"),
                "anonymous" => {
                    claims.as_object_mut().unwrap().remove("iss");
                }
                "elsewhere" => claims["aud"] = json!("another-app"),
                "unaddressed" => {
                    claims.as_object_mut().unwrap().remove("aud");
                }
                "refresh" => claims["typ"] = json!("Refresh"),
                "expired" => claims["exp"] = json!(1),
                _ => claims = json!({"active": "true"}),
            }
            (200, claims.to_string())
        })
        .await;
        let introspection = |client_secret: &str| {
            OpaqueTokens::Introspection(Introspection {
                url: Some(format!("{base}/introspect")),
                client_id: "inbuxa".to_string(),
                client_secret: client_secret.to_string(),
            })
        };
        let directory = test_directory_with(&base, Some("inbuxa"), introspection("se cret/+"));

        assert_eq!(
            sign_in(&directory, "good+token".to_string())
                .await
                .map(|account| account.email)
                .ok()
                .as_deref(),
            Some("john@example.org")
        );
        for token in [
            "inactive",
            "foreign",
            "anonymous",
            "elsewhere",
            "unaddressed",
            "refresh",
            "expired",
            "not-a-boolean",
        ] {
            let err = sign_in(&directory, token.to_string()).await.unwrap_err();
            assert!(
                err.matches(trc::EventType::Auth(AuthEvent::Failed)),
                "{token}: {err:?}"
            );
        }

        // A refusal of the server's own credentials is not the person's fault
        let directory = test_directory_with(&base, Some("inbuxa"), introspection("wrong"));
        let err = sign_in(&directory, "good+token".to_string())
            .await
            .unwrap_err();
        assert!(
            err.matches(trc::EventType::Auth(AuthEvent::Error)),
            "{err:?}"
        );
    }

    #[test]
    fn extract_string_list_distinguishes_absent_from_empty() {
        assert_eq!(
            extract_string_list(&json!(["sales", "support"])),
            Some(vec!["sales".to_string(), "support".to_string()])
        );
        assert_eq!(
            extract_string_list(&json!("sales support")),
            Some(vec!["sales".to_string(), "support".to_string()])
        );
        assert_eq!(extract_string_list(&json!([])), Some(vec![]));
        assert_eq!(extract_string_list(&json!("")), Some(vec![]));
        assert_eq!(extract_string_list(&json!(null)), None);
        assert_eq!(extract_string_list(&json!({"groups": []})), None);
        assert_eq!(extract_string_list(&json!(42)), None);
    }

    #[test]
    fn is_claim_missing_treats_null_as_absent() {
        let claims = json!({"groups": null, "name": "John Doe", "roles": []});

        assert!(is_claim_missing(&claims, Some(&"groups".to_string())));
        assert!(is_claim_missing(&claims, Some(&"unknown".to_string())));
        assert!(!is_claim_missing(&claims, Some(&"name".to_string())));
        assert!(!is_claim_missing(&claims, Some(&"roles".to_string())));
        assert!(!is_claim_missing(&claims, None));
    }
}
