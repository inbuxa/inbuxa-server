/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use ahash::AHashMap;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use utils::Client;

pub mod config;
pub mod lookup;

pub struct OidcConfig {
    pub issue_url: String,
    pub require_aud: Option<String>,
    pub require_scopes: Vec<String>,
    pub claim_email: String,
    pub claim_name: Option<String>,
    pub claim_groups: Option<String>,
    pub default_domain: Option<String>,
    pub opaque_tokens: OpaqueTokens,
}

/// inbuxa: http-directory-services-13: what a bearer token that isn't a
/// JWT signs in by.
pub enum OpaqueTokens {
    /// Nothing: refused.
    Reject,
    /// The provider's user info endpoint answering for it, which it does for
    /// any token it issued, to any application.
    Userinfo,
    /// The provider's token introspection endpoint (RFC 7662).
    Introspection(Introspection),
}

pub struct Introspection {
    /// None until discovery: then the discovery document's, if not set.
    pub url: Option<String>,
    pub client_id: String,
    pub client_secret: String,
}

pub struct OidcDiscovery {
    pub url: String,
    pub document: DiscoveryDocument,
}

#[derive(Deserialize, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: String,
    pub token_endpoint: String,
    pub authorization_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    // inbuxa: read for opaque tokens, not passed on to clients
    #[serde(default, skip_serializing)]
    pub introspection_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

struct CachedKey {
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

struct JwksCache {
    keys: AHashMap<String, Arc<CachedKey>>,
    last_updated: Instant,
}

pub struct OpenIdDirectory {
    config: OidcConfig,
    pub discovery: OidcDiscovery,
    http: Client,
    cache: RwLock<JwksCache>,
}

#[derive(Debug)]
pub enum OidcError {
    TokenValidation(String),
    AuthorizationFailed(String),
    Network(String),
    Provider(String),
    Config(String),
}

impl OidcError {
    pub fn is_transient(&self) -> bool {
        matches!(self, OidcError::Network(_) | OidcError::Provider(_))
    }
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OidcError::TokenValidation(msg) => write!(f, "Token validation error: {msg}"),
            OidcError::AuthorizationFailed(msg) => write!(f, "Authorization failed: {msg}"),
            OidcError::Network(msg) => write!(f, "Network error: {msg}"),
            OidcError::Provider(msg) => write!(f, "Provider error: {msg}"),
            OidcError::Config(msg) => write!(f, "Configuration error: {msg}"),
        }
    }
}

impl std::error::Error for OidcError {}
