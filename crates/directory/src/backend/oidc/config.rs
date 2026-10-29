/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::Directory;
use crate::backend::oidc::lookup::{fetch_jwks_keys, read_body};
use crate::backend::oidc::{
    CachedKey, DiscoveryDocument, Introspection, JwksCache, OidcConfig, OidcDiscovery, OidcError,
    OpaqueTokens, OpenIdDirectory,
};
use ahash::AHashMap;
use registry::schema::{enums::OidcOpaqueTokens, structs};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use trc::AuthEvent;
use utils::Client;

const DISCOVERY_RETRY_FOR: Duration = Duration::from_secs(30);
const DISCOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(3);

/// inbuxa: http-directory-services-13: what a bearer token that isn't a JWT
/// signs in by. Unset, as on a new directory: introspection when an
/// introspection endpoint is set, else nothing. A directory saved before the
/// setting existed reads as userinfo, which it always used.
pub fn opaque_token_policy(config: &structs::OidcDirectory) -> OidcOpaqueTokens {
    config
        .opaque_tokens
        .unwrap_or(if config.introspection_url.is_some() {
            OidcOpaqueTokens::Introspection
        } else {
            OidcOpaqueTokens::Reject
        })
}

impl OpenIdDirectory {
    pub async fn open(config: structs::OidcDirectory) -> Result<Directory, String> {
        // inbuxa: http-directory-services-13: only a directory saved before
        // the audience was required has none; it keeps working, with a
        // warning every time it loads
        if config.require_audience.is_none() {
            trc::event!(
                Auth(AuthEvent::Warning),
                Url = config.issuer_url.clone(),
                Details = config.description.clone(),
                Reason = "No required audience is set, so tokens this provider issued to any \
                          other application sign in. Set requireAudience to the client ID \
                          registered for this server; a later release will require it."
            );
        }

        let opaque_tokens = match opaque_token_policy(&config) {
            OidcOpaqueTokens::Reject => OpaqueTokens::Reject,
            OidcOpaqueTokens::Userinfo => OpaqueTokens::Userinfo,
            OidcOpaqueTokens::Introspection => OpaqueTokens::Introspection(Introspection {
                url: config.introspection_url,
                client_id: config.introspection_client_id.ok_or_else(|| {
                    "Opaque tokens are checked by introspection, which needs a client ID"
                        .to_string()
                })?,
                client_secret: config
                    .introspection_client_secret
                    .secret()
                    .await?
                    .map(|secret| secret.into_owned())
                    .ok_or_else(|| {
                        "Opaque tokens are checked by introspection, which needs a client secret"
                            .to_string()
                    })?,
            }),
        };

        Self::new(OidcConfig {
            issue_url: config.issuer_url,
            require_aud: config.require_audience,
            require_scopes: config.require_scopes.into_inner(),
            claim_email: config.claim_username,
            claim_name: config.claim_name,
            claim_groups: config.claim_groups,
            default_domain: config.username_domain,
            opaque_tokens,
        })
        .await
        .map(Directory::OpenId)
        .map_err(|err| err.to_string())
    }

    pub async fn new(mut config: OidcConfig) -> Result<Self, OidcError> {
        let http = utils::http::http_client_builder(false)
            .user_agent("inbuxa/1.0") // types::brand!(); this crate does not depend on types
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| OidcError::Network(format!("HTTP client build failed: {e}")))?;

        let started_at = Instant::now();
        let (document, keys) = loop {
            match Self::discover(&http, &config).await {
                Ok(discovery) => break discovery,
                Err(err) if err.is_transient() && started_at.elapsed() < DISCOVERY_RETRY_FOR => {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = config.issue_url.to_string(),
                        Reason = format!(
                            "{err}, retrying in {} seconds",
                            DISCOVERY_RETRY_INTERVAL.as_secs()
                        )
                    );
                    tokio::time::sleep(DISCOVERY_RETRY_INTERVAL).await;
                }
                Err(err) => return Err(err),
            }
        };

        // inbuxa: http-directory-services-13
        if let OpaqueTokens::Introspection(introspection) = &mut config.opaque_tokens
            && introspection.url.is_none()
        {
            introspection.url = Some(document.introspection_endpoint.clone().ok_or_else(|| {
                OidcError::Config(
                    "Opaque tokens are checked by introspection, but no introspection endpoint \
                     is set and the provider's discovery document names none"
                        .to_string(),
                )
            })?);
        }

        Ok(Self {
            discovery: OidcDiscovery {
                url: config.issue_url.clone(),
                document,
            },
            config,
            http,
            cache: RwLock::new(JwksCache {
                keys,
                last_updated: Instant::now(),
            }),
        })
    }

    async fn discover(
        http: &Client,
        config: &OidcConfig,
    ) -> Result<(DiscoveryDocument, AHashMap<String, Arc<CachedKey>>), OidcError> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issue_url.trim_end_matches('/')
        );
        let discovery_bytes = read_body(
            http.get(&discovery_url)
                .send()
                .await
                .map_err(|e| OidcError::Network(format!("Discovery fetch failed: {e}")))?
                .error_for_status()
                .map_err(|e| OidcError::Provider(format!("Discovery HTTP error: {e}")))?,
            "Discovery",
        )
        .await?;
        let discovery: DiscoveryDocument = serde_json::from_slice(&discovery_bytes)
            .map_err(|e| OidcError::Provider(format!("Discovery JSON parse error: {e}")))?;

        let normalised_issue = config.issue_url.trim_end_matches('/');
        let normalised_issuer = discovery.issuer.trim_end_matches('/');
        if normalised_issuer != normalised_issue {
            return Err(OidcError::Config(format!(
                "Issuer mismatch: discovery document says '{}' but configured issue_url is '{}'",
                discovery.issuer, config.issue_url,
            )));
        }

        if let Some(supported) = &discovery.scopes_supported {
            for scope in &config.require_scopes {
                if !supported.contains(scope) {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = config.issue_url.to_string(),
                        Reason = format!(
                            "Required scope '{}' is not in scopes_supported from the IdP",
                            scope
                        )
                    );
                }
            }
        }

        if let Some(supported) = &discovery.claims_supported {
            let check = |name: &str, label: &str| {
                if !supported.iter().any(|c| c == name) {
                    trc::event!(
                        Auth(AuthEvent::Warning),
                        Url = config.issue_url.to_string(),
                        Reason = format!(
                            "Configured {} claim '{}' is not in claims_supported from the IdP",
                            label, name
                        )
                    );
                }
            };
            check(&config.claim_email, "claim_email");
            if let Some(n) = &config.claim_name {
                check(n, "claim_name");
            }
            if let Some(g) = &config.claim_groups {
                check(g, "claim_groups");
            }
        }

        /*{
            let cache = Arc::clone(&cache);
            let http = http.clone();
            let jwks_uri = discovery.jwks_uri.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(24 * 3600));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    match fetch_jwks_keys(&http, &jwks_uri).await {
                        Ok(new_keys) => {
                            let mut guard = cache.write().await;
                            guard.keys = new_keys;
                            guard.last_updated = Instant::now();
                        }
                        Err(e) => {
                            trc::event!(
                                Auth(AuthEvent::Warning),
                                Url = jwks_uri.to_string(),
                                Reason = format!("Background JWKS refresh failed: {e}")
                            );
                        }
                    }
                }
            });
        }*/

        let keys = fetch_jwks_keys(http, &discovery.jwks_uri).await?;

        Ok((discovery, keys))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_directories_refuse_opaque_tokens_unless_they_name_an_endpoint() {
        let new = structs::OidcDirectory::default();
        assert_eq!(opaque_token_policy(&new), OidcOpaqueTokens::Reject);
        assert_eq!(
            opaque_token_policy(&structs::OidcDirectory {
                introspection_url: Some("https://idp.example.org/introspect".to_string()),
                ..new.clone()
            }),
            OidcOpaqueTokens::Introspection
        );
        for chosen in [
            OidcOpaqueTokens::Reject,
            OidcOpaqueTokens::Userinfo,
            OidcOpaqueTokens::Introspection,
        ] {
            assert_eq!(
                opaque_token_policy(&structs::OidcDirectory {
                    opaque_tokens: Some(chosen),
                    introspection_url: Some("https://idp.example.org/introspect".to_string()),
                    ..new.clone()
                }),
                chosen
            );
        }
    }
}
