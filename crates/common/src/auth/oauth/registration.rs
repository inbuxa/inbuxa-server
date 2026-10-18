/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub struct ClientRegistrationRequest {
    pub redirect_uris: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub response_types: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub grant_types: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<ApplicationType>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>, // Using serde_json::Value for flexibility

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<SubjectType>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<u64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub default_acr_values: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub request_uris: Vec<String>,

    #[serde(flatten)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub struct ClientRegistrationResponse {
    // Required fields
    pub client_id: String,

    // Optional fields specific to the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<u64>,

    // Echo back the request
    #[serde(flatten)]
    pub request: ClientRegistrationRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationType {
    Web,
    Native,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Pairwise,
    Public,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    ClientSecretPost,
    ClientSecretBasic,
    ClientSecretJwt,
    PrivateKeyJwt,
    None,
}

#[derive(Serialize, Debug)]
pub struct ClientRegistrationError {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<&'static str>,
}

impl ClientRegistrationError {
    pub fn invalid_redirect_uri(description: &'static str) -> Self {
        ClientRegistrationError {
            error: "invalid_redirect_uri",
            error_description: Some(description),
        }
    }

    pub fn invalid_client_metadata(description: &'static str) -> Self {
        ClientRegistrationError {
            error: "invalid_client_metadata",
            error_description: Some(description),
        }
    }
}

pub fn loopback_redirect_parts(uri: &str) -> Option<(&str, &str)> {
    let uri = uri.strip_prefix("http://")?;

    for host in ["127.0.0.1", "[::1]"] {
        if let Some(rest) = uri.strip_prefix(host) {
            let rest = match rest.strip_prefix(':') {
                Some(after_colon) => {
                    let rest = after_colon.trim_start_matches(|c: char| c.is_ascii_digit());
                    if rest.len() == after_colon.len() {
                        return None;
                    }
                    rest
                }
                None => rest,
            };
            return if let Some(path) = rest.strip_prefix('/') {
                Some((host, path))
            } else if rest.is_empty() || rest.starts_with('?') {
                Some((host, rest))
            } else {
                None
            };
        }
    }
    None
}

pub fn redirect_uri_matches(registered: &str, presented: &str) -> bool {
    registered == presented
        || matches!(
            (
                loopback_redirect_parts(registered),
                loopback_redirect_parts(presented),
            ),
            (Some(reg), Some(pres)) if reg == pres
        )
}

pub fn validate_redirect_uri(uri: &str) -> Result<(), ClientRegistrationError> {
    if uri.contains('#') {
        return Err(ClientRegistrationError::invalid_redirect_uri(
            "Redirect URI must not contain a fragment.",
        ));
    } else if uri.contains("..") {
        return Err(ClientRegistrationError::invalid_redirect_uri(
            "Redirect URI must not contain consecutive dots.",
        ));
    } else if uri.starts_with("https://") || loopback_redirect_parts(uri).is_some() {
        return Ok(());
    } else if let Some((scheme, _)) = uri.split_once(':')
        && scheme.contains('.')
        && scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
    {
        return Ok(());
    }

    Err(ClientRegistrationError::invalid_redirect_uri(
        "Redirect URI must be an https URL, a loopback (http://127.0.0.1/, http://[::1]/) or a private-use scheme URI.",
    ))
}

pub fn validate_grant_metadata(
    request: &ClientRegistrationRequest,
) -> Result<(), ClientRegistrationError> {
    if !request.response_types.is_empty() && !request.response_types.iter().any(|t| t == "code") {
        return Err(ClientRegistrationError::invalid_client_metadata(
            "response_types must include \"code\".",
        ));
    }
    if !request.grant_types.is_empty() {
        if !request
            .grant_types
            .iter()
            .any(|t| t == "authorization_code")
        {
            return Err(ClientRegistrationError::invalid_client_metadata(
                "grant_types must include \"authorization_code\".",
            ));
        }
        if !request.grant_types.iter().any(|t| t == "refresh_token") {
            return Err(ClientRegistrationError::invalid_client_metadata(
                "grant_types must include \"refresh_token\".",
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{loopback_redirect_parts, redirect_uri_matches};

    #[test]
    fn loopback_matches_any_port() {
        // Loopback redirects match regardless of port and of an empty versus "/" path (RFC 8252 §7.3)
        for (registered, presented) in [
            ("http://127.0.0.1", "http://127.0.0.1:45678"),
            ("http://127.0.0.1/", "http://127.0.0.1:45678"),
            ("http://127.0.0.1", "http://127.0.0.1:45678/"),
            ("http://127.0.0.1/cb", "http://127.0.0.1:45678/cb"),
            ("http://127.0.0.1/?a=1", "http://127.0.0.1:45678?a=1"),
            ("http://[::1]", "http://[::1]:8080"),
            ("http://[::1]/", "http://[::1]:8080/"),
        ] {
            assert!(
                redirect_uri_matches(registered, presented),
                "{registered} should match {presented}"
            );
        }

        // Different paths, hosts or schemes never match
        for (registered, presented) in [
            ("http://127.0.0.1/cb", "http://127.0.0.1:45678"),
            ("http://127.0.0.1", "http://127.0.0.1:45678/cb"),
            ("http://127.0.0.1", "http://[::1]:45678"),
            ("http://127.0.0.1", "https://127.0.0.1:45678"),
            ("http://127.0.0.1", "http://127.0.0.1.evil.com"),
            ("http://127.0.0.1", "http://127.0.0.1:80@evil.com"),
            ("http://127.0.0.1", "http://127.0.0.1:45678#frag"),
        ] {
            assert!(
                !redirect_uri_matches(registered, presented),
                "{registered} should not match {presented}"
            );
        }

        // Malformed loopback URIs are not recognised
        for uri in [
            "http://127.0.0.1:",
            "http://127.0.0.1:/cb",
            "http://127.0.0.1:abc/",
            "http://127.0.0.1.evil.com/",
            "http://127.0.0.1@evil.com/",
            "http://localhost:8080/",
        ] {
            assert_eq!(loopback_redirect_parts(uri), None, "{uri}");
        }
    }
}
