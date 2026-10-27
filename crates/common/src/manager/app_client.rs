/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::oauth::{
    cimd::{CIMD_MAX_DOCUMENT_SIZE, is_dot_segment},
    client::ApplicationClient,
    registration::{check_client_name, is_https_url, is_safe_redirect_target},
};
use serde::{Deserialize, Serialize, de::IgnoredAny};

pub const APP_CLIENT_DOCUMENT: &str = "oauth-client.json";
const MAX_AUTHORITY_LEN: usize = 261;
const MAX_FIELD_LEN: usize = 512;
const MAX_REDIRECT_URIS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppClientTemplate {
    client_name: Option<Box<str>>,
    client_uri: Option<AppUri>,
    logo_uri: Option<AppUri>,
    scope: Option<Box<str>>,
    software_id: Option<Box<str>>,
    software_version: Option<Box<str>>,
    redirect_uris: Box<[Box<str>]>,
    post_logout_redirect_uris: Box<[Box<str>]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AppUri {
    Relative(Box<str>),
    Absolute(Box<str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppClientId<'x> {
    pub is_tls: bool,
    pub authority: &'x str,
    pub prefix: &'x str,
}

#[derive(Deserialize)]
struct RawTemplate {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    client_uri: Option<String>,
    #[serde(default)]
    logo_uri: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    software_id: Option<String>,
    #[serde(default)]
    software_version: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    client_id: Option<IgnoredAny>,
    #[serde(default)]
    client_secret: Option<IgnoredAny>,
    #[serde(default)]
    jwks: Option<IgnoredAny>,
    #[serde(default)]
    jwks_uri: Option<IgnoredAny>,
}

#[derive(Serialize)]
struct ClientDocument<'x> {
    client_id: &'x str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<&'x str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'x str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_id: Option<&'x str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_version: Option<&'x str>,
    redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    post_logout_redirect_uris: Vec<String>,
    token_endpoint_auth_method: &'static str,
    grant_types: [&'static str; 2],
    response_types: [&'static str; 1],
}

impl AppClientTemplate {
    pub fn parse(
        bytes: &[u8],
        max_prefix_len: usize,
        has_file: impl Fn(&str) -> bool,
    ) -> Result<Self, &'static str> {
        let raw = serde_json::from_slice::<RawTemplate>(bytes)
            .map_err(|_| "oauth-client.json is not a valid JSON object")?;

        if raw.client_id.is_some() {
            return Err("oauth-client.json must not contain client_id");
        } else if raw.client_secret.is_some() {
            return Err("oauth-client.json must not contain client_secret");
        } else if raw.jwks.is_some() || raw.jwks_uri.is_some() {
            return Err("oauth-client.json must not contain jwks or jwks_uri");
        } else if raw.redirect_uris.is_empty() || raw.redirect_uris.len() > MAX_REDIRECT_URIS {
            return Err("oauth-client.json must list between 1 and 16 redirect_uris");
        } else if raw.post_logout_redirect_uris.len() > MAX_REDIRECT_URIS {
            return Err("oauth-client.json lists too many post_logout_redirect_uris");
        }

        let relative_list = |uris: Vec<String>| {
            uris.into_iter()
                .map(|uri| {
                    if is_relative_path(&uri) {
                        Ok(uri.into_boxed_str())
                    } else {
                        Err("oauth-client.json redirect URIs must be relative paths")
                    }
                })
                .collect::<Result<Box<[_]>, _>>()
        };
        let uri = |uri: Option<String>| -> Result<Option<AppUri>, &'static str> {
            match uri {
                Some(uri) if is_relative_path(&uri) => {
                    Ok(Some(AppUri::Relative(uri.into_boxed_str())))
                }
                Some(uri) if is_https_url(&uri) && uri.len() <= MAX_FIELD_LEN => {
                    Ok(Some(AppUri::Absolute(uri.into_boxed_str())))
                }
                Some(_) => Err("oauth-client.json URIs must be relative paths or https URLs"),
                None => Ok(None),
            }
        };

        if let Some(name) = &raw.client_name {
            check_client_name(name).map_err(|_| {
                "oauth-client.json client_name is too long or contains control or bidirectional formatting characters"
            })?;
        }

        let template = AppClientTemplate {
            client_name: text(raw.client_name)?,
            client_uri: uri(raw.client_uri)?,
            logo_uri: uri(raw.logo_uri)?,
            scope: text(raw.scope)?,
            software_id: text(raw.software_id)?,
            software_version: text(raw.software_version)?,
            redirect_uris: relative_list(raw.redirect_uris)?,
            post_logout_redirect_uris: relative_list(raw.post_logout_redirect_uris)?,
        };

        if let Some(AppUri::Relative(logo)) = &template.logo_uri
            && !has_file(path_of(logo))
        {
            return Err("oauth-client.json logo_uri does not exist in the bundle");
        }

        let base = format!(
            "https://{}/{}/",
            "a".repeat(MAX_AUTHORITY_LEN),
            "a".repeat(max_prefix_len)
        );
        if template.document(&base).len() > CIMD_MAX_DOCUMENT_SIZE {
            return Err("oauth-client.json exceeds the 5 KB limit");
        }

        Ok(template)
    }

    pub fn client(&self, base: &str) -> ApplicationClient {
        ApplicationClient {
            client_name: self.client_name.as_deref().map(str::to_string),
            logo_uri: match &self.logo_uri {
                Some(AppUri::Relative(logo)) => Some(resolve(base, logo)),
                _ => None,
            },
            redirect_uris: self
                .redirect_uris
                .iter()
                .map(|uri| resolve(base, uri))
                .collect(),
        }
    }

    pub fn post_logout_redirect_uri_matches(&self, client_id: &AppClientId<'_>, uri: &str) -> bool {
        is_safe_redirect_target(uri)
            && client_id.strip_base(uri).is_some_and(|path| {
                self.post_logout_redirect_uris
                    .iter()
                    .any(|registered| registered.as_ref() == path)
            })
    }

    pub fn document(&self, base: &str) -> Vec<u8> {
        let client_id = resolve(base, APP_CLIENT_DOCUMENT);
        serde_json::to_vec(&ClientDocument {
            client_id: &client_id,
            client_name: self.client_name.as_deref(),
            client_uri: self.client_uri.as_ref().map(|uri| uri.resolve(base)),
            logo_uri: self.logo_uri.as_ref().map(|uri| uri.resolve(base)),
            scope: self.scope.as_deref(),
            software_id: self.software_id.as_deref(),
            software_version: self.software_version.as_deref(),
            redirect_uris: self
                .redirect_uris
                .iter()
                .map(|uri| resolve(base, uri))
                .collect(),
            post_logout_redirect_uris: self
                .post_logout_redirect_uris
                .iter()
                .map(|uri| resolve(base, uri))
                .collect(),
            token_endpoint_auth_method: "none",
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
        })
        .unwrap_or_default()
    }
}

impl AppUri {
    fn resolve(&self, base: &str) -> String {
        match self {
            AppUri::Relative(path) => resolve(base, path),
            AppUri::Absolute(uri) => uri.to_string(),
        }
    }
}

impl<'x> AppClientId<'x> {
    pub fn parse(client_id: &'x str) -> Option<Self> {
        let (is_tls, rest) = if let Some(rest) = client_id.strip_prefix("https://") {
            (true, rest)
        } else {
            (false, client_id.strip_prefix("http://")?)
        };
        let (authority, path) = rest.split_once('/')?;
        let prefix = match path.strip_suffix(APP_CLIENT_DOCUMENT)? {
            #[cfg(feature = "dev_mode")]
            "" => "",
            prefix => {
                let prefix = prefix.strip_suffix('/')?;
                if !is_url_prefix(prefix) {
                    return None;
                }
                prefix
            }
        };

        if !authority.is_empty() && authority.bytes().all(is_authority_byte) {
            Some(AppClientId {
                is_tls,
                authority,
                prefix,
            })
        } else {
            None
        }
    }

    pub fn base(&self) -> String {
        app_base(self.is_tls, self.authority, self.prefix)
    }

    fn strip_base<'u>(&self, uri: &'u str) -> Option<&'u str> {
        let scheme = if self.is_tls { "https://" } else { "http://" };
        let rest = uri
            .strip_prefix(scheme)?
            .strip_prefix(self.authority)?
            .strip_prefix('/')?;
        if self.prefix.is_empty() {
            Some(rest)
        } else {
            rest.strip_prefix(self.prefix)?.strip_prefix('/')
        }
    }
}

pub fn app_base(is_tls: bool, authority: &str, prefix: &str) -> String {
    let scheme = if is_tls { "https" } else { "http" };
    let mut base = String::with_capacity(scheme.len() + authority.len() + prefix.len() + 5);
    base.push_str(scheme);
    base.push_str("://");
    base.push_str(authority);
    base.push('/');
    if !prefix.is_empty() {
        base.push_str(prefix);
        base.push('/');
    }
    base
}

pub fn normalize_url_prefix(prefix: &str) -> &str {
    prefix.trim_matches('/')
}

pub fn validate_url_prefix(prefix: &str) -> Result<(), &'static str> {
    let prefix = normalize_url_prefix(prefix);
    if !is_url_prefix(prefix) {
        Err(concat!(
            "URL prefixes must be a single non-empty path segment such as \"/admin\", ",
            "made of letters, digits, '-', '.', '_' or '~'"
        ))
    } else if is_reserved_url_prefix(prefix) {
        Err("This URL prefix is reserved for a built-in server endpoint")
    } else {
        Ok(())
    }
}

fn is_reserved_url_prefix(prefix: &str) -> bool {
    hashify::set_ignore_case!(
        prefix.as_bytes(),
        "jmap",
        "dav",
        ".well-known",
        "auth",
        "scim",
        "api",
        "mail",
        "calendar",
        "autodiscover",
        "robots.txt",
        "healthz",
        "metrics",
        "logo",
        "form",
        "login",
        "device",
    )
}

fn is_url_prefix(prefix: &str) -> bool {
    !prefix.is_empty() && prefix.bytes().all(is_prefix_byte) && prefix != "." && prefix != ".."
}

fn resolve(base: &str, path: &str) -> String {
    let mut uri = String::with_capacity(base.len() + path.len());
    uri.push_str(base);
    uri.push_str(path);
    uri
}

fn text(value: Option<String>) -> Result<Option<Box<str>>, &'static str> {
    match value {
        Some(value) if value.len() > MAX_FIELD_LEN => {
            Err("oauth-client.json contains a value that is too long")
        }
        Some(value) if !value.trim().is_empty() => Ok(Some(value.into_boxed_str())),
        _ => Ok(None),
    }
}

fn path_of(uri: &str) -> &str {
    uri.split_once('?').map_or(uri, |(path, _)| path)
}

fn is_relative_path(uri: &str) -> bool {
    !uri.is_empty()
        && uri.len() <= MAX_FIELD_LEN
        && !uri.starts_with('/')
        && !uri.contains("..")
        && uri.bytes().all(is_relative_byte)
        && !path_of(uri).split('/').any(is_dot_segment)
}

pub fn is_safe_authority(authority: &str) -> bool {
    !authority.is_empty()
        && authority.len() <= MAX_AUTHORITY_LEN
        && authority.bytes().all(is_authority_byte)
}

fn is_relative_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'/'
                | b'?'
                | b'='
                | b'&'
                | b'%'
                | b'+'
                | b'!'
                | b'$'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b','
                | b';'
                | b'@'
        )
}

fn is_authority_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':' | b'[' | b']' | b'_')
}

fn is_prefix_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

