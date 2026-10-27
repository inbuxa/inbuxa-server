/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:FrontEnds`, where the server's front ends are (contract C-4): the
//! console's address, the webmail's and its client secret, and any further
//! origins allowed to call the server from a browser.
//!
//! It stands beside the `INBUXA_ADMIN_URL`, `INBUXA_WEBMAIL_URL` and
//! `INBUXA_WEBMAIL_CLIENT_SECRET` environment variables rather than replacing
//! them: a server configured through its environment keeps working, and what
//! is stored here is added to it. That is what lets a second machine add its
//! front ends over JMAP (the installer's `inbuxa join`) without touching the
//! server's environment.
//!
//! The webmail's secret is kept only as its Argon2 hash, the form the OAuth
//! client holds it in, so nothing here can be read back as the secret.
//!
//! Stored as JSON in the fork's subspace under `F` + `e`; unset reads as
//! empty, which changes nothing.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrontEnds {
    /// Where INBUXA Admin is served: registers `inbuxa-admin`'s redirect URI
    /// and allows its origin (C-6, C-14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_url: Option<String>,
    /// Where inbuxa-webmail is served: registers `ihasmail-inbuxa`'s redirect
    /// URI and allows its origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webmail_url: Option<String>,
    /// The Argon2 hash of the webmail's client secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webmail_secret_hash: Option<String>,
    /// Further origins allowed to call the server from a browser.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_origins: Vec<String>,
    /// Seconds since the epoch, and who: the console shows them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_by: Option<String>,
}

fn key() -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: b"Fe".to_vec(),
    })
}

struct Json(FrontEnds);

impl Deserialize for Json {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

/// What is stored, or the empty default.
pub async fn get(data: &Store) -> trc::Result<FrontEnds> {
    Ok(data
        .get_value::<Json>(ValueKey::from(key()))
        .await
        .caused_by(trc::location!())?
        .map(|Json(front_ends)| front_ends)
        .unwrap_or_default())
}

/// Stores it.
pub async fn set(data: &Store, front_ends: &FrontEnds) -> trc::Result<()> {
    let bytes = serde_json::to_vec(front_ends).map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .caused_by(trc::location!())
            .reason(err)
    })?;
    let mut batch = BatchBuilder::new();
    batch.set(key(), bytes);
    data.write_batch(&mut batch)
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// Why an address can't be a front end's, or `None` when it can: an
/// absolute `http` or `https` URL with a host, and nothing after the path a
/// redirect URI could be built on.
pub fn invalid_url(url: &str) -> Option<&'static str> {
    let url = url.trim();
    let rest = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else {
        return Some("must start with https:// or http://");
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.starts_with(':') {
        return Some("must name a host");
    }
    if rest.contains('?') || rest.contains('#') {
        return Some("must not have a query or a fragment");
    }
    if rest.chars().any(char::is_whitespace) {
        return Some("must not contain spaces");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_its_own() {
        let ValueClass::Any(k) = key() else { panic!() };
        assert_eq!(k.key, b"Fe");
    }

    #[test]
    fn urls() {
        assert_eq!(invalid_url("https://admin.example.org"), None);
        assert_eq!(invalid_url("http://127.0.0.1:8082/"), None);
        assert_eq!(invalid_url("https://example.org/console"), None);
        assert!(invalid_url("admin.example.org").is_some());
        assert!(invalid_url("ftp://example.org").is_some());
        assert!(invalid_url("https://").is_some());
        assert!(invalid_url("https://:8080").is_some());
        assert!(invalid_url("https://example.org/?x=1").is_some());
        assert!(invalid_url("https://exa mple.org").is_some());
    }

    #[test]
    fn the_hash_is_never_called_a_secret() {
        let json = serde_json::to_string(&FrontEnds {
            webmail_secret_hash: Some("$argon2id$...".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(json.contains("webmailSecretHash"));
        assert!(!json.contains("\"webmailClientSecret\""));
    }
}
