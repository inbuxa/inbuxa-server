/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! First-party OAuth clients (docs/spec/contract.md C-6).
//!
//! INBUXA requires OAuth clients to be registered (C-5), so the front ends
//! that ship with it are registered for it, on every start:
//!
//! - the web interface the server serves itself (`Application`, `/admin` and
//!   `/account`), as its OAuth client id, `inbuxa-webui` unless the
//!   application names another;
//! - INBUXA Admin hosted elsewhere, as `inbuxa-admin`, when `INBUXA_ADMIN_URL`
//!   is set;
//! - inbuxa-webmail, as the confidential client `ihasmail-inbuxa`, when
//!   `INBUXA_WEBMAIL_URL` and `INBUXA_WEBMAIL_CLIENT_SECRET` are set.
//!
//! inbuxa: `inbuxa:FrontEnds` (C-4) holds the same addresses, set over JMAP
//! by the installer (`inbuxa join`) or INBUXA Admin; the environment
//! variables keep working beside it, and both are registered. Where both
//! give the webmail a secret, the environment's wins, so a server configured
//! through its environment is never changed by what was stored.
//!
//! A missing client is created. An existing one gains any redirect URI it
//! lacks and, for inbuxa-webmail, the configured secret; nothing an operator
//! added is removed. This runs on every start, and again whenever
//! `inbuxa:FrontEnds` is set.

use directory::core::{
    secret::{hash_secret, verify_secret_hash},
    verifier::PasswordVerifier,
};
use inbuxa_features::security::front_ends::{self, FrontEnds};
use registry::{
    schema::{
        enums::{PasswordHashAlgorithm, ServiceProtocol},
        prelude::{Object, ObjectInner, ObjectType, Property, UTCDateTime},
        structs::{Application, OAuthClient, SystemSettings},
    },
    types::map::Map,
};
use store::registry::{
    bootstrap::Bootstrap,
    write::{RegistryWrite, RegistryWriteResult},
};

/// The client id the upstream web interface uses when its application names none.
pub const WEB_INTERFACE_CLIENT_ID: &str = "inbuxa-webui";
pub const ADMIN_CLIENT_ID: &str = "inbuxa-admin";
pub const WEBMAIL_CLIENT_ID: &str = "ihasmail-inbuxa";
/// The web interface's client id before the fork renamed it (SPEC §2.4).
/// Only ever read to retire it.
const LEGACY_WEB_INTERFACE_CLIENT_ID: &str = "stalwart-webui";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstPartyClient {
    pub client_id: String,
    pub description: String,
    pub redirect_uris: Vec<String>,
    pub secret: Option<ClientSecret>,
}

/// A confidential client's secret: given in the clear (the environment), or
/// already hashed (`inbuxa:FrontEnds`, which never keeps it in the clear).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientSecret {
    Plain(String),
    Hash(String),
}

/// The first-party clients this server should have, from its applications and
/// the front-end addresses it was given. Each front end may have several
/// addresses (the environment's and `inbuxa:FrontEnds`'), each a redirect URI
/// of the same client.
pub fn first_party_clients(
    base_url: &str,
    applications: &[Application],
    admin_urls: &[&str],
    webmail_urls: &[&str],
    webmail_secret: Option<ClientSecret>,
) -> Vec<FirstPartyClient> {
    let base_url = base_url.trim_end_matches('/');
    let mut clients: Vec<FirstPartyClient> = Vec::new();

    for app in applications.iter().filter(|app| app.enable) {
        let client_id = app
            .oauth_client_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .unwrap_or(WEB_INTERFACE_CLIENT_ID);
        let redirect_uris = app
            .url_prefix
            .iter()
            .map(|prefix| {
                format!(
                    "{base_url}/{}/oauth/callback",
                    prefix.trim_matches('/')
                )
            })
            .collect::<Vec<_>>();
        if redirect_uris.is_empty() {
            continue;
        }

        if let Some(client) = clients.iter_mut().find(|c| c.client_id == client_id) {
            for uri in redirect_uris {
                if !client.redirect_uris.contains(&uri) {
                    client.redirect_uris.push(uri);
                }
            }
        } else {
            clients.push(FirstPartyClient {
                client_id: client_id.to_string(),
                description: format!("{} (served by this server)", app.description),
                redirect_uris,
                secret: None,
            });
        }
    }

    let uris = |urls: &[&str], path: &str| {
        let mut uris: Vec<String> = Vec::new();
        for url in urls {
            let url = url.trim().trim_end_matches('/');
            let uri = format!("{url}{path}");
            if !url.is_empty() && !uris.contains(&uri) {
                uris.push(uri);
            }
        }
        uris
    };

    let admin = uris(admin_urls, "/oauth/callback");
    if !admin.is_empty() {
        clients.push(FirstPartyClient {
            client_id: ADMIN_CLIENT_ID.to_string(),
            description: "inbuxa Admin".to_string(),
            redirect_uris: admin,
            secret: None,
        });
    }

    let webmail = uris(webmail_urls, "/api/auth/callback");
    let webmail_secret = webmail_secret.filter(|secret| match secret {
        ClientSecret::Plain(s) | ClientSecret::Hash(s) => !s.is_empty(),
    });
    if !webmail.is_empty()
        && let Some(secret) = webmail_secret
    {
        clients.push(FirstPartyClient {
            client_id: WEBMAIL_CLIENT_ID.to_string(),
            description: "ihasmail webmail".to_string(),
            redirect_uris: webmail,
            secret: Some(secret),
        });
    }

    clients
}

/// The address the server's own pages are served from, as `Http` works it out.
fn base_url(bp: &Bootstrap, system: &SystemSettings) -> String {
    if let Some(url) = bp.registry.public_url() {
        return url.to_string();
    }
    let default_hostname = if !system.default_hostname.is_empty() {
        system.default_hostname.as_str()
    } else {
        bp.registry.local_hostname()
    };
    let host = system
        .services
        .iter()
        .find(|(service, _)| matches!(service, ServiceProtocol::Jmap))
        .and_then(|(_, details)| details.hostname.as_deref())
        .unwrap_or(default_hostname);
    format!("https://{host}")
}

/// The origin (`scheme://host[:port]`) of a front end's address, lowercased,
/// without a default port. `None` if it isn't an `http` or `https` URL.
pub fn origin_of(url: &str) -> Option<String> {
    let uri = url.trim().parse::<hyper::Uri>().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    let host = uri.host()?.to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(match uri.port_u16() {
        Some(port) if port != default_port => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    })
}

/// The origins allowed to make cross-origin requests (contract C-14): INBUXA
/// Admin's, the webmail's, and `INBUXA_CORS_EXTRA_ORIGINS` (comma-separated),
/// from the environment and from `inbuxa:FrontEnds` alike.
pub fn front_end_origins(stored: &FrontEnds) -> Vec<String> {
    let mut origins = Vec::new();
    for url in [env("ADMIN_URL"), env("WEBMAIL_URL")]
        .into_iter()
        .flatten()
        .chain(stored.admin_url.clone())
        .chain(stored.webmail_url.clone())
        .chain(stored.extra_origins.iter().cloned())
    {
        origins.extend(origin_of(&url));
    }
    if let Some(extra) = env("CORS_EXTRA_ORIGINS") {
        origins.extend(extra.split(',').filter_map(origin_of));
    }
    origins.sort();
    origins.dedup();
    origins
}

/// Whether the environment gives the webmail its secret. `inbuxa:FrontEnds`
/// can't set one then: the environment's would be put back at every start.
pub fn webmail_secret_from_environment() -> bool {
    env("WEBMAIL_CLIENT_SECRET").is_some()
}

fn env(name: &str) -> Option<String> {
    types::branding::env_var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Registers the first-party clients: at every start, and again whenever
/// `inbuxa:FrontEnds` is set.
pub async fn ensure_first_party_clients(bp: &mut Bootstrap) -> trc::Result<()> {
    retire_legacy_web_interface_client(bp).await?;
    let system = bp.setting_infallible::<SystemSettings>().await;
    let base_url = base_url(bp, &system);
    let applications = bp
        .list_infallible::<Application>()
        .await
        .into_iter()
        .map(|app| app.object)
        .collect::<Vec<_>>();
    let stored = front_ends::get(&bp.data_store).await?;
    let admin_urls: Vec<String> = env("ADMIN_URL").into_iter().chain(stored.admin_url.clone()).collect();
    let webmail_urls: Vec<String> = env("WEBMAIL_URL").into_iter().chain(stored.webmail_url.clone()).collect();
    let webmail_secret = env("WEBMAIL_CLIENT_SECRET")
        .map(ClientSecret::Plain)
        .or_else(|| stored.webmail_secret_hash.clone().map(ClientSecret::Hash));
    if !webmail_urls.is_empty() && webmail_secret.is_none() {
        trc::event!(
            Auth(trc::AuthEvent::Error),
            Details = "The webmail's address is set without its client secret; the webmail client was not registered."
        );
    }
    let admin_urls: Vec<&str> = admin_urls.iter().map(String::as_str).collect();
    let webmail_urls: Vec<&str> = webmail_urls.iter().map(String::as_str).collect();

    for client in first_party_clients(&base_url, &applications, &admin_urls, &webmail_urls, webmail_secret) {
        ensure_client(bp, client).await?;
    }

    Ok(())
}

/// An install from before the rename, upstream's or this fork's, has the web
/// interface registered as `stalwart-webui`, and may
/// have an application naming it. The application is moved to the current id
/// and the old client removed, so the old id stops working rather than
/// living on as an alias; anyone signed in to the web interface signs in
/// again. Runs on every start and does nothing once both are gone.
async fn retire_legacy_web_interface_client(bp: &mut Bootstrap) -> trc::Result<()> {
    for app in bp.list_infallible::<Application>().await {
        if app.object.oauth_client_id.as_deref() != Some(LEGACY_WEB_INTERFACE_CLIENT_ID) {
            continue;
        }
        let mut updated = app.object.clone();
        updated.oauth_client_id = Some(WEB_INTERFACE_CLIENT_ID.to_string());
        // The old object carries its revision: the write asserts on it.
        let current = Object::with_revision(ObjectInner::from(app.object), app.revision);
        let result = bp
            .registry
            .write(RegistryWrite::update(app.id.id(), &updated.into(), &current))
            .await?;
        if !matches!(result, RegistryWriteResult::Success(_)) {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to move an application to the renamed web interface client.")
                .reason(result.to_string())
                .caused_by(trc::location!()));
        }
    }

    if let Some(object_id) = bp
        .registry
        .primary_key(
            ObjectType::OAuthClient.into(),
            Property::ClientId,
            LEGACY_WEB_INTERFACE_CLIENT_ID.as_bytes().to_vec(),
        )
        .await?
    {
        let result = bp.registry.write(RegistryWrite::delete(object_id)).await?;
        if !matches!(result, RegistryWriteResult::Success(_)) {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to remove the web interface's pre-rename OAuth client.")
                .reason(result.to_string())
                .caused_by(trc::location!()));
        }
    }

    Ok(())
}

async fn ensure_client(bp: &mut Bootstrap, client: FirstPartyClient) -> trc::Result<()> {
    // At boot there is no server yet, so a verifier of our own
    let verifier = PasswordVerifier::new(std::num::NonZeroUsize::MIN);
    let existing = match bp
        .registry
        .primary_key(
            ObjectType::OAuthClient.into(),
            Property::ClientId,
            client.client_id.as_bytes().to_vec(),
        )
        .await?
    {
        // inbuxa: read as an Object, keeping the revision the update below
        // asserts on (a bare OAuthClient converts back with revision 0, which
        // never matches, so any update failed start-up).
        Some(object_id) => bp
            .registry
            .get(object_id)
            .await?
            .map(|object| (object_id.id(), object.revision, OAuthClient::from(object))),
        None => None,
    };

    let result = if let Some((id, revision, current)) = existing {
        let mut updated = current.clone();
        for uri in &client.redirect_uris {
            if !updated.redirect_uris.contains(uri) {
                updated.redirect_uris.push(uri.clone());
            }
        }
        match &client.secret {
            Some(ClientSecret::Plain(secret)) => {
                let matches = match updated.secret.as_deref() {
                    Some(hash) if !hash.is_empty() => {
                        verify_secret_hash(&verifier, hash, secret.as_bytes()).await?
                    }
                    _ => false,
                };
                if !matches {
                    updated.secret = Some(
                        hash_secret(&verifier, PasswordHashAlgorithm::Argon2id, secret.as_bytes().to_vec())
                            .await?,
                    );
                }
            }
            Some(ClientSecret::Hash(hash)) => {
                if updated.secret.as_deref() != Some(hash.as_str()) {
                    updated.secret = Some(hash.clone());
                }
            }
            None => {}
        }
        if updated == current {
            return Ok(());
        }
        let current = Object::with_revision(ObjectInner::from(current), revision);
        bp.registry
            .write(RegistryWrite::update(id, &updated.into(), &current))
            .await?
    } else {
        let secret = match &client.secret {
            Some(ClientSecret::Plain(secret)) => Some(
                hash_secret(&verifier, PasswordHashAlgorithm::Argon2id, secret.as_bytes().to_vec()).await?,
            ),
            Some(ClientSecret::Hash(hash)) => Some(hash.clone()),
            None => None,
        };
        bp.registry
            .write(RegistryWrite::insert(
                &OAuthClient {
                    client_id: client.client_id.clone(),
                    description: Some(client.description),
                    redirect_uris: Map::new(client.redirect_uris),
                    secret,
                    created_at: UTCDateTime::now(),
                    ..Default::default()
                }
                .into(),
            ))
            .await?
    };

    if !matches!(result, RegistryWriteResult::Success(_)) {
        return Err(trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Failed to register a first-party OAuth client.")
            .ctx(trc::Key::Id, client.client_id)
            .reason(result.to_string())
            .caused_by(trc::location!()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn web_interface() -> Application {
        Application {
            description: "inbuxa Web Interface".to_string(),
            enable: true,
            url_prefix: Map::new(vec!["/admin".into(), "/account".into()]),
            ..Default::default()
        }
    }

    #[test]
    fn web_interface_gets_one_uri_per_prefix() {
        let clients = first_party_clients("https://mail.example.org/", &[web_interface()], &[], &[], None);
        assert_eq!(
            clients,
            vec![FirstPartyClient {
                client_id: WEB_INTERFACE_CLIENT_ID.to_string(),
                description: "inbuxa Web Interface (served by this server)".to_string(),
                redirect_uris: vec![
                    "https://mail.example.org/admin/oauth/callback".to_string(),
                    "https://mail.example.org/account/oauth/callback".to_string(),
                ],
                secret: None,
            }]
        );
    }

    #[test]
    fn disabled_applications_and_named_clients() {
        let mut disabled = web_interface();
        disabled.enable = false;
        let mut named = web_interface();
        named.oauth_client_id = Some("custom".to_string());
        named.url_prefix = Map::new(vec!["portal".into()]);
        let clients = first_party_clients("https://h", &[disabled, named], &[], &[], None);
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].client_id, "custom");
        assert_eq!(clients[0].redirect_uris, vec!["https://h/portal/oauth/callback"]);
    }

    #[test]
    fn front_ends_from_their_addresses() {
        let clients = first_party_clients(
            "https://h",
            &[],
            &["https://admin.example.org/"],
            &["https://webmail.example.org"],
            Some(ClientSecret::Plain("s3cret".into())),
        );
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].client_id, ADMIN_CLIENT_ID);
        assert_eq!(clients[0].redirect_uris, vec!["https://admin.example.org/oauth/callback"]);
        assert_eq!(clients[0].secret, None);
        assert_eq!(clients[1].client_id, WEBMAIL_CLIENT_ID);
        assert_eq!(clients[1].redirect_uris, vec!["https://webmail.example.org/api/auth/callback"]);
        assert_eq!(clients[1].secret, Some(ClientSecret::Plain("s3cret".into())));
    }

    #[test]
    fn origins() {
        assert_eq!(origin_of("https://Admin.Example.org/"), Some("https://admin.example.org".into()));
        assert_eq!(origin_of("https://admin.example.org:443/x"), Some("https://admin.example.org".into()));
        assert_eq!(origin_of("http://localhost:5173"), Some("http://localhost:5173".into()));
        assert_eq!(origin_of("https://h:8443/app"), Some("https://h:8443".into()));
        assert_eq!(origin_of("ftp://h"), None);
        assert_eq!(origin_of("not a url"), None);
        assert_eq!(origin_of(""), None);
    }

    #[test]
    fn webmail_needs_a_secret() {
        let clients = first_party_clients("https://h", &[], &[" "], &["https://w"], Some(ClientSecret::Plain(String::new())));
        assert!(clients.is_empty());
        let clients = first_party_clients("https://h", &[], &[], &["https://w"], None);
        assert!(clients.is_empty());
    }

    #[test]
    fn both_addresses_of_a_front_end_are_registered() {
        // The environment's and inbuxa:FrontEnds', once each
        let clients = first_party_clients(
            "https://h",
            &[],
            &["https://admin.a.example", "https://admin.b.example/", "https://admin.a.example/"],
            &["https://webmail.b.example"],
            Some(ClientSecret::Hash("$argon2id$x".into())),
        );
        assert_eq!(
            clients[0].redirect_uris,
            vec![
                "https://admin.a.example/oauth/callback",
                "https://admin.b.example/oauth/callback"
            ]
        );
        assert_eq!(clients[1].secret, Some(ClientSecret::Hash("$argon2id$x".into())));
    }

    #[test]
    fn stored_front_ends_are_allowed_origins() {
        let stored = FrontEnds {
            admin_url: Some("https://Admin.Example.org/console".into()),
            extra_origins: vec!["http://localhost:5173".into(), "not a url".into()],
            ..Default::default()
        };
        let origins = front_end_origins(&stored);
        assert!(origins.contains(&"https://admin.example.org".to_string()));
        assert!(origins.contains(&"http://localhost:5173".to_string()));
        assert!(!origins.iter().any(|o| o.contains("not a url")));
    }
}
