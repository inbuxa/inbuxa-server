/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! First-party OAuth clients (docs/spec/contract.md C-6).
//!
//! INBUXA requires OAuth clients to be registered (C-5), so the front ends
//! that ship with it are registered for it, on every start:
//!
//! - the web interface the server serves itself (`Application`, `/admin` and
//!   `/account`), as its OAuth client id, `stalwart-webui` unless the
//!   application names another;
//! - INBUXA Admin hosted elsewhere, as `inbuxa-admin`, when `INBUXA_ADMIN_URL`
//!   is set;
//! - ihasmail-inbuxa, as the confidential client `ihasmail-inbuxa`, when
//!   `INBUXA_WEBMAIL_URL` and `INBUXA_WEBMAIL_CLIENT_SECRET` are set.
//!
//! inbuxa: the environment variables stand in for `x:FrontEnds` (C-4) until
//! that object exists; the installer and INBUXA Admin's setup wizard will set
//! it instead.
//!
//! A missing client is created. An existing one gains any redirect URI it
//! lacks and, for ihasmail-inbuxa, the configured secret; nothing an operator
//! added is removed.

use directory::core::secret::{hash_secret, verify_secret_hash};
use registry::{
    schema::{
        enums::{PasswordHashAlgorithm, ServiceProtocol},
        prelude::{ObjectType, Property, UTCDateTime},
        structs::{Application, OAuthClient, SystemSettings},
    },
    types::map::Map,
};
use store::registry::{
    bootstrap::Bootstrap,
    write::{RegistryWrite, RegistryWriteResult},
};

/// The client id the upstream web interface uses when its application names none.
pub const WEB_INTERFACE_CLIENT_ID: &str = "stalwart-webui";
pub const ADMIN_CLIENT_ID: &str = "inbuxa-admin";
pub const WEBMAIL_CLIENT_ID: &str = "ihasmail-inbuxa";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstPartyClient {
    pub client_id: String,
    pub description: String,
    pub redirect_uris: Vec<String>,
    pub secret: Option<String>,
}

/// The first-party clients this server should have, from its applications and
/// the front-end addresses it was given.
pub fn first_party_clients(
    base_url: &str,
    applications: &[Application],
    admin_url: Option<&str>,
    webmail: Option<(&str, &str)>,
) -> Vec<FirstPartyClient> {
    let base_url = base_url.trim_end_matches('/');
    let mut clients: Vec<FirstPartyClient> = Vec::new();

    for app in applications.iter().filter(|app| app.enabled) {
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

    if let Some(url) = admin_url.map(|url| url.trim().trim_end_matches('/')).filter(|url| !url.is_empty()) {
        clients.push(FirstPartyClient {
            client_id: ADMIN_CLIENT_ID.to_string(),
            description: "INBUXA Admin".to_string(),
            redirect_uris: vec![format!("{url}/oauth/callback")],
            secret: None,
        });
    }

    if let Some((url, secret)) = webmail {
        let url = url.trim().trim_end_matches('/');
        if !url.is_empty() && !secret.is_empty() {
            clients.push(FirstPartyClient {
                client_id: WEBMAIL_CLIENT_ID.to_string(),
                description: "ihasmail webmail".to_string(),
                redirect_uris: vec![format!("{url}/api/auth/callback")],
                secret: Some(secret.to_string()),
            });
        }
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
/// Admin's, the webmail's, and `INBUXA_CORS_EXTRA_ORIGINS` (comma-separated).
///
/// inbuxa: read from the environment until `x:FrontEnds` exists (C-4).
pub fn front_end_origins() -> Vec<String> {
    let mut origins = Vec::new();
    for url in [env("ADMIN_URL"), env("WEBMAIL_URL")].into_iter().flatten() {
        origins.extend(origin_of(&url));
    }
    if let Some(extra) = env("CORS_EXTRA_ORIGINS") {
        origins.extend(extra.split(',').filter_map(origin_of));
    }
    origins.sort();
    origins.dedup();
    origins
}

fn env(name: &str) -> Option<String> {
    types::branding::env_var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) async fn ensure_first_party_clients(bp: &mut Bootstrap) -> trc::Result<()> {
    let system = bp.setting_infallible::<SystemSettings>().await;
    let base_url = base_url(bp, &system);
    let applications = bp
        .list_infallible::<Application>()
        .await
        .into_iter()
        .map(|app| app.object)
        .collect::<Vec<_>>();
    let admin_url = env("ADMIN_URL");
    let webmail_url = env("WEBMAIL_URL");
    let webmail_secret = env("WEBMAIL_CLIENT_SECRET");
    if webmail_url.is_some() && webmail_secret.is_none() {
        trc::event!(
            Auth(trc::AuthEvent::Error),
            Details = "INBUXA_WEBMAIL_URL is set without INBUXA_WEBMAIL_CLIENT_SECRET; the webmail client was not registered."
        );
    }
    let webmail = webmail_url.as_deref().zip(webmail_secret.as_deref());

    for client in first_party_clients(&base_url, &applications, admin_url.as_deref(), webmail) {
        ensure_client(bp, client).await?;
    }

    Ok(())
}

async fn ensure_client(bp: &mut Bootstrap, client: FirstPartyClient) -> trc::Result<()> {
    let existing = match bp
        .registry
        .primary_key(
            ObjectType::OAuthClient.into(),
            Property::ClientId,
            client.client_id.as_bytes().to_vec(),
        )
        .await?
    {
        Some(object_id) => bp
            .registry
            .object::<OAuthClient>(object_id.id())
            .await?
            .map(|object| (object_id.id(), object)),
        None => None,
    };

    let result = if let Some((id, current)) = existing {
        let mut updated = current.clone();
        for uri in &client.redirect_uris {
            if !updated.redirect_uris.contains(uri) {
                updated.redirect_uris.push(uri.clone());
            }
        }
        if let Some(secret) = &client.secret {
            let matches = match updated.secret.as_deref() {
                Some(hash) if !hash.is_empty() => {
                    verify_secret_hash(hash, secret.as_bytes()).await?
                }
                _ => false,
            };
            if !matches {
                updated.secret = Some(
                    hash_secret(PasswordHashAlgorithm::Argon2id, secret.as_bytes().to_vec())
                        .await?,
                );
            }
        }
        if updated == current {
            return Ok(());
        }
        bp.registry
            .write(RegistryWrite::update(id, &updated.into(), &current.into()))
            .await?
    } else {
        let secret = match &client.secret {
            Some(secret) => Some(
                hash_secret(PasswordHashAlgorithm::Argon2id, secret.as_bytes().to_vec()).await?,
            ),
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
            description: "INBUXA Web Interface".to_string(),
            enabled: true,
            url_prefix: Map::new(vec!["/admin".into(), "/account".into()]),
            ..Default::default()
        }
    }

    #[test]
    fn web_interface_gets_one_uri_per_prefix() {
        let clients = first_party_clients("https://mail.example.org/", &[web_interface()], None, None);
        assert_eq!(
            clients,
            vec![FirstPartyClient {
                client_id: WEB_INTERFACE_CLIENT_ID.to_string(),
                description: "INBUXA Web Interface (served by this server)".to_string(),
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
        disabled.enabled = false;
        let mut named = web_interface();
        named.oauth_client_id = Some("custom".to_string());
        named.url_prefix = Map::new(vec!["portal".into()]);
        let clients = first_party_clients("https://h", &[disabled, named], None, None);
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].client_id, "custom");
        assert_eq!(clients[0].redirect_uris, vec!["https://h/portal/oauth/callback"]);
    }

    #[test]
    fn front_ends_from_their_addresses() {
        let clients = first_party_clients(
            "https://h",
            &[],
            Some("https://admin.example.org/"),
            Some(("https://webmail.example.org", "s3cret")),
        );
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].client_id, ADMIN_CLIENT_ID);
        assert_eq!(clients[0].redirect_uris, vec!["https://admin.example.org/oauth/callback"]);
        assert_eq!(clients[0].secret, None);
        assert_eq!(clients[1].client_id, WEBMAIL_CLIENT_ID);
        assert_eq!(clients[1].redirect_uris, vec!["https://webmail.example.org/api/auth/callback"]);
        assert_eq!(clients[1].secret.as_deref(), Some("s3cret"));
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
        let clients = first_party_clients("https://h", &[], Some(" "), Some(("https://w", "")));
        assert!(clients.is_empty());
    }
}
