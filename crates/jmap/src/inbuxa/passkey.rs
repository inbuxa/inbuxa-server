/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Passkey` (passkeys spec, PK-5 to PK-16): an account's passkeys.
//! The request's `accountId` names the account. A person manages their own
//! with the `sysPasskey*` permissions; an administrator reaches another
//! account's when it is in reach and holds no permission the administrator
//! lacks, as for changing the account. Creating one starts registration: a
//! `pending` record with the page that finishes it. Removing one ends every
//! session of the account (PK-15). The request layer records every change in
//! the audit log (PK-17).

use common::{
    Server,
    auth::AccessToken,
    cache::invalidate::CacheInvalidationBuilder,
    ipc::{BroadcastEvent, CacheInvalidation, PushEvent},
};
use inbuxa_features::passkey::{self, Created, Passkey, State};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_passkey::{Passkey as PasskeyObject, PasskeyProperty as P, PasskeyValue},
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use rand::{RngExt, distr::Alphanumeric, rng};
use registry::schema::{
    enums::Permission,
    prelude::{Object, ObjectInner, Property},
    structs::{Account, Authentication, Domain, Tenant},
};
use store::write::now;
use trc::AddContext;
use types::id::Id;

type PValue = Value<'static, P, PasskeyValue>;

const ALL: &[P] = &[
    P::Id,
    P::AccountId,
    P::Name,
    P::State,
    P::RegistrationUrl,
    P::RpId,
    P::Usable,
    P::BackedUp,
    P::Transports,
    P::CreatedAt,
    P::LastUsedAt,
];

const TICKET_LEN: usize = 43;

/// Where the browser part of registration runs (PK-6).
fn registration_url(server: &Server, ticket: &str) -> String {
    format!(
        "{}/passkey/register?ticket={ticket}",
        server.core.network.http.url_https.trim_end_matches('/')
    )
}

/// The passkey settings on `x:Authentication`.
pub async fn settings(server: &Server) -> trc::Result<Authentication> {
    Ok(server
        .registry()
        .object::<Authentication>(Id::singleton())
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default())
}

/// The relying-party id passkeys are registered for now (PK-3):
/// `passkeyRpId`, or the host of the server's public HTTPS URL.
pub fn current_rp_id(server: &Server, settings: &Authentication) -> String {
    settings
        .passkey_rp_id
        .as_deref()
        .map(|id| id.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| host_of(&server.core.network.http.url_https))
}

/// PK-3: whether `rp_id` may be the relying-party id for a server reached at
/// `url`: its host, or a registrable parent of it, never a public suffix.
pub fn check_rp_id(url: &str, rp_id: &str) -> Result<(), &'static str> {
    let host = host_of(url);
    let rp_id = rp_id.trim().trim_end_matches('.').to_ascii_lowercase();
    if rp_id.is_empty() || rp_id.starts_with('.') || rp_id.contains(['/', ':', '@', ' ']) {
        return Err("Give a domain name, such as example.com.");
    }
    if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
        return Err("It must be the host of the server's public URL or a parent domain of it.");
    }
    if rp_id == "localhost" {
        return Ok(());
    }
    match psl::suffix(rp_id.as_bytes()) {
        Some(suffix) if suffix.as_bytes() != rp_id.as_bytes() => Ok(()),
        _ => Err("A public suffix such as com or co.uk can't be used."),
    }
}

/// PK-3: a new or changed `passkeyRpId` must fit the server's public URL;
/// `invalidProperties` names it otherwise.
pub fn check_write(
    server: &Server,
    old: Option<&Object>,
    new: &Object,
) -> Result<(), SetError<Property>> {
    let ObjectInner::Authentication(auth) = &new.inner else {
        return Ok(());
    };
    let Some(rp_id) = auth.passkey_rp_id.as_deref() else {
        return Ok(());
    };
    let unchanged = old.is_some_and(|old| {
        matches!(&old.inner, ObjectInner::Authentication(o) if o.passkey_rp_id.as_deref() == Some(rp_id))
    });
    if unchanged {
        return Ok(());
    }
    check_rp_id(&server.core.network.http.url_https, rp_id).map_err(|reason| {
        SetError::invalid_properties()
            .with_property(Property::PasskeyRpId)
            .with_description(reason)
    })
}

/// PK-12, PK-13: whether the account may add passkeys and sign in with
/// them. Not on an external directory; then the server, the account's
/// tenant and its domain can each switch them off.
pub async fn allowed_for(
    server: &Server,
    settings: &Authentication,
    account_id: u32,
) -> trc::Result<bool> {
    if !settings.passkeys_allowed {
        return Ok(false);
    }
    let account = server
        .account(account_id)
        .await
        .caused_by(trc::location!())?;
    let domain = match account.name.rsplit_once('@') {
        Some((_, domain)) => server.domain(domain).await?,
        None => None,
    };
    // PK-13: the directory owns sign-in
    let directory = domain
        .as_ref()
        .and_then(|domain| domain.id_directory)
        .or(settings.directory_id.map(|id| id.document_id()));
    if directory.is_some() {
        return Ok(false);
    }
    if let Some(domain) = &domain
        && let Some(object) = server
            .registry()
            .object::<Domain>(Id::from(domain.id))
            .await
            .caused_by(trc::location!())?
        && !object.passkeys_allowed
    {
        return Ok(false);
    }
    let tenant = account
        .id_tenant
        .or(domain.as_ref().and_then(|domain| domain.id_tenant));
    if let Some(tenant) = tenant
        && let Some(object) = server
            .registry()
            .object::<Tenant>(Id::from(tenant))
            .await
            .caused_by(trc::location!())?
        && !object.passkeys_allowed
    {
        return Ok(false);
    }
    Ok(true)
}

/// The host of a URL, lowercased, without a port.
fn host_of(url: &str) -> String {
    let host = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = if host.starts_with('[') {
        host.split_once(']')
            .map_or(host, |(v6, _)| &host[..v6.len() + 1])
    } else {
        match host.rsplit_once(':') {
            Some((name, port))
                if !name.contains(':') && port.chars().all(|c| c.is_ascii_digit()) =>
            {
                name
            }
            _ => host,
        }
    };
    host.to_ascii_lowercase()
}

fn date(seconds: u64) -> PValue {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

fn to_value(
    server: &Server,
    rp_id: &str,
    passkey: &Passkey,
    properties: &[P],
    ticket: Option<&str>,
) -> PValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(PasskeyValue::Id(Id::from(passkey.id()))),
            P::AccountId => Value::Element(PasskeyValue::Id(Id::from(passkey.account_id))),
            P::Name => Value::Str(passkey.name.clone().into()),
            P::State => Value::Str(passkey.state.as_str().into()),
            P::RegistrationUrl => match ticket {
                Some(ticket) => Value::Str(registration_url(server, ticket).into()),
                None => Value::Null,
            },
            P::RpId => match passkey.state {
                State::Active => Value::Str(passkey.rp_id.clone().into()),
                State::Pending => Value::Null,
            },
            P::Usable => Value::Bool(passkey.state == State::Active && passkey.rp_id == rp_id),
            P::BackedUp => Value::Bool(passkey.backed_up),
            P::Transports => Value::Array(
                passkey
                    .transports
                    .iter()
                    .map(|t| Value::Str(t.clone().into()))
                    .collect(),
            ),
            P::CreatedAt => date(passkey.created_at),
            P::LastUsedAt => match passkey.last_used_at {
                Some(at) => date(at),
                None => Value::Null,
            },
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// Whether the caller reaches `account_id`'s passkeys: its own, or, for an
/// administrator who may change accounts, a person's account in reach that
/// holds no permission the administrator lacks.
async fn reach(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
) -> trc::Result<Result<(), SetError<P>>> {
    if access_token.is_account_id(account_id) {
        return Ok(Ok(()));
    }
    // Someone else's passkeys take the right to change accounts
    if !access_token.has_permission(Permission::SysAccountUpdate) {
        return Ok(Err(
            SetError::forbidden().with_description("You can't reach that account's passkeys.")
        ));
    }
    let Ok(account) = server.account(account_id).await else {
        return Ok(Err(SetError::not_found()));
    };
    if !account.is_user_account() {
        return Ok(Err(SetError::not_found()));
    }
    if let Some(tenant_id) = access_token.tenant_id()
        && account.id_tenant != Some(tenant_id)
    {
        return Ok(Err(SetError::not_found()));
    }
    let Some(registered) = server
        .registry()
        .object::<Account>(Id::from(account_id))
        .await?
    else {
        return Ok(Err(SetError::not_found()));
    };
    Ok(server
        .can_set_permissions(access_token, &registered)
        .await?
        .map_err(|_| {
            SetError::forbidden().with_description("That account holds permissions you don't have.")
        }))
}

fn not_reached() -> trc::Error {
    trc::JmapEvent::Forbidden
        .into_err()
        .details("You can't reach that account's passkeys.")
}

/// Ends the account's open sessions, here and on every node (PK-15). The
/// credential version moves with the removal, so OAuth tokens stop working
/// once the cached access token is rebuilt.
async fn end_sessions(server: &Server, account_id: u32) -> trc::Result<()> {
    passkey::bump_epoch(server.store(), account_id).await?;
    let mut changes = CacheInvalidationBuilder::default();
    changes.invalidate(CacheInvalidation::AccessToken(account_id));
    server
        .invalidate_caches(changes)
        .await
        .caused_by(trc::location!())?;
    let _ = server
        .inner
        .ipc
        .push_tx
        .send(PushEvent::Revoke { account_id })
        .await;
    server
        .cluster_broadcast(BroadcastEvent::EndSessions(account_id))
        .await;
    Ok(())
}

/// `inbuxa:Passkey/get`: the account's passkeys, by number.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<PasskeyObject>,
) -> trc::Result<GetResponse<PasskeyObject>> {
    let account_id = request.account_id.document_id();
    if reach(server, access_token, account_id).await?.is_err() {
        return Err(not_reached());
    }
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let rp_id = current_rp_id(server, &settings(server).await?);
    let all = passkey::list(server.store(), account_id, now()).await?;
    match ids {
        None => {
            response.list = all
                .iter()
                .map(|p| to_value(server, &rp_id, p, &properties, None))
                .collect();
        }
        Some(ids) => {
            for id in ids {
                match all.iter().find(|p| p.id() == id.id()) {
                    Some(p) => response
                        .list
                        .push(to_value(server, &rp_id, p, &properties, None)),
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

/// `inbuxa:Passkey/set`: start registering a passkey, rename one, or remove
/// one.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, PasskeyObject>,
) -> trc::Result<SetResponse<PasskeyObject>> {
    let account_id = request.account_id.document_id();
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let reached = reach(server, access_token, account_id).await?;
    let data = server.store();
    let settings = settings(server).await?;
    let rp_id = current_rp_id(server, &settings);
    let mut allowed = None;

    for (client_id, value) in request.unwrap_create() {
        if let Err(error) = &reached {
            response.not_created.append(client_id, error.clone());
            continue;
        }
        let mut name = None;
        let mut refused = None;
        for (key, value) in value.into_expanded_object() {
            match (&key, value) {
                (Key::Property(P::Name), Value::Str(text)) => match passkey::clean_name(&text) {
                    Ok(text) => name = Some(text),
                    Err(reason) => {
                        refused = Some(
                            SetError::invalid_properties()
                                .with_property(P::Name)
                                .with_description(reason),
                        );
                    }
                },
                (Key::Property(P::AccountId), Value::Element(PasskeyValue::Id(id)))
                    if id.document_id() == account_id => {}
                (Key::Property(property), _) => {
                    refused = Some(
                        SetError::invalid_properties()
                            .with_property(property.clone())
                            .with_description("The server sets this."),
                    );
                }
                _ => {
                    refused = Some(SetError::invalid_properties());
                }
            }
        }
        if let Some(error) = refused {
            response.not_created.append(client_id, error);
            continue;
        }
        let Some(name) = name else {
            response.not_created.append(
                client_id,
                SetError::invalid_properties()
                    .with_property(P::Name)
                    .with_description("Give the passkey a name, such as the device it's on."),
            );
            continue;
        };
        // PK-12, PK-13
        let allowed = match allowed {
            Some(allowed) => allowed,
            None => *allowed.insert(allowed_for(server, &settings, account_id).await?),
        };
        if !allowed {
            response.not_created.append(
                client_id,
                SetError::forbidden().with_description("Passkeys are turned off for this account."),
            );
            continue;
        }
        let ticket = rng()
            .sample_iter(Alphanumeric)
            .take(TICKET_LEN)
            .map(char::from)
            .collect::<String>();
        let max = settings.max_passkeys.clamp(1, 100) as usize;
        match passkey::create_pending(data, account_id, name, &ticket, now(), max).await? {
            Created::Pending(created) => {
                let out = to_value(
                    server,
                    &rp_id,
                    &created,
                    &[P::Id, P::State, P::RegistrationUrl, P::CreatedAt],
                    Some(&ticket),
                );
                response.created.insert(client_id, out);
            }
            Created::Full => {
                response.not_created.append(
                    client_id,
                    SetError::over_quota().with_description(format!(
                        "An account can have {max} passkeys. Remove one first."
                    )),
                );
            }
        }
    }

    for (id, value) in request.unwrap_update().into_valid() {
        if let Err(error) = &reached {
            response.not_updated.append(id, error.clone());
            continue;
        }
        let (owner, number) = passkey::split_id(id.id());
        let found = if owner == account_id {
            passkey::get(data, owner, number)
                .await?
                .filter(|p| !p.is_expired(now()))
        } else {
            None
        };
        let Some(mut found) = found else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        let mut refused = None;
        for (key, value) in value.into_expanded_object() {
            match (&key, value) {
                (Key::Property(P::Name), Value::Str(text)) => match passkey::clean_name(&text) {
                    Ok(text) => found.name = text,
                    Err(reason) => {
                        refused = Some(
                            SetError::invalid_properties()
                                .with_property(P::Name)
                                .with_description(reason),
                        );
                    }
                },
                (Key::Property(property), _) => {
                    refused = Some(
                        SetError::invalid_properties()
                            .with_property(property.clone())
                            .with_description("Only the name can be changed."),
                    );
                }
                _ => refused = Some(SetError::invalid_properties()),
            }
        }
        if let Some(error) = refused {
            response.not_updated.append(id, error);
            continue;
        }
        passkey::save(data, &found).await?;
        response.updated.append(id, None);
    }

    let mut removed_active = false;
    for id in request.unwrap_destroy().into_valid() {
        if let Err(error) = &reached {
            response.not_destroyed.append(id, error.clone());
            continue;
        }
        let (owner, number) = passkey::split_id(id.id());
        let found = if owner == account_id {
            passkey::get(data, owner, number).await?
        } else {
            None
        };
        match found {
            Some(found) => {
                passkey::remove(data, &found).await?;
                removed_active |= found.state == State::Active;
                response.destroyed.push(id);
            }
            None => response.not_destroyed.append(id, SetError::not_found()),
        }
    }
    if removed_active {
        end_sessions(server, account_id).await?;
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::{check_rp_id, host_of};

    #[test]
    fn rp_id_is_the_host() {
        assert_eq!(host_of("https://Mail.Example.com"), "mail.example.com");
        assert_eq!(
            host_of("https://mail.example.com:8443/"),
            "mail.example.com"
        );
        assert_eq!(host_of("https://mail.example.com/path"), "mail.example.com");
        assert_eq!(host_of("https://[::1]:443"), "[::1]");
    }

    // PK-3: the host or a registrable parent of it, never a public suffix
    #[test]
    fn rp_id_must_fit_the_public_url() {
        let url = "https://mail.example.co.uk";
        assert!(check_rp_id(url, "mail.example.co.uk").is_ok());
        assert!(check_rp_id(url, "example.co.uk").is_ok());
        assert!(check_rp_id(url, "Example.CO.uk.").is_ok());
        assert!(check_rp_id(url, "co.uk").is_err());
        assert!(check_rp_id(url, "uk").is_err());
        assert!(check_rp_id(url, "other.co.uk").is_err());
        assert!(check_rp_id(url, "ample.co.uk").is_err());
        assert!(check_rp_id(url, "https://example.co.uk").is_err());
        assert!(check_rp_id(url, "").is_err());
        assert!(check_rp_id("https://localhost:8899", "localhost").is_ok());
    }
}
