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
use registry::schema::{enums::Permission, structs::Account};
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

/// The relying-party id passkeys are registered for now (PK-3): the host of
/// the server's public HTTPS URL.
pub fn current_rp_id(server: &Server) -> String {
    host_of(&server.core.network.http.url_https)
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

fn to_value(server: &Server, passkey: &Passkey, properties: &[P], ticket: Option<&str>) -> PValue {
    let rp_id = current_rp_id(server);
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
    let all = passkey::list(server.store(), account_id, now()).await?;
    match ids {
        None => {
            response.list = all
                .iter()
                .map(|p| to_value(server, p, &properties, None))
                .collect();
        }
        Some(ids) => {
            for id in ids {
                match all.iter().find(|p| p.id() == id.id()) {
                    Some(p) => response.list.push(to_value(server, p, &properties, None)),
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
        let ticket = rng()
            .sample_iter(Alphanumeric)
            .take(TICKET_LEN)
            .map(char::from)
            .collect::<String>();
        match passkey::create_pending(data, account_id, name, &ticket, now()).await? {
            Created::Pending(created) => {
                let out = to_value(
                    server,
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
                        "An account can have {} passkeys. Remove one first.",
                        passkey::MAX_PASSKEYS
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
    use super::host_of;

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
}
