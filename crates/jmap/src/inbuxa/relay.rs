/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Relay` (docs/spec/features/relay.md, "Registry objects"): the
//! inbuxa Relays this server or cluster links to. A relay serves the whole
//! downstream, so nobody in a tenant reaches them. A create returns the
//! join token, once; so does an update with `rejoin: true`, which starts
//! over with a relay that was reset. An update with `upgrade` hands the
//! relay a signed release over this node's link (RL-29). The request layer
//! records every change in the audit log, with the private key and the
//! token left out.

use crate::blob::download::BlobDownload;
use common::{Server, auth::AccessToken, network::acme::relay::relay_certificate_not_after};
use inbuxa_features::relay::{
    self as relays, JoinState, Relay as StoredRelay, certificate::CertificateOrder, link::NodeLink,
};
use inbuxa_relay_proto::{
    b64,
    release::{self, Version},
    types::RelaySettings,
};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_relay::{Relay, RelayProperty as P, RelayValue},
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Property, Value};
use registry::schema::prelude::MASKED_PASSWORD;
use std::{borrow::Cow, str::FromStr};
use store::write::now;
use types::{blob::BlobId, id::Id};

type RValue = Value<'static, P, RelayValue>;
type JsonMap = serde_json::Map<String, serde_json::Value>;

/// Tries at an update that keeps meeting another write.
const UPDATE_ATTEMPTS: usize = 5;

const ALL: &[P] = &[
    P::Id,
    P::Name,
    P::Description,
    P::Address,
    P::LinkPort,
    P::Enabled,
    P::SendThrough,
    P::InboundOnly,
    P::MxPreference,
    P::Settings,
    P::SmtpCertificate,
    P::SmtpPrivateKey,
    P::CertificateNotAfter,
    P::CertificateError,
    P::JoinState,
    P::JoinExpiresAt,
    P::JoinedAt,
    P::LinkKeyPin,
    P::Links,
    P::OlderThanServer,
    P::CreatedBy,
    P::CreatedAt,
    P::UpdatedAt,
];

/// This server's release, which its relays are compared with (RL-28).
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Properties the server sets; a client that sends them is refused.
const SERVER_SET: &[P] = &[
    P::Id,
    P::CertificateNotAfter,
    P::CertificateError,
    P::JoinState,
    P::JoinExpiresAt,
    P::JoinedAt,
    P::LinkKeyPin,
    P::JoinToken,
    P::Links,
    P::OlderThanServer,
    P::CreatedBy,
    P::CreatedAt,
    P::UpdatedAt,
];

pub(super) fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("A relay serves the whole server, not a tenant."))
    } else {
        Ok(())
    }
}

/// A JSON value as a JMAP one, its object keys kept as plain keys.
pub(super) fn json_to_value<P, E>(json: serde_json::Value) -> Value<'static, P, E>
where
    P: Property,
    E: jmap_tools::Element<Property = P>,
{
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(n) = n.as_u64() {
                Value::Number(n.into())
            } else if let Some(n) = n.as_i64() {
                Value::Number(n.into())
            } else {
                Value::Number(n.as_f64().unwrap_or_default().into())
            }
        }
        serde_json::Value::String(s) => Value::Str(Cow::Owned(s)),
        serde_json::Value::Array(items) => {
            Value::Array(items.into_iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, value) in map {
                out.insert_unchecked(Key::Owned(key), json_to_value(value));
            }
            Value::Object(out)
        }
    }
}

fn date(seconds: u64) -> RValue {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

fn text(value: Option<&str>) -> RValue {
    value.map_or(Value::Null, |value| Value::Str(value.to_string().into()))
}

/// Each node's link, with its times as dates.
fn links_value(links: &[NodeLink]) -> RValue {
    let date = |at: u64| UTCDate::from_timestamp(at as i64).to_string();
    let list = links
        .iter()
        .map(|link| {
            let mut json = serde_json::to_value(link).unwrap_or_default();
            json["nodeId"] = link.node_id.to_string().into();
            json["since"] = date(link.since).into();
            json["updatedAt"] = date(link.updated_at).into();
            json["lastSeen"] = link.last_seen.map(date).into();
            json
        })
        .collect::<Vec<_>>();
    json_to_value(serde_json::Value::Array(list))
}

/// Whether any link last heard an older release than this server's.
fn older_than_server(links: &[NodeLink]) -> Option<bool> {
    let server = Version::parse(SERVER_VERSION)?;
    let versions: Vec<Version> = links
        .iter()
        .filter_map(|link| Version::parse(&link.relay.as_ref()?.relay_version))
        .collect();
    (!versions.is_empty()).then(|| versions.iter().any(|version| *version < server))
}

fn to_value(
    relay: &StoredRelay,
    links: &[NodeLink],
    order: Option<&CertificateOrder>,
    properties: &[P],
    now: u64,
) -> RValue {
    let state = relay.join.state(now);
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(RelayValue::Id(Id::from(relay.id))),
            P::Name => text(Some(&relay.name)),
            P::Description => text(Some(&relay.description)),
            P::Address => text(Some(&relay.address)),
            P::LinkPort => Value::Number(u64::from(relay.link_port).into()),
            P::Enabled => Value::Bool(relay.enabled),
            P::SendThrough => Value::Bool(relay.send_through),
            P::InboundOnly => Value::Bool(relay.inbound_only),
            P::MxPreference => Value::Number(u64::from(relay.mx_preference).into()),
            P::Settings => json_to_value(serde_json::to_value(&relay.settings).unwrap_or_default()),
            P::SmtpCertificate => text(relay.smtp_certificate.as_deref()),
            P::SmtpPrivateKey => text(relay.smtp_private_key.as_ref().map(|_| MASKED_PASSWORD)),
            P::CertificateNotAfter => relay
                .smtp_certificate
                .as_deref()
                .and_then(relay_certificate_not_after)
                .map_or(Value::Null, |at| date(at.max(0) as u64)),
            P::CertificateError => text(order.and_then(|order| order.error())),
            P::JoinState => text(Some(match state {
                JoinState::Waiting => "waiting",
                JoinState::Expired => "expired",
                JoinState::Joined => "joined",
            })),
            P::JoinExpiresAt if state != JoinState::Joined => date(relay.join.expires_at),
            P::JoinedAt => relay.join.joined_at.map_or(Value::Null, date),
            P::LinkKeyPin => text(relay.join.relay_pin.map(|pin| b64::encode(&pin)).as_deref()),
            P::Links => links_value(links),
            P::OlderThanServer => older_than_server(links).map_or(Value::Null, Value::Bool),
            P::CreatedBy => text(Some(&relay.created_by)),
            P::CreatedAt => date(relay.created_at),
            P::UpdatedAt => date(relay.updated_at),
            _ => Value::Null,
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// What a client sent: the properties it may set, `rejoin`, and changes to
/// single settings sent as `settings/<name>`.
#[derive(Default)]
struct Sent {
    properties: JsonMap,
    settings: JsonMap,
    rejoin: bool,
    upgrade: Option<Upgrade>,
}

/// A release to hand the relay: an upload, and its signature file's text.
struct Upgrade {
    blob_id: String,
    signature: String,
}

fn client_json(value: Value<'_, P, RelayValue>) -> Result<Sent, SetError<P>> {
    let mut sent = Sent::default();
    for (key, value) in value.into_expanded_object() {
        match &key {
            Key::Property(p) if SERVER_SET.contains(p) => {
                return Err(SetError::invalid_properties()
                    .with_property(p.clone())
                    .with_description("The server sets this."));
            }
            Key::Property(P::Rejoin) => match value.as_bool() {
                Some(rejoin) => sent.rejoin = rejoin,
                None => {
                    return Err(SetError::invalid_properties()
                        .with_property(P::Rejoin)
                        .with_description("true, to start a new join."));
                }
            },
            Key::Property(P::Upgrade) => {
                let json: serde_json::Value = value.into();
                match (json["blobId"].as_str(), json["signature"].as_str()) {
                    (Some(blob_id), Some(signature)) => {
                        sent.upgrade = Some(Upgrade {
                            blob_id: blob_id.to_string(),
                            signature: signature.to_string(),
                        })
                    }
                    _ => {
                        return Err(SetError::invalid_properties()
                            .with_property(P::Upgrade)
                            .with_description(
                                "{blobId, signature}: the release binary, uploaded, \
                                 and its signature file's text.",
                            ));
                    }
                }
            }
            Key::Property(p) => {
                sent.properties
                    .insert(p.to_cow().into_owned(), value.into());
            }
            _ => match key.to_string().strip_prefix("settings/") {
                Some(name) if !name.is_empty() && !name.contains('/') => {
                    sent.settings.insert(name.to_string(), value.into());
                }
                _ => {
                    return Err(
                        SetError::invalid_properties().with_property(key.clone().into_owned())
                    );
                }
            },
        }
    }
    Ok(sent)
}

/// The settings an administrator may name: everything the relay takes but
/// for the certificate and the keys, which the server adds.
fn settable_settings() -> Vec<String> {
    match serde_json::to_value(RelaySettings::default()) {
        Ok(serde_json::Value::Object(map)) => map.into_iter().map(|(name, _)| name).collect(),
        _ => Vec::new(),
    }
}

/// Merges `changes` into a settings object: a `null` puts a setting back to
/// its default. Refuses a name the relay doesn't have.
fn merge_settings(settings: &mut JsonMap, changes: JsonMap) -> Result<(), SetError<P>> {
    let known = settable_settings();
    for (name, value) in changes {
        if !known.contains(&name) {
            return Err(SetError::invalid_properties()
                .with_property(P::Settings)
                .with_description(format!("There is no setting {name}.")));
        }
        if value.is_null() {
            settings.remove(&name);
        } else {
            settings.insert(name, value);
        }
    }
    Ok(())
}

/// The relay `json` describes, checked whole.
fn parse(mut json: JsonMap) -> Result<StoredRelay, SetError<P>> {
    // Nulls are defaults, inside settings too
    json.retain(|_, value| !value.is_null());
    if let Some(serde_json::Value::Object(settings)) = json.get_mut("settings") {
        let given = std::mem::take(settings);
        merge_settings(settings, given)?;
    }
    let relay: StoredRelay =
        serde_json::from_value(serde_json::Value::Object(json)).map_err(|err| {
            SetError::invalid_properties().with_description(format!("Not a valid relay: {err}"))
        })?;
    relay.validate().map_err(|invalid| {
        SetError::invalid_properties()
            .with_property(invalid.property.parse::<P>().unwrap_or(P::Settings))
            .with_description(invalid.reason)
    })?;
    Ok(relay)
}

fn relay_id(id: Id) -> Option<u32> {
    u32::try_from(id.id()).ok()
}

fn token_value(id: Option<u32>, token: String) -> RValue {
    let mut out = Map::with_capacity(2);
    if let Some(id) = id {
        out.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(RelayValue::Id(Id::from(id))),
        );
    }
    out.insert_unchecked(Key::Property(P::JoinToken), Value::Str(token.into()));
    Value::Object(out)
}

/// `current` with what was sent applied: each property replacing its own
/// and each `settings/<name>` its one setting, checked whole. The keys, the
/// join and the record keeping stay the server's.
fn apply(current: &StoredRelay, sent: &Sent) -> Result<StoredRelay, SetError<P>> {
    let mut json = match serde_json::to_value(current) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => JsonMap::new(),
    };
    json.extend(sent.properties.clone());
    // `****` written back keeps the stored key
    if sent
        .properties
        .get("smtpPrivateKey")
        .and_then(|v| v.as_str())
        == Some(MASKED_PASSWORD)
    {
        json.insert(
            "smtpPrivateKey".into(),
            current.smtp_private_key.clone().into(),
        );
    }
    if !sent.settings.is_empty() {
        let mut settings = match json.remove("settings") {
            Some(serde_json::Value::Object(settings)) => settings,
            _ => JsonMap::new(),
        };
        merge_settings(&mut settings, sent.settings.clone())?;
        json.insert("settings".into(), settings.into());
    }
    let next = parse(json)?;
    Ok(StoredRelay {
        id: current.id,
        recipient_key: current.recipient_key,
        join: current.join.clone(),
        created_by: current.created_by.clone(),
        created_at: current.created_at,
        updated_at: current.updated_at,
        ..next
    })
}

/// Hands a relay a signed release over this node's link (RL-29), once the
/// release checks out here. The relay checks it again, with its own target
/// and version, installs it and restarts.
async fn upgrade_relay(
    server: &Server,
    access_token: &AccessToken,
    id: Id,
    upgrade: &Upgrade,
) -> trc::Result<Result<(), SetError<P>>> {
    let refused = |text: String| {
        SetError::invalid_properties()
            .with_property(P::Upgrade)
            .with_description(text)
    };
    let Some(relay) = (match relay_id(id) {
        Some(relay_id) => relays::get(server.store(), relay_id).await?,
        None => None,
    }) else {
        return Ok(Err(SetError::not_found()));
    };
    let binary = match BlobId::from_str(&upgrade.blob_id) {
        Ok(blob_id) => server.blob_download(&blob_id, access_token).await?,
        Err(_) => None,
    };
    let Some(binary) = binary else {
        return Ok(Err(refused(format!(
            "No blob {} that you can read.",
            upgrade.blob_id
        ))));
    };
    if let Err(err) = release::verify(&binary, &upgrade.signature, release::RELEASE_KEYS) {
        return Ok(Err(refused(format!("{err}."))));
    }
    let Some(linked) = server.inner.data.relay_senders.linked(relay.id) else {
        return Ok(Err(SetError::forbidden().with_description(format!(
            "This node has no link to {} now; try again once it is linked.",
            relay.name
        ))));
    };
    match linked
        .sender
        .upgrade(binary, upgrade.signature.clone())
        .await
    {
        // The relay's own relay.upgraded event follows over the link
        Ok(_) => Ok(Ok(())),
        Err(why) => Ok(Err(refused(why))),
    }
}

/// `inbuxa:Relay/get`: every relay, oldest first.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<Relay>,
) -> trc::Result<GetResponse<Relay>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let data = server.store();
    let all = relays::all(data).await?;
    let now = now();
    let wanted: Vec<&StoredRelay> = match ids {
        None => all.iter().collect(),
        Some(ids) => {
            let mut wanted = Vec::with_capacity(ids.len());
            for id in ids {
                match relay_id(id).and_then(|id| all.iter().find(|r| r.id == id)) {
                    Some(relay) => wanted.push(relay),
                    None => response.push_not_found(id),
                }
            }
            wanted
        }
    };
    for relay in wanted {
        let links = if properties.contains(&P::Links) || properties.contains(&P::OlderThanServer) {
            relays::link::statuses(data, relay.id).await?
        } else {
            Vec::new()
        };
        let order = if properties.contains(&P::CertificateError) {
            relays::certificate::last_order(data, relay.id).await?
        } else {
            None
        };
        response
            .list
            .push(to_value(relay, &links, order.as_ref(), &properties, now));
    }
    Ok(response)
}

/// `inbuxa:Relay/set`: add relays (each with a join token), change them,
/// start a new join, or remove them.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, Relay>,
) -> trc::Result<SetResponse<Relay>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    for (client_id, value) in request.unwrap_create() {
        let relay = match client_json(value).and_then(|sent| {
            if sent.rejoin {
                return Err(SetError::invalid_properties()
                    .with_property(P::Rejoin)
                    .with_description("A new relay gets its join token anyway."));
            }
            if sent.upgrade.is_some() {
                return Err(SetError::invalid_properties()
                    .with_property(P::Upgrade)
                    .with_description("A relay is upgraded once it has joined."));
            }
            if sent
                .properties
                .get("smtpPrivateKey")
                .and_then(|v| v.as_str())
                == Some(MASKED_PASSWORD)
            {
                return Err(SetError::invalid_properties()
                    .with_property(P::SmtpPrivateKey)
                    .with_description("There is no stored key for **** to keep."));
            }
            let mut json = sent.properties;
            if !sent.settings.is_empty() {
                let mut settings = match json.remove("settings") {
                    Some(serde_json::Value::Object(settings)) => settings,
                    _ => JsonMap::new(),
                };
                merge_settings(&mut settings, sent.settings)?;
                json.insert("settings".into(), settings.into());
            }
            parse(json)
        }) {
            Ok(relay) => relay,
            Err(error) => {
                response.not_created.append(client_id, error);
                continue;
            }
        };
        let at = now();
        let relay = StoredRelay {
            created_by: actor.name.clone(),
            created_at: at,
            updated_at: at,
            ..relay
        };
        let (stored, token) = relays::create(data, &relay, at).await?;
        response
            .created
            .insert(client_id, token_value(Some(stored.id), token));
    }

    for (id, value) in request.unwrap_update().into_valid() {
        let sent = match client_json(value) {
            Ok(sent) => sent,
            Err(error) => {
                response.not_updated.append(id, error);
                continue;
            }
        };
        if let Some(upgrade) = &sent.upgrade {
            let outcome = if sent.rejoin || !sent.properties.is_empty() || !sent.settings.is_empty()
            {
                Err(SetError::invalid_properties()
                    .with_property(P::Upgrade)
                    .with_description("Send an upgrade on its own."))
            } else {
                upgrade_relay(server, access_token, id, upgrade).await?
            };
            match outcome {
                Ok(()) => response.updated.append(id, None),
                Err(error) => response.not_updated.append(id, error),
            }
            continue;
        }
        let mut outcome = None;
        // A node may record the join while this runs: start over from the
        // relay as it is then, a few times
        for _ in 0..UPDATE_ATTEMPTS {
            let Some((current, version)) = (match relay_id(id) {
                Some(relay_id) => relays::get_versioned(data, relay_id).await?,
                None => None,
            }) else {
                outcome = Some(Err(SetError::not_found()));
                break;
            };
            let mut next = match apply(&current, &sent) {
                Ok(next) => next,
                Err(error) => {
                    outcome = Some(Err(error));
                    break;
                }
            };
            let at = now();
            let token = if sent.rejoin {
                let keys = relays::keys_or_new(data, at).await?;
                Some(next.start_join(&keys, at))
            } else {
                None
            };
            if next != current {
                next.updated_at = at;
                if !relays::replace(data, &next, version).await? {
                    continue;
                }
            }
            outcome = Some(Ok(token));
            break;
        }
        match outcome {
            Some(Ok(token)) => response
                .updated
                .append(id, token.map(|token| token_value(None, token))),
            Some(Err(error)) => response.not_updated.append(id, error),
            None => response.not_updated.append(
                id,
                SetError::forbidden().with_description("The relay kept changing; try again."),
            ),
        }
    }

    for id in request.unwrap_destroy().into_valid() {
        let Some(current) = (match relay_id(id) {
            Some(relay_id) => relays::get(data, relay_id).await?,
            None => None,
        }) else {
            response.not_destroyed.append(id, SetError::not_found());
            continue;
        };
        relays::delete(data, current.id).await?;
        response.destroyed.push(id);
    }

    if !response.created.is_empty()
        || !response.updated.is_empty()
        || !response.destroyed.is_empty()
    {
        relays::changed();
    }
    Ok(response)
}
