/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:SecurityAcceptance` (security to-do list spec, SS-23 to SS-26):
//! the security to-do items an administrator accepted, with why, so every
//! administrator sees the same accepted risks. Created and destroyed, never
//! updated (the request gate refuses an update). Seeing them needs what the
//! security page needs; changing them needs `sysSecurityAccept`. Every
//! check is server-wide, so nobody in a tenant reaches them. The request
//! layer records every change in the audit log (SS-26).

use common::{Server, auth::AccessToken};
use inbuxa_features::security::acceptance::{self, Acceptance, Created};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_security_acceptance::{
        SecurityAcceptance, SecurityAcceptanceProperty as P, SecurityAcceptanceValue,
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Property, Value};
use std::borrow::Cow;
use store::write::now;
use types::id::Id;

type RValue = Value<'static, P, SecurityAcceptanceValue>;

const ALL: &[P] = &[
    P::Id,
    P::Check,
    P::Subject,
    P::AcceptedValue,
    P::Note,
    P::AcceptedBy,
    P::AcceptedAt,
];

/// Properties the server sets; a client that sends them is refused.
const SERVER_SET: &[P] = &[P::Id, P::AcceptedBy, P::AcceptedAt];

fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Security checks are the server's."))
    } else {
        Ok(())
    }
}

fn json_to_value(json: serde_json::Value) -> RValue {
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

fn to_value(acceptance: &Acceptance, properties: &[P]) -> RValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(SecurityAcceptanceValue::Id(Id::from(acceptance.id))),
            P::Check => Value::Str(acceptance.check.clone().into()),
            P::Subject => Value::Str(acceptance.subject.clone().into()),
            P::AcceptedValue => json_to_value(acceptance.accepted_value.clone()),
            P::Note => Value::Str(acceptance.note.clone().into()),
            P::AcceptedBy => Value::Str(acceptance.accepted_by.clone().into()),
            P::AcceptedAt => Value::Str(
                UTCDate::from_timestamp(acceptance.accepted_at as i64)
                    .to_string()
                    .into(),
            ),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// An acceptance as sent, checked whole.
fn parse(value: Value<'_, P, SecurityAcceptanceValue>) -> Result<Acceptance, SetError<P>> {
    let mut map = serde_json::Map::new();
    for (key, value) in value.into_expanded_object() {
        match &key {
            Key::Property(p) if SERVER_SET.contains(p) => {
                return Err(SetError::invalid_properties()
                    .with_property(p.clone())
                    .with_description("The server sets this."));
            }
            Key::Property(p) => {
                map.insert(p.to_cow().into_owned(), value.into());
            }
            _ => {
                return Err(SetError::invalid_properties().with_property(key.clone().into_owned()));
            }
        }
    }
    let acceptance: Acceptance =
        serde_json::from_value(serde_json::Value::Object(map)).map_err(|err| {
            SetError::invalid_properties()
                .with_description(format!("Not a valid acceptance: {err}"))
        })?;
    acceptance.validate().map_err(|invalid| {
        let property = invalid.property.parse::<P>().unwrap_or(P::Note);
        SetError::invalid_properties()
            .with_property(property)
            .with_description(invalid.reason)
    })?;
    Ok(Acceptance {
        note: acceptance.note.trim().to_string(),
        ..acceptance
    })
}

fn acceptance_id(id: Id) -> Option<u32> {
    u32::try_from(id.id()).ok()
}

/// `inbuxa:SecurityAcceptance/get`: every acceptance, oldest first.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<SecurityAcceptance>,
) -> trc::Result<GetResponse<SecurityAcceptance>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let all = acceptance::all(server.store()).await?;
    match ids {
        None => {
            response.list = all.iter().map(|a| to_value(a, &properties)).collect();
        }
        Some(ids) => {
            for id in ids {
                match acceptance_id(id).and_then(|id| all.iter().find(|a| a.id == id)) {
                    Some(a) => response.list.push(to_value(a, &properties)),
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

/// `inbuxa:SecurityAcceptance/set`: accept an item, or remove an acceptance.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, SecurityAcceptance>,
) -> trc::Result<SetResponse<SecurityAcceptance>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    for (client_id, value) in request.unwrap_create() {
        let parsed = match parse(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                response.not_created.append(client_id, error);
                continue;
            }
        };
        let accepted = Acceptance {
            accepted_by: actor.name.clone(),
            accepted_at: now(),
            ..parsed
        };
        match acceptance::create(data, &accepted).await? {
            Created::Id(id) => {
                let mut out = Map::with_capacity(3);
                out.insert_unchecked(
                    Key::Property(P::Id),
                    Value::Element(SecurityAcceptanceValue::Id(Id::from(id))),
                );
                out.insert_unchecked(
                    Key::Property(P::AcceptedBy),
                    Value::Str(accepted.accepted_by.clone().into()),
                );
                out.insert_unchecked(
                    Key::Property(P::AcceptedAt),
                    Value::Str(
                        UTCDate::from_timestamp(accepted.accepted_at as i64)
                            .to_string()
                            .into(),
                    ),
                );
                response.created.insert(client_id, Value::Object(out));
            }
            Created::Full => {
                response.not_created.append(
                    client_id,
                    SetError::over_quota().with_description(format!(
                        "There are already {} acceptances. Remove some first.",
                        acceptance::MAX_ACCEPTANCES
                    )),
                );
            }
        }
    }

    for (id, _) in request.unwrap_update().into_valid() {
        response.not_updated.append(
            id,
            SetError::forbidden().with_description("An acceptance is replaced, not edited."),
        );
    }

    for id in request.unwrap_destroy().into_valid() {
        let found = match acceptance_id(id) {
            Some(acceptance_id) => acceptance::get(data, acceptance_id).await?,
            None => None,
        };
        match found {
            Some(found) => {
                acceptance::delete(data, found.id).await?;
                response.destroyed.push(id);
            }
            None => response.not_destroyed.append(id, SetError::not_found()),
        }
    }

    Ok(response)
}
