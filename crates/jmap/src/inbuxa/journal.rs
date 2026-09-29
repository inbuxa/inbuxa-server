/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Journal` (journaling spec, JR-9, JR-12, JR-18): journals, seen
//! with `sysJournalGet` and changed with `sysJournalUpdate`, which the
//! request layer checks. Journals are the server's: nobody in a tenant
//! reaches them. The request layer records every change in the audit log.
//! Changing or removing a journal never touches what it has taken.

use common::{Server, auth::AccessToken};
use inbuxa_features::journal::{self, Journal as Stored};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_journal::{Journal, JournalProperty as P, JournalValue},
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Property, Value};
use std::borrow::Cow;
use store::write::now;
use types::id::Id;

type JValue = Value<'static, P, JournalValue>;

const ALL: &[P] = &[
    P::Id,
    P::Name,
    P::Description,
    P::Enabled,
    P::Direction,
    P::Scope,
    P::RetentionDays,
    P::CreatedBy,
    P::CreatedAt,
    P::UpdatedAt,
];

/// Properties the server sets; a client that sends them is refused.
const SERVER_SET: &[P] = &[P::Id, P::CreatedBy, P::CreatedAt, P::UpdatedAt];

fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Journals are the server's."))
    } else {
        Ok(())
    }
}

fn json_to_value(json: serde_json::Value) -> JValue {
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

fn date(seconds: u64) -> JValue {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

fn to_value(journal: &Stored, properties: &[P]) -> JValue {
    let json = serde_json::to_value(journal).unwrap_or_default();
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(JournalValue::Id(Id::from(journal.id))),
            P::CreatedAt => date(journal.created_at),
            P::UpdatedAt => date(journal.updated_at),
            other => json
                .get(other.to_cow().as_ref())
                .cloned()
                .map_or(Value::Null, json_to_value),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// A journal as sent: its JSON object, top-level keys only those a client
/// may set.
fn client_json(
    value: Value<'_, P, JournalValue>,
) -> Result<serde_json::Map<String, serde_json::Value>, SetError<P>> {
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
    Ok(map)
}

fn parse(json: serde_json::Map<String, serde_json::Value>) -> Result<Stored, SetError<P>> {
    let journal: Stored =
        serde_json::from_value(serde_json::Value::Object(json)).map_err(|err| {
            SetError::invalid_properties().with_description(format!("Not a valid journal: {err}"))
        })?;
    journal.validate().map_err(|invalid| {
        let property = invalid.property.parse::<P>().unwrap_or(P::Name);
        SetError::invalid_properties()
            .with_property(property)
            .with_description(invalid.reason)
    })?;
    Ok(journal)
}

fn journal_id(id: Id) -> Option<u32> {
    u32::try_from(id.id()).ok()
}

/// `inbuxa:Journal/get`: every journal, oldest first.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<Journal>,
) -> trc::Result<GetResponse<Journal>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let journals = journal::all(server.store()).await?;
    match ids {
        None => {
            response.list = journals
                .iter()
                .map(|journal| to_value(journal, &properties))
                .collect()
        }
        Some(ids) => {
            for id in ids {
                match journal_id(id).and_then(|id| journals.iter().find(|j| j.id == id)) {
                    Some(journal) => response.list.push(to_value(journal, &properties)),
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

/// `inbuxa:Journal/set`: create, change or remove journals.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, Journal>,
) -> trc::Result<SetResponse<Journal>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    for (client_id, value) in request.unwrap_create() {
        let stored = match client_json(value).and_then(parse) {
            Ok(stored) => stored,
            Err(error) => {
                response.not_created.append(client_id, error);
                continue;
            }
        };
        let at = now();
        let stored = Stored {
            created_by: actor.name.clone(),
            created_at: at,
            updated_at: at,
            ..stored
        };
        let id = journal::create(data, &stored).await?;
        let mut out = Map::with_capacity(1);
        out.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(JournalValue::Id(Id::from(id))),
        );
        response.created.insert(client_id, Value::Object(out));
    }

    for (id, value) in request.unwrap_update().into_valid() {
        let Some(current) = (match journal_id(id) {
            Some(journal_id) => journal::get(data, journal_id).await?,
            None => None,
        }) else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        // The stored journal, with each property sent replacing its own
        let mut json = match serde_json::to_value(&current) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        };
        let changes = match client_json(value) {
            Ok(changes) => changes,
            Err(error) => {
                response.not_updated.append(id, error);
                continue;
            }
        };
        json.extend(changes);
        let next = match parse(json) {
            Ok(next) => next,
            Err(error) => {
                response.not_updated.append(id, error);
                continue;
            }
        };
        let next = Stored {
            id: current.id,
            created_by: current.created_by.clone(),
            created_at: current.created_at,
            updated_at: now(),
            ..next
        };
        if next != current {
            journal::update(data, &next).await?;
        }
        response.updated.append(id, None);
    }

    for id in request.unwrap_destroy().into_valid() {
        let Some(current) = (match journal_id(id) {
            Some(journal_id) => journal::get(data, journal_id).await?,
            None => None,
        }) else {
            response.not_destroyed.append(id, SetError::not_found());
            continue;
        };
        journal::delete(data, current.id).await?;
        response.destroyed.push(id);
    }

    Ok(response)
}
