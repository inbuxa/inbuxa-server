/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:MailRule` (dlp-and-mail-flow-rules spec, §2.2, §2.8): mail flow
//! rules and DLP rules. One object, two kinds, each with its own
//! permissions: `sysMailRuleGet`/`Update` for transport rules,
//! `sysDlpPolicyGet`/`Update` for DLP rules. Rules are the server's: nobody
//! in a tenant reaches them (settled answer 3). The request layer records
//! every change in the audit log.

use common::{Server, auth::AccessToken};
use inbuxa_features::mailflow::rules::{self, Kind, Rule};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_mail_rule::{MailRule, MailRuleProperty as P, MailRuleValue},
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Property, Value};
use registry::schema::enums::Permission;
use std::borrow::Cow;
use store::write::now;
use types::id::Id;

type RValue = Value<'static, P, MailRuleValue>;

const ALL: &[P] = &[
    P::Id,
    P::Name,
    P::Description,
    P::Kind,
    P::Enabled,
    P::Priority,
    P::Direction,
    P::Conditions,
    P::Exceptions,
    P::Actions,
    P::StopProcessing,
    P::CreatedBy,
    P::CreatedAt,
    P::UpdatedAt,
];

/// Properties the server sets; a client that sends them is refused.
const SERVER_SET: &[P] = &[P::Id, P::CreatedBy, P::CreatedAt, P::UpdatedAt];

fn can_see(access_token: &AccessToken, kind: Kind) -> bool {
    access_token.has_permission(match kind {
        Kind::Dlp => Permission::SysDlpPolicyGet,
        Kind::Transport => Permission::SysMailRuleGet,
    })
}

fn can_change(access_token: &AccessToken, kind: Kind) -> bool {
    access_token.has_permission(match kind {
        Kind::Dlp => Permission::SysDlpPolicyUpdate,
        Kind::Transport => Permission::SysMailRuleUpdate,
    })
}

fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Mail rules are the server's."))
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

fn date(seconds: u64) -> RValue {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

fn to_value(rule: &Rule, properties: &[P]) -> RValue {
    let json = serde_json::to_value(rule).unwrap_or_default();
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(MailRuleValue::Id(Id::from(rule.id))),
            P::CreatedAt => date(rule.created_at),
            P::UpdatedAt => date(rule.updated_at),
            other => json
                .get(other.to_cow().as_ref())
                .cloned()
                .map_or(Value::Null, json_to_value),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// A rule as sent: its JSON object, top-level keys only those a client may
/// set.
fn client_json(value: Value<'_, P, MailRuleValue>) -> Result<serde_json::Map<String, serde_json::Value>, SetError<P>> {
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

fn parse(json: serde_json::Map<String, serde_json::Value>) -> Result<Rule, SetError<P>> {
    let rule: Rule = serde_json::from_value(serde_json::Value::Object(json)).map_err(|err| {
        SetError::invalid_properties().with_description(format!("Not a valid rule: {err}"))
    })?;
    rule.validate().map_err(|invalid| {
        let property = invalid.property.parse::<P>().unwrap_or(P::Name);
        SetError::invalid_properties()
            .with_property(property)
            .with_description(invalid.reason)
    })?;
    Ok(rule)
}

fn forbidden(kind: Kind) -> SetError<P> {
    SetError::forbidden().with_description(match kind {
        Kind::Dlp => "Changing DLP rules needs the permission to change DLP rules.",
        Kind::Transport => "Changing mail flow rules needs the permission to change them.",
    })
}

fn rule_id(id: Id) -> Option<u32> {
    u32::try_from(id.id()).ok()
}

/// `inbuxa:MailRule/get`: the rules the caller may see, in the order they
/// run.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<MailRule>,
) -> trc::Result<GetResponse<MailRule>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let visible: Vec<Rule> = rules::all(server.store())
        .await?
        .into_iter()
        .filter(|rule| can_see(access_token, rule.kind))
        .collect();
    match ids {
        None => {
            response.list = visible
                .iter()
                .map(|rule| to_value(rule, &properties))
                .collect()
        }
        Some(ids) => {
            for id in ids {
                match rule_id(id).and_then(|id| visible.iter().find(|r| r.id == id)) {
                    Some(rule) => response.list.push(to_value(rule, &properties)),
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

/// `inbuxa:MailRule/set`: create, change or delete rules, each checked
/// against the permissions for its kind (and, on a change of kind, both).
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, MailRule>,
) -> trc::Result<SetResponse<MailRule>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    for (client_id, value) in request.unwrap_create() {
        let rule = match client_json(value).and_then(parse) {
            Ok(rule) => rule,
            Err(error) => {
                response.not_created.append(client_id, error);
                continue;
            }
        };
        if !can_change(access_token, rule.kind) {
            response.not_created.append(client_id, forbidden(rule.kind));
            continue;
        }
        let at = now();
        let rule = Rule {
            created_by: actor.name.clone(),
            created_at: at,
            updated_at: at,
            ..rule
        };
        let id = rules::create(data, &rule).await?;
        let mut out = Map::with_capacity(1);
        out.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(MailRuleValue::Id(Id::from(id))),
        );
        response.created.insert(client_id, Value::Object(out));
    }

    for (id, value) in request.unwrap_update().into_valid() {
        let Some(current) = (match rule_id(id) {
            Some(rule_id) => rules::get(data, rule_id).await?,
            None => None,
        }) else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        if !can_see(access_token, current.kind) {
            response.not_updated.append(id, SetError::not_found());
            continue;
        }
        if !can_change(access_token, current.kind) {
            response.not_updated.append(id, forbidden(current.kind));
            continue;
        }
        // The stored rule, with each property sent replacing its own
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
        if next.kind != current.kind && !can_change(access_token, next.kind) {
            response.not_updated.append(id, forbidden(next.kind));
            continue;
        }
        let next = Rule {
            id: current.id,
            created_by: current.created_by.clone(),
            created_at: current.created_at,
            updated_at: now(),
            ..next
        };
        if next != current {
            rules::update(data, &next).await?;
        }
        response.updated.append(id, None);
    }

    for id in request.unwrap_destroy().into_valid() {
        let Some(current) = (match rule_id(id) {
            Some(rule_id) => rules::get(data, rule_id).await?,
            None => None,
        }) else {
            response.not_destroyed.append(id, SetError::not_found());
            continue;
        };
        if !can_see(access_token, current.kind) {
            response.not_destroyed.append(id, SetError::not_found());
            continue;
        }
        if !can_change(access_token, current.kind) {
            response.not_destroyed.append(id, forbidden(current.kind));
            continue;
        }
        rules::delete(data, current.id).await?;
        response.destroyed.push(id);
    }

    Ok(response)
}
