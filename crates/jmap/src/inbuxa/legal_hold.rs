/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:LegalHold` (audit-hold-lock spec, LH-1 to LH-14): placing,
//! widening and releasing holds. Only server-level administrators reach
//! this: the tenant ceiling strips the permissions from everyone in a
//! tenant (LH-13). What a hold keeps is the undelete hooks' job.

use common::{Server, auth::AccessToken, hold::HoldSummary};
use inbuxa_features::hold::{self, Hold, Refusal, Release, Scope};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_legal_hold::{
        LegalHold, LegalHoldProperty as P, LegalHoldSetArguments, LegalHoldValue,
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use std::str::FromStr;
use store::write::now;
use types::id::Id;

type LValue = Value<'static, P, LegalHoldValue>;

const ALL: &[P] = &[
    P::Id,
    P::Name,
    P::Reference,
    P::Description,
    P::Scope,
    P::From,
    P::To,
    P::PlacedAt,
    P::PlacedBy,
    P::Released,
    P::ReleasedAt,
    P::ReleasedBy,
    P::ReleaseReason,
];

/// The longest a name, reference or description may be.
const MAX_TEXT: usize = 500;

fn date(seconds: u64) -> LValue {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

fn text(value: &Option<String>) -> LValue {
    value
        .as_ref()
        .map_or(Value::Null, |v| Value::Str(v.clone().into()))
}

fn ids(list: &[u32]) -> LValue {
    Value::Array(
        list.iter()
            .map(|id| Value::Str(Id::from(*id).to_string().into()))
            .collect(),
    )
}

fn to_value(hold: &Hold, properties: &[P], summary: Option<&HoldSummary>) -> LValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(LegalHoldValue::Id(Id::from(hold.id))),
            P::Name => Value::Str(hold.name.clone().into()),
            P::Reference => text(&hold.reference),
            P::Description => text(&hold.description),
            P::Scope => {
                let mut scope = Map::with_capacity(5);
                scope.insert_unchecked(Key::Borrowed("server"), Value::Bool(hold.scope.server));
                scope.insert_unchecked(Key::Borrowed("accounts"), ids(&hold.scope.accounts));
                scope.insert_unchecked(Key::Borrowed("groups"), ids(&hold.scope.groups));
                scope.insert_unchecked(Key::Borrowed("domains"), ids(&hold.scope.domains));
                scope.insert_unchecked(Key::Borrowed("tenants"), ids(&hold.scope.tenants));
                Value::Object(scope)
            }
            P::From => hold.from.map_or(Value::Null, date),
            P::To => hold.to.map_or(Value::Null, date),
            P::Reason => Value::Null,
            P::PlacedAt => date(hold.placed_at),
            P::PlacedBy => Value::Str(hold.placed_by.clone().into()),
            P::Released => Value::Bool(!hold.is_active()),
            P::ReleasedAt => hold.released.as_ref().map_or(Value::Null, |r| date(r.at)),
            P::ReleasedBy => hold
                .released
                .as_ref()
                .map_or(Value::Null, |r| Value::Str(r.by.clone().into())),
            P::ReleaseReason => hold
                .released
                .as_ref()
                .map_or(Value::Null, |r| Value::Str(r.reason.clone().into())),
            P::AccountsCovered => Value::Number(summary.map_or(0, |s| s.accounts).into()),
            P::ItemsHeld => Value::Number(summary.map_or(0, |s| s.items).into()),
            P::SizeHeld => Value::Number(summary.map_or(0, |s| s.size).into()),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:LegalHold/get`: every hold, released ones included (LH-1).
pub async fn get(
    server: &Server,
    mut request: GetRequest<LegalHold>,
) -> trc::Result<GetResponse<LegalHold>> {
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let data = server.store();
    // LH-9: only when asked for, since it walks the archive
    let summaries = if properties
        .iter()
        .any(|p| matches!(p, P::AccountsCovered | P::ItemsHeld | P::SizeHeld))
    {
        server.hold_summaries().await?
    } else {
        Default::default()
    };
    // LH-14: the holds on one account, whether it's live or deleted and kept
    if let Some(account) = request.arguments.covering_account.take() {
        let account_id = account.document_id();
        let covering = match server.member_of(account_id).await {
            Some(member) => hold::covering(data, &member).await?,
            None => match inbuxa_features::undelete::data::kept_account(data, account_id).await? {
                Some(kept) => {
                    hold::covering(data, &common::hold::kept_member(account_id, &kept)).await?
                }
                None => Vec::new(),
            },
        };
        for current in covering {
            response
                .list
                .push(to_value(&current, &properties, summaries.get(&current.id)));
        }
        return Ok(response);
    }
    match ids {
        None => {
            for current in hold::all(data).await? {
                response
                    .list
                    .push(to_value(&current, &properties, summaries.get(&current.id)));
            }
        }
        Some(ids) => {
            for id in ids {
                match u32::try_from(id.id())
                    .ok()
                    .map(|id| hold::get(data, id))
                {
                    Some(found) => match found.await? {
                        Some(current) => response.list.push(to_value(
                            &current,
                            &properties,
                            summaries.get(&current.id),
                        )),
                        None => response.push_not_found(id),
                    },
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

fn reason_of(reason: Option<&str>) -> Option<String> {
    reason
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(|r| r.chars().take(MAX_TEXT).collect())
}

fn reason_required() -> SetError<P> {
    SetError::invalid_properties()
        .with_property(P::Reason)
        .with_description("Say why: a reason is required and is kept in the audit log.")
}

fn refused(refusal: Refusal) -> SetError<P> {
    let property = match refusal {
        Refusal::Released => P::Released,
        Refusal::Narrowed | Refusal::Backwards => P::From,
        Refusal::ScopeShrunk | Refusal::EmptyScope => P::Scope,
    };
    SetError::invalid_properties()
        .with_property(property)
        .with_description(refusal.describe())
}

fn invalid(property: P, why: &str) -> SetError<P> {
    SetError::invalid_properties()
        .with_property(property)
        .with_description(why.to_string())
}

/// A text property: a string, trimmed and capped, or null for none.
fn parse_text(
    property: P,
    value: &Value<'_, P, LegalHoldValue>,
    required: bool,
) -> Result<Option<String>, SetError<P>> {
    match value {
        Value::Str(s) => {
            let s = s.trim();
            if s.is_empty() {
                if required {
                    Err(invalid(property, "This can't be empty."))
                } else {
                    Ok(None)
                }
            } else {
                Ok(Some(s.chars().take(MAX_TEXT).collect()))
            }
        }
        Value::Null if !required => Ok(None),
        _ => Err(invalid(property, "Expected text.")),
    }
}

fn parse_date(property: P, value: &Value<'_, P, LegalHoldValue>) -> Result<Option<u64>, SetError<P>> {
    match value {
        Value::Null => Ok(None),
        Value::Str(s) => UTCDate::from_str(s)
            .ok()
            .map(|d| Some(d.timestamp().max(0) as u64))
            .ok_or_else(|| invalid(property, "Expected a UTC date, or null.")),
        _ => Err(invalid(property, "Expected a UTC date, or null.")),
    }
}

/// Reads a scope and checks that every account, group, domain and tenant
/// it names exists and is the right kind (LH-1).
async fn parse_scope(server: &Server, value: &Value<'_, P, LegalHoldValue>) -> Result<Scope, SetError<P>> {
    let Value::Object(map) = value else {
        return Err(invalid(P::Scope, "Expected an object."));
    };
    let mut scope = Scope::default();
    for (key, value) in map.iter() {
        let name: String = key.to_string().to_string();
        if name == "server" {
            match value {
                Value::Bool(b) => scope.server = *b,
                _ => return Err(invalid(P::Scope, "`server` must be true or false.")),
            }
            continue;
        }
        let Value::Array(items) = value else {
            return Err(invalid(P::Scope, &format!("`{name}` must be a list of ids.")));
        };
        let mut list = Vec::with_capacity(items.len());
        for item in items {
            let id = match item {
                Value::Str(s) => Id::from_str(s).ok(),
                Value::Element(LegalHoldValue::Id(id)) => Some(*id),
                _ => None,
            }
            .and_then(|id| u32::try_from(id.id()).ok())
            .ok_or_else(|| invalid(P::Scope, &format!("`{name}` must be a list of ids.")))?;
            list.push(id);
        }
        for id in &list {
            let exists = match name.as_str() {
                "accounts" => server.account(*id).await.is_ok_and(|a| a.is_user_account()),
                "groups" => server.account(*id).await.is_ok_and(|a| !a.is_user_account()),
                "domains" => server.domain_by_id(*id).await.ok().flatten().is_some(),
                "tenants" => server.tenant(*id).await.is_ok(),
                _ => return Err(invalid(P::Scope, &format!("Unknown scope entry `{name}`."))),
            };
            if !exists {
                return Err(invalid(
                    P::Scope,
                    &format!("No such {} as {}.", name.trim_end_matches('s'), Id::from(*id)),
                ));
            }
        }
        match name.as_str() {
            "accounts" => scope.accounts = list,
            "groups" => scope.groups = list,
            "domains" => scope.domains = list,
            _ => scope.tenants = list,
        }
    }
    Ok(scope)
}

/// `inbuxa:LegalHold/set`: create places a hold; update renames it, widens
/// its range or scope, or releases it; destroy is refused (LH-13). The
/// request layer records each, with its reason.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, LegalHold>,
) -> trc::Result<SetResponse<LegalHold>> {
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let arguments: LegalHoldSetArguments = std::mem::take(&mut request.arguments);
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    'create: for (client_id, value) in request.unwrap_create() {
        let mut new = Hold {
            id: 0,
            name: String::new(),
            reference: None,
            description: None,
            scope: Scope::default(),
            from: None,
            to: None,
            placed_at: now(),
            placed_by: actor.name.clone(),
            placed_by_id: actor.account_id,
            released: None,
        };
        let mut reason = reason_of(arguments.reason.as_deref());
        for (key, value) in value.into_expanded_object() {
            let parsed = match &key {
                Key::Property(P::Name) => parse_text(P::Name, &value, true).map(|v| {
                    new.name = v.unwrap_or_default();
                }),
                Key::Property(P::Reference) => {
                    parse_text(P::Reference, &value, false).map(|v| new.reference = v)
                }
                Key::Property(P::Description) => {
                    parse_text(P::Description, &value, false).map(|v| new.description = v)
                }
                Key::Property(P::Scope) => parse_scope(server, &value).await.map(|v| new.scope = v),
                Key::Property(P::From) => parse_date(P::From, &value).map(|v| new.from = v),
                Key::Property(P::To) => parse_date(P::To, &value).map(|v| new.to = v),
                Key::Property(P::Reason) => {
                    if let Value::Str(r) = &value {
                        reason = reason_of(Some(r)).or(reason);
                    }
                    Ok(())
                }
                _ => Err(SetError::invalid_properties().with_property(key.clone().into_owned())),
            };
            if let Err(error) = parsed {
                response.not_created.append(client_id, error);
                continue 'create;
            }
        }
        if new.name.is_empty() {
            response
                .not_created
                .append(client_id, invalid(P::Name, "A hold needs a case name."));
            continue;
        }
        if reason.is_none() {
            response.not_created.append(client_id, reason_required());
            continue;
        }
        if let Err(refusal) = new.check_new() {
            response.not_created.append(client_id, refused(refusal));
            continue;
        }
        let id = hold::create(data, &new).await?;
        let mut out = Map::with_capacity(1);
        out.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(LegalHoldValue::Id(Id::from(id))),
        );
        response.created.insert(client_id, Value::Object(out));
    }

    'update: for (id, value) in request.unwrap_update().into_valid() {
        let Some(current) = (match u32::try_from(id.id()) {
            Ok(hold_id) => hold::get(data, hold_id).await?,
            Err(_) => None,
        }) else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        let Some(reason) = reason_of(arguments.reason.as_deref()) else {
            response.not_updated.append(id, reason_required());
            continue;
        };
        let mut next = current.clone();
        let mut release = false;
        for (key, value) in value.into_expanded_object() {
            let parsed = match &key {
                Key::Property(P::Name) => {
                    parse_text(P::Name, &value, true).map(|v| next.name = v.unwrap_or_default())
                }
                Key::Property(P::Reference) => {
                    parse_text(P::Reference, &value, false).map(|v| next.reference = v)
                }
                Key::Property(P::Description) => {
                    parse_text(P::Description, &value, false).map(|v| next.description = v)
                }
                Key::Property(P::Scope) => parse_scope(server, &value).await.map(|v| next.scope = v),
                Key::Property(P::From) => parse_date(P::From, &value).map(|v| next.from = v),
                Key::Property(P::To) => parse_date(P::To, &value).map(|v| next.to = v),
                Key::Property(P::Released) => match value {
                    Value::Bool(true) => {
                        release = true;
                        Ok(())
                    }
                    Value::Bool(false) if current.is_active() => Ok(()),
                    _ => Err(invalid(
                        P::Released,
                        "A released hold can't be put back; place a new one instead.",
                    )),
                },
                _ => Err(SetError::invalid_properties().with_property(key.clone().into_owned())),
            };
            if let Err(error) = parsed {
                response.not_updated.append(id, error);
                continue 'update;
            }
        }
        if let Err(refusal) = current.check_update(&mut next) {
            response.not_updated.append(id, refused(refusal));
            continue;
        }
        if release {
            next.released = Some(Release {
                at: now(),
                by: actor.name.clone(),
                by_id: actor.account_id,
                reason,
            });
        }
        if next != current {
            hold::update(data, &next).await?;
        }
        response.updated.append(id, None);
    }

    // LH-6, LH-10, LH-11: the archive follows what's now held
    if !response.created.is_empty() || !response.updated.is_empty() {
        server.settle_archive().await?;
    }

    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(
            id,
            SetError::forbidden()
                .with_description("A hold is never deleted. Release it, and it stays listed."),
        );
    }

    Ok(response)
}
