/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Fastmail's Masked Email API: `MaskedEmail/get` and `MaskedEmail/set`
//! (masked-email spec, "Fastmail's"). Masks created here start `pending`
//! unless the create sets `state` (ME-7a); `createdBy` is set by the server
//! (ME-16).

use crate::inbuxa::masked_email::{assert_can_manage, prepare_create, state};
use common::{Server, auth::AccessToken};
use inbuxa_features::masked_email::{
    State,
    ops::{self, Mask},
};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::fastmail_masked_email::{
        FastmailMaskedEmail, FastmailMaskedEmailProperty as P, FastmailMaskedEmailValue,
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use registry::{
    schema::{
        prelude::{Object, ObjectType},
        structs::MaskedEmail,
    },
    types::id::ObjectId,
};
use std::borrow::Cow;
use store::registry::write::{RegistryWrite, RegistryWriteResult};

type FValue = Value<'static, P, FastmailMaskedEmailValue>;

const ALL: &[P] = &[
    P::Id,
    P::Email,
    P::State,
    P::ForDomain,
    P::Description,
    P::LastMessageAt,
    P::CreatedAt,
    P::CreatedBy,
    P::Url,
];

fn text(value: &Option<String>) -> FValue {
    match value {
        Some(value) => Value::Str(Cow::Owned(value.clone())),
        None => Value::Null,
    }
}

fn date(timestamp: i64) -> FValue {
    Value::Element(FastmailMaskedEmailValue::Date(UTCDate::from_timestamp(
        timestamp,
    )))
}

/// A mask in Fastmail's terms. An expired mask reads `deleted`, since it
/// refuses mail (ME-6a).
fn to_value(mask: &Mask, properties: &[P]) -> FValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(FastmailMaskedEmailValue::Id(mask.id)),
            P::Email => Value::Str(Cow::Owned(mask.object.email.clone())),
            P::State => Value::Str(Cow::Borrowed(if mask.expired {
                State::Deleted.as_fastmail()
            } else {
                mask.state.as_fastmail()
            })),
            P::ForDomain => text(&mask.object.for_domain),
            P::Description => Value::Str(Cow::Owned(
                mask.object.description.clone().unwrap_or_default(),
            )),
            P::LastMessageAt => match mask.last_message_at {
                Some(at) => date(at as i64),
                None => Value::Null,
            },
            P::CreatedAt => date(mask.object.created_at.timestamp()),
            P::CreatedBy => text(&mask.object.created_by),
            P::Url => text(&mask.object.url),
            P::EmailPrefix => continue,
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `MaskedEmail/get`, in the user's own JMAP account.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<FastmailMaskedEmail>,
) -> trc::Result<GetResponse<FastmailMaskedEmail>> {
    let account_id = request.account_id.document_id();
    assert_can_manage(server, access_token, account_id).await?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: state(server, account_id).await?.into(),
        list: Vec::new(),
        not_found,
    };

    let data = &server.core.storage.data;
    match ids {
        None => {
            for mask in ops::of_account(data, server.registry(), account_id).await? {
                response.list.push(to_value(&mask, &properties));
            }
        }
        Some(ids) => {
            for id in ids {
                match ops::load(data, server.registry(), id).await? {
                    Some(mask) if mask.object.account_id.document_id() == account_id => {
                        response.list.push(to_value(&mask, &properties));
                    }
                    _ => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

fn string_of(value: &Value<'_, P, FastmailMaskedEmailValue>) -> Option<Option<String>> {
    match value {
        Value::Str(s) => Some(Some(s.to_string())),
        Value::Null => Some(None),
        _ => None,
    }
}

fn invalid(property: P, description: &'static str) -> SetError<P> {
    SetError::invalid_properties()
        .with_property(property)
        .with_description(description)
}

/// Applies the mutable fields of a create or update to a mask, returning
/// the state it asks for, if any.
fn apply(
    mask: &mut MaskedEmail,
    object: Value<'_, P, FastmailMaskedEmailValue>,
    is_create: bool,
    prefix: &mut Option<String>,
) -> Result<Option<State>, SetError<P>> {
    let mut state = None;
    for (key, value) in object.into_expanded_object() {
        let Key::Property(property) = key else {
            return Err(SetError::invalid_properties().with_description("Unknown property."));
        };
        match property {
            P::State => match value.as_str().and_then(|s| State::parse_fastmail(&s)) {
                Some(new) => state = Some(new),
                None => return Err(invalid(P::State, "Invalid state.")),
            },
            P::ForDomain | P::Description | P::Url => {
                let Some(text) = string_of(&value) else {
                    return Err(invalid(property, "Expected a string."));
                };
                match property {
                    P::ForDomain => mask.for_domain = text,
                    P::Description => mask.description = text.filter(|d| !d.is_empty()),
                    _ => mask.url = text,
                }
            }
            P::EmailPrefix if is_create => match string_of(&value) {
                Some(value) => *prefix = value,
                None => return Err(invalid(P::EmailPrefix, "Expected a string.")),
            },
            // Server-set: ignored on create, as the Fastmail API does
            P::Id | P::Email | P::CreatedAt | P::CreatedBy | P::LastMessageAt if is_create => {}
            _ => return Err(invalid(property, "This property can't be changed.")),
        }
    }
    Ok(state)
}

/// `MaskedEmail/set`, in the user's own JMAP account.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, FastmailMaskedEmail>,
) -> trc::Result<SetResponse<FastmailMaskedEmail>> {
    let account_id = request.account_id.document_id();
    assert_can_manage(server, access_token, account_id).await?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let data = &server.core.storage.data;
    let registry = server.registry();

    // Creates
    for (client_id, object) in request.unwrap_create() {
        let mut mask = MaskedEmail {
            enabled: true,
            ..Default::default()
        };
        let mut prefix = None;
        let state = match apply(&mut mask, object, true, &mut prefix) {
            Ok(state) => state.unwrap_or(State::Pending),
            Err(err) => {
                response.not_created.append(client_id, err);
                continue;
            }
        };
        if let Err(refusal) =
            prepare_create(server, account_id, &mut mask, prefix.as_deref(), None).await?
        {
            response
                .not_created
                .append(client_id, refusal.into_set_error(P::EmailPrefix, P::Email));
            continue;
        }
        mask.enabled = state.is_live();
        mask.created_by = None;
        match registry
            .write(RegistryWrite::insert(&Object::from(mask.clone())))
            .await?
        {
            RegistryWriteResult::Success(id) => {
                ops::created(data, registry, id, &mask, state).await?;
                let created = Mask {
                    id,
                    object: mask,
                    state,
                    expired: false,
                    last_message_at: None,
                };
                response.created.insert(client_id, to_value(&created, ALL));
            }
            err => {
                response.not_created.append(
                    client_id,
                    SetError::forbidden().with_description(err.to_string()),
                );
            }
        }
    }

    // Updates
    for (id, object) in request.unwrap_update().into_valid() {
        let Some(mask) = ops::load(data, registry, id)
            .await?
            .filter(|mask| mask.object.account_id.document_id() == account_id)
        else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        let mut changed = mask.object.clone();
        let requested = match apply(&mut changed, object, false, &mut None) {
            Ok(state) => state,
            Err(err) => {
                response.not_updated.append(id, err);
                continue;
            }
        };
        let new_state = requested.unwrap_or(mask.state);
        if !mask.state.can_become(new_state) {
            response
                .not_updated
                .append(id, invalid(P::State, "A mask can't return to pending."));
            continue;
        }
        changed.enabled = new_state.is_live();
        if changed != mask.object {
            // The stored object carries the revision the write is checked against
            let Some(old) = registry
                .get(ObjectId::new(ObjectType::MaskedEmail, id))
                .await?
            else {
                response.not_updated.append(id, SetError::not_found());
                continue;
            };
            let mut new = old.clone();
            new.inner = Object::from(changed.clone()).inner;
            match registry
                .write(RegistryWrite::update(id, &new, &old))
                .await?
            {
                RegistryWriteResult::Success(_) => {}
                err => {
                    response
                        .not_updated
                        .append(id, SetError::forbidden().with_description(err.to_string()));
                    continue;
                }
            }
        }
        ops::updated(data, registry, &mask, new_state).await?;
        response.updated.append(id, None);
    }

    // Destroys
    for id in request.unwrap_destroy().into_valid() {
        let Some(mask) = ops::load(data, registry, id)
            .await?
            .filter(|mask| mask.object.account_id.document_id() == account_id)
        else {
            response.not_destroyed.append(id, SetError::not_found());
            continue;
        };
        match registry
            .write(RegistryWrite::delete(ObjectId::new(
                ObjectType::MaskedEmail,
                id,
            )))
            .await?
        {
            RegistryWriteResult::Success(_) => {
                ops::destroyed(data, registry, id, &mask.object).await?;
                response.destroyed.push(id);
            }
            err => {
                response
                    .not_destroyed
                    .append(id, SetError::forbidden().with_description(err.to_string()));
            }
        }
    }

    response.new_state = state(server, account_id).await?.into();
    Ok(response)
}
