/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:ProtocolPolicy/get` and `/set`: the server-wide legacy mail
//! protocols switch (legacy-protocols spec). Server-level: a principal in a
//! tenant can neither read nor change it, and turns its own switch instead
//! (LP-9).
//!
//! `/set` does not write the policy itself. It hands what was asked to
//! [`Server::set_protocol_policy`], which applies the locks (LP-21), removes
//! or restores the listener objects (LP-1, LP-5) and closes or opens their
//! sockets (LP-2). What comes back is what actually happened.

use common::{Server, auth::AccessToken, network::legacy::PolicyChange};
use inbuxa_features::security::{
    listeners,
    protocol_policy::{LOCKED_PROTOCOLS, LegacyProtocols, ProtocolPolicy as Policy, SavedListener},
};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_protocol_policy::{
        ProtocolPolicy, ProtocolPolicyProperty as P, ProtocolPolicyValue,
    },
    request::IntoValid,
};
use jmap_tools::{Key, Map, Value};
use types::id::Id;

type PValue = Value<'static, P, ProtocolPolicyValue>;

const ALL: &[P] = &[
    P::Id,
    P::LegacyProtocols,
    P::CloseSubmission,
    P::SavedListeners,
    P::ChangedAt,
    P::ChangedBy,
    P::LockedProtocols,
    P::WouldClose,
];

fn assert_server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("The server-wide protocol policy is server-level."))
    } else {
        Ok(())
    }
}

/// A saved or would-be-closed listener, as the confirmation shows it (LP-16).
fn listener_value(listener: &SavedListener) -> PValue {
    let mut out = Map::with_capacity(3);
    out.insert_unchecked(
        Key::Property(P::Id),
        Value::Str(listener.id.clone().into()),
    );
    out.insert_unchecked(
        Key::Property(P::LegacyProtocols),
        Value::Str(listener.protocol.clone().into()),
    );
    out.insert_unchecked(
        Key::Property(P::WouldClose),
        Value::Array(
            listener
                .ports
                .iter()
                .map(|port| Value::Number((*port as u64).into()))
                .collect(),
        ),
    );
    Value::Object(out)
}

fn to_value(policy: &Policy, would_close: &[SavedListener], properties: &[P]) -> PValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(ProtocolPolicyValue::Id(Id::singleton())),
            P::LegacyProtocols => Value::Str(
                match policy.legacy_protocols {
                    LegacyProtocols::Enabled => "enabled",
                    LegacyProtocols::Disabled => "disabled",
                }
                .into(),
            ),
            P::CloseSubmission => Value::Bool(policy.close_submission),
            P::SavedListeners => Value::Array(
                policy
                    .saved_listeners
                    .iter()
                    .map(listener_value)
                    .collect(),
            ),
            P::ChangedAt => policy
                .changed_at
                .map(|at| Value::Number(at.into()))
                .unwrap_or(Value::Null),
            P::ChangedBy => policy
                .changed_by
                .as_ref()
                .map(|by| Value::Str(by.clone().into()))
                .unwrap_or(Value::Null),
            // The selector renders these locked rather than carrying its own
            // list, so unlocking later needs no admin release (LP-21).
            P::LockedProtocols => Value::Array(
                LOCKED_PROTOCOLS
                    .iter()
                    .map(|protocol| Value::Str((*protocol).into()))
                    .collect(),
            ),
            // Exactly what turning the switch on would close, by name and
            // port, so the confirmation can say so before anything happens
            // (LP-16).
            P::WouldClose => Value::Array(would_close.iter().map(listener_value).collect()),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// The listeners turning the switch on would close, whatever it is now.
async fn would_close(server: &Server, policy: &Policy) -> trc::Result<Vec<SavedListener>> {
    let mut hypothetical = policy.clone();
    hypothetical.legacy_protocols = LegacyProtocols::Disabled;
    hypothetical.apply_locks();
    listeners::would_close(server.registry(), &hypothetical).await
}

/// `inbuxa:ProtocolPolicy/get`.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<ProtocolPolicy>,
) -> trc::Result<GetResponse<ProtocolPolicy>> {
    assert_server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(1)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };

    let policy = server.protocol_policy().await?;
    // Only worth asking the registry when the answer is wanted.
    let would_close = if properties.contains(&P::WouldClose) {
        would_close(server, &policy).await?
    } else {
        Vec::new()
    };

    match ids {
        None => response
            .list
            .push(to_value(&policy, &would_close, &properties)),
        Some(ids) => {
            for id in ids {
                if id.is_singleton() {
                    response
                        .list
                        .push(to_value(&policy, &would_close, &properties));
                } else {
                    response.push_not_found(id);
                }
            }
        }
    }
    Ok(response)
}

fn apply(
    policy: &mut Policy,
    property: &P,
    value: &Value<'_, P, ProtocolPolicyValue>,
) -> Result<(), String> {
    match property {
        P::LegacyProtocols => {
            policy.legacy_protocols = match value.as_str().as_deref() {
                Some("enabled") => LegacyProtocols::Enabled,
                Some("disabled") => LegacyProtocols::Disabled,
                _ => return Err(r#"must be "enabled" or "disabled""#.to_string()),
            }
        }
        P::CloseSubmission => {
            policy.close_submission = value
                .as_bool()
                .ok_or_else(|| "must be true or false".to_string())?
        }
        P::Id => return Err("is immutable".to_string()),
        // savedListeners, changedAt, changedBy, lockedProtocols and wouldClose
        // are the server's to say (LP-1, LP-16, LP-21).
        other if other.is_server_set() => return Err("is set by the server".to_string()),
        _ => return Err("is immutable".to_string()),
    }
    Ok(())
}

/// Puts a property back to its default (a `null` in `/set`).
fn reset(policy: &mut Policy, property: &P, defaults: &Policy) -> Result<(), String> {
    match property {
        P::LegacyProtocols => policy.legacy_protocols = defaults.legacy_protocols,
        P::CloseSubmission => policy.close_submission = defaults.close_submission,
        P::Id => return Err("is immutable".to_string()),
        other if other.is_server_set() => return Err("is set by the server".to_string()),
        _ => return Err("is immutable".to_string()),
    }
    Ok(())
}

/// What the server made of the update, when that differs from what was asked.
///
/// A locked property is overruled rather than refused (LP-21), so the client
/// is told by being handed the value that was actually stored. `None` when
/// nothing was overruled, which JMAP reads as "exactly as you asked".
fn updated_value(change: &PolicyChange) -> Option<PValue> {
    if change.overruled.is_empty() {
        return None;
    }
    let mut out = Map::with_capacity(change.overruled.len());
    for property in &change.overruled {
        if *property == "closeSubmission" {
            out.insert_unchecked(Key::Property(P::CloseSubmission), Value::Bool(false));
        }
    }
    Some(Value::Object(out))
}

/// `inbuxa:ProtocolPolicy/set`: turns the switch. Unset (`null`) restores a
/// property's default.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, ProtocolPolicy>,
) -> trc::Result<SetResponse<ProtocolPolicy>> {
    assert_server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (client_id, _) in request.unwrap_create() {
        response.not_created.append(client_id, SetError::singleton());
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(id, SetError::singleton());
    }

    for (id, value) in request.unwrap_update().into_valid() {
        if !id.is_singleton() {
            response.not_updated.append(id, SetError::not_found());
            continue;
        }

        let mut policy = server.protocol_policy().await?;
        let defaults = Policy::default();
        let mut error = None;

        for (key, value) in value.into_expanded_object() {
            let Key::Property(property) = &key else {
                error = Some(SetError::invalid_properties().with_property(key.into_owned()));
                break;
            };
            let result = if matches!(value, Value::Null) {
                reset(&mut policy, property, &defaults)
            } else {
                apply(&mut policy, property, &value)
            };
            if let Err(why) = result {
                error = Some(
                    SetError::invalid_properties()
                        .with_property(property.clone())
                        .with_description(why),
                );
                break;
            }
        }

        if error.is_none()
            && let Err((property, why)) = policy.check()
        {
            error = Some(
                SetError::invalid_properties()
                    .with_property(property.parse::<P>().unwrap_or(P::Id))
                    .with_description(format!("{property} {why}.")),
            );
        }

        match error {
            Some(error) => response.not_updated.append(id, error),
            None => {
                let change = server
                    .set_protocol_policy(policy, Some(Id::from(access_token.account_id()).to_string()))
                    .await?;

                // An overruled property is reported, not refused: the value
                // is specified and the lock is temporary (LP-21). The update
                // succeeded, so the client is told by being handed what was
                // actually stored.
                response.updated.append(id, updated_value(&change));
            }
        }
    }
    Ok(response)
}
