/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:AiLimits/get` and `/set`: the fork's limits on AI model calls
//! (AI spam classification spec, "Added by inbuxa-server"). Server-level:
//! a principal in a tenant can neither read nor change them (AI-27).

use common::{Server, auth::AccessToken};
use inbuxa_features::ai::limits::{self, AiLimits as Limits};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_ai_limits::{AiLimits, AiLimitsProperty as P, AiLimitsValue},
    request::IntoValid,
};
use jmap_tools::{Key, Map, Value};
use registry::types::duration::Duration;
use types::id::Id;

type LValue = Value<'static, P, AiLimitsValue>;

const ALL: &[P] = &[
    P::Id,
    P::SpamMaxAdded,
    P::SpamMaxSubtracted,
    P::SpamCallCeiling,
    P::MaxConcurrentCalls,
    P::MaxContentBytes,
    P::FailureBackoff,
    P::UserCallsPerHour,
    P::ExplainEnabled,
    P::ExplainModelId,
    P::ExplainCallsPerHour,
    P::ExplainCeiling,
];

fn assert_server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("AI model settings are server-level."))
    } else {
        Ok(())
    }
}

fn to_value(limits: &Limits, properties: &[P]) -> LValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(AiLimitsValue::Id(Id::singleton())),
            P::SpamMaxAdded => Value::Number((limits.spam_max_added).into()),
            P::SpamMaxSubtracted => Value::Number((limits.spam_max_subtracted).into()),
            P::SpamCallCeiling => Value::Number((limits.spam_call_ceiling.into_inner().as_millis() as u64).into()),
            P::MaxConcurrentCalls => Value::Number((limits.max_concurrent_calls).into()),
            P::MaxContentBytes => Value::Number((limits.max_content_bytes).into()),
            P::FailureBackoff => Value::Number((limits.failure_backoff.into_inner().as_millis() as u64).into()),
            P::UserCallsPerHour => Value::Number((limits.user_calls_per_hour).into()),
            P::ExplainEnabled => Value::Bool(limits.explain_enabled),
            P::ExplainModelId => match limits.explain_model_id {
                Some(id) => Value::Element(AiLimitsValue::Id(Id::from(id))),
                None => Value::Null,
            },
            P::ExplainCallsPerHour => Value::Number((limits.explain_calls_per_hour).into()),
            P::ExplainCeiling => Value::Number((limits.explain_ceiling.into_inner().as_millis() as u64).into()),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:AiLimits/get`.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<AiLimits>,
) -> trc::Result<GetResponse<AiLimits>> {
    assert_server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(1)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let limits = limits::get(&server.core.storage.data).await?;
    match ids {
        None => response.list.push(to_value(&limits, &properties)),
        Some(ids) => {
            for id in ids {
                if id.is_singleton() {
                    response.list.push(to_value(&limits, &properties));
                } else {
                    response.push_not_found(id);
                }
            }
        }
    }
    Ok(response)
}

fn apply(limits: &mut Limits, property: &P, value: &Value<'_, P, AiLimitsValue>) -> Result<(), String> {
    let number = || value.as_f64().ok_or_else(|| "must be a number".to_string());
    let whole = || value.as_u64().ok_or_else(|| "must be a whole number".to_string());
    match property {
        P::SpamMaxAdded => limits.spam_max_added = number()?,
        P::SpamMaxSubtracted => limits.spam_max_subtracted = number()?,
        P::SpamCallCeiling => limits.spam_call_ceiling = Duration::from_millis(whole()?),
        P::MaxConcurrentCalls => limits.max_concurrent_calls = whole()?,
        P::MaxContentBytes => limits.max_content_bytes = whole()?,
        P::FailureBackoff => limits.failure_backoff = Duration::from_millis(whole()?),
        P::UserCallsPerHour => limits.user_calls_per_hour = whole()?,
        P::ExplainEnabled => {
            limits.explain_enabled = value.as_bool().ok_or_else(|| "must be true or false".to_string())?
        }
        P::ExplainModelId => match value {
            Value::Element(AiLimitsValue::Id(id)) => limits.explain_model_id = Some(id.id()),
            _ => return Err("must be the id of an x:AiModel".to_string()),
        },
        P::ExplainCallsPerHour => limits.explain_calls_per_hour = whole()?,
        P::ExplainCeiling => limits.explain_ceiling = Duration::from_millis(whole()?),
        P::Id => return Err("is immutable".to_string()),
    }
    Ok(())
}

/// Puts a property back to its default (a `null` in `/set`).
fn reset(limits: &mut Limits, property: &P, defaults: &Limits) -> Result<(), String> {
    match property {
        P::SpamMaxAdded => limits.spam_max_added = defaults.spam_max_added,
        P::SpamMaxSubtracted => limits.spam_max_subtracted = defaults.spam_max_subtracted,
        P::SpamCallCeiling => limits.spam_call_ceiling = defaults.spam_call_ceiling,
        P::MaxConcurrentCalls => limits.max_concurrent_calls = defaults.max_concurrent_calls,
        P::MaxContentBytes => limits.max_content_bytes = defaults.max_content_bytes,
        P::FailureBackoff => limits.failure_backoff = defaults.failure_backoff,
        P::UserCallsPerHour => limits.user_calls_per_hour = defaults.user_calls_per_hour,
        P::ExplainEnabled => limits.explain_enabled = defaults.explain_enabled,
        P::ExplainModelId => limits.explain_model_id = defaults.explain_model_id,
        P::ExplainCallsPerHour => limits.explain_calls_per_hour = defaults.explain_calls_per_hour,
        P::ExplainCeiling => limits.explain_ceiling = defaults.explain_ceiling,
        P::Id => return Err("is immutable".to_string()),
    }
    Ok(())
}

/// `inbuxa:AiLimits/set`: updates the singleton. Unset (`null`) restores a
/// property's default.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, AiLimits>,
) -> trc::Result<SetResponse<AiLimits>> {
    assert_server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (client_id, _) in request.unwrap_create() {
        response.not_created.append(client_id, SetError::singleton());
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(id, SetError::singleton());
    }
    let data = &server.core.storage.data;
    for (id, value) in request.unwrap_update().into_valid() {
        if !id.is_singleton() {
            response.not_updated.append(id, SetError::not_found());
            continue;
        }
        let mut limits = limits::get(data).await?;
        let defaults = Limits::default();
        let mut error = None;
        for (key, value) in value.into_expanded_object() {
            let Key::Property(property) = &key else {
                error = Some(SetError::invalid_properties().with_property(key.into_owned()));
                break;
            };
            let result = if matches!(value, Value::Null) {
                reset(&mut limits, property, &defaults)
            } else {
                apply(&mut limits, property, &value)
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
            && let Err((property, why)) = limits.check()
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
                limits::set(data, &limits).await?;
                // inbuxa: personal-data catalog: the inventory's history
                server.inventory_snapshot_after("inbuxa:AiLimits").await;
                response.updated.append(id, None);
            }
        }
    }
    Ok(response)
}
