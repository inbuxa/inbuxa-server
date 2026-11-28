/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:CountSettings/get` and `/set`: the opt-in count (count spec).
//! Server-level, with the tracers' permissions, as `inbuxa:LogSettings` is.
//! Nothing here touches the network: turning the count off queues the one
//! `/forget` for this node's count task (CNT-7), which recovery mode never
//! starts (CNT-11).

use common::{Server, auth::AccessToken};
use inbuxa_features::count::{self, CountSettings as Settings};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_count_settings::{
        CountSettings, CountSettingsProperty as P, CountSettingsValue,
    },
    request::IntoValid,
};
use jmap_tools::{Key, Map, Property, Value};
use types::id::Id;

type CValue = Value<'static, P, CountSettingsValue>;

const ALL: &[P] = &[
    P::Id,
    P::Enabled,
    P::Decided,
    P::Endpoint,
    P::InstallId,
    P::LastCheckIn,
    P::Preview,
];

/// What `/set` reports back: the values the server sets.
const SERVER_SET: &[P] = &[P::InstallId, P::LastCheckIn, P::Preview];

fn assert_server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("The count settings are server-level."))
    } else {
        Ok(())
    }
}

fn text(value: Option<&String>) -> CValue {
    value.map_or(Value::Null, |text| Value::Str(text.clone().into()))
}

fn to_value(settings: &Settings, properties: &[P]) -> CValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(CountSettingsValue::Id(Id::singleton())),
            P::Enabled => Value::Bool(settings.enabled),
            P::Decided => Value::Bool(settings.decided),
            P::Endpoint => Value::Str(settings.endpoint().to_string().into()),
            P::InstallId => text(settings.install_id.as_ref()),
            P::LastCheckIn => text(settings.last_check_in.as_ref()),
            P::Preview => Value::Str(settings.preview().into()),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:CountSettings/get`.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<CountSettings>,
) -> trc::Result<GetResponse<CountSettings>> {
    assert_server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(1)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let settings = count::get(&server.core.storage.data).await?;
    match ids {
        None => response.list.push(to_value(&settings, &properties)),
        Some(ids) => {
            for id in ids {
                if id.is_singleton() {
                    response.list.push(to_value(&settings, &properties));
                } else {
                    response.push_not_found(id);
                }
            }
        }
    }
    Ok(response)
}

fn apply(
    settings: &mut Settings,
    property: &P,
    value: &Value<'_, P, CountSettingsValue>,
) -> Result<(), String> {
    match property {
        P::Enabled => {
            settings.enabled = value
                .as_bool()
                .ok_or_else(|| "must be true or false".to_string())?
        }
        P::Decided => {
            settings.decided = value
                .as_bool()
                .ok_or_else(|| "must be true or false".to_string())?
        }
        // CNT-8; null or empty goes back to the default collector
        P::Endpoint => match value {
            Value::Null => settings.endpoint = None,
            value => {
                let endpoint = value
                    .as_str()
                    .ok_or_else(|| "must be an https:// URL, or null".to_string())?;
                if endpoint.is_empty() {
                    settings.endpoint = None;
                } else {
                    count::check_endpoint(&endpoint)?;
                    settings.endpoint = Some(endpoint.into_owned());
                }
            }
        },
        P::Id => return Err("is immutable".to_string()),
        other if other.is_server_set() => return Err("is set by the server".to_string()),
        _ => return Err("is immutable".to_string()),
    }
    Ok(())
}

/// `inbuxa:CountSettings/set`: updates the singleton.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, CountSettings>,
) -> trc::Result<SetResponse<CountSettings>> {
    assert_server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (client_id, _) in request.unwrap_create() {
        response
            .not_created
            .append(client_id, SetError::singleton());
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
        let before = count::get(data).await?;
        let mut settings = before.clone();
        let mut answered = false;
        let mut error = None;
        for (key, value) in value.into_expanded_object() {
            let Key::Property(property) = &key else {
                error = Some(SetError::invalid_properties().with_property(key.into_owned()));
                break;
            };
            if let Err(why) = apply(&mut settings, property, &value) {
                error = Some(
                    SetError::invalid_properties()
                        .with_property(property.clone())
                        .with_description(format!("{} {why}.", property.to_cow())),
                );
                break;
            }
            answered |= *property == P::Enabled;
        }
        if let Some(error) = error {
            response.not_updated.append(id, error);
            continue;
        }
        // Answering the question either way decides it
        if answered {
            settings.decided = true;
        }
        // CNT-3, CNT-7: a new ID on, none off, and the /forget owed
        let forget = settings.transition_from(&before);
        count::set(data, &settings).await?;
        if let Some(forget) = forget
            && !server.registry().is_recovery_mode()
        {
            count::queue_forget(forget);
        }
        // This node's task reads them now; the others within the hour
        count::CHANGED.notify_one();
        server
            .inventory_snapshot_after("inbuxa:CountSettings")
            .await;
        response
            .updated
            .append(id, Some(to_value(&settings, SERVER_SET)));
    }
    Ok(response)
}
