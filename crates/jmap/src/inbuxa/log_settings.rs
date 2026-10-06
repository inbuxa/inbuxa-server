/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:LogSettings/get` and `/set`: how long rotated log files are kept
//! (personal-data catalog spec, D1). Server-level: log files belong to the
//! server, not to a tenant. `null` restores the default, which keeps every
//! file.

use common::{Server, auth::AccessToken};
use inbuxa_features::security::log_files::{self, LogSettings as Settings};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_log_settings::{LogSettings, LogSettingsProperty as P, LogSettingsValue},
    request::IntoValid,
};
use jmap_tools::{Key, Map, Value};
use types::id::Id;

type LValue = Value<'static, P, LogSettingsValue>;

const ALL: &[P] = &[P::Id, P::KeepForDays];

fn assert_server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Log file settings are server-level."))
    } else {
        Ok(())
    }
}

fn to_value(settings: &Settings, properties: &[P]) -> LValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(LogSettingsValue::Id(Id::singleton())),
            P::KeepForDays => settings
                .keep_for_days
                .map_or(Value::Null, |days| Value::Number(days.into())),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:LogSettings/get`.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<LogSettings>,
) -> trc::Result<GetResponse<LogSettings>> {
    assert_server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(1)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let settings = log_files::get(&server.core.storage.data).await?;
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
    value: &Value<'_, P, LogSettingsValue>,
) -> Result<(), String> {
    match property {
        P::KeepForDays => match value {
            Value::Null => settings.keep_for_days = None,
            value => {
                settings.keep_for_days = Some(
                    value
                        .as_u64()
                        .ok_or_else(|| "must be a whole number of days, or null".to_string())?,
                )
            }
        },
        P::Id => return Err("is immutable".to_string()),
    }
    Ok(())
}

/// `inbuxa:LogSettings/set`: updates the singleton.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, LogSettings>,
) -> trc::Result<SetResponse<LogSettings>> {
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
        let mut settings = log_files::get(data).await?;
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
                        .with_description(why),
                );
                break;
            }
        }
        if error.is_none()
            && let Err((property, why)) = settings.check()
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
                log_files::set(data, &settings).await?;
                // This node purges now; the others within the hour
                log_files::CHANGED.notify_one();
                server.inventory_snapshot_after("inbuxa:LogSettings").await;
                response.updated.append(id, None);
            }
        }
    }
    Ok(response)
}
