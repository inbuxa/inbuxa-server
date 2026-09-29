/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:DlpSettings/get` and `/set`: how many days held mail waits for a
//! reviewer (dlp-and-mail-flow-rules spec, §2.6), 1 to 90, 7 by default.
//! Server-level, like the rules; applies to mail held from then on.

use common::{Server, auth::AccessToken};
use inbuxa_features::mailflow::held::{self, Settings};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_dlp_settings::{DlpSettings, DlpSettingsProperty as P, DlpSettingsValue},
    request::IntoValid,
};
use jmap_tools::{Key, Map, Value};
use types::id::Id;

type LValue = Value<'static, P, DlpSettingsValue>;

const ALL: &[P] = &[P::Id, P::KeepHeldDays];

fn assert_server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("DLP settings are server-level."))
    } else {
        Ok(())
    }
}

fn to_value(settings: &Settings, properties: &[P]) -> LValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(DlpSettingsValue::Id(Id::singleton())),
            P::KeepHeldDays => Value::Number(settings.keep_held_days.into()),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:DlpSettings/get`.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<DlpSettings>,
) -> trc::Result<GetResponse<DlpSettings>> {
    assert_server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(1)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let settings = held::settings(server.store()).await?;
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
    value: &Value<'_, P, DlpSettingsValue>,
) -> Result<(), String> {
    match property {
        P::KeepHeldDays => {
            settings.keep_held_days = value
                .as_u64()
                .ok_or_else(|| "must be a whole number of days".to_string())?
        }
        P::Id => return Err("is immutable".to_string()),
    }
    Ok(())
}

/// `inbuxa:DlpSettings/set`: updates the singleton.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, DlpSettings>,
) -> trc::Result<SetResponse<DlpSettings>> {
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
    let data = server.store();
    for (id, value) in request.unwrap_update().into_valid() {
        if !id.is_singleton() {
            response.not_updated.append(id, SetError::not_found());
            continue;
        }
        let mut settings = held::settings(data).await?;
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
                held::set_settings(data, &settings).await?;
                response.updated.append(id, None);
            }
        }
    }
    Ok(response)
}
