/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:DeliverabilityReport` and `inbuxa:DeliverabilitySettings`
//! (deliverability spec).
//!
//! A report is one sending node's last check, written by that node. Reading
//! reports needs `sysDeliverabilityGet`; a tenant administrator gets only
//! their tenant's domains and nothing about the nodes (DL-20). Creating a
//! report asks every node to check itself now (DL-15): it needs
//! `sysDeliverabilityCheck`, returns at once with the node's last check
//! time, and the new report replaces the old one when it's done. The
//! settings say which built-in lists are left out (DL-6).

use common::{Server, auth::AccessToken, ipc::BroadcastEvent};
use inbuxa_features::deliverability::{
    self as model, Report, Settings,
    lists::{self, Scope},
};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::{
        inbuxa_deliverability_report::{
            DeliverabilityReport, DeliverabilityReportProperty as R, DeliverabilityReportValue,
        },
        inbuxa_deliverability_settings::{
            DeliverabilitySettings, DeliverabilitySettingsProperty as S,
            DeliverabilitySettingsValue,
        },
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Element, Key, Map, Property, Value};
use std::borrow::Cow;
use types::id::Id;

const REPORT: &[R] = &[
    R::Id,
    R::NodeId,
    R::Hostname,
    R::CheckedAt,
    R::Addresses,
    R::Domains,
    R::Certificates,
];

const SETTINGS: &[S] = &[S::Id, S::DisabledLists, S::Lists];

fn server_level(access_token: &AccessToken, what: &'static str) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden.into_err().details(what))
    } else {
        Ok(())
    }
}

fn json_to_value<P: Property, E: Element>(json: serde_json::Value) -> Value<'static, P, E> {
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

fn date(seconds: u64) -> Value<'static, R, DeliverabilityReportValue> {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

fn report_value(report: &Report, properties: &[R]) -> Value<'static, R, DeliverabilityReportValue> {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            R::Id => Value::Element(DeliverabilityReportValue::Id(Id::from(report.node_id))),
            R::NodeId => Value::Number(report.node_id.into()),
            R::Hostname => Value::Str(report.hostname.clone().into()),
            R::CheckedAt => date(report.checked_at),
            R::Addresses => {
                json_to_value(serde_json::to_value(&report.addresses).unwrap_or_default())
            }
            R::Domains => json_to_value(serde_json::to_value(&report.domains).unwrap_or_default()),
            R::Certificates => {
                json_to_value(serde_json::to_value(&report.certificates).unwrap_or_default())
            }
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:DeliverabilityReport/get`: every sending node's last report.
pub async fn get_reports(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<DeliverabilityReport>,
) -> trc::Result<GetResponse<DeliverabilityReport>> {
    let properties = request.unwrap_properties(REPORT);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let mut reports = model::reports(server.store()).await?;
    // DL-20
    if let Some(tenant_id) = access_token.tenant_id() {
        reports = reports.iter().map(|r| r.for_tenant(tenant_id)).collect();
    }
    match ids {
        None => {
            response.list = reports
                .iter()
                .map(|r| report_value(r, &properties))
                .collect();
        }
        Some(ids) => {
            for id in ids {
                match reports.iter().find(|r| r.node_id == id.id()) {
                    Some(report) => response.list.push(report_value(report, &properties)),
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

/// `inbuxa:DeliverabilityReport/set`: a create asks every node to check
/// itself now (DL-15). Reports are the server's: nothing else is allowed.
pub async fn set_reports(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, DeliverabilityReport>,
) -> trc::Result<SetResponse<DeliverabilityReport>> {
    server_level(access_token, "The deliverability check is the server's.")?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let node_id = server.core.network.node_id;

    let mut asked = false;
    for (client_id, _) in request.unwrap_create() {
        if !asked {
            asked = true;
            services::inbuxa_deliverability::CHECK_NOW.notify_one();
            server
                .cluster_broadcast(BroadcastEvent::DeliverabilityCheck)
                .await;
        }
        // The node's last check, so the console knows when the new one lands
        let last = model::report(server.store(), node_id).await?;
        let mut out = Map::with_capacity(2);
        out.insert_unchecked(
            Key::Property(R::Id),
            Value::Element(DeliverabilityReportValue::Id(Id::from(node_id))),
        );
        out.insert_unchecked(
            Key::Property(R::CheckedAt),
            last.map(|r| date(r.checked_at)).unwrap_or(Value::Null),
        );
        response.created.insert(client_id, Value::Object(out));
    }
    for (id, _) in request.unwrap_update().into_valid() {
        response.not_updated.append(
            id,
            SetError::forbidden().with_description("Reports are written by the check."),
        );
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(
            id,
            SetError::forbidden().with_description("Reports are written by the check."),
        );
    }
    Ok(response)
}

fn lists_value() -> Value<'static, S, DeliverabilitySettingsValue> {
    Value::Array(
        lists::LISTS
            .iter()
            .map(|list| {
                json_to_value(serde_json::json!({
                    "name": list.name,
                    "zone": list.zone,
                    "scope": match list.scope {
                        Scope::Ip => "ip",
                        Scope::Domain => "domain",
                    },
                    "lookup": list.lookup,
                    "note": list.note,
                }))
            })
            .collect(),
    )
}

fn settings_value(
    settings: &Settings,
    properties: &[S],
) -> Value<'static, S, DeliverabilitySettingsValue> {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            S::Id => Value::Element(DeliverabilitySettingsValue::Id(Id::singleton())),
            S::DisabledLists => Value::Array(
                settings
                    .disabled_lists
                    .iter()
                    .map(|name| Value::Str(name.clone().into()))
                    .collect(),
            ),
            S::Lists => lists_value(),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:DeliverabilitySettings/get`: which lists are left out, and the lists.
pub async fn get_settings(
    server: &Server,
    _access_token: &AccessToken,
    mut request: GetRequest<DeliverabilitySettings>,
) -> trc::Result<GetResponse<DeliverabilitySettings>> {
    let properties = request.unwrap_properties(SETTINGS);
    let (ids, not_found) = request.unwrap_ids(1)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let settings = model::settings(server.store()).await?;
    match ids {
        None => response.list.push(settings_value(&settings, &properties)),
        Some(ids) => {
            for id in ids {
                if id.is_singleton() {
                    response.list.push(settings_value(&settings, &properties));
                } else {
                    response.push_not_found(id);
                }
            }
        }
    }
    Ok(response)
}

/// `inbuxa:DeliverabilitySettings/set`: updates the singleton.
pub async fn set_settings(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, DeliverabilitySettings>,
) -> trc::Result<SetResponse<DeliverabilitySettings>> {
    server_level(access_token, "The blocklists checked are the server's.")?;
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
        let mut settings = model::settings(data).await?;
        let mut error = None;
        for (key, value) in value.into_expanded_object() {
            match &key {
                Key::Property(S::DisabledLists) => {
                    let names = value.as_array().map(|items| {
                        items
                            .iter()
                            .map(|item| item.as_str().map(|s| s.to_string()))
                            .collect::<Option<Vec<_>>>()
                    });
                    match names {
                        Some(Some(names)) => settings.disabled_lists = names,
                        _ => {
                            error = Some(
                                SetError::invalid_properties()
                                    .with_property(S::DisabledLists)
                                    .with_description("A list of list names."),
                            );
                            break;
                        }
                    }
                }
                Key::Property(property) => {
                    error = Some(
                        SetError::invalid_properties()
                            .with_property(property.clone())
                            .with_description("The server sets this."),
                    );
                    break;
                }
                _ => {
                    error = Some(SetError::invalid_properties().with_property(key.into_owned()));
                    break;
                }
            }
        }
        if error.is_none()
            && let Err(why) = settings.validate()
        {
            error = Some(
                SetError::invalid_properties()
                    .with_property(S::DisabledLists)
                    .with_description(why),
            );
        }
        match error {
            Some(error) => response.not_updated.append(id, error),
            None => {
                model::put_settings(data, &settings).await?;
                response.updated.append(id, None);
            }
        }
    }
    Ok(response)
}
