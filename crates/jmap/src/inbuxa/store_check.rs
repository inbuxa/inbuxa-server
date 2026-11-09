/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:StoreCheck` (store-check spec): starting a check of the store's
//! blobs, seeing how far it got and what it found, stopping it, and
//! forgetting it. The run is `services::inbuxa_store_check`. Starting and
//! stopping one are audited by the request layer (SV-9).

use super::json::json_to_value;
use common::{Server, auth::AccessToken};
use inbuxa_features::store_check::{self as model, Mode, Refusal, Status, StoreCheck as Stored};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_store_check::{StoreCheck, StoreCheckProperty as P, StoreCheckValue},
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use serde_json::json;
use services::inbuxa_store_check as runs;
use store::write::now;
use types::id::Id;

type CValue = Value<'static, P, StoreCheckValue>;

const ALL: &[P] = &[
    P::Id,
    P::Mode,
    P::BlobsPerSecond,
    P::BytesPerSecond,
    P::Status,
    P::CreatedAt,
    P::CreatedBy,
    P::FinishedAt,
    P::Node,
    P::Progress,
    P::BlobsChecked,
    P::LinksChecked,
    P::BytesRead,
    P::MessagesChecked,
    P::Missing,
    P::Damaged,
    P::Unlinked,
    P::Unreadable,
    P::Problems,
    P::Error,
];

/// SV-9: a check reads every account's data, so only the server's own
/// administrators run one.
fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("A store check reads the whole server, not a tenant."))
    } else {
        Ok(())
    }
}

fn date(seconds: u64) -> serde_json::Value {
    json!(UTCDate::from_timestamp(seconds as i64).to_string())
}

async fn to_value(server: &Server, c: &Stored, properties: &[P], now: u64) -> trc::Result<CValue> {
    let status = c.status_at(now);
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let p = &c.progress;
        let json = match property {
            P::Id => {
                out.insert_unchecked(
                    Key::Property(P::Id),
                    Value::Element(StoreCheckValue::Id(Id::from(c.id))),
                );
                continue;
            }
            P::Mode => json!(c.mode.as_str()),
            P::BlobsPerSecond => json!(c.blobs_per_second),
            P::BytesPerSecond => json!(c.bytes_per_second),
            P::Status => json!(status.as_str()),
            P::CreatedAt => date(c.created_at),
            P::CreatedBy => json!(c.created_by),
            P::FinishedAt => c.finished_at.map_or(serde_json::Value::Null, date),
            P::Node => json!(c.node_id.to_string()),
            P::Progress => json!(p.share(status)),
            P::BlobsChecked => json!(p.blobs_checked),
            P::LinksChecked => json!(p.links_checked),
            P::BytesRead => json!(p.bytes_read),
            P::MessagesChecked => json!(p.messages_checked),
            P::Missing => json!(p.missing),
            P::Damaged => json!(p.damaged),
            P::Unlinked => json!(p.unlinked),
            P::Unreadable => json!(p.unreadable),
            P::Problems => {
                let problems = model::problems(server.store(), c.id).await?;
                let mut list = serde_json::to_value(&problems).unwrap_or_default();
                // The account as a JMAP id, like every other account id
                if let Some(items) = list.as_array_mut() {
                    for item in items {
                        if let Some(account) = item.get("accountId").and_then(|v| v.as_u64()) {
                            item["accountId"] = json!(Id::from(account).to_string());
                        }
                    }
                }
                list
            }
            P::Error => json!(c.error),
            // Write-only
            P::Action => continue,
        };
        out.insert_unchecked(Key::Property(property.clone()), json_to_value(json));
    }
    Ok(Value::Object(out))
}

/// `inbuxa:StoreCheck/get`: every check kept, newest first.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<StoreCheck>,
) -> trc::Result<GetResponse<StoreCheck>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let mut checks = model::all(server.store()).await?;
    checks.reverse();
    let now = now();
    match ids {
        None => {
            for c in &checks {
                response
                    .list
                    .push(to_value(server, c, &properties, now).await?);
            }
        }
        Some(ids) => {
            for id in ids {
                match checks.iter().find(|c| u64::from(c.id) == id.id()) {
                    Some(c) => response
                        .list
                        .push(to_value(server, c, &properties, now).await?),
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

fn invalid(property: P, why: impl Into<String>) -> SetError<P> {
    SetError::invalid_properties()
        .with_property(property)
        .with_description(why.into())
}

/// A limit: a whole number, 0 for none (SV-6).
fn limit(property: P, value: &Value<'_, P, StoreCheckValue>) -> Result<u64, SetError<P>> {
    match value {
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| invalid(property, "A whole number of 0 or more; 0 is no limit.")),
        _ => Err(invalid(
            property,
            "A whole number of 0 or more; 0 is no limit.",
        )),
    }
}

/// `inbuxa:StoreCheck/set`: create starts a check; an update can only stop
/// one; destroy forgets a finished one (SV-2, SV-8, SV-10).
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, StoreCheck>,
) -> trc::Result<SetResponse<StoreCheck>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    'create: for (client_id, value) in request.unwrap_create() {
        let mut mode = Mode::Quick;
        let mut blobs_per_second = None;
        let mut bytes_per_second = None;
        for (key, value) in value.into_expanded_object() {
            let outcome = match &key {
                Key::Property(P::Mode) => match value.as_str().and_then(|s| Mode::parse(&s)) {
                    Some(m) => {
                        mode = m;
                        Ok(())
                    }
                    None => Err(invalid(P::Mode, "quick or full.")),
                },
                Key::Property(P::BlobsPerSecond) => {
                    limit(P::BlobsPerSecond, &value).map(|l| blobs_per_second = Some(l))
                }
                Key::Property(P::BytesPerSecond) => {
                    limit(P::BytesPerSecond, &value).map(|l| bytes_per_second = Some(l))
                }
                _ => Err(SetError::invalid_properties().with_property(key.clone().into_owned())),
            };
            if let Err(error) = outcome {
                response.not_created.append(client_id, error);
                continue 'create;
            }
        }
        match runs::start(
            server,
            mode,
            blobs_per_second,
            bytes_per_second,
            actor.name.clone(),
        )
        .await?
        {
            Ok(id) => {
                let mut out = Map::with_capacity(1);
                out.insert_unchecked(
                    Key::Property(P::Id),
                    Value::Element(StoreCheckValue::Id(Id::from(id))),
                );
                response.created.insert(client_id, Value::Object(out));
            }
            Err(Refusal::Running(id)) => response.not_created.append(
                client_id,
                SetError::forbidden().with_description(format!(
                    "Check {} runs now; one check runs at a time. Stop it or wait for it.",
                    Id::from(id)
                )),
            ),
        }
    }

    for (id, value) in request.unwrap_update().into_valid() {
        let Ok(check_id) = u32::try_from(id.id()) else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        let mut action = None;
        let mut bad = None;
        for (key, value) in value.into_expanded_object() {
            match &key {
                Key::Property(P::Action) => action = value.as_str().map(|s| s.to_string()),
                _ => {
                    bad = Some(
                        SetError::invalid_properties()
                            .with_property(key.clone().into_owned())
                            .with_description("A check can't be changed, only stopped."),
                    )
                }
            }
        }
        if let Some(error) = bad {
            response.not_updated.append(id, error);
            continue;
        }
        if action.as_deref() != Some("stop") {
            response
                .not_updated
                .append(id, invalid(P::Action, "The one action is stop."));
            continue;
        }
        let Some(check) = model::get(data, check_id).await? else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        if check.status_at(now()) != Status::Running {
            response.not_updated.append(
                id,
                SetError::forbidden().with_description("That check isn't running."),
            );
            continue;
        }
        runs::stop(server, check_id).await?;
        response.updated.append(id, None);
    }

    for id in request.unwrap_destroy().into_valid() {
        let Ok(check_id) = u32::try_from(id.id()) else {
            response.not_destroyed.append(id, SetError::not_found());
            continue;
        };
        match model::get(data, check_id).await? {
            None => response.not_destroyed.append(id, SetError::not_found()),
            Some(c) if c.status_at(now()) == Status::Running => response.not_destroyed.append(
                id,
                SetError::forbidden().with_description("It's running; stop it first."),
            ),
            Some(_) => {
                model::remove(data, check_id).await?;
                response.destroyed.push(id);
            }
        }
    }
    Ok(response)
}
