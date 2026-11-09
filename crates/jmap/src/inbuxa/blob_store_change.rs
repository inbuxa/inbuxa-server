/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:BlobStoreChange` (blob-store-change spec): the changes of blob
//! store the server noticed at start-up, copying what the new store lacks
//! from the old one, stopping that, and dismissing a change. The copy is
//! `services::inbuxa_blob_move`. Copying, stopping and dismissing are
//! audited by the request layer (BM-9).

use super::json::json_to_value;
use common::{Server, auth::AccessToken};
use inbuxa_features::blob_move::{self as model, BlobStoreChange as Stored, Refusal, Status};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_blob_store_change::{
        BlobStoreChange, BlobStoreChangeProperty as P, BlobStoreChangeValue,
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use serde_json::json;
use services::inbuxa_blob_move as copies;
use store::write::now;
use types::id::Id;

type CValue = Value<'static, P, BlobStoreChangeValue>;

const ALL: &[P] = &[
    P::Id,
    P::From,
    P::To,
    P::ChangedAt,
    P::Node,
    P::Status,
    P::CopyStartedAt,
    P::CopyFinishedAt,
    P::CopyStartedBy,
    P::CopyNode,
    P::BlobsPerSecond,
    P::BytesPerSecond,
    P::Progress,
    P::BlobsChecked,
    P::Copied,
    P::AlreadyThere,
    P::BytesCopied,
    P::Missing,
    P::Damaged,
    P::Unreadable,
    P::Problems,
    P::Error,
];

/// BM-9: a change is about the whole server's blobs, so only the server's
/// own administrators see and act on one.
fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("A blob store change is about the whole server, not a tenant."))
    } else {
        Ok(())
    }
}

fn date(seconds: u64) -> serde_json::Value {
    json!(UTCDate::from_timestamp(seconds as i64).to_string())
}

async fn to_value(server: &Server, c: &Stored, properties: &[P], now: u64) -> trc::Result<CValue> {
    let status = c.status_at(now);
    let copy = c.copy.as_ref();
    let p = copy.map(|copy| copy.progress.clone()).unwrap_or_default();
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let json = match property {
            P::Id => {
                out.insert_unchecked(
                    Key::Property(P::Id),
                    Value::Element(BlobStoreChangeValue::Id(Id::from(c.id))),
                );
                continue;
            }
            // BM-9: where the stores are, never their settings
            P::From => json!(c.from),
            P::To => json!(c.to),
            P::ChangedAt => date(c.changed_at),
            P::Node => json!(c.node_id.to_string()),
            P::Status => json!(status.as_str()),
            P::CopyStartedAt => copy.map_or(serde_json::Value::Null, |c| date(c.started_at)),
            P::CopyFinishedAt => copy
                .and_then(|c| c.finished_at)
                .map_or(serde_json::Value::Null, date),
            P::CopyStartedBy => copy.map_or(serde_json::Value::Null, |c| json!(c.started_by)),
            P::CopyNode => copy.map_or(serde_json::Value::Null, |c| json!(c.node_id.to_string())),
            P::BlobsPerSecond => {
                copy.map_or(serde_json::Value::Null, |c| json!(c.blobs_per_second))
            }
            P::BytesPerSecond => {
                copy.map_or(serde_json::Value::Null, |c| json!(c.bytes_per_second))
            }
            P::Progress => match status {
                Status::Copied | Status::Reverted => json!(1.0),
                _ => json!(p.share()),
            },
            P::BlobsChecked => json!(p.blobs_checked),
            P::Copied => json!(p.copied),
            P::AlreadyThere => json!(p.already_there),
            P::BytesCopied => json!(p.bytes_copied),
            P::Missing => json!(p.missing),
            P::Damaged => json!(p.damaged),
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
            P::Error => json!(copy.and_then(|c| c.error.clone())),
            // Write-only
            P::Action => continue,
        };
        out.insert_unchecked(Key::Property(property.clone()), json_to_value(json));
    }
    Ok(Value::Object(out))
}

/// `inbuxa:BlobStoreChange/get`: every change kept, newest first.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<BlobStoreChange>,
) -> trc::Result<GetResponse<BlobStoreChange>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let mut changes = model::all(server.store()).await?;
    changes.reverse();
    let now = now();
    match ids {
        None => {
            for c in &changes {
                response
                    .list
                    .push(to_value(server, c, &properties, now).await?);
            }
        }
        Some(ids) => {
            for id in ids {
                match changes.iter().find(|c| u64::from(c.id) == id.id()) {
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

/// A limit: a whole number, 0 for none (BM-5).
fn limit(property: P, value: &Value<'_, P, BlobStoreChangeValue>) -> Result<u64, SetError<P>> {
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

/// `inbuxa:BlobStoreChange/set`: the server records changes, so there's no
/// create. An update copies or stops a copy; destroy dismisses (BM-5 to
/// BM-7).
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, BlobStoreChange>,
) -> trc::Result<SetResponse<BlobStoreChange>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    for (client_id, _) in request.unwrap_create() {
        response.not_created.append(
            client_id,
            SetError::forbidden().with_description(
                "The server records a change when it starts with the blob store moved.",
            ),
        );
    }

    'update: for (id, value) in request.unwrap_update().into_valid() {
        let Ok(change_id) = u32::try_from(id.id()) else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        let mut action = None;
        let mut blobs_per_second = None;
        let mut bytes_per_second = None;
        for (key, value) in value.into_expanded_object() {
            let outcome = match &key {
                Key::Property(P::Action) => {
                    action = value.as_str().map(|s| s.to_string());
                    Ok(())
                }
                Key::Property(P::BlobsPerSecond) => {
                    limit(P::BlobsPerSecond, &value).map(|l| blobs_per_second = Some(l))
                }
                Key::Property(P::BytesPerSecond) => {
                    limit(P::BytesPerSecond, &value).map(|l| bytes_per_second = Some(l))
                }
                _ => Err(SetError::invalid_properties()
                    .with_property(key.clone().into_owned())
                    .with_description("A change can't be edited, only copied or stopped.")),
            };
            if let Err(error) = outcome {
                response.not_updated.append(id, error);
                continue 'update;
            }
        }
        let Some(change) = model::get(data, change_id).await? else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        match action.as_deref() {
            Some("copy") => {
                match copies::start(
                    server,
                    change_id,
                    blobs_per_second,
                    bytes_per_second,
                    actor.name.clone(),
                )
                .await?
                {
                    Ok(()) => response.updated.append(id, None),
                    Err(Refusal::Running(running)) => response.not_updated.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "A copy of change {} runs now; one copy runs at a time. \
                             Stop it or wait for it.",
                            Id::from(running)
                        )),
                    ),
                    Err(Refusal::Resolved) => response.not_updated.append(
                        id,
                        SetError::forbidden()
                            .with_description("That change is resolved; there's nothing to copy."),
                    ),
                    Err(Refusal::NotFound) => {
                        response.not_updated.append(id, SetError::not_found())
                    }
                }
            }
            Some("stop") => {
                if change.status_at(now()) != Status::Copying {
                    response.not_updated.append(
                        id,
                        SetError::forbidden().with_description("That change isn't being copied."),
                    );
                    continue;
                }
                copies::stop(server, change_id).await?;
                response.updated.append(id, None);
            }
            _ => response
                .not_updated
                .append(id, invalid(P::Action, "The actions are copy and stop.")),
        }
    }

    for id in request.unwrap_destroy().into_valid() {
        let Ok(change_id) = u32::try_from(id.id()) else {
            response.not_destroyed.append(id, SetError::not_found());
            continue;
        };
        match model::get(data, change_id).await? {
            None => response.not_destroyed.append(id, SetError::not_found()),
            Some(c) if c.status_at(now()) == Status::Copying => response.not_destroyed.append(
                id,
                SetError::forbidden().with_description("It's being copied; stop the copy first."),
            ),
            Some(_) => {
                model::remove(data, change_id).await?;
                // BM-7: this node stops reading through it at once; the
                // others within a minute (BM-10)
                copies::refresh(server).await;
                response.destroyed.push(id);
            }
        }
    }
    Ok(response)
}
