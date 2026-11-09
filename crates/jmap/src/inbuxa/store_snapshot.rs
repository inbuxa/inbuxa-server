/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:StoreSnapshot` (store-snapshot spec): taking a snapshot of the
//! store without stopping the server, listing the snapshots on disk, and
//! deleting one. The run is `services::inbuxa_store_snapshot`. Taking and
//! destroying one are audited by the request layer (SN-8).

use super::json::json_to_value;
use common::{Server, auth::AccessToken};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_store_snapshot::{
        StoreSnapshot, StoreSnapshotProperty as P, StoreSnapshotValue,
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use serde_json::json;
use services::inbuxa_store_snapshot::{self as runs, Destroyed, Refusal, Snapshot};
use types::id::Id;

type SValue = Value<'static, P, StoreSnapshotValue>;

const ALL: &[P] = &[
    P::Id,
    P::Status,
    P::CreatedAt,
    P::CreatedBy,
    P::FinishedAt,
    P::Node,
    P::Name,
    P::Path,
    P::Holds,
    P::Size,
    P::BlobFiles,
    P::Error,
];

/// SN-8: a snapshot holds every account's data, so only the server's own
/// administrators take one.
fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("A snapshot holds the whole server, not a tenant."))
    } else {
        Ok(())
    }
}

fn date(seconds: u64) -> serde_json::Value {
    json!(UTCDate::from_timestamp(seconds as i64).to_string())
}

fn to_value(s: &Snapshot, properties: &[P]) -> SValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let json = match property {
            P::Id => {
                out.insert_unchecked(
                    Key::Property(P::Id),
                    Value::Element(StoreSnapshotValue::Id(Id::from(s.id))),
                );
                continue;
            }
            P::Status => json!(s.status.as_str()),
            P::CreatedAt => date(s.created_at),
            P::CreatedBy => json!(s.created_by),
            P::FinishedAt => s.finished_at.map_or(serde_json::Value::Null, date),
            P::Node => json!(s.node_id.to_string()),
            P::Name => json!(s.name),
            P::Path => json!(s.path.to_string_lossy()),
            P::Holds => json!(s.holds),
            P::Size => json!(s.size),
            P::BlobFiles => json!(s.blob_files),
            P::Error => json!(s.error),
        };
        out.insert_unchecked(Key::Property(property.clone()), json_to_value(json));
    }
    Value::Object(out)
}

/// `inbuxa:StoreSnapshot/get`: the snapshots on disk and the one being
/// taken, newest first (SN-7).
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<StoreSnapshot>,
) -> trc::Result<GetResponse<StoreSnapshot>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let snapshots = runs::list(server).await;
    match ids {
        None => {
            for s in &snapshots {
                response.list.push(to_value(s, &properties));
            }
        }
        Some(ids) => {
            for id in ids {
                match snapshots.iter().find(|s| s.id == id.id()) {
                    Some(s) => response.list.push(to_value(s, &properties)),
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

/// `inbuxa:StoreSnapshot/set`: create takes one; destroy deletes one; a
/// snapshot can't be changed (SN-1, SN-6, SN-9).
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, StoreSnapshot>,
) -> trc::Result<SetResponse<StoreSnapshot>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let actor = server.audit_actor(access_token).await;

    for (client_id, value) in request.unwrap_create() {
        if let Some((key, _)) = value.into_expanded_object().next() {
            response.not_created.append(
                client_id,
                SetError::invalid_properties()
                    .with_property(key.into_owned())
                    .with_description("A snapshot is taken as it is; it takes no properties."),
            );
            continue;
        }
        match runs::start(server, actor.name.clone()).await? {
            Ok(snapshot) => {
                response
                    .created
                    .insert(client_id, to_value(&snapshot, &[P::Id, P::Name, P::Path]));
            }
            Err(Refusal::Running(id)) => response.not_created.append(
                client_id,
                SetError::forbidden().with_description(format!(
                    "Snapshot {} is being taken; one is taken at a time. Wait for it.",
                    Id::from(id)
                )),
            ),
            Err(Refusal::Unsupported(why)) => response
                .not_created
                .append(client_id, SetError::forbidden().with_description(why)),
        }
    }

    for (id, _) in request.unwrap_update().into_valid() {
        response.not_updated.append(
            id,
            SetError::forbidden().with_description("A snapshot can't be changed."),
        );
    }

    for id in request.unwrap_destroy().into_valid() {
        match runs::destroy(server, id.id()).await? {
            Destroyed::Gone => response.destroyed.push(id),
            Destroyed::NotFound => response.not_destroyed.append(id, SetError::not_found()),
            Destroyed::Running => response.not_destroyed.append(
                id,
                SetError::forbidden().with_description("It's being taken; wait for it to finish."),
            ),
        }
    }
    Ok(response)
}
