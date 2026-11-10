/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:BlobStoreChange` (blob-store-change spec): the changes of blob
//! store the server noticed at start-up, copying what the new store lacks
//! from the old one, stopping that, and dismissing a change. A create plans
//! one, which is copied ahead and applied to the setting
//! (blob-store-copy-ahead spec). A resolved change's old store is cleaned
//! up, or a cleanup previewed (blob-store-cleanup spec). The copy is
//! `services::inbuxa_blob_move`, the cleanup `services::inbuxa_blob_cleanup`.
//! Planning, copying, applying, cleaning up, stopping and dismissing are
//! audited by the request layer (BM-9, CA-9, OC-12).

use super::relay::json_to_value;
use common::{Server, auth::AccessToken};
use inbuxa_features::blob_move::{
    self as model, BlobStoreChange as Stored, CleanupRefusal, PlanRefusal, Refusal, Stage, Status,
};
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
use registry::schema::{
    prelude::{Object, ObjectImpl, ObjectType},
    structs,
};
use serde_json::json;
use services::{
    inbuxa_blob_cleanup::{self as cleanups, NotCleaned},
    inbuxa_blob_move::{self as copies, NotPlanned},
};
use std::str::FromStr;
use store::{
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::now,
};
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
    P::Stage,
    P::CopiedAhead,
    P::AppliedAt,
    P::AppliedBy,
    P::OldStoreKept,
    P::Cleanup,
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
            // CA-1: a planned change hasn't happened yet
            P::ChangedAt | P::Node if c.stage == Stage::Planned => serde_json::Value::Null,
            P::ChangedAt => date(c.changed_at),
            P::Node => json!(c.node_id.to_string()),
            P::Stage => json!(c.stage.as_str()),
            P::CopiedAhead => match &c.copied_ahead {
                Some(a) => json!({
                    "startedAt": date(a.started_at),
                    "finishedAt": a.finished_at.map_or(serde_json::Value::Null, date),
                    "status": a.status.as_str(),
                    "copied": a.copied,
                    "alreadyThere": a.already_there,
                    "bytesCopied": a.bytes_copied,
                    "problems": a.problems,
                }),
                None => serde_json::Value::Null,
            },
            P::AppliedAt => c.applied_at.map_or(serde_json::Value::Null, date),
            // OC-1: whether there's an old store to clean up, never its settings
            P::OldStoreKept => json!(c.stage == Stage::Changed && c.old_settings.is_some()),
            P::Cleanup => match &c.cleanup {
                Some(cleanup) => {
                    let p = &cleanup.progress;
                    let status = cleanup.status_at(now);
                    json!({
                        "status": status.as_str(),
                        "dryRun": cleanup.dry_run,
                        "startedAt": date(cleanup.started_at),
                        "startedBy": cleanup.started_by,
                        "finishedAt": cleanup.finished_at.map_or(serde_json::Value::Null, date),
                        "node": cleanup.node_id.to_string(),
                        "blobsPerSecond": cleanup.blobs_per_second,
                        "bytesPerSecond": cleanup.bytes_per_second,
                        "progress": match status {
                            model::CleanupStatus::Done => 1.0,
                            _ => p.share(),
                        },
                        "blobsChecked": p.blobs_checked,
                        "deleted": p.deleted,
                        "bytesFreed": p.bytes_freed,
                        "notThere": p.not_there,
                        "missing": p.missing,
                        "damaged": p.damaged,
                        "different": p.different,
                        "unreadable": p.unreadable,
                        "problems": problems(server, c.id).await?,
                        "snapshotsBefore": cleanup.snapshots_before,
                        "error": cleanup.error,
                    })
                }
                None => serde_json::Value::Null,
            },
            P::AppliedBy => json!(c.applied_by),
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
            // A cleanup's problems are its own, under cleanup (OC-6)
            P::Problems if c.cleanup.is_some() => json!([]),
            P::Problems => problems(server, c.id).await?,
            P::Error => json!(copy.and_then(|c| c.error.clone())),
            // Write-only; a planned store's settings are never shown (CA-1)
            P::Action | P::Target | P::DryRun | P::Confirm => continue,
        };
        out.insert_unchecked(Key::Property(property.clone()), json_to_value(json));
    }
    Ok(Value::Object(out))
}

/// The kept problems of a change's latest copy or cleanup.
async fn problems(server: &Server, id: u32) -> trc::Result<serde_json::Value> {
    let problems = model::problems(server.store(), id).await?;
    let mut list = serde_json::to_value(&problems).unwrap_or_default();
    // The account as a JMAP id, like every other account id
    if let Some(items) = list.as_array_mut() {
        for item in items {
            if let Some(account) = item.get("accountId").and_then(|v| v.as_u64()) {
                item["accountId"] = json!(Id::from(account).to_string());
            }
        }
    }
    Ok(list)
}

/// OC-3: why a cleanup was refused, for the administrator.
fn cleanup_refused(refusal: CleanupRefusal) -> SetError<P> {
    let why = match refusal {
        CleanupRefusal::NotFound => return SetError::not_found(),
        CleanupRefusal::Running(id) => format!(
            "A copy or cleanup of change {} runs now; one runs at a time. Stop it or wait for it.",
            Id::from(id)
        ),
        CleanupRefusal::NotResolved => {
            "Only a change whose copy ended copied can be cleaned up.".into()
        }
        CleanupRefusal::Reverted => {
            "The blob store went back to this change's old store; there's nothing to clean up."
                .into()
        }
        CleanupRefusal::NoOldStore => "The server doesn't keep this change's old store any \
             more: its cleanup is done, or the change was resolved before old stores were kept."
            .into(),
        CleanupRefusal::NotCurrent => "This change's new store isn't the blob store now, so \
             the old store may still be needed."
            .into(),
        CleanupRefusal::PlannedThere(id) => format!(
            "Change {} is planned to copy ahead to this store. Dismiss it first.",
            Id::from(id)
        ),
        CleanupRefusal::NodeElsewhere(node, place) => format!(
            "Node {node} still has its blob store at {place}. Restart it with the new setting \
             first."
        ),
    };
    SetError::forbidden().with_description(why)
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

/// CA-7: writes a planned store's settings to the blob store setting, as an
/// update of the setting would. The reason when the registry refused it.
async fn write_setting(
    server: &Server,
    target: structs::BlobStore,
) -> trc::Result<Result<(), String>> {
    let registry = server.registry();
    let result = match registry.get(ObjectType::BlobStore.singleton()).await? {
        Some(old) if old.revision != 0 => {
            let mut new = old.clone();
            new.inner = Object::from(target).inner;
            registry
                .write(RegistryWrite::update(Id::singleton(), &new, &old))
                .await?
        }
        _ => {
            registry
                .write(RegistryWrite::insert(&Object::from(target)))
                .await?
        }
    };
    Ok(match result {
        RegistryWriteResult::Success(_) => Ok(()),
        RegistryWriteResult::ValidationError { errors } => Err(errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ")),
        other => Err(format!("{other:?}")),
    })
}

/// CA-1: the planned store's settings, as the blob store setting takes them.
fn target_settings(
    value: &Value<'_, P, BlobStoreChangeValue>,
) -> Result<structs::BlobStore, SetError<P>> {
    let json = serde_json::to_value(value).unwrap_or_default();
    let settings: structs::BlobStore = serde_json::from_value(json).map_err(|err| {
        invalid(
            P::Target,
            format!("Not a blob store setting, as x:BlobStore takes it: {err}"),
        )
    })?;
    let mut errors = Vec::new();
    if !settings.validate(&mut errors) {
        return Err(invalid(
            P::Target,
            errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    Ok(settings)
}

/// `inbuxa:BlobStoreChange/set`: the server records changes; a create plans
/// one (CA-1). An update copies or stops a copy, or applies a planned one;
/// destroy dismisses (BM-5 to BM-7, CA-2 to CA-8).
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, BlobStoreChange>,
) -> trc::Result<SetResponse<BlobStoreChange>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    'create: for (client_id, value) in request.unwrap_create() {
        let mut target = None;
        for (key, value) in value.into_expanded_object() {
            match &key {
                Key::Property(P::Target) => match target_settings(&value) {
                    Ok(settings) => target = Some(settings),
                    Err(error) => {
                        response.not_created.append(client_id, error);
                        continue 'create;
                    }
                },
                _ => {
                    response.not_created.append(
                        client_id,
                        SetError::invalid_properties()
                            .with_property(key.clone().into_owned())
                            .with_description(
                                "Planning a change takes only the new store's settings, \
                                 as target.",
                            ),
                    );
                    continue 'create;
                }
            }
        }
        let Some(target) = target else {
            response.not_created.append(
                client_id,
                SetError::forbidden().with_description(
                    "The server records a change when it starts with the blob store moved. \
                     To plan one ahead, give the new store's settings as target.",
                ),
            );
            continue;
        };
        let refused = |why: String| SetError::forbidden().with_description(why);
        match copies::plan(server, target).await? {
            Ok(change) => {
                let mut out = Map::with_capacity(1);
                out.insert_unchecked(
                    Key::Property(P::Id),
                    Value::Element(BlobStoreChangeValue::Id(Id::from(change.id))),
                );
                response.created.insert(client_id, Value::Object(out));
            }
            Err(NotPlanned::Unusable(why)) => response
                .not_created
                .append(client_id, invalid(P::Target, why)),
            Err(NotPlanned::Refused(refusal)) => response.not_created.append(
                client_id,
                refused(match refusal {
                    PlanRefusal::SamePlace => {
                        "That's where the blob store is now; there's nothing to move.".into()
                    }
                    PlanRefusal::AlreadyPlanned(id) => format!(
                        "Change {} is planned already; one at a time. Dismiss it first.",
                        Id::from(id)
                    ),
                    PlanRefusal::Unresolved(id) => format!(
                        "Change {} isn't settled: blobs only its old store has wouldn't be \
                         copied ahead. Copy or dismiss it first.",
                        Id::from(id)
                    ),
                    PlanRefusal::NoLocation => {
                        "The server hasn't recorded where its blob store is yet.".into()
                    }
                }),
            ),
        }
    }

    'update: for (id, value) in request.unwrap_update().into_valid() {
        let Ok(change_id) = u32::try_from(id.id()) else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        let mut action = None;
        let mut blobs_per_second = None;
        let mut bytes_per_second = None;
        let mut dry_run = false;
        let mut confirm = None;
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
                Key::Property(P::DryRun) => match value {
                    Value::Bool(b) => {
                        dry_run = b;
                        Ok(())
                    }
                    _ => Err(invalid(P::DryRun, "true or false.")),
                },
                Key::Property(P::Confirm) => match value {
                    Value::Element(BlobStoreChangeValue::Id(confirmed)) => {
                        confirm = Some(confirmed);
                        Ok(())
                    }
                    Value::Str(text) => {
                        confirm = Id::from_str(&text).ok();
                        Ok(())
                    }
                    _ => Err(invalid(P::Confirm, "The change's own id.")),
                },
                _ => Err(SetError::invalid_properties()
                    .with_property(key.clone().into_owned())
                    .with_description(
                        "A change can't be edited, only copied, cleaned up or stopped.",
                    )),
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
                    Err(Refusal::Moved) => response.not_updated.append(
                        id,
                        SetError::forbidden().with_description(
                            "The blob store moved since this change was planned. Dismiss it \
                             and plan again from where the blob store is now.",
                        ),
                    ),
                    Err(Refusal::NotFound) => {
                        response.not_updated.append(id, SetError::not_found())
                    }
                }
            }
            Some("apply") => {
                let why = if change.stage != Stage::Planned {
                    Some("Only a planned change can be applied.")
                } else if change.applied_at.is_some() {
                    Some("It's applied already; the setting takes effect when the nodes restart.")
                } else if change.status_at(now()) != Status::Copied {
                    Some("Copy it ahead first: it can be applied once that copy ends copied.")
                } else {
                    None
                };
                if let Some(why) = why {
                    response
                        .not_updated
                        .append(id, SetError::forbidden().with_description(why));
                    continue;
                }
                let Some(target) = change.target_settings.clone() else {
                    response.not_updated.append(id, SetError::not_found());
                    continue;
                };
                match write_setting(server, target).await? {
                    Ok(()) => {
                        let by = actor.name.clone();
                        model::update(data, change_id, |c| {
                            c.applied_at = Some(now());
                            c.applied_by = Some(by.clone());
                            true
                        })
                        .await?;
                        response.updated.append(id, None);
                    }
                    Err(why) => response.not_updated.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "The blob store setting wasn't written: {why}"
                        )),
                    ),
                }
            }
            Some("cleanUp") => {
                // OC-8: backups taken before the change still need the old store
                if !dry_run && confirm != Some(id) {
                    response.not_updated.append(
                        id,
                        SetError::forbidden().with_description(
                            "Backups of the data store taken before this change was resolved \
                             need the old store's blobs to restore in full. Keep the old store \
                             until those backups have aged out, then set confirm to this \
                             change's id. A preview (dryRun) needs no confirmation.",
                        ),
                    );
                    continue;
                }
                match cleanups::start(
                    server,
                    change_id,
                    dry_run,
                    blobs_per_second,
                    bytes_per_second,
                    actor.name.clone(),
                )
                .await?
                {
                    Ok(()) => response.updated.append(id, None),
                    Err(NotCleaned::Refused(refusal)) => {
                        response.not_updated.append(id, cleanup_refused(refusal))
                    }
                    Err(NotCleaned::Unusable(why)) => response
                        .not_updated
                        .append(id, SetError::forbidden().with_description(why)),
                    Err(NotCleaned::Overlap) => response.not_updated.append(
                        id,
                        SetError::forbidden().with_description(
                            "The old store and the blob store share a place, so deleting from \
                             one would delete from the other. Nothing was deleted.",
                        ),
                    ),
                }
            }
            Some("stop") => {
                if !change.busy(now()) {
                    response.not_updated.append(
                        id,
                        SetError::forbidden()
                            .with_description("That change isn't being copied or cleaned up."),
                    );
                    continue;
                }
                copies::stop(server, change_id).await?;
                response.updated.append(id, None);
            }
            _ => response.not_updated.append(
                id,
                invalid(P::Action, "The actions are copy, stop, apply and cleanUp."),
            ),
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
            Some(c) if c.cleaning_up(now()) => response.not_destroyed.append(
                id,
                SetError::forbidden()
                    .with_description("Its old store is being cleaned up; stop that first."),
            ),
            Some(_) => {
                model::remove(data, change_id).await?;
                // BM-7: this node stops reading through it at once, or
                // following deletes to it (CA-8); the others within a minute
                // (BM-10)
                copies::refresh(server).await;
                response.destroyed.push(id);
            }
        }
    }
    Ok(response)
}
