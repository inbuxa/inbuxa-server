/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:HoldExport` (audit-hold-lock spec, LH-12): starting a collection
//! of what a hold keeps, and seeing how it went. The ZIP is the creator's
//! blob, to download once it's ready. Creating one is audited, with its
//! reason (AU-1.9, AU-12).

use common::{Server, auth::AccessToken};
use inbuxa_features::hold::{self, Export, ExportStatus};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_hold_export::{
        HoldExport, HoldExportProperty as P, HoldExportSetArguments, HoldExportValue,
    },
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use store::write::now;
use types::id::Id;

type LValue = Value<'static, P, HoldExportValue>;

const ALL: &[P] = &[
    P::Id,
    P::HoldId,
    P::AccountIds,
    P::Reason,
    P::Status,
    P::CreatedAt,
    P::CreatedBy,
    P::FinishedAt,
    P::BlobId,
    P::Size,
    P::Items,
    P::Sha256,
    P::Error,
];

fn date(seconds: u64) -> LValue {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

fn opt_text(value: &Option<String>) -> LValue {
    value.as_ref().map_or(Value::Null, |v| Value::Str(v.clone().into()))
}

fn to_value(export: &Export, properties: &[P]) -> LValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(HoldExportValue::Id(Id::from(export.id))),
            P::HoldId => Value::Str(Id::from(export.hold_id).to_string().into()),
            P::AccountIds => Value::Array(
                export
                    .accounts
                    .iter()
                    .map(|id| Value::Str(Id::from(*id).to_string().into()))
                    .collect(),
            ),
            P::Reason => Value::Str(export.reason.clone().into()),
            P::Status => Value::Str(
                match export.status {
                    ExportStatus::Running => "running",
                    ExportStatus::Ready => "ready",
                    ExportStatus::Failed => "failed",
                }
                .into(),
            ),
            P::CreatedAt => date(export.created_at),
            P::CreatedBy => Value::Str(export.created_by.clone().into()),
            P::FinishedAt => export.finished_at.map_or(Value::Null, date),
            P::BlobId => opt_text(&export.blob_id),
            P::Size => Value::Number(export.size.into()),
            P::Items => Value::Number(export.items.into()),
            P::Sha256 => opt_text(&export.sha256),
            P::Error => opt_text(&export.error),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:HoldExport/get`: every export, newest first.
pub async fn get(
    server: &Server,
    mut request: GetRequest<HoldExport>,
) -> trc::Result<GetResponse<HoldExport>> {
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let mut exports = hold::exports(server.store()).await?;
    exports.reverse();
    match ids {
        None => response
            .list
            .extend(exports.iter().map(|e| to_value(e, &properties))),
        Some(ids) => {
            for id in ids {
                match exports.iter().find(|e| u64::from(e.id) == id.id()) {
                    Some(export) => response.list.push(to_value(export, &properties)),
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

fn invalid(property: P, why: &str) -> SetError<P> {
    SetError::invalid_properties()
        .with_property(property)
        .with_description(why.to_string())
}

/// `inbuxa:HoldExport/set`: create starts an export; nothing else is
/// allowed. The request layer records it with its reason.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, HoldExport>,
) -> trc::Result<SetResponse<HoldExport>> {
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let arguments: HoldExportSetArguments = std::mem::take(&mut request.arguments);
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    'create: for (client_id, value) in request.unwrap_create() {
        let mut hold_id = None;
        let mut accounts = Vec::new();
        let mut reason = arguments.reason.clone();
        for (key, value) in value.into_expanded_object() {
            match (&key, &value) {
                (Key::Property(P::HoldId), Value::Str(id)) => {
                    hold_id = Id::from_str(id).ok().and_then(|id| u32::try_from(id.id()).ok())
                }
                (Key::Property(P::AccountIds), Value::Array(items)) => {
                    for item in items {
                        match item {
                            Value::Str(id) => match Id::from_str(id) {
                                Ok(id) => accounts.push(id.document_id()),
                                Err(_) => {
                                    response.not_created.append(
                                        client_id,
                                        invalid(P::AccountIds, "accountIds must be account ids."),
                                    );
                                    continue 'create;
                                }
                            },
                            _ => {
                                response.not_created.append(
                                    client_id,
                                    invalid(P::AccountIds, "accountIds must be account ids."),
                                );
                                continue 'create;
                            }
                        }
                    }
                }
                (Key::Property(P::Reason), Value::Str(r)) => reason = Some(r.to_string()),
                _ => {
                    response.not_created.append(
                        client_id,
                        SetError::invalid_properties().with_property(key.clone().into_owned()),
                    );
                    continue 'create;
                }
            }
        }
        let Some(reason) = reason
            .map(|r| r.trim().chars().take(500).collect::<String>())
            .filter(|r| !r.is_empty())
        else {
            response.not_created.append(
                client_id,
                invalid(P::Reason, "Say why: a reason is required and is kept in the audit log."),
            );
            continue;
        };
        let hold = match hold_id {
            Some(id) => hold::get(data, id).await?,
            None => None,
        };
        let Some(hold) = hold else {
            response
                .not_created
                .append(client_id, invalid(P::HoldId, "No such legal hold."));
            continue;
        };
        if !hold.is_active() {
            response.not_created.append(
                client_id,
                invalid(P::HoldId, "That hold was released; export while a hold is in place."),
            );
            continue;
        }
        let Some(created_by_id) = actor.account_id else {
            response
                .not_created
                .append(client_id, SetError::forbidden().with_description("Sign in as a person to export."));
            continue;
        };
        accounts.sort_unstable();
        accounts.dedup();
        let export = Export {
            id: 0,
            hold_id: hold.id,
            accounts,
            reason,
            created_at: now(),
            created_by: actor.name.clone(),
            created_by_id,
            status: ExportStatus::Running,
            finished_at: None,
            blob_id: None,
            size: 0,
            items: 0,
            sha256: None,
            error: None,
        };
        let id = hold::create_export(data, &export).await?;
        let export = Export { id, ..export };

        // The collection runs on its own; get says when it's ready
        let server = server.clone();
        tokio::spawn(async move {
            let mut done = export.clone();
            match crate::inbuxa::hold_export::build(&server, &hold, &export.accounts).await {
                Ok((bytes, items)) => match server.put_jmap_blob(export.created_by_id, &bytes).await {
                    Ok(blob) => {
                        done.status = ExportStatus::Ready;
                        done.blob_id = Some(blob.to_string());
                        done.size = bytes.len() as u64;
                        done.items = items as u64;
                        done.sha256 = Some(
                            Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect(),
                        );
                    }
                    Err(err) => {
                        done.status = ExportStatus::Failed;
                        done.error = Some(err.to_string());
                    }
                },
                Err(err) => {
                    done.status = ExportStatus::Failed;
                    done.error = Some(
                        err.value_as_str(trc::Key::Details)
                            .map(str::to_string)
                            .unwrap_or_else(|| err.to_string()),
                    );
                }
            }
            done.finished_at = Some(now());
            if let Err(err) = hold::update_export(server.store(), &done).await {
                trc::error!(err.details("Failed to save a legal hold export's result"));
            }
        });

        let mut out = Map::with_capacity(1);
        out.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(HoldExportValue::Id(Id::from(id))),
        );
        response.created.insert(client_id, Value::Object(out));
    }

    for (id, _) in request.unwrap_update() {
        response.not_updated.append(
            id,
            SetError::forbidden().with_description("An export can't be changed; start a new one."),
        );
    }
    for id in request.unwrap_destroy() {
        response.not_destroyed.append(
            id,
            SetError::forbidden().with_description("Exports stay listed; the file expires on its own."),
        );
    }
    Ok(response)
}
