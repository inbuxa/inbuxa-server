/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Migration` (migrations spec): what to move into this server,
//! and the runs that move it. A create records a migration; an update's
//! `action` previews, moves, makes the final pass, stops, hands over the
//! new passwords or closes it. Destroy is refused: a closed migration stays
//! listed. Server-wide, so a tenant is refused (MG-10).

use super::relay::json_to_value;
use common::{Server, auth::AccessToken};
use inbuxa_features::{
    audit::Via,
    migration::{self as model, Migration as Stored, RunKind, Source, SourceKind, Status},
};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_migration::{Migration, MigrationProperty as P, MigrationValue},
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Property, Value};
use serde_json::json;
use services::inbuxa_migrations::{self as runs, Refusal};
use store::write::now;
use types::id::Id;

type MValue = Value<'static, P, MigrationValue>;

const ALL: &[P] = &[
    P::Id,
    P::Description,
    P::SourceKind,
    P::Source,
    P::Accounts,
    P::CreateAccounts,
    P::Parallel,
    P::Status,
    P::Run,
    P::Result,
    P::Error,
    P::Progress,
    P::Failures,
    P::NodeId,
    P::Heartbeat,
    P::Moved,
    P::DiskUsed,
    P::PasswordsWaiting,
    P::ReportBlobId,
    P::CreatedAt,
    P::CreatedBy,
    P::StartedAt,
    P::FinishedAt,
];

/// What a client may write; everything else the server sets.
const WRITABLE: &[P] = &[
    P::Description,
    P::SourceKind,
    P::Source,
    P::Accounts,
    P::CreateAccounts,
    P::Parallel,
];

/// The accounts moved at once unless the console says otherwise.
const DEFAULT_PARALLEL: u32 = 4;

fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("A migration writes into the whole server, not a tenant."))
    } else if matches!(access_token.origin(), Some(Via::Migration { .. })) {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("A migration's run can't manage migrations."))
    } else {
        Ok(())
    }
}

fn date(seconds: u64) -> serde_json::Value {
    json!(UTCDate::from_timestamp(seconds as i64).to_string())
}

fn to_value(m: &Stored, properties: &[P]) -> MValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let json = match property {
            P::Id => {
                out.insert_unchecked(
                    Key::Property(P::Id),
                    Value::Element(MigrationValue::Id(Id::from(m.id))),
                );
                continue;
            }
            P::Description => json!(m.description),
            P::SourceKind => json!(m.source_kind.as_str()),
            P::Source => serde_json::to_value(&m.source).unwrap_or_default(),
            P::Accounts => json!(m.accounts),
            P::CreateAccounts => json!(m.create_accounts),
            P::Parallel => json!(m.parallel),
            P::Status => json!(m.status.as_str()),
            P::Run => json!(m.run.map(|r| r.as_str())),
            P::Result => json!(m.result.map(|r| r.as_str())),
            P::Error => json!(m.error),
            P::Progress => serde_json::to_value(&m.progress).unwrap_or_default(),
            P::Failures => serde_json::to_value(&m.failures).unwrap_or_default(),
            P::NodeId => json!(m.node_id.map(|n| n.to_string())),
            P::Heartbeat => m.heartbeat.map_or(serde_json::Value::Null, date),
            P::Moved => json!(m.moved),
            P::DiskUsed => json!(m.disk_used),
            P::PasswordsWaiting => json!(m.passwords_waiting),
            P::ReportBlobId => json!(m.report_blob_id),
            P::CreatedAt => date(m.created_at),
            P::CreatedBy => json!(m.created_by),
            P::StartedAt => m.started_at.map_or(serde_json::Value::Null, date),
            P::FinishedAt => m.finished_at.map_or(serde_json::Value::Null, date),
            // Write-only, or only in a response
            P::Action | P::Secret | P::PasswordsBlobId => continue,
        };
        out.insert_unchecked(Key::Property(property.clone()), json_to_value(json));
    }
    Value::Object(out)
}

/// `inbuxa:Migration/get`: every migration, newest first.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<Migration>,
) -> trc::Result<GetResponse<Migration>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let mut migrations = model::all(server.store()).await?;
    migrations.reverse();
    match ids {
        None => response
            .list
            .extend(migrations.iter().map(|m| to_value(m, &properties))),
        Some(ids) => {
            for id in ids {
                match migrations.iter().find(|m| u64::from(m.id) == id.id()) {
                    Some(m) => response.list.push(to_value(m, &properties)),
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

/// What a create or an update sent.
#[derive(Default)]
struct Sent {
    fields: serde_json::Map<String, serde_json::Value>,
    action: Option<String>,
    secret: Option<String>,
}

fn sent(value: Value<'_, P, MigrationValue>) -> Result<Sent, SetError<P>> {
    let mut sent = Sent::default();
    for (key, value) in value.into_expanded_object() {
        match &key {
            Key::Property(P::Action) => match value.as_str() {
                Some(action) => sent.action = Some(action.to_string()),
                None => return Err(invalid(P::Action, "Name the action.")),
            },
            Key::Property(P::Secret) => match value.as_str() {
                Some(secret) => sent.secret = Some(secret.to_string()),
                None => return Err(invalid(P::Secret, "The secret is text.")),
            },
            Key::Property(p) if WRITABLE.contains(p) => {
                sent.fields
                    .insert(p.to_cow().into_owned(), serde_json::Value::from(value));
            }
            Key::Property(p) => return Err(invalid(p.clone(), "The server sets this.")),
            _ => {
                return Err(SetError::invalid_properties()
                    .with_property(key.into_owned())
                    .with_description("Unknown property."));
            }
        }
    }
    Ok(sent)
}

/// Applies the writable fields to a migration, checked (MG-2, MG-3).
fn apply(
    m: &mut Stored,
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), SetError<P>> {
    for (name, value) in fields {
        match name.as_str() {
            "description" => match value.as_str() {
                Some(text) => m.description = text.trim().to_string(),
                None => return Err(invalid(P::Description, "The description is text.")),
            },
            "sourceKind" => match value.as_str().and_then(SourceKind::parse) {
                Some(kind) => m.source_kind = kind,
                None => {
                    return Err(invalid(
                        P::SourceKind,
                        "imap, jmap, microsoft or google. Maildir isn't offered here: the \
                         folders would have to be on the server.",
                    ));
                }
            },
            "source" => match serde_json::from_value::<Source>(value.clone()) {
                Ok(source) => m.source = source,
                Err(err) => return Err(invalid(P::Source, err.to_string())),
            },
            "accounts" => {
                let Some(items) = value.as_array() else {
                    return Err(invalid(P::Accounts, "A list of addresses."));
                };
                let mut accounts = Vec::with_capacity(items.len());
                for item in items {
                    let Some(email) = item.as_str().and_then(model::account_email) else {
                        return Err(invalid(P::Accounts, format!("{item} isn't an address.")));
                    };
                    if !accounts.contains(&email) {
                        accounts.push(email);
                    }
                }
                m.accounts = accounts;
            }
            "createAccounts" => match value.as_bool() {
                Some(create) => m.create_accounts = create,
                None => return Err(invalid(P::CreateAccounts, "true or false.")),
            },
            "parallel" => match value.as_u64().and_then(|n| u32::try_from(n).ok()) {
                Some(parallel) => m.parallel = parallel,
                None => return Err(invalid(P::Parallel, "A number of accounts.")),
            },
            _ => {}
        }
    }
    model::validate(m).map_err(|err| {
        let property = match err.property {
            "description" => P::Description,
            "accounts" => P::Accounts,
            "parallel" => P::Parallel,
            _ => P::Source,
        };
        invalid(property, err.reason)
    })
}

fn refused(refusal: Refusal) -> SetError<P> {
    let error = match refusal {
        Refusal::NotFound => return SetError::not_found(),
        Refusal::SecretNeeded => invalid(P::Secret, refusal.describe()),
        _ => SetError::forbidden(),
    };
    error.with_description(refusal.describe())
}

/// `inbuxa:Migration/set`. The request layer records it, the secret
/// redacted (AU-3).
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, Migration>,
) -> trc::Result<SetResponse<Migration>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let data = server.store();
    let actor = server.audit_actor(access_token).await;

    for (client_id, value) in request.unwrap_create() {
        let sent = match sent(value) {
            Ok(sent) => sent,
            Err(error) => {
                response.not_created.append(client_id, error);
                continue;
            }
        };
        if sent.action.is_some() || sent.secret.is_some() {
            response.not_created.append(
                client_id,
                invalid(
                    P::Action,
                    "Create the migration first, then run it with an update.",
                ),
            );
            continue;
        }
        let Some(created_by_id) = actor.account_id else {
            response.not_created.append(
                client_id,
                SetError::forbidden().with_description("Sign in as a person to migrate."),
            );
            continue;
        };
        let mut migration = Stored {
            id: 0,
            description: String::new(),
            source_kind: SourceKind::Imap,
            source: Source::default(),
            accounts: Vec::new(),
            create_accounts: false,
            parallel: DEFAULT_PARALLEL,
            status: Status::Idle,
            run: None,
            result: None,
            error: None,
            progress: Default::default(),
            failures: Vec::new(),
            node_id: None,
            heartbeat: None,
            moved: false,
            disk_used: 0,
            passwords_waiting: false,
            report_blob_id: None,
            created_at: now(),
            created_by: actor.name.clone(),
            created_by_id,
            started_at: None,
            finished_at: None,
        };
        if !sent.fields.contains_key("sourceKind") {
            response.not_created.append(
                client_id,
                invalid(P::SourceKind, "Say where the mail is now."),
            );
            continue;
        }
        if let Err(error) = apply(&mut migration, &sent.fields) {
            response.not_created.append(client_id, error);
            continue;
        }
        let id = model::create(data, &migration).await?;
        let mut out = Map::with_capacity(1);
        out.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(MigrationValue::Id(Id::from(id))),
        );
        response.created.insert(client_id, Value::Object(out));
    }

    for (id, value) in request.unwrap_update().into_valid() {
        let sent = match sent(value) {
            Ok(sent) => sent,
            Err(error) => {
                response.not_updated.append(id, error);
                continue;
            }
        };
        let Ok(migration_id) = u32::try_from(id.id()) else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };

        // The answers first: only while nothing runs and before a move
        if !sent.fields.is_empty() {
            let mut error = None;
            let found = model::update(data, migration_id, |m| {
                error = if m.status != Status::Idle {
                    Some(SetError::forbidden().with_description(
                        "Change a migration while nothing runs, and before it's closed.",
                    ))
                } else if m.moved
                    && sent
                        .fields
                        .keys()
                        .any(|k| k == "sourceKind" || k == "source")
                {
                    Some(invalid(
                        P::Source,
                        "The accounts were moved from this source; start a new migration \
                         for another.",
                    ))
                } else {
                    let mut next = m.clone();
                    match apply(&mut next, &sent.fields) {
                        Ok(()) => {
                            *m = next;
                            None
                        }
                        Err(err) => Some(err),
                    }
                };
                error.is_none()
            })
            .await?;
            match (found, error) {
                (None, _) => {
                    response.not_updated.append(id, SetError::not_found());
                    continue;
                }
                (_, Some(error)) => {
                    response.not_updated.append(id, error);
                    continue;
                }
                _ => {}
            }
        }

        let outcome = match sent.action.as_deref() {
            None if sent.secret.is_some() => Err(invalid(
                P::Secret,
                "Give the secret with the action that needs it.",
            )),
            None => Ok(None),
            Some("preview") => runs::start(server, migration_id, RunKind::Preview, sent.secret)
                .await
                .map(|_| None)
                .map_err(refused),
            Some("move") => runs::start(server, migration_id, RunKind::Move, sent.secret)
                .await
                .map(|_| None)
                .map_err(refused),
            Some("finalPass") => runs::start(server, migration_id, RunKind::FinalPass, sent.secret)
                .await
                .map(|_| None)
                .map_err(refused),
            Some("stop") => runs::stop(server, migration_id)
                .await
                .map(|_| None)
                .map_err(refused),
            Some("close") => runs::close(server, migration_id)
                .await
                .map(|_| None)
                .map_err(refused),
            Some("passwords") => runs::take_passwords(server, migration_id)
                .await
                .map(|blob| {
                    let mut out = Map::with_capacity(1);
                    out.insert_unchecked(
                        Key::Property(P::PasswordsBlobId),
                        Value::Str(blob.into()),
                    );
                    Some(Value::Object(out))
                })
                .map_err(refused),
            Some(_) => Err(invalid(
                P::Action,
                "preview, move, finalPass, stop, passwords or close.",
            )),
        };
        match outcome {
            Ok(value) => response.updated.append(id, value),
            Err(error) => response.not_updated.append(id, error),
        }
    }

    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(
            id,
            SetError::forbidden().with_description("Close the migration instead; it stays listed."),
        );
    }
    Ok(response)
}
