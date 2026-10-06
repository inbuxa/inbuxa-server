/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The audit log over JMAP (audit-hold-lock spec, AU-6, AU-7, AU-9 to
//! AU-11): reading records, the retention setting, exports and
//! verification. Tenant administrators see only records whose actor or
//! target is in their tenant; retention and verification are the server's.

use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use inbuxa_features::audit::{
    Action, EntryId, Outcome, Record, Target,
    log::{self, ChainReport, Filter, MIN_KEEP_FOR_SECS, Settings},
};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        query::{Filter as QueryFilter, QueryRequest, QueryResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_audit::{
        AuditEvent, AuditExport, AuditFilter, AuditProperty as P, AuditSettings, AuditValue,
        AuditVerification,
    },
    request::IntoValid,
    types::{date::UTCDate, state::State},
};
use jmap_tools::{Key, Map, Value};
use sha2::{Digest, Sha256};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

type AValue = Value<'static, P, AuditValue>;

/// Most records one export holds.
const MAX_EXPORT: usize = 100_000;

const EVENT_PROPERTIES: &[P] = &[
    P::Id,
    P::At,
    P::Node,
    P::Actor,
    P::Via,
    P::RemoteIp,
    P::Action,
    P::Target,
    P::Changes,
    P::Details,
    P::Reason,
    P::Outcome,
];

fn ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A record's time, to the millisecond, in RFC 3339.
fn iso(at_ms: u64) -> String {
    let date = UTCDate::from_timestamp((at_ms / 1000) as i64).to_string();
    // `2026-09-27T10:00:00Z` becomes `2026-09-27T10:00:00.123Z`
    match date.strip_suffix('Z') {
        Some(date) => format!("{date}.{:03}Z", at_ms % 1000),
        None => date,
    }
}

fn json_to_value(json: serde_json::Value) -> AValue {
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

fn to_json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or_default()
}

/// Account and tenant ids as JMAP ids, not the numbers they're stored as.
fn with_jmap_ids(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(map) = value.as_object_mut() {
        for key in ["accountId", "tenantId"] {
            if let Some(id) = map.get(key).and_then(serde_json::Value::as_u64) {
                map.insert(key.into(), Id::from(id as u32).to_string().into());
            }
        }
    }
    value
}

/// One record as a JMAP object.
fn event_value(id: EntryId, record: &Record, properties: &[P]) -> AValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(AuditValue::Id(Id::new(id.to_u64()))),
            P::At => Value::Str(iso(record.at).into()),
            P::Node => Value::Number(id.node.into()),
            P::Actor => json_to_value(with_jmap_ids(to_json(&record.actor))),
            P::Via => record.via.as_ref().map_or(Value::Null, |via| {
                json_to_value(with_jmap_ids(to_json(via)))
            }),
            P::RemoteIp => record
                .remote_ip
                .map_or(Value::Null, |ip| Value::Str(ip.to_string().into())),
            P::Action => Value::Str(record.action.as_str().into()),
            P::Target => json_to_value(with_jmap_ids(to_json(&record.target))),
            P::Changes => json_to_value(to_json(&record.changes)),
            P::Details => record
                .details
                .as_ref()
                .map_or(Value::Null, |d| Value::Str(d.clone().into())),
            P::Reason => record
                .reason
                .as_ref()
                .map_or(Value::Null, |r| Value::Str(r.clone().into())),
            P::Outcome => json_to_value(to_json(&record.outcome)),
            _ => continue,
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// The tenant a caller's view is limited to (AU-9).
fn view_tenant(access_token: &AccessToken) -> Option<u32> {
    access_token.tenant_id()
}

fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("This is for server administrators."))
    } else {
        Ok(())
    }
}

/// `inbuxa:AuditEvent/get`.
pub async fn event_get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<AuditEvent>,
) -> trc::Result<GetResponse<AuditEvent>> {
    let properties = request.unwrap_properties(EVENT_PROPERTIES);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let Some(ids) = ids else {
        return Err(trc::JmapEvent::RequestTooLarge
            .into_err()
            .details("Name the records to get; use inbuxa:AuditEvent/query to find them."));
    };
    let tenant = view_tenant(access_token);
    for id in ids {
        let entry = EntryId::from_u64(id.id());
        match log::get(server.store(), entry).await? {
            Some(record) if tenant.is_none_or(|tenant| log::in_tenant(&record, tenant)) => {
                response.list.push(event_value(entry, &record, &properties));
            }
            _ => response.push_not_found(id),
        }
    }
    Ok(response)
}

fn date_ms(value: &str) -> Result<u64, String> {
    UTCDate::from_str(value)
        .map(|date| date.timestamp().max(0) as u64 * 1000)
        .map_err(|_| format!("{value} isn't a UTC date."))
}

/// The conditions of a query filter, all of which must hold. `Or` and
/// `Not` aren't supported.
fn build_filter(conditions: Vec<QueryFilter<AuditFilter>>) -> trc::Result<Filter> {
    let unsupported = |why: String| trc::JmapEvent::UnsupportedFilter.into_err().details(why);
    let mut filter = Filter::default();
    for condition in conditions {
        match condition {
            QueryFilter::Property(condition) => match condition {
                AuditFilter::After(date) => {
                    filter.after = Some(date_ms(&date).map_err(unsupported)?)
                }
                AuditFilter::Before(date) => {
                    filter.before = Some(date_ms(&date).map_err(unsupported)?)
                }
                AuditFilter::ActorId(id) => filter.actor_id = Some(id.document_id()),
                AuditFilter::Action(action) => {
                    filter.action =
                        Some(Action::parse(&action).ok_or_else(|| {
                            unsupported(format!("{action} isn't an audit action."))
                        })?)
                }
                AuditFilter::TargetKind(kind) => filter.target_kind = Some(kind),
                AuditFilter::TargetId(id) => filter.target_id = Some(id),
                AuditFilter::AccountId(id) => filter.account_id = Some(id.document_id()),
                AuditFilter::TenantId(id) => filter.tenant_id = Some(id.document_id()),
                AuditFilter::Outcome(outcome) => filter.outcome = Some(outcome),
                AuditFilter::RemoteIp(ip) => {
                    filter.remote_ip = Some(
                        ip.parse()
                            .map_err(|_| unsupported(format!("{ip} isn't an IP address.")))?,
                    )
                }
                AuditFilter::Text(text) => filter.text = Some(text),
                AuditFilter::_T(other) => {
                    return Err(unsupported(format!("Unknown filter property {other}.")));
                }
            },
            QueryFilter::And | QueryFilter::Close => {}
            QueryFilter::Or | QueryFilter::Not => {
                return Err(unsupported(
                    "Audit queries take conditions that must all hold; OR and NOT aren't supported."
                        .into(),
                ));
            }
        }
    }
    Ok(filter)
}

/// Applies the caller's reach: a tenant administrator sees its tenant only.
fn scoped(mut filter: Filter, access_token: &AccessToken) -> Option<Filter> {
    if let Some(tenant) = view_tenant(access_token) {
        match filter.tenant_id {
            Some(asked) if asked != tenant => return None,
            _ => filter.tenant_id = Some(tenant),
        }
    }
    Some(filter)
}

/// `inbuxa:AuditEvent/query`: newest first.
pub async fn event_query(
    server: &Server,
    access_token: &AccessToken,
    request: QueryRequest<AuditEvent>,
) -> trc::Result<QueryResponse> {
    let filter = build_filter(request.filter)?;
    let position = request.position.unwrap_or(0);
    if position < 0 || request.anchor.is_some() {
        return Err(trc::JmapEvent::UnsupportedFilter
            .into_err()
            .details("Audit queries page by a position from the start."));
    }
    let limit = request
        .limit
        .unwrap_or(log::MAX_QUERY_LIMIT)
        .min(log::MAX_QUERY_LIMIT);
    let count_all = request.calculate_total.unwrap_or(false);
    let (ids, total) = match scoped(filter, access_token) {
        Some(filter) => {
            log::query(server.store(), &filter, position as usize, limit, count_all).await?
        }
        None => (Vec::new(), 0),
    };
    Ok(QueryResponse {
        account_id: request.account_id,
        query_state: State::Initial,
        can_calculate_changes: false,
        position,
        ids: ids.into_iter().map(|id| Id::new(id.to_u64())).collect(),
        total: count_all.then_some(total),
        limit: Some(limit),
    })
}

fn settings_value(settings: &Settings, properties: &[P]) -> Value<'static, P, AuditValue> {
    let mut out = Map::with_capacity(2);
    for property in properties {
        let value = match property {
            P::Id => Value::Element(AuditValue::Id(Id::singleton())),
            P::KeepForDays => Value::Number((settings.keep_for_secs / 86_400).into()),
            _ => continue,
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:AuditSettings/get`: a singleton.
pub async fn settings_get(
    server: &Server,
    mut request: GetRequest<AuditSettings>,
) -> trc::Result<GetResponse<AuditSettings>> {
    let properties = request.unwrap_properties(&[P::Id, P::KeepForDays]);
    let (ids, not_found) = request.unwrap_ids(1)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let settings = log::settings(server.store()).await?;
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

/// `inbuxa:AuditSettings/set`: update `keepForDays` on the singleton
/// (AU-7). The request layer records the change.
pub async fn settings_set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, AuditSettings>,
) -> trc::Result<SetResponse<AuditSettings>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (client_id, _) in request.unwrap_create() {
        response
            .not_created
            .append(client_id, SetError::singleton());
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(id, SetError::singleton());
    }
    for (id, value) in request.unwrap_update().into_valid() {
        if !id.is_singleton() {
            response.not_updated.append(id, SetError::not_found());
            continue;
        }
        let mut settings = log::settings(server.store()).await?;
        let mut error = None;
        for (key, value) in value.into_expanded_object() {
            match (&key, value) {
                (Key::Property(P::KeepForDays), Value::Number(days)) => {
                    let secs = days.cast_to_u64().saturating_mul(86_400);
                    if secs < MIN_KEEP_FOR_SECS {
                        error = Some(
                            SetError::invalid_properties()
                                .with_property(P::KeepForDays)
                                .with_description(format!(
                                    "Records are kept for at least {} days.",
                                    MIN_KEEP_FOR_SECS / 86_400
                                )),
                        );
                        break;
                    }
                    settings.keep_for_secs = secs;
                }
                (Key::Property(P::KeepForDays), Value::Null) => {
                    settings = Settings::default();
                }
                (Key::Property(P::Id), _) => {}
                _ => {
                    error = Some(SetError::invalid_properties().with_property(key.into_owned()));
                    break;
                }
            }
        }
        match error {
            Some(error) => response.not_updated.append(id, error),
            None => {
                log::set_settings(server.store(), &settings).await?;
                // Audit retention is also the inventory's (personal-data catalog)
                server.inventory_snapshot_after("inbuxa:AuditSettings").await;
                response.updated.append(id, None);
            }
        }
    }
    Ok(response)
}

/// Reads an export's `filter` object, the same conditions a query takes.
fn export_filter(value: Option<AValue>) -> Result<Filter, String> {
    let Some(value) = value else {
        return Ok(Filter::default());
    };
    let json: serde_json::Value = value.into();
    let Some(map) = json.as_object() else {
        return Err("The filter must be an object.".into());
    };
    let mut filter = Filter::default();
    for (key, value) in map {
        let text = || {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{key} must be a string."))
        };
        let id = || {
            Id::from_str(&text()?)
                .map(|id| id.document_id())
                .map_err(|_| format!("{key} must be an id."))
        };
        match key.as_str() {
            "after" => filter.after = Some(date_ms(&text()?)?),
            "before" => filter.before = Some(date_ms(&text()?)?),
            "actorId" => filter.actor_id = Some(id()?),
            "action" => {
                filter.action =
                    Some(Action::parse(&text()?).ok_or_else(|| "Unknown action.".to_string())?)
            }
            "targetKind" => filter.target_kind = Some(text()?),
            "targetId" => filter.target_id = Some(text()?),
            "accountId" => filter.account_id = Some(id()?),
            "tenantId" => filter.tenant_id = Some(id()?),
            "outcome" => filter.outcome = Some(text()?),
            "remoteIp" => {
                filter.remote_ip = Some(
                    text()?
                        .parse()
                        .map_err(|_| "remoteIp must be an address.")?,
                )
            }
            "text" => filter.text = Some(text()?),
            other => return Err(format!("Unknown filter property {other}.")),
        }
    }
    Ok(filter)
}

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Csv,
    JsonLines,
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// The export file's text: one line per record, then a manifest line
/// (AU-11). Each line carries the entry's hash and the hash it follows.
fn render(
    format: Format,
    entries: &[(EntryId, Record, String, String)],
    filter_json: &serde_json::Value,
) -> (Vec<u8>, String) {
    let mut out = String::new();
    if format == Format::Csv {
        out.push_str(
            "id,at,node,actor,actorId,actorTenantId,via,remoteIp,action,targetKind,targetId,\
             targetName,targetAccountId,targetTenantId,outcome,error,changes,details,reason,\
             hash,prev\r\n",
        );
    }
    for (id, record, hash, prev) in entries {
        match format {
            Format::Csv => {
                let (outcome, error) = match &record.outcome {
                    Outcome::Refused { error, .. } => ("refused", error.as_str()),
                    other => (other.as_str(), ""),
                };
                let opt = |v: Option<u32>| v.map(|v| Id::from(v).to_string()).unwrap_or_default();
                let fields = [
                    Id::new(id.to_u64()).to_string(),
                    iso(record.at),
                    id.node.to_string(),
                    record.actor.name.clone(),
                    opt(record.actor.account_id),
                    opt(record.actor.tenant_id),
                    record
                        .via
                        .as_ref()
                        .map(|via| to_json(via).to_string())
                        .unwrap_or_default(),
                    record
                        .remote_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_default(),
                    record.action.as_str().to_string(),
                    record.target.kind.clone(),
                    record.target.id.clone().unwrap_or_default(),
                    record.target.name.clone().unwrap_or_default(),
                    opt(record.target.account_id),
                    opt(record.target.tenant_id),
                    outcome.to_string(),
                    error.to_string(),
                    if record.changes.is_empty() {
                        String::new()
                    } else {
                        to_json(&record.changes).to_string()
                    },
                    record.details.clone().unwrap_or_default(),
                    record.reason.clone().unwrap_or_default(),
                    hash.clone(),
                    prev.clone(),
                ];
                out.push_str(
                    &fields
                        .iter()
                        .map(|field| csv_field(field))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                out.push_str("\r\n");
            }
            Format::JsonLines => {
                let mut line = to_json(record);
                if let Some(map) = line.as_object_mut() {
                    for key in ["actor", "target", "via"] {
                        if let Some(value) = map.remove(key) {
                            map.insert(key.into(), with_jmap_ids(value));
                        }
                    }
                    map.insert("id".into(), Id::new(id.to_u64()).to_string().into());
                    map.insert("node".into(), id.node.into());
                    map.insert("at".into(), iso(record.at).into());
                    map.insert("hash".into(), hash.clone().into());
                    map.insert("prev".into(), prev.clone().into());
                }
                out.push_str(&line.to_string());
                out.push('\n');
            }
        }
    }
    let body_hash = hex(&Sha256::digest(out.as_bytes()));
    let manifest = serde_json::json!({
        "manifest": {
            "exportedAt": iso(ms()),
            "filter": filter_json,
            "count": entries.len(),
            "first": entries.last().map(|(id, ..)| Id::new(id.to_u64()).to_string()),
            "last": entries.first().map(|(id, ..)| Id::new(id.to_u64()).to_string()),
            "recordsSha256": body_hash,
        }
    });
    match format {
        Format::Csv => {
            out.push_str("# ");
            out.push_str(&manifest.to_string());
            out.push_str("\r\n");
        }
        Format::JsonLines => {
            out.push_str(&manifest.to_string());
            out.push('\n');
        }
    }
    let file_hash = hex(&Sha256::digest(out.as_bytes()));
    (out.into_bytes(), file_hash)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `inbuxa:AuditExport/set`: create `{format, filter}`; the created object
/// names the file's blob, its size, the number of records and its SHA-256
/// (AU-11). The export is recorded before the file is built, and refused
/// if it can't be (AU-1.9, AU-3).
pub async fn export_set(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    mut request: SetRequest<'_, AuditExport>,
) -> trc::Result<SetResponse<AuditExport>> {
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (id, _) in request.unwrap_update().into_valid() {
        response.not_updated.append(
            id,
            SetError::forbidden().with_description("Exports can't be changed."),
        );
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(
            id,
            SetError::forbidden().with_description("Exports aren't kept to destroy."),
        );
    }

    for (client_id, value) in request.unwrap_create() {
        let mut format = Format::Csv;
        let mut filter_value = None;
        let mut reason = None;
        let mut invalid = None;
        for (key, value) in value.into_expanded_object() {
            match (&key, value) {
                (Key::Property(P::Format), Value::Str(f)) if f == "csv" => format = Format::Csv,
                (Key::Property(P::Format), Value::Str(f)) if f == "jsonl" => {
                    format = Format::JsonLines
                }
                (Key::Property(P::Filter), value) => filter_value = Some(value.into_owned()),
                (Key::Property(P::Reason), Value::Str(r)) => {
                    reason = Some(r.chars().take(500).collect::<String>())
                }
                (Key::Property(P::Reason), Value::Null) => {}
                _ => {
                    invalid = Some(SetError::invalid_properties().with_property(key.into_owned()));
                    break;
                }
            }
        }
        if let Some(error) = invalid {
            response.not_created.append(client_id, error);
            continue;
        }
        let filter_json: serde_json::Value = filter_value
            .clone()
            .map(Into::into)
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let filter = match export_filter(filter_value) {
            Ok(filter) => filter,
            Err(why) => {
                response.not_created.append(
                    client_id,
                    SetError::invalid_properties()
                        .with_property(P::Filter)
                        .with_description(why),
                );
                continue;
            }
        };

        // Recorded first: no export leaves without its record
        let record = Record {
            at: ms(),
            actor: server.audit_actor(access_token).await,
            via: access_token.origin().cloned(),
            remote_ip: Some(session.remote_ip),
            action: Action::Export,
            target: Target {
                kind: "inbuxa:AuditEvent".into(),
                tenant_id: access_token.tenant_id(),
                ..Default::default()
            },
            changes: vec![],
            details: Some(format!(
                "{} export, filter {filter_json}",
                if format == Format::Csv {
                    "CSV"
                } else {
                    "JSON Lines"
                }
            )),
            reason,
            outcome: Outcome::Pending,
        };
        let entry = server.audit_append(&record).await.map_err(|err| {
            err.details("The audit log couldn't be written, so nothing was exported.")
        })?;

        let result = build_export(server, access_token, format, filter, &filter_json).await;
        let outcome = match &result {
            Ok(_) => Outcome::success(),
            Err(_) => Outcome::refused("serverFail", None),
        };
        let _ = server.audit_finish(entry, outcome).await;
        let (blob_id, size, count, sha256) = result?;

        let mut created = Map::with_capacity(5);
        created.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(AuditValue::Id(Id::new(entry.to_u64()))),
        );
        created.insert_unchecked(Key::Property(P::BlobId), Value::Str(blob_id.into()));
        created.insert_unchecked(Key::Property(P::Size), Value::Number((size as u64).into()));
        created.insert_unchecked(
            Key::Property(P::Count),
            Value::Number((count as u64).into()),
        );
        created.insert_unchecked(Key::Property(P::Sha256), Value::Str(sha256.into()));
        response.created.insert(client_id, Value::Object(created));
    }
    Ok(response)
}

async fn build_export(
    server: &Server,
    access_token: &AccessToken,
    format: Format,
    filter: Filter,
    filter_json: &serde_json::Value,
) -> trc::Result<(String, usize, usize, String)> {
    let mut entries = Vec::new();
    if let Some(filter) = scoped(filter, access_token) {
        for id in log::query_all(server.store(), &filter, MAX_EXPORT).await? {
            if let Some((record, hash, prev)) = log::get_with_hash(server.store(), id).await? {
                entries.push((id, record, hash, prev));
            }
        }
    }
    let (bytes, sha256) = render(format, &entries, filter_json);
    let blob = server
        .put_jmap_blob(access_token.account_id(), &bytes)
        .await?;
    Ok((blob.to_string(), bytes.len(), entries.len(), sha256))
}

/// `inbuxa:AuditVerification/set`: create `{}` to recheck every node's
/// chain (AU-6). Server administrators only.
pub async fn verification_set(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    mut request: SetRequest<'_, AuditVerification>,
) -> trc::Result<SetResponse<AuditVerification>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (id, _) in request.unwrap_update().into_valid() {
        response.not_updated.append(id, SetError::forbidden());
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(id, SetError::forbidden());
    }
    for (client_id, _) in request.unwrap_create() {
        let chains = log::verify(server.store()).await?;
        let verified = chains.iter().all(|chain| chain.broken_at.is_none());
        let record = Record {
            at: ms(),
            actor: server.audit_actor(access_token).await,
            via: access_token.origin().cloned(),
            remote_ip: Some(session.remote_ip),
            action: Action::Verify,
            target: Target {
                kind: "inbuxa:AuditEvent".into(),
                ..Default::default()
            },
            changes: vec![],
            details: Some(summary(&chains)),
            reason: None,
            outcome: if verified {
                Outcome::success()
            } else {
                Outcome::refused("chainBroken", None)
            },
        };
        let entry = server.audit_append(&record).await.ok();

        let mut created = Map::with_capacity(3);
        created.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(AuditValue::Id(Id::new(
                entry.map_or(0, |entry| entry.to_u64()),
            ))),
        );
        created.insert_unchecked(Key::Property(P::Verified), Value::Bool(verified));
        created.insert_unchecked(Key::Property(P::Chains), json_to_value(to_json(&chains)));
        response.created.insert(client_id, Value::Object(created));
    }
    Ok(response)
}

fn summary(chains: &[ChainReport]) -> String {
    chains
        .iter()
        .map(|chain| match (&chain.broken_at, &chain.reason) {
            (Some(at), Some(reason)) => format!("node {}: broken at {at}: {reason}", chain.node),
            _ => format!(
                "node {}: {} entries verified ({} to {})",
                chain.node, chain.entries, chain.first_seq, chain.last_seq
            ),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use inbuxa_features::audit::{Actor, Change};

    #[test]
    fn times_keep_milliseconds() {
        assert_eq!(iso(1_790_000_000_123), "2026-09-21T14:13:20.123Z");
        assert_eq!(iso(1_790_000_000_000), "2026-09-21T14:13:20.000Z");
    }

    #[test]
    fn csv_quotes_what_needs_it() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn exports_end_with_a_manifest() {
        let record = Record {
            at: 1_790_000_000_000,
            actor: Actor::account(3, "admin@example.com", None),
            via: None,
            remote_ip: None,
            action: Action::Update,
            target: Target {
                kind: "x:Domain".into(),
                name: Some("example.com".into()),
                ..Default::default()
            },
            changes: vec![Change::new(
                "isEnabled",
                Some(true.into()),
                Some(false.into()),
            )],
            details: None,
            reason: None,
            outcome: Outcome::success(),
        };
        let entries = vec![(EntryId { node: 1, seq: 9 }, record, "h".into(), "p".into())];
        let filter = serde_json::json!({});
        for format in [Format::Csv, Format::JsonLines] {
            let (bytes, sha) = render(format, &entries, &filter);
            let text = String::from_utf8(bytes.clone()).unwrap();
            let last = text.trim_end().lines().last().unwrap();
            assert!(last.contains("\"manifest\""), "{last}");
            assert!(last.contains("\"count\":1"));
            assert_eq!(sha, hex(&Sha256::digest(&bytes)));
            assert!(text.contains("example.com"));
        }
    }

    #[test]
    fn filters_parse() {
        let filter = build_filter(vec![
            QueryFilter::Property(AuditFilter::Action("signIn".into())),
            QueryFilter::Property(AuditFilter::After("2026-09-01T00:00:00Z".into())),
        ])
        .unwrap();
        assert_eq!(filter.action, Some(Action::SignIn));
        assert!(filter.after.is_some());
        assert!(build_filter(vec![QueryFilter::Or]).is_err());
        assert!(
            build_filter(vec![QueryFilter::Property(AuditFilter::Action("x".into()))]).is_err()
        );
    }

    #[test]
    fn tenant_view_is_forced() {
        let token = AccessToken::from_permissions(5, []);
        let filter = scoped(Filter::default(), &token).unwrap();
        assert_eq!(filter.tenant_id, None);
    }
}
