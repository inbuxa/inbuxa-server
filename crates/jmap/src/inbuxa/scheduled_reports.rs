/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:ScheduledReport` and `inbuxa:ScheduledReportSettings`
//! (scheduled-reports spec).
//!
//! Reading needs `sysScheduledReportGet`, changing (and Send now, RP-18)
//! `sysScheduledReportUpdate`. A tenant administrator sees and changes only
//! their own tenant's reports, and a report they create is their tenant's
//! (RP-22). The weekly digest can be changed or turned off, not deleted, and
//! its recipients are the system administrators (RP-21). Recipients must be
//! accounts on this server (RP-23).

use common::{Server, auth::AccessToken};
use inbuxa_features::scheduled_reports::{self as model, Report, RunStatus, Schedule, Section};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::{
        inbuxa_report_export::{ReportExport, ReportExportProperty as X, ReportExportValue},
        inbuxa_scheduled_report::{
            ScheduledReport, ScheduledReportProperty as R, ScheduledReportValue,
        },
        inbuxa_scheduled_report_settings::{
            ScheduledReportSettings, ScheduledReportSettingsProperty as S,
            ScheduledReportSettingsValue,
        },
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Element, Key, Map, Property, Value};
use std::{borrow::Cow, str::FromStr};
use store::write::now;
use types::id::Id;

const REPORT: &[R] = &[
    R::Id,
    R::Name,
    R::Enabled,
    R::BuiltIn,
    R::Sections,
    R::Schedule,
    R::Recipients,
    R::AttachCsv,
    R::MemberTenantId,
    R::CreatedAt,
    R::NextRunAt,
    R::Runs,
];

const SETTINGS: &[S] = &[S::Id, S::FromName, S::FromAddress];

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

fn date<P: Property, E: Element>(seconds: u64) -> Value<'static, P, E> {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

/// Whether this administrator may see or change the report (RP-22).
fn visible(access_token: &AccessToken, report: &Report) -> bool {
    match access_token.tenant_id() {
        Some(tenant) => report.tenant_id == Some(tenant),
        None => true,
    }
}

fn report_value(report: &Report, properties: &[R]) -> Value<'static, R, ScheduledReportValue> {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            R::Id => Value::Element(ScheduledReportValue::Id(Id::from(report.id))),
            R::Name => Value::Str(report.name.clone().into()),
            R::Enabled => Value::Bool(report.enabled),
            R::BuiltIn => Value::Bool(report.built_in),
            R::Sections => Value::Array(
                report
                    .sections
                    .iter()
                    .map(|s| Value::Str(s.as_str().into()))
                    .collect(),
            ),
            R::Schedule => {
                json_to_value(serde_json::to_value(&report.schedule).unwrap_or_default())
            }
            R::Recipients => Value::Array(
                report
                    .recipients
                    .iter()
                    .map(|r| Value::Str(r.clone().into()))
                    .collect(),
            ),
            R::AttachCsv => Value::Bool(report.attach_csv),
            R::MemberTenantId => report
                .tenant_id
                .map(|t| Value::Element(ScheduledReportValue::Id(Id::from(t))))
                .unwrap_or(Value::Null),
            R::CreatedAt => date(report.created_at),
            R::NextRunAt => report
                .enabled
                .then(|| report.schedule.next_due(report.last_due))
                .flatten()
                .map(date)
                .unwrap_or(Value::Null),
            R::Runs => Value::Array(
                report
                    .runs
                    .iter()
                    .map(|run| {
                        json_to_value(serde_json::json!({
                            "at": UTCDate::from_timestamp(run.at as i64).to_string(),
                            "byHand": run.by_hand,
                            "status": match run.status {
                                RunStatus::Sent => "sent",
                                RunStatus::Failed => "failed",
                            },
                            "reason": run.reason,
                            "recipients": run.recipients,
                            "size": run.size,
                        }))
                    })
                    .collect(),
            ),
            R::SendNow => Value::Null,
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:ScheduledReport/get`.
pub async fn get_reports(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<ScheduledReport>,
) -> trc::Result<GetResponse<ScheduledReport>> {
    let properties = request.unwrap_properties(REPORT);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    model::ensure_digest(server.store(), now()).await?;
    let reports: Vec<Report> = model::reports(server.store())
        .await?
        .into_iter()
        .filter(|r| visible(access_token, r))
        .collect();
    match ids {
        None => {
            response.list = reports
                .iter()
                .map(|r| report_value(r, &properties))
                .collect();
        }
        Some(ids) => {
            for id in ids {
                match reports.iter().find(|r| r.id == id.id()) {
                    Some(report) => response.list.push(report_value(report, &properties)),
                    None => response.push_not_found(id),
                }
            }
        }
    }
    Ok(response)
}

/// What a create or an update may set, applied onto `report`. Returns
/// whether Send now was asked for.
fn apply(
    report: &mut Report,
    value: Value<'_, R, ScheduledReportValue>,
) -> Result<bool, SetError<R>> {
    let invalid = |property: R, why: &str| {
        SetError::invalid_properties()
            .with_property(property)
            .with_description(why.to_string())
    };
    let mut send_now = false;
    for (key, value) in value.into_expanded_object() {
        let Key::Property(property) = key else {
            return Err(SetError::invalid_properties().with_property(key.into_owned()));
        };
        let json = serde_json::to_value(&value).unwrap_or_default();
        match property {
            R::Name => match json.as_str() {
                Some(name) => report.name = name.trim().to_string(),
                None => return Err(invalid(R::Name, "A name.")),
            },
            R::Enabled => match json.as_bool() {
                Some(enabled) => report.enabled = enabled,
                None => return Err(invalid(R::Enabled, "true or false.")),
            },
            R::AttachCsv => match json.as_bool() {
                Some(attach) => report.attach_csv = attach,
                None => return Err(invalid(R::AttachCsv, "true or false.")),
            },
            R::Sections => {
                let sections = json.as_array().and_then(|items| {
                    items
                        .iter()
                        .map(|i| i.as_str().and_then(Section::parse))
                        .collect::<Option<Vec<_>>>()
                });
                match sections {
                    Some(sections) => report.sections = sections,
                    None => return Err(invalid(R::Sections, "A list of section names.")),
                }
            }
            R::Schedule => match serde_json::from_value::<Schedule>(json) {
                Ok(schedule) => report.schedule = schedule,
                Err(_) => return Err(invalid(R::Schedule, "A schedule.")),
            },
            R::Recipients => {
                let recipients = json.as_array().and_then(|items| {
                    items
                        .iter()
                        .map(|i| i.as_str().map(|s| s.trim().to_lowercase()))
                        .collect::<Option<Vec<_>>>()
                });
                match recipients {
                    Some(r) if report.built_in && !r.is_empty() => {
                        return Err(invalid(
                            R::Recipients,
                            "The weekly digest goes to the system administrators.",
                        ));
                    }
                    Some(r) => report.recipients = r,
                    None => return Err(invalid(R::Recipients, "A list of addresses.")),
                }
            }
            R::SendNow => send_now = json.as_bool().unwrap_or(false),
            other => return Err(invalid(other, "The server sets this.")),
        }
    }
    Ok(send_now)
}

/// RP-23: every recipient is an account on this server.
async fn check_recipients(server: &Server, report: &Report) -> trc::Result<Option<String>> {
    for address in &report.recipients {
        if server.rcpt_id_from_email(address).await?.is_none() {
            return Ok(Some(format!(
                "{address} isn't an account on this server. Reports only go to accounts here."
            )));
        }
    }
    Ok(None)
}

/// `inbuxa:ScheduledReport/set`.
pub async fn set_reports(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, ScheduledReport>,
) -> trc::Result<SetResponse<ScheduledReport>> {
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let data = server.store();
    model::ensure_digest(data, now()).await?;

    for (client_id, value) in request.unwrap_create() {
        let existing = model::reports(data).await?;
        let mut report = Report {
            id: model::next_id(&existing),
            enabled: true,
            tenant_id: access_token.tenant_id(),
            created_at: now(),
            last_due: now(),
            ..Report::default()
        };
        let send_now = match apply(&mut report, value) {
            Ok(send_now) => send_now,
            Err(err) => {
                response.not_created.append(client_id, err);
                continue;
            }
        };
        if let Err(why) = report.validate() {
            response.not_created.append(
                client_id,
                SetError::invalid_properties().with_description(why),
            );
            continue;
        }
        if let Some(why) = check_recipients(server, &report).await? {
            response.not_created.append(
                client_id,
                SetError::invalid_properties()
                    .with_property(R::Recipients)
                    .with_description(why),
            );
            continue;
        }
        model::put_report(data, &report).await?;
        if send_now {
            services::inbuxa_scheduled_reports::send_now(server.clone(), report.id);
        }
        response
            .created
            .insert(client_id, report_value(&report, &[R::Id, R::NextRunAt]));
    }

    for (id, value) in request.unwrap_update().into_valid() {
        let Some(mut report) = model::report(data, id.id())
            .await?
            .filter(|r| visible(access_token, r))
        else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        let schedule_before = report.schedule.clone();
        let send_now = match apply(&mut report, value) {
            Ok(send_now) => send_now,
            Err(err) => {
                response.not_updated.append(id, err);
                continue;
            }
        };
        if let Err(why) = report.validate() {
            response
                .not_updated
                .append(id, SetError::invalid_properties().with_description(why));
            continue;
        }
        if let Some(why) = check_recipients(server, &report).await? {
            response.not_updated.append(
                id,
                SetError::invalid_properties()
                    .with_property(R::Recipients)
                    .with_description(why),
            );
            continue;
        }
        // A new schedule counts from now, not from the last run
        if report.schedule != schedule_before {
            report.last_due = report.last_due.max(now());
        }
        model::put_report(data, &report).await?;
        if send_now {
            services::inbuxa_scheduled_reports::send_now(server.clone(), report.id);
        }
        response.updated.append(id, None);
    }

    for id in request.unwrap_destroy().into_valid() {
        match model::report(data, id.id())
            .await?
            .filter(|r| visible(access_token, r))
        {
            None => response.not_destroyed.append(id, SetError::not_found()),
            Some(report) if report.built_in => response.not_destroyed.append(
                id,
                SetError::forbidden()
                    .with_description("The weekly digest can be turned off, not deleted."),
            ),
            Some(_) => {
                model::delete_report(data, id.id()).await?;
                response.destroyed.push(id);
            }
        }
    }
    Ok(response)
}

fn settings_value(
    settings: &model::Settings,
    default_address: &str,
    properties: &[S],
) -> Value<'static, S, ScheduledReportSettingsValue> {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            S::Id => Value::Element(ScheduledReportSettingsValue::Id(Id::singleton())),
            S::FromName => Value::Str(settings.from_name().to_string().into()),
            S::FromAddress => Value::Str(
                settings
                    .from_address
                    .clone()
                    .unwrap_or_else(|| default_address.to_string())
                    .into(),
            ),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

fn default_address(server: &Server) -> String {
    format!("postmaster@{}", server.core.email.default_domain_name)
}

/// `inbuxa:ScheduledReportSettings/get`.
pub async fn get_settings(
    server: &Server,
    _access_token: &AccessToken,
    mut request: GetRequest<ScheduledReportSettings>,
) -> trc::Result<GetResponse<ScheduledReportSettings>> {
    let properties = request.unwrap_properties(SETTINGS);
    let (ids, not_found) = request.unwrap_ids(1)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let settings = model::settings(server.store()).await?;
    let default = default_address(server);
    match ids {
        None => response
            .list
            .push(settings_value(&settings, &default, &properties)),
        Some(ids) => {
            for id in ids {
                if id.is_singleton() {
                    response
                        .list
                        .push(settings_value(&settings, &default, &properties));
                } else {
                    response.push_not_found(id);
                }
            }
        }
    }
    Ok(response)
}

/// `inbuxa:ScheduledReportSettings/set`: the server's, not a tenant's.
pub async fn set_settings(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, ScheduledReportSettings>,
) -> trc::Result<SetResponse<ScheduledReportSettings>> {
    if access_token.tenant_id().is_some() {
        return Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Who reports come from is the server's."));
    }
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
            let json = serde_json::to_value(&value).unwrap_or_default();
            match &key {
                Key::Property(S::FromName) => {
                    settings.from_name = json
                        .as_str()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                }
                Key::Property(S::FromAddress) => {
                    match json.as_str().map(|s| s.trim().to_lowercase()) {
                        Some(a) if a.is_empty() => settings.from_address = None,
                        Some(a) if a.contains('@') && !a.ends_with('@') => {
                            settings.from_address = Some(a)
                        }
                        _ => {
                            error = Some(
                                SetError::invalid_properties()
                                    .with_property(S::FromAddress)
                                    .with_description("An email address."),
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

/// RP-19: the furthest back a download goes, as far as metrics are kept.
const EXPORT_MAX_AGE: u64 = 90 * 86_400;

fn parse_date(value: &serde_json::Value) -> Option<u64> {
    value
        .as_str()
        .and_then(|s| UTCDate::from_str(s).ok())
        .map(|d| d.timestamp().max(0) as u64)
}

/// `inbuxa:ReportExport/get`: exports aren't kept, so there's never one.
pub async fn get_exports(
    _server: &Server,
    _access_token: &AccessToken,
    mut request: GetRequest<ReportExport>,
) -> trc::Result<GetResponse<ReportExport>> {
    let (ids, not_found) = request.unwrap_ids(1)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    for id in ids.unwrap_or_default() {
        response.push_not_found(id);
    }
    Ok(response)
}

/// `inbuxa:ReportExport/set`: create `{reportId, from?, to?}` builds that
/// report for the period (by default its last full one) as a ZIP of a
/// summary and CSVs, stored as an upload, and mails nobody (RP-19).
pub async fn set_exports(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, ReportExport>,
) -> trc::Result<SetResponse<ReportExport>> {
    use sha2::{Digest, Sha256};
    use std::io::{Cursor, Write};
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

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
        let json = serde_json::to_value(&value).unwrap_or_default();
        let invalid = |property: X, why: &str| {
            SetError::invalid_properties()
                .with_property(property)
                .with_description(why.to_string())
        };
        let report = match json
            .get("reportId")
            .and_then(|v| v.as_str())
            .and_then(|s| Id::from_str(s).ok())
        {
            Some(id) => model::report(server.store(), id.id())
                .await?
                .filter(|r| visible(access_token, r)),
            None => None,
        };
        let Some(report) = report else {
            response
                .not_created
                .append(client_id, invalid(X::ReportId, "A report you can see."));
            continue;
        };
        let now = now();
        let (default_from, default_to) = report.schedule.period(
            report
                .schedule
                .next_due(report.last_due.min(now))
                .filter(|d| *d <= now)
                .unwrap_or(report.last_due.min(now)),
        );
        let from = json
            .get("from")
            .and_then(parse_date)
            .unwrap_or(default_from);
        let to = json.get("to").and_then(parse_date).unwrap_or(default_to);
        if from >= to || to > now + 60 || from + EXPORT_MAX_AGE < now {
            response.not_created.append(
                client_id,
                invalid(
                    X::From,
                    "A period that has started, ends no later than now, and goes back at most 90 days.",
                ),
            );
            continue;
        }
        let files =
            services::inbuxa_scheduled_reports::export_files(server, &report, from, to).await?;
        let fail = |err: zip::result::ZipError| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to write a report export")
                .reason(err)
        };
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        let names: Vec<String> = files.iter().map(|(name, _)| name.clone()).collect();
        for (name, body) in &files {
            zip.start_file(name.as_str(), options).map_err(fail)?;
            zip.write_all(body).map_err(|err| {
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("Failed to write a report export")
                    .reason(err)
            })?;
        }
        let bytes = zip.finish().map_err(fail)?.into_inner();
        let sha256 = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let blob = server
            .put_jmap_blob(access_token.account_id(), &bytes)
            .await?;

        let mut created = Map::with_capacity(7);
        created.insert_unchecked(
            Key::Property(X::Id),
            Value::Element(ReportExportValue::Id(Id::from(now))),
        );
        created.insert_unchecked(
            Key::Property(X::BlobId),
            Value::Str(blob.to_string().into()),
        );
        created.insert_unchecked(
            Key::Property(X::Size),
            Value::Number((bytes.len() as u64).into()),
        );
        created.insert_unchecked(Key::Property(X::Sha256), Value::Str(sha256.into()));
        created.insert_unchecked(Key::Property(X::From), date(from));
        created.insert_unchecked(Key::Property(X::To), date(to));
        created.insert_unchecked(
            Key::Property(X::Files),
            Value::Array(names.into_iter().map(|n| Value::Str(n.into())).collect()),
        );
        response.created.insert(client_id, Value::Object(created));
    }
    Ok(response)
}
