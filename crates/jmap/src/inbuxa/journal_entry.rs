/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The journal over JMAP (journaling spec, JR-6, JR-15 to JR-17):
//!
//! - `inbuxa:JournalEntry/query` and `/get`: searching and reading what was
//!   journaled (`sysJournalSearch`). `report` is the whole journal report,
//!   only when asked for.
//! - `inbuxa:JournalExport/set`: a ZIP of the reports a filter matches, in
//!   the hold export's shape (`sysJournalExport`).
//! - `inbuxa:JournalVerification/set`: rechecks every chain and every report
//!   (`sysJournalGet`).
//!
//! Every search, read and export is written to the audit log first; if it
//! can't be, nothing is returned (JR-17). All of it is the server's: nobody
//! in a tenant reaches it.

use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use inbuxa_features::{
    audit::{Action, Outcome, Record, Target},
    journal::{
        Direction,
        entries::{self, ChainReport, Entry, EntryId, Filter, MAX_QUERY_LIMIT},
    },
};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        query::{Filter as QueryFilter, QueryRequest, QueryResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_journal_entry::{
        JournalEntry, JournalEntryProperty as P, JournalEntryValue, JournalExport, JournalFilter,
        JournalVerification,
    },
    request::IntoValid,
    types::{date::UTCDate, state::State},
};
use jmap_tools::{Key, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    io::{Cursor, Write},
    str::FromStr,
};
use types::id::Id;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

type JValue = Value<'static, P, JournalEntryValue>;

/// Properties a get returns unless asked otherwise: all but the report.
const LISTED: &[P] = &[
    P::Id,
    P::ReceivedAt,
    P::Direction,
    P::Sender,
    P::Authenticated,
    P::Recipients,
    P::Subject,
    P::MessageId,
    P::JournalIds,
    P::Held,
    P::Size,
    P::Sha256,
    P::ExpiresAt,
];

/// Most reports one export holds, and most bytes.
const MAX_EXPORT_ENTRIES: usize = 10_000;
const MAX_EXPORT_BYTES: u64 = 1024 * 1024 * 1024;
/// Most of one report `get` returns as text.
const MAX_REPORT_TEXT: usize = 10 * 1024 * 1024;

fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("The journal is the server's."))
    } else {
        Ok(())
    }
}

fn date(seconds: u64) -> JValue {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

fn text(value: &str) -> JValue {
    Value::Str(value.to_string().into())
}

fn json_to_value(json: serde_json::Value) -> JValue {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(b),
        serde_json::Value::Number(n) => match n.as_u64() {
            Some(n) => Value::Number(n.into()),
            None => Value::Number(n.as_i64().unwrap_or_default().into()),
        },
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

fn entry_value(id: EntryId, entry: &Entry, report: Option<&str>, properties: &[P]) -> JValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(JournalEntryValue::Id(Id::new(id.to_u64()))),
            P::ReceivedAt => date(entry.at),
            P::Direction => text(entry.direction.as_str()),
            P::Sender => text(&entry.sender),
            P::Authenticated => Value::Bool(entry.authenticated),
            P::Recipients => Value::Array(entry.recipients.iter().map(|r| text(r)).collect()),
            P::Subject => text(&entry.subject),
            P::MessageId => text(&entry.message_id),
            P::JournalIds => Value::Array(
                entry
                    .journals
                    .iter()
                    .map(|j| text(&Id::from(*j).to_string()))
                    .collect(),
            ),
            P::Held => Value::Bool(entry.held),
            P::Size => Value::Number(entry.size.into()),
            P::Sha256 => text(&entry.sha256),
            P::ExpiresAt => date(entry.expires_at),
            P::Report => report.map_or(Value::Null, text),
            _ => Value::Null,
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// Writes a record before anything is returned; an error means nothing
/// may be (JR-17).
async fn record(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    action: Action,
    target_id: Option<String>,
    target_name: Option<String>,
    details: String,
    reason: Option<String>,
) -> trc::Result<()> {
    server
        .audit_append(&Record {
            at: store::write::now() * 1000,
            actor: server.audit_actor(access_token).await,
            via: access_token.origin().cloned(),
            remote_ip: Some(session.remote_ip),
            action,
            target: Target {
                kind: "inbuxa:JournalEntry".into(),
                id: target_id,
                name: target_name,
                ..Default::default()
            },
            changes: vec![],
            details: Some(details),
            reason,
            outcome: Outcome::success(),
        })
        .await
        .map(|_| ())
        .map_err(|err| {
            err.details("The audit log couldn't be written, so the journal wasn't read.")
        })
}

async fn report_bytes(server: &Server, entry: &Entry) -> trc::Result<Option<Vec<u8>>> {
    match entry.blob_hash() {
        Some(hash) => {
            server
                .blob_store()
                .get_blob(hash.as_slice(), 0..usize::MAX)
                .await
        }
        None => Ok(None),
    }
}

/// `inbuxa:JournalEntry/get`: the entries named. Listing them is recorded
/// once; each report read is recorded on its own.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    mut request: GetRequest<JournalEntry>,
) -> trc::Result<GetResponse<JournalEntry>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(LISTED);
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
            .details("Name the entries to get; use inbuxa:JournalEntry/query to find them."));
    };
    let mut found = Vec::with_capacity(ids.len());
    for id in ids {
        let entry_id = EntryId::from_u64(id.id());
        match entries::get(server.store(), entry_id).await? {
            Some(entry) => found.push((entry_id, entry)),
            None => response.push_not_found(id),
        }
    }
    if found.is_empty() {
        return Ok(response);
    }
    let with_report = properties.contains(&P::Report);
    if !with_report {
        record(
            server,
            access_token,
            session,
            Action::BlobAccess,
            None,
            None,
            format!("Listed {} journal entries", found.len()),
            None,
        )
        .await?;
    }
    for (entry_id, entry) in found {
        let report = if with_report {
            record(
                server,
                access_token,
                session,
                Action::BlobAccess,
                Some(Id::new(entry_id.to_u64()).to_string()),
                Some(entry.subject.clone()),
                format!("Read a journaled message from {}", entry.sender),
                None,
            )
            .await?;
            report_bytes(server, &entry).await?.map(|bytes| {
                let end = bytes.len().min(MAX_REPORT_TEXT);
                String::from_utf8_lossy(&bytes[..end]).into_owned()
            })
        } else {
            None
        };
        response.list.push(entry_value(
            entry_id,
            &entry,
            report.as_deref(),
            &properties,
        ));
    }
    Ok(response)
}

fn seconds(value: &str) -> Result<u64, String> {
    UTCDate::from_str(value)
        .map(|date| date.timestamp().max(0) as u64)
        .map_err(|_| format!("{value} isn't a UTC date."))
}

fn direction(value: &str) -> Result<Direction, String> {
    match value {
        "outgoing" => Ok(Direction::Outgoing),
        "incoming" => Ok(Direction::Incoming),
        "internal" => Ok(Direction::Internal),
        "any" => Ok(Direction::Any),
        other => Err(format!("{other} isn't a direction.")),
    }
}

/// The conditions of a query filter, all of which must hold. `Or` and
/// `Not` aren't supported.
fn build_filter(conditions: Vec<QueryFilter<JournalFilter>>) -> trc::Result<Filter> {
    let unsupported = |why: String| trc::JmapEvent::UnsupportedFilter.into_err().details(why);
    let mut filter = Filter::default();
    for condition in conditions {
        match condition {
            QueryFilter::Property(condition) => match condition {
                JournalFilter::After(date) => {
                    filter.after = Some(seconds(&date).map_err(unsupported)?)
                }
                JournalFilter::Before(date) => {
                    filter.before = Some(seconds(&date).map_err(unsupported)?)
                }
                JournalFilter::Sender(s) => filter.sender = Some(s),
                JournalFilter::Recipient(r) => filter.recipient = Some(r),
                JournalFilter::Address(a) => filter.address = Some(a),
                JournalFilter::Direction(d) => {
                    filter.direction = Some(direction(&d).map_err(unsupported)?)
                }
                JournalFilter::Text(t) => filter.text = Some(t),
                JournalFilter::MessageId(m) => filter.message_id = Some(m),
                JournalFilter::JournalId(id) => filter.journal_id = Some(id.document_id()),
                JournalFilter::_T(other) => {
                    return Err(unsupported(format!("Unknown filter property {other}.")));
                }
            },
            QueryFilter::And | QueryFilter::Close => {}
            QueryFilter::Or | QueryFilter::Not => {
                return Err(unsupported(
                    "Journal searches take conditions that must all hold; OR and NOT aren't \
                     supported."
                        .into(),
                ));
            }
        }
    }
    Ok(filter)
}

fn filter_text(filter: &Filter) -> String {
    serde_json::to_string(filter).unwrap_or_default()
}

/// `inbuxa:JournalEntry/query`: newest first. The search is recorded, with
/// its terms, before anything is returned.
pub async fn query(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    request: QueryRequest<JournalEntry>,
) -> trc::Result<QueryResponse> {
    server_level(access_token)?;
    let filter = build_filter(request.filter)?;
    let position = request.position.unwrap_or(0);
    if position < 0 || request.anchor.is_some() {
        return Err(trc::JmapEvent::UnsupportedFilter
            .into_err()
            .details("Journal searches page by a position from the start."));
    }
    let limit = request
        .limit
        .unwrap_or(MAX_QUERY_LIMIT)
        .min(MAX_QUERY_LIMIT);
    let count_all = request.calculate_total.unwrap_or(false);
    record(
        server,
        access_token,
        session,
        Action::BlobAccess,
        None,
        None,
        format!("Searched the journal: {}", filter_text(&filter)),
        None,
    )
    .await?;
    let (ids, total) =
        entries::query(server.store(), &filter, position as usize, limit, count_all).await?;
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

/// An export's filter, as sent: the query's conditions in one object.
fn export_filter(value: Option<Value<'_, P, JournalEntryValue>>) -> Result<Filter, String> {
    let json: serde_json::Value = value
        .map(Into::into)
        .unwrap_or(serde_json::Value::Object(Default::default()));
    let serde_json::Value::Object(map) = json else {
        return Err("The filter is an object of conditions.".into());
    };
    let mut filter = Filter::default();
    for (key, value) in map {
        let text = || {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{key} is text."))
        };
        match key.as_str() {
            "after" => filter.after = Some(seconds(&text()?)?),
            "before" => filter.before = Some(seconds(&text()?)?),
            "sender" => filter.sender = Some(text()?),
            "recipient" => filter.recipient = Some(text()?),
            "address" => filter.address = Some(text()?),
            "direction" => filter.direction = Some(direction(&text()?)?),
            "text" => filter.text = Some(text()?),
            "messageId" => filter.message_id = Some(text()?),
            "journalId" => {
                filter.journal_id = Some(
                    Id::from_str(&text()?)
                        .map_err(|_| "journalId is a journal's id.".to_string())?
                        .document_id(),
                )
            }
            other => return Err(format!("Unknown filter property {other}.")),
        }
    }
    Ok(filter)
}

fn csv(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A ZIP of reports in the hold export's shape: each report as `.eml`,
/// `manifest.csv` with the envelope and a SHA-256 per file, the entries
/// whose report couldn't be read in `exceptions.csv`, and
/// `manifest.sha256` over both. Returns its bytes and how many reports went
/// in.
pub(crate) fn build_zip(
    items: &[(EntryId, Entry, Option<Vec<u8>>)],
) -> trc::Result<(Vec<u8>, usize)> {
    let fail = |err: zip::result::ZipError| {
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Failed to write the export")
            .reason(err)
    };
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let mut manifest = String::from(
        "path,receivedAt,direction,sender,recipients,subject,messageId,queueId,size,sha256\n",
    );
    let mut exceptions = String::from("entry,receivedAt,sender,subject,reason\n");
    let mut written = 0u64;
    let mut count = 0;
    for (id, entry, bytes) in items {
        let received = UTCDate::from_timestamp(entry.at as i64).to_string();
        let Some(bytes) = bytes else {
            exceptions.push_str(&format!(
                "{},{},{},{},{}\n",
                Id::new(id.to_u64()),
                received,
                csv(&entry.sender),
                csv(&entry.subject),
                "The report couldn't be read."
            ));
            continue;
        };
        written += bytes.len() as u64;
        if written > MAX_EXPORT_BYTES {
            return Err(trc::StoreEvent::UnexpectedError.into_err().details(
                "The reports are larger than one export can hold (1 GB). Narrow the search.",
            ));
        }
        let path = format!(
            "reports/{}-{:x}.eml",
            received.replace(':', ""),
            entry.queue_id
        );
        zip.start_file(path.as_str(), options).map_err(fail)?;
        zip.write_all(bytes).map_err(|e| fail(e.into()))?;
        manifest.push_str(&format!(
            "{},{},{},{},{},{},{},{:x},{},{}\n",
            csv(&path),
            received,
            entry.direction.as_str(),
            csv(&entry.sender),
            csv(&entry.recipients.join(" ")),
            csv(&entry.subject),
            csv(&entry.message_id),
            entry.queue_id,
            bytes.len(),
            hex(&Sha256::digest(bytes))
        ));
        count += 1;
    }
    let manifest_hash = hex(&Sha256::digest(manifest.as_bytes()));
    let exceptions_hash = hex(&Sha256::digest(exceptions.as_bytes()));
    zip.start_file("manifest.csv", options).map_err(fail)?;
    zip.write_all(manifest.as_bytes())
        .map_err(|e| fail(e.into()))?;
    zip.start_file("exceptions.csv", options).map_err(fail)?;
    zip.write_all(exceptions.as_bytes())
        .map_err(|e| fail(e.into()))?;
    zip.start_file("manifest.sha256", options).map_err(fail)?;
    zip.write_all(
        format!("{manifest_hash}  manifest.csv\n{exceptions_hash}  exceptions.csv\n").as_bytes(),
    )
    .map_err(|e| fail(e.into()))?;
    Ok((zip.finish().map_err(fail)?.into_inner(), count))
}

/// `inbuxa:JournalExport/set`: create `{filter, reason}`; the created
/// object names the ZIP's blob (the caller's), its size, how many reports it
/// holds and its SHA-256. A reason is required; the export is recorded
/// before it's built.
pub async fn export_set(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    mut request: SetRequest<'_, JournalExport>,
) -> trc::Result<SetResponse<JournalExport>> {
    server_level(access_token)?;
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
        let mut filter_value = None;
        let mut reason = None;
        let mut invalid = None;
        for (key, value) in value.into_expanded_object() {
            match (&key, value) {
                (Key::Property(P::Filter), value) => filter_value = Some(value.into_owned()),
                (Key::Property(P::Reason), Value::Str(r)) => {
                    reason = Some(r.trim().chars().take(500).collect::<String>())
                }
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
        let Some(reason) = reason.filter(|r| !r.is_empty()) else {
            response.not_created.append(
                client_id,
                SetError::invalid_properties()
                    .with_property(P::Reason)
                    .with_description(
                        "Say why: a reason is required and is kept in the audit log.",
                    ),
            );
            continue;
        };
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

        let (ids, total) =
            entries::query(server.store(), &filter, 0, MAX_EXPORT_ENTRIES, true).await?;
        if total > MAX_EXPORT_ENTRIES {
            response.not_created.append(
                client_id,
                SetError::invalid_properties()
                    .with_property(P::Filter)
                    .with_description(format!(
                        "{total} entries match; one export holds {MAX_EXPORT_ENTRIES}. Narrow the search."
                    )),
            );
            continue;
        }

        // Recorded first: no export leaves without its record
        record(
            server,
            access_token,
            session,
            Action::Export,
            None,
            None,
            format!(
                "Exported {} journal entries: {}",
                ids.len(),
                filter_text(&filter)
            ),
            Some(reason),
        )
        .await?;

        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(entry) = entries::get(server.store(), id).await? {
                let bytes = report_bytes(server, &entry).await?;
                items.push((id, entry, bytes));
            }
        }
        let (bytes, count) = build_zip(&items)?;
        let blob = server
            .put_jmap_blob(access_token.account_id(), &bytes)
            .await?;

        let mut created = Map::with_capacity(5);
        created.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(JournalEntryValue::Id(Id::new(store::write::now()))),
        );
        created.insert_unchecked(
            Key::Property(P::BlobId),
            Value::Str(blob.to_string().into()),
        );
        created.insert_unchecked(
            Key::Property(P::Size),
            Value::Number((bytes.len() as u64).into()),
        );
        created.insert_unchecked(
            Key::Property(P::Count),
            Value::Number((count as u64).into()),
        );
        created.insert_unchecked(
            Key::Property(P::Sha256),
            Value::Str(hex(&Sha256::digest(&bytes)).into()),
        );
        response.created.insert(client_id, Value::Object(created));
    }
    Ok(response)
}

fn summary(chains: &[ChainReport]) -> String {
    if chains.is_empty() {
        return "The journal is empty.".into();
    }
    chains
        .iter()
        .map(|chain| match (&chain.broken_at, &chain.reason) {
            (Some(at), Some(reason)) => format!("node {}: broken at {at}: {reason}", chain.node),
            _ => format!(
                "node {}: {} entries and {} purged verified ({} to {})",
                chain.node, chain.entries, chain.purged, chain.first_seq, chain.last_seq
            ),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// `inbuxa:JournalVerification/set`: create `{}` to recheck every node's
/// chain and every report against its entry (JR-6). Recorded, with what it
/// found.
pub async fn verification_set(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    mut request: SetRequest<'_, JournalVerification>,
) -> trc::Result<SetResponse<JournalVerification>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (id, _) in request.unwrap_update().into_valid() {
        response.not_updated.append(id, SetError::forbidden());
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(id, SetError::forbidden());
    }
    for (client_id, _) in request.unwrap_create() {
        let chains = entries::verify(server.store(), Some(server.blob_store())).await?;
        let verified = chains.iter().all(|chain| chain.broken_at.is_none());
        let entry = server
            .audit_append(&Record {
                at: store::write::now() * 1000,
                actor: server.audit_actor(access_token).await,
                via: access_token.origin().cloned(),
                remote_ip: Some(session.remote_ip),
                action: Action::Verify,
                target: Target {
                    kind: "inbuxa:JournalEntry".into(),
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
            })
            .await
            .ok();

        let mut created = Map::with_capacity(3);
        created.insert_unchecked(
            Key::Property(P::Id),
            Value::Element(JournalEntryValue::Id(Id::new(
                entry.map_or(0, |entry| entry.to_u64()),
            ))),
        );
        created.insert_unchecked(Key::Property(P::Verified), Value::Bool(verified));
        created.insert_unchecked(
            Key::Property(P::Chains),
            json_to_value(serde_json::to_value(&chains).unwrap_or_default()),
        );
        response.created.insert(client_id, Value::Object(created));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(queue_id: u64) -> Entry {
        Entry {
            queue_id,
            at: 1_790_000_000,
            direction: Direction::Outgoing,
            sender: "alice@example.com".into(),
            authenticated: true,
            recipients: vec!["pay@bank.example".into()],
            subject: "Q3, final".into(),
            message_id: "<abc@example.com>".into(),
            accounts: vec![],
            tenants: vec![],
            journals: vec![1],
            held: false,
            blob: String::new(),
            size: 0,
            sha256: String::new(),
            expires_at: 0,
        }
    }

    #[test]
    fn exports_list_every_report_and_what_was_missing() {
        let items = vec![
            (
                EntryId { node: 1, seq: 1 },
                entry(0x1a),
                Some(b"report one".to_vec()),
            ),
            (EntryId { node: 1, seq: 2 }, entry(0x1b), None),
        ];
        let (bytes, count) = build_zip(&items).unwrap();
        assert_eq!(count, 1);
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut read = |name: &str| {
            let mut out = String::new();
            std::io::Read::read_to_string(&mut zip.by_name(name).unwrap(), &mut out).unwrap();
            out
        };
        let manifest = read("manifest.csv");
        assert!(manifest.contains("\"Q3, final\""), "{manifest}");
        assert!(manifest.contains(&hex(&Sha256::digest(b"report one"))));
        assert!(read("exceptions.csv").contains("couldn't be read"));
        let sums = read("manifest.sha256");
        assert!(sums.contains(&hex(&Sha256::digest(manifest.as_bytes()))));
    }

    #[test]
    fn export_filters_parse() {
        let filter: Value<'_, P, JournalEntryValue> = json_to_value(serde_json::json!({
            "sender": "alice", "direction": "outgoing", "journalId": "b",
            "after": "2026-09-01T00:00:00Z"
        }));
        let filter = export_filter(Some(filter)).unwrap();
        assert_eq!(filter.sender.as_deref(), Some("alice"));
        assert_eq!(filter.direction, Some(Direction::Outgoing));
        assert_eq!(filter.journal_id, Some(1));
        assert!(filter.after.is_some());
        let bad: Value<'_, P, JournalEntryValue> =
            json_to_value(serde_json::json!({"colour": "red"}));
        assert!(export_filter(Some(bad)).is_err());
    }
}
