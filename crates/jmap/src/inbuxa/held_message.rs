/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:HeldMessage` (dlp-and-mail-flow-rules spec, §2.6, §2.8): the
//! review queue. `sysDlpReviewGet` lists held mail and reads it;
//! `sysDlpReviewUpdate` releases or rejects it, with a reason the request
//! layer records. Reading a held message's text is recorded as access to
//! the sender's mail. Nobody in a tenant reaches this (settled answer 3).

use common::{Server, auth::AccessToken, config::smtp::queue::QueueName};
use inbuxa_features::{
    audit::{Action, Outcome, Record, Target},
    mailflow::held::{self, Held},
};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_held_message::{
        HeldMessage, HeldMessageProperty as P, HeldMessageSetArguments, HeldMessageValue,
    },
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use smtp::queue::spool::SmtpSpool;
use std::borrow::Cow;
use types::id::Id;

type HValue = Value<'static, P, HeldMessageValue>;

const ALL: &[P] = &[
    P::Id,
    P::Sender,
    P::Recipients,
    P::Subject,
    P::Size,
    P::Rules,
    P::Counts,
    P::HeldAt,
    P::ExpiresAt,
];

/// How much of a held message's text a preview shows.
const PREVIEW_LIMIT: usize = 64 * 1024;

fn server_level(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Held mail is the server's to review."))
    } else {
        Ok(())
    }
}

fn date(seconds: u64) -> HValue {
    Value::Str(UTCDate::from_timestamp(seconds as i64).to_string().into())
}

fn text(s: &str) -> HValue {
    Value::Str(Cow::Owned(s.to_string()))
}

/// The text a reviewer reads: the subject, each body as text, and the
/// attachments' names; at most [`PREVIEW_LIMIT`].
async fn preview(server: &Server, queue_id: u64) -> trc::Result<Option<String>> {
    let Some(message) = server.read_message(queue_id, QueueName::default()).await else {
        return Ok(None);
    };
    let Some(raw) = server
        .blob_store()
        .get_blob(message.message.blob_hash.as_slice(), 0..usize::MAX)
        .await?
    else {
        return Ok(None);
    };
    let Some(parsed) = MessageParser::new().parse(&raw) else {
        return Ok(Some(
            String::from_utf8_lossy(&raw[..raw.len().min(PREVIEW_LIMIT)]).into_owned(),
        ));
    };
    let mut out = String::new();
    for part in parsed.text_bodies() {
        match &part.body {
            PartType::Text(text) => out.push_str(text),
            PartType::Html(html) => out.push_str(&mail_parser::decoders::html::html_to_text(html)),
            _ => {}
        }
        out.push_str("\n\n");
    }
    let attachments: Vec<&str> = parsed
        .attachments()
        .filter_map(|a| a.attachment_name())
        .collect();
    if !attachments.is_empty() {
        out.push_str(&format!("Attachments: {}\n", attachments.join(", ")));
    }
    if out.len() > PREVIEW_LIMIT {
        let mut cut = PREVIEW_LIMIT;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
    }
    Ok(Some(out))
}

fn to_value(record: &Held, properties: &[P], preview: Option<&str>) -> HValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(HeldMessageValue::Id(Id::from(record.queue_id))),
            P::Sender => text(&record.sender),
            P::Recipients => Value::Array(record.recipients.iter().map(|r| text(r)).collect()),
            P::Subject => text(&record.subject),
            P::Size => Value::Number(record.size.into()),
            P::Rules => Value::Array(
                record
                    .rules
                    .iter()
                    .map(|rule| {
                        let mut map = Map::with_capacity(2);
                        map.insert_unchecked(Key::Borrowed("name"), text(&rule.name));
                        map.insert_unchecked(Key::Borrowed("notice"), text(&rule.notice));
                        Value::Object(map)
                    })
                    .collect(),
            ),
            P::Counts => Value::Array(
                record
                    .counts
                    .iter()
                    .map(|(detector, count)| {
                        let mut map = Map::with_capacity(2);
                        map.insert_unchecked(Key::Borrowed("detector"), text(detector));
                        map.insert_unchecked(
                            Key::Borrowed("count"),
                            Value::Number((*count as u64).into()),
                        );
                        Value::Object(map)
                    })
                    .collect(),
            ),
            P::HeldAt => date(record.held_at),
            P::ExpiresAt => date(record.expires_at),
            P::Preview => preview.map_or(Value::Null, text),
            P::Decision | P::Note => Value::Null,
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:HeldMessage/get`: held mail, oldest first.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<HeldMessage>,
) -> trc::Result<GetResponse<HeldMessage>> {
    server_level(access_token)?;
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let all = held::all(server.store()).await?;
    let wanted: Vec<&Held> = match &ids {
        None => all.iter().collect(),
        Some(ids) => {
            let mut found = Vec::new();
            for id in ids {
                match all.iter().find(|h| h.queue_id == id.id()) {
                    Some(record) => found.push(record),
                    None => response.push_not_found(*id),
                }
            }
            found
        }
    };
    let with_preview = properties.contains(&P::Preview);
    for record in wanted {
        let text = if with_preview {
            let text = preview(server, record.queue_id).await?;
            // Reading someone's mail is recorded, as any access is
            server
                .audit_note(Record {
                    at: store::write::now() * 1000,
                    actor: server.audit_actor(access_token).await,
                    via: access_token.origin().cloned(),
                    remote_ip: None,
                    action: Action::BlobAccess,
                    target: Target {
                        kind: "inbuxa:HeldMessage".into(),
                        id: Some(Id::from(record.queue_id).to_string()),
                        name: Some(record.subject.clone()),
                        account_id: record.account_id,
                        tenant_id: record.tenant_id,
                    },
                    changes: vec![],
                    details: Some(format!(
                        "Read a message held for review, from {}",
                        record.sender
                    )),
                    reason: None,
                    outcome: Outcome::success(),
                })
                .await;
            text
        } else {
            None
        };
        response
            .list
            .push(to_value(record, &properties, text.as_deref()));
    }
    Ok(response)
}

fn invalid(property: P, why: &str) -> SetError<P> {
    SetError::invalid_properties()
        .with_property(property)
        .with_description(why.to_string())
}

/// `inbuxa:HeldMessage/set`: update with `decision` release or reject (and
/// an optional `note` for the sender). There is no create or destroy.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, HeldMessage>,
) -> trc::Result<SetResponse<HeldMessage>> {
    server_level(access_token)?;
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    let arguments: HeldMessageSetArguments = std::mem::take(&mut request.arguments);
    let has_reason = arguments
        .reason
        .as_deref()
        .is_some_and(|r| !r.trim().is_empty());

    for (client_id, _) in request.unwrap_create() {
        response.not_created.append(
            client_id,
            SetError::forbidden().with_description("Mail is held by DLP rules, not created."),
        );
    }

    'update: for (id, value) in request.unwrap_update().into_valid() {
        let Some(record) = held::get(server.store(), id.id()).await? else {
            response.not_updated.append(id, SetError::not_found());
            continue;
        };
        if !has_reason {
            response.not_updated.append(
                id,
                SetError::invalid_properties().with_description(
                    "Say why: a reason is required and is kept in the audit log.",
                ),
            );
            continue;
        }
        let mut decision = None;
        let mut note = None;
        for (key, value) in value.into_expanded_object() {
            match (&key, value) {
                (Key::Property(P::Decision), Value::Str(s)) if s == "release" || s == "reject" => {
                    decision = Some(s.to_string());
                }
                (Key::Property(P::Note), Value::Str(s)) => {
                    let s = s.trim();
                    if !s.is_empty() {
                        note = Some(s.chars().take(1000).collect::<String>());
                    }
                }
                (Key::Property(P::Note), Value::Null) => {}
                _ => {
                    response.not_updated.append(
                        id,
                        invalid(
                            P::Decision,
                            "Send decision: \"release\" or \"reject\", and an optional note.",
                        ),
                    );
                    continue 'update;
                }
            }
        }
        let done = match decision.as_deref() {
            Some("release") => smtp::queue::held::release(server, record.queue_id).await?,
            Some("reject") => smtp::queue::held::reject(server, &record, note.as_deref()).await?,
            _ => {
                response
                    .not_updated
                    .append(id, invalid(P::Decision, "Say release or reject."));
                continue;
            }
        };
        if done {
            response.updated.append(id, None);
        } else {
            response.not_updated.append(
                id,
                SetError::not_found().with_description("The message is no longer in the queue."),
            );
        }
    }

    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(
            id,
            SetError::forbidden().with_description("Release or reject it instead."),
        );
    }

    Ok(response)
}
