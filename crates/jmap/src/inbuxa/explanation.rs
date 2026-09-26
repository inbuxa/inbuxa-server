/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Explanation/set`: "Explain this" (`inbuxa-drafts/specs/ai-explain.md`).
//! The console names a subject; this reads the data behind it, builds the
//! prompt from the fixed prompts in `inbuxa_features::ai::explain`, and asks
//! this node's model. Nothing is stored.

use crate::registry::mapping::{log::read_log_entries, queued_message::map_message};
use common::{
    Server,
    auth::AccessToken,
    config::mailstore::spamfilter::SpamFilterAction,
    enterprise::llm::{Call, Explain, Failure},
};
use inbuxa_features::ai::{
    explain::{
        self, DROPPED_KEYS, Facts, Subject, TagScore, prompts,
        schema::{PropertyInfo, Schema},
        status,
    },
    gate::Refused,
};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::inbuxa_explanation::{Explanation, ExplanationProperty as P, ExplanationValue},
    request::IntoValid,
};
use jmap_tools::{Key, Map, Value};
use mail_auth::flate2::read::GzDecoder;
use registry::{
    jmap::IntoValue,
    schema::{
        enums::SpamClassifyResult,
        prelude::{OBJ_SINGLETON, Object, ObjectType},
        structs::{QueuedMessage, QueuedRecipient, RecipientStatus},
    },
    types::{EnumImpl, id::ObjectId},
};
use smtp::queue::spool::SmtpSpool;
use std::{
    io::Read,
    str::FromStr,
    sync::OnceLock,
    time::Instant,
};
use types::id::Id;

type EValue = Value<'static, P, ExplanationValue>;

/// A stored log line's details can be long; they're the event's substance.
const MAX_DETAILS_CHARS: usize = 2_000;

/// The most spam tags put in one prompt, the heaviest first.
const MAX_PROMPT_TAGS: usize = 40;

/// Objects that aren't settings: queue items, reports, logs, credentials
/// and the like, which have views and rules of their own.
const NOT_SETTINGS: &[ObjectType] = &[
    ObjectType::AccountPassword,
    ObjectType::AccountSettings,
    ObjectType::Action,
    ObjectType::ApiKey,
    ObjectType::AppPassword,
    ObjectType::ArchivedItem,
    ObjectType::ArfExternalReport,
    ObjectType::Bootstrap,
    ObjectType::ClusterNode,
    ObjectType::DmarcExternalReport,
    ObjectType::DmarcInternalReport,
    ObjectType::Log,
    ObjectType::Metric,
    ObjectType::QueuedMessage,
    ObjectType::SpamTrainingSample,
    ObjectType::Task,
    ObjectType::TlsExternalReport,
    ObjectType::TlsInternalReport,
    ObjectType::Trace,
];

/// The registry schema the console downloads, read once.
fn schema() -> Option<&'static Schema> {
    static SCHEMA: OnceLock<Option<Schema>> = OnceLock::new();
    static SCHEMA_JSON: &[u8] = include_bytes!("../../../../resources/schema/schema.json.gz");
    SCHEMA
        .get_or_init(|| {
            let mut json = Vec::new();
            GzDecoder::new(SCHEMA_JSON).read_to_end(&mut json).ok()?;
            serde_json::from_slice(&json).ok().map(Schema::new)
        })
        .as_ref()
}

fn server_fail(why: &'static str) -> SetError<P> {
    SetError::new(SetErrorType::ServerFail).with_description(why)
}

fn invalid_subject(why: impl Into<String>) -> SetError<P> {
    SetError::invalid_properties()
        .with_property(P::Subject)
        .with_description(why.into())
}

/// `inbuxa:Explanation/set`: create only (EX-4, EX-11).
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, Explanation>,
) -> trc::Result<SetResponse<Explanation>> {
    if access_token.tenant_id().is_some() {
        return Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Explanations are for server-level administrators."));
    }
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (id, _) in request.unwrap_update().into_valid() {
        response.not_updated.append(
            id,
            SetError::forbidden().with_description("Explanations aren't stored."),
        );
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(
            id,
            SetError::forbidden().with_description("Explanations aren't stored."),
        );
    }
    for (client_id, value) in request.unwrap_create() {
        match explain_one(server, access_token, value).await? {
            Ok(created) => {
                response.created.insert(client_id, created);
            }
            Err(error) => response.not_created.append(client_id, error),
        }
    }
    Ok(response)
}

async fn explain_one(
    server: &Server,
    access_token: &AccessToken,
    value: Value<'_, P, ExplanationValue>,
) -> trc::Result<Result<EValue, SetError<P>>> {
    // Only the subject goes in; everything else is the server's (EX-5)
    let mut subject = None;
    for (key, value) in value.into_expanded_object() {
        match key {
            Key::Property(P::Subject) => {
                subject = serde_json::to_value(&value).ok();
            }
            key => {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(key.into_owned())
                    .with_description("is set by the server")));
            }
        }
    }
    let Some(subject) = subject else {
        return Ok(Err(invalid_subject("subject is required")));
    };
    let subject = match explain::parse(&subject) {
        Ok(subject) => subject,
        Err(invalid) => {
            return Ok(Err(invalid_subject(format!(
                "{} {}.",
                invalid.field, invalid.reason
            ))));
        }
    };

    // EX-1 to EX-3
    let limits = server.ai_limits().await;
    let Some((model_id, model)) = server.ai_explain_model(&limits).await else {
        return Ok(Err(server_fail("unavailable")));
    };

    // Everything is read and checked before the model is asked (EX-8)
    let facts = match facts(server, access_token, &subject).await? {
        Ok(facts) => facts,
        Err(error) => return Ok(Err(error)),
    };

    let nonce = format!("{:016x}", rand::random::<u64>());
    let (system, user) = prompts::messages(subject.kind(), &facts, &nonce);
    let started = Instant::now();
    let answer = server
        .ai_call(Call {
            model_id,
            model: &model,
            account_id: Some(access_token.account_id()),
            system: Some(&system),
            user: &user,
            temperature: model.temperature.into_inner(),
            max_tokens: explain::MAX_TOKENS,
            // EX-13
            timeout: model.timeout.into_inner().min(limits.explain_ceiling.into_inner()),
            explain: Some(Explain {
                calls_per_hour: limits.explain_calls_per_hour.min(u32::MAX as u64) as u32,
                subject: subject.type_name(),
            }),
        })
        .await;
    let elapsed = started.elapsed();
    let text = match answer {
        Ok(answer) => explain::tidy_answer(&answer),
        Err(Failure::Refused(Refused::Busy | Refused::OneAtATime)) => {
            return Ok(Err(server_fail("busy")));
        }
        Err(Failure::Refused(Refused::Paused)) => return Ok(Err(server_fail("paused"))),
        Err(Failure::Refused(Refused::HourlyLimit)) => {
            return Ok(Err(SetError::new(SetErrorType::RateLimit).with_description(
                "You've asked for as many explanations as this hour allows.",
            )));
        }
        Err(Failure::Timeout) => return Ok(Err(server_fail("timeout"))),
        Err(_) => return Ok(Err(server_fail("unavailable"))),
    };
    if text.is_empty() {
        return Ok(Err(server_fail("unavailable")));
    }

    let mut out = Map::with_capacity(6);
    out.insert_unchecked(
        Key::Property(P::Id),
        Value::Element(ExplanationValue::Id(Id::from(rand::random::<u32>() as u64))),
    );
    out.insert_unchecked(Key::Property(P::Text), Value::Str(text.into()));
    out.insert_unchecked(Key::Property(P::Model), Value::Str(model.name.clone().into()));
    out.insert_unchecked(
        Key::Property(P::Node),
        Value::Str(server.registry().local_hostname().to_string().into()),
    );
    out.insert_unchecked(
        Key::Property(P::ElapsedMs),
        Value::Number((elapsed.as_millis() as u64).into()),
    );
    out.insert_unchecked(
        Key::Property(P::Grounded),
        Value::Array(
            facts
                .grounded
                .iter()
                .map(|tag| Value::Str((*tag).into()))
                .collect(),
        ),
    );
    Ok(Ok(Value::Object(out)))
}

/// What the server knows about the subject (EX-5, EX-7, EX-9).
async fn facts(
    server: &Server,
    access_token: &AccessToken,
    subject: &Subject,
) -> trc::Result<Result<Facts, SetError<P>>> {
    let mut facts = Facts::default();
    match subject {
        Subject::DeliveryFailure {
            queue_id,
            recipient,
        } => {
            let not_found = || {
                SetError::not_found().with_description("That message is no longer in the queue.")
            };
            let Ok(id) = Id::from_str(queue_id) else {
                return Ok(Err(not_found()));
            };
            let Some(archive) = server.read_message_archive(id.id()).await? else {
                return Ok(Err(not_found()));
            };
            let message = map_message(archive.unarchive::<smtp::queue::Message>()?);
            if let Err(error) = delivery_facts(&mut facts, &message, recipient) {
                return Ok(Err(error));
            }
        }
        Subject::SpamVerdict { result, score, tags } => {
            if SpamClassifyResult::parse(result).is_none() {
                return Ok(Err(invalid_subject("result isn't a spam filter result.")));
            }
            facts.push("Result", result);
            facts.push("Total score", format!("{score:.2}"));
            // The server's own scores, not what the console sent back
            let scores = &server.core.spam.lists.scores;
            let mut weighed: Vec<(&String, f64, &'static str)> = tags
                .iter()
                .map(|(name, _): (&String, &TagScore)| match scores.get(name.as_str()) {
                    Some(SpamFilterAction::Allow(s)) => (name, *s as f64, "score"),
                    Some(SpamFilterAction::Reject) => (name, f64::MAX, "rejects the message"),
                    Some(SpamFilterAction::Discard) => (name, f64::MAX, "discards the message"),
                    _ => (name, 0.0, "no score of its own"),
                })
                .collect();
            weighed.sort_by(|a, b| b.1.abs().total_cmp(&a.1.abs()).then_with(|| a.0.cmp(b.0)));
            for (name, weight, how) in weighed.iter().take(MAX_PROMPT_TAGS) {
                let text = match *how {
                    "score" => format!("{weight:+.2}"),
                    other => other.to_string(),
                };
                facts.push(format!("Tag {name}"), text);
            }
            if weighed.len() > MAX_PROMPT_TAGS {
                facts.push(
                    "Other tags",
                    format!("{} more, each weighing less", weighed.len() - MAX_PROMPT_TAGS),
                );
            }
            facts.ground(
                "spamTagScores",
                "Tag scores are the server's configured scores; a positive score counts toward spam, \
a negative one toward legitimate mail. The result follows the total against the server's thresholds.",
            );
        }
        Subject::LogEntry { log_id } => {
            let not_found = || SetError::not_found().with_description("That log entry isn't on this node.");
            let (Some(path), Ok(id)) = (server.core.metrics.log_path.clone(), Id::from_str(log_id)) else {
                return Ok(Err(not_found()));
            };
            let entries = tokio::task::spawn_blocking(move || read_log_entries(path, Some(vec![id]), 1))
                .await
                .map_err(|err| {
                    trc::EventType::Server(trc::ServerEvent::ThreadError)
                        .reason(err)
                        .caused_by(trc::location!())
                })?
                .map_err(|err| {
                    trc::EventType::Telemetry(trc::TelemetryEvent::LogError)
                        .reason(err)
                        .details("Failed to read log files")
                        .caused_by(trc::location!())
                })?;
            let Some((_, log)) = entries.into_iter().next() else {
                return Ok(Err(not_found()));
            };
            let event = log.event.as_str();
            if explain::is_raw_event(event) {
                return Ok(Err(raw_refused()));
            }
            facts.push("Event", event);
            facts.push("Level", log.level.as_str());
            facts.push("When", log.timestamp.to_string());
            let details = explain::cut_chars(log.details.trim(), MAX_DETAILS_CHARS);
            if !details.is_empty() {
                facts.lines.push(("Details".to_string(), details));
            }
            ground_event(&mut facts, event);
        }
        Subject::StoredTraceEvent { trace_id, index } => {
            let not_found = || SetError::not_found().with_description("That trace is no longer stored.");
            let Ok(id) = Id::from_str(trace_id) else {
                return Ok(Err(not_found()));
            };
            if server.tracing_store().is_none() {
                return Ok(Err(not_found()));
            }
            let Some(trace) = crate::inbuxa::telemetry::read_trace(server, id.id()).await? else {
                return Ok(Err(not_found()));
            };
            let opened_by = trace.events.iter().next().map(|e| e.event.as_str());
            let Some(event) = trace.events.iter().nth(*index) else {
                return Ok(Err(invalid_subject("That trace has no event at that index.")));
            };
            let name = event.event.as_str();
            if explain::is_raw_event(name) {
                return Ok(Err(raw_refused()));
            }
            facts.push("Event", name);
            facts.push("When", event.timestamp.to_string());
            if let Some(first) = opened_by.filter(|first| *first != name) {
                facts.push("Part of a trace that began with", first);
            }
            let mut kept = 0;
            for pair in event.key_values.iter() {
                let Ok(pair) = serde_json::to_value(pair) else {
                    continue;
                };
                let key = pair["key"].as_str().unwrap_or_default();
                if key.is_empty() || DROPPED_KEYS.contains(&key) {
                    continue;
                }
                if kept == explain::MAX_KEY_VALUES {
                    break;
                }
                kept += 1;
                facts.push(key, explain::value_text(&pair["value"]));
            }
            ground_event(&mut facts, name);
        }
        Subject::LiveTraceEvent { event, key_values } => {
            if trc::EventType::parse(event).is_none() {
                return Ok(Err(invalid_subject("event isn't a known event.")));
            }
            if explain::is_raw_event(event) {
                return Ok(Err(raw_refused()));
            }
            facts.push("Event", event);
            for (key, value) in key_values {
                facts.push(key.as_str(), value);
            }
            ground_event(&mut facts, event);
        }
        Subject::Setting {
            object,
            id,
            property,
        } => {
            let Some(object_type) = ObjectType::parse(&object[2..]) else {
                return Ok(Err(invalid_subject(format!("{object} isn't a settings object."))));
            };
            if NOT_SETTINGS.contains(&object_type) {
                return Ok(Err(invalid_subject(format!("{object} isn't a setting."))));
            }
            // Explain can't show what the administrator couldn't open
            if !access_token.has_permission(object_type.get_permission()) {
                return Ok(Err(SetError::forbidden()
                    .with_description(format!("You don't have permission to view {object}."))));
            }
            let Some(info) = schema().and_then(|s| s.property(object, property)) else {
                return Ok(Err(invalid_subject(format!("{object} has no property {property}."))));
            };
            // EX-9: refused, not explained with the value hidden
            if info.secret {
                return Ok(Err(SetError::forbidden().with_description(
                    "That setting holds a secret, so it isn't sent to the model.",
                )));
            }
            let not_found = || SetError::not_found().with_description(format!("No such {object}."));
            let Ok(id) = Id::from_str(id) else {
                return Ok(Err(not_found()));
            };
            // A singleton never saved holds its defaults, as its /get shows it
            let stored = match server.registry().get(ObjectId::new(object_type, id)).await? {
                Some(stored) => stored,
                None if id.is_singleton() && object_type.flags() & OBJ_SINGLETON != 0 => {
                    Object::from(object_type)
                }
                None => return Ok(Err(not_found())),
            };
            let stored = serde_json::to_value(stored.into_value()).unwrap_or_default();
            let current = stored.get(property.as_str()).cloned().unwrap_or(serde_json::Value::Null);
            push_setting(&mut facts, object, property, &info, &current);
        }
    }
    Ok(Ok(facts))
}

/// A failed recipient's facts and grounding (EX-7, EX-9). Addresses are
/// sent, since a failure often turns on them; the message itself, its
/// subject and body, never are: they aren't read.
fn delivery_facts(facts: &mut Facts, message: &QueuedMessage, recipient: &str) -> Result<(), SetError<P>> {
    let Some((address, rcpt)) = message
        .recipients
        .iter()
        .find(|(address, _)| address.eq_ignore_ascii_case(recipient))
    else {
        return Err(invalid_subject("That message has no such recipient."));
    };
    let (temporary, error) = match &rcpt.status {
        RecipientStatus::TemporaryFailure(error) => (true, error),
        RecipientStatus::PermanentFailure(error) => (false, error),
        _ => {
            return Err(invalid_subject(
                "That recipient hasn't failed, so there's nothing to explain.",
            ));
        }
    };
    facts.push("Sender (return path)", &message.return_path);
    facts.push("Recipient", address);
    facts.push("Status", if temporary { "Temporary failure" } else { "Permanent failure" });
    facts.push("Error type", error.error_type.as_str());
    facts.push("Error", error.error_message.as_deref().unwrap_or_default());
    facts.push("Command that failed", error.error_command.as_deref().unwrap_or_default());
    facts.push("Remote host", error.response_hostname.as_deref().unwrap_or_default());
    if let Some(code) = error.response_code {
        facts.push("Remote reply code", code.to_string());
    }
    facts.push("Enhanced status code", error.response_enhanced.as_deref().unwrap_or_default());
    facts.push("Remote reply", error.response_message.as_deref().unwrap_or_default());
    push_recipient_timing(facts, rcpt, temporary);
    facts.push("Message size", format!("{} bytes", message.size));
    facts.push("Queued at", message.created_at.to_string());
    for note in status::notes(
        error.response_code.and_then(|c| u16::try_from(c).ok()),
        error.response_enhanced.as_deref(),
    ) {
        facts.ground("rfc3463", note);
    }
    Ok(())
}

fn raw_refused() -> SetError<P> {
    SetError::forbidden()
        .with_description("Raw protocol traffic isn't sent to the model: it can hold messages and passwords.")
}

fn push_recipient_timing(facts: &mut Facts, rcpt: &QueuedRecipient, temporary: bool) {
    facts.push("Attempts so far", rcpt.retry_count.to_string());
    if temporary {
        facts.push("Next attempt", rcpt.retry_due.to_string());
    }
    facts.push(
        "Delivery status notices sent to the sender",
        rcpt.notify_count.to_string(),
    );
}

fn ground_event(facts: &mut Facts, event: &str) {
    if let Some((label, explanation)) = schema().and_then(|s| s.event(event)) {
        facts.ground(
            "eventExplanation",
            format!("{event} is \"{label}\": {explanation}"),
        );
    }
}

fn push_setting(
    facts: &mut Facts,
    object: &str,
    property: &str,
    info: &PropertyInfo,
    current: &serde_json::Value,
) {
    let shown = |value: &serde_json::Value| match value {
        serde_json::Value::Null => "not set".to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    facts.push(
        "Setting",
        format!("{object} › {}", info.label.as_deref().unwrap_or(property)),
    );
    facts.push("Property", property);
    facts.push("Current value", shown(current));
    if let Some(default) = &info.default {
        facts.push("Default", shown(default));
        facts.push(
            "Differs from the default",
            if default == current { "no" } else { "yes" },
        );
    }
    if !info.allowed.is_empty() {
        facts.push("Allowed values", info.allowed.join("; "));
    }
    facts.ground(
        "schemaDescription",
        format!("{property}: {}", info.description),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_schema_secrets_and_text() {
        let schema = schema().expect("the embedded schema reads");
        // Plain settings are explained, with their description
        let enabled = schema.property("x:Domain", "isEnabled").unwrap();
        assert!(!enabled.secret);
        assert!(!enabled.description.is_empty());
        // EX-9: a secret, and an object with a secret inside one variant
        assert!(schema.property("x:AccountPassword", "secret").unwrap().secret);
        assert!(schema.property("x:AcmeProvider", "accountKey").unwrap().secret);
        assert!(schema.property("x:AiModel", "httpAuth").unwrap().secret);
        // Events carry an explanation
        let (label, text) = schema.event("delivery.start-tls-disabled").unwrap();
        assert!(!label.is_empty() && !text.is_empty());
    }

    #[test]
    fn delivery_failure_facts() {
        use registry::schema::{
            enums::DeliveryErrorType,
            structs::{DeliveryError, QueueExpiry, QueueExpiryTtl},
        };
        use registry::types::datetime::UTCDateTime;
        let failed = |status| QueuedRecipient {
            retry_count: 3,
            retry_due: UTCDateTime::from_timestamp(0),
            notify_count: 1,
            notify_due: UTCDateTime::from_timestamp(0),
            expires: QueueExpiry::Ttl(QueueExpiryTtl {
                expires_at: UTCDateTime::from_timestamp(0),
            }),
            queue_name: "remote".into(),
            status,
            flags: Default::default(),
            orcpt: None,
        };
        let error = DeliveryError {
            error_type: DeliveryErrorType::UnexpectedResponse,
            error_message: None,
            error_command: Some("DATA".into()),
            response_hostname: Some("mx.example.com".into()),
            response_code: Some(550),
            response_enhanced: Some("5.7.26".into()),
            response_message: Some("Unauthenticated email is not accepted".into()),
        };
        let mut message = QueuedMessage {
            return_path: "sender@example.org".into(),
            size: 1234,
            ..Default::default()
        };
        message.recipients.append(
            "rcpt@example.com",
            failed(RecipientStatus::PermanentFailure(error)),
        );
        message
            .recipients
            .append("ok@example.com", failed(RecipientStatus::Scheduled));

        let mut facts = Facts::default();
        delivery_facts(&mut facts, &message, "RCPT@example.com").unwrap();
        let text = format!("{:?}", facts.lines);
        // Acceptance test 4: the addresses and the reply, grounded in RFC 3463
        assert!(text.contains("sender@example.org") && text.contains("rcpt@example.com"));
        assert!(text.contains("5.7.26") && text.contains("Permanent failure"));
        assert!(!text.contains("Next attempt"), "no retry for a permanent failure");
        assert_eq!(facts.grounded, vec!["rfc3463"]);
        assert!(facts.grounding.iter().any(|g| g.starts_with("x.7.26:")));
        // A recipient that hasn't failed, or isn't there
        assert!(delivery_facts(&mut Facts::default(), &message, "ok@example.com").is_err());
        assert!(delivery_facts(&mut Facts::default(), &message, "no@example.com").is_err());
    }

    #[test]
    fn not_settings_parse() {
        for object in NOT_SETTINGS {
            assert_eq!(ObjectType::parse(object.as_str()), Some(*object));
        }
    }
}
