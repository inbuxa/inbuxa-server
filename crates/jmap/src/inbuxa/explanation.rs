/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:Explanation/set`: "Explain this" (`inbuxa-drafts/specs/ai-explain.md`).
//! The console names a subject; this reads the data behind it, builds the
//! prompt from the fixed prompts in `inbuxa_features::ai::explain`, and asks
//! this node's model, unless the release prepared an answer or this node
//! remembers one (EX-24, EX-26). Nothing is written to storage.

use crate::registry::mapping::{log::read_log_entries, queued_message::map_message};
use common::{
    Server,
    auth::AccessToken,
    config::mailstore::spamfilter::SpamFilterAction,
    enterprise::llm::{Call, Explain, Failure},
};
use inbuxa_features::ai::{
    explain::{
        self, DROPPED_KEYS, Facts, Subject, TagScore,
        memory::{self, Memory, Prepared, Remembered},
        prompts,
        schema::{PropertyInfo, Schema},
        status,
    },
    gate::Refused,
    limits::AiLimits,
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
        enums::{Permission, SpamClassifyResult},
        prelude::{OBJ_SINGLETON, Object, ObjectType},
        structs::{AiModel, QueuedMessage, QueuedRecipient, RecipientStatus},
    },
    types::{EnumImpl, datetime::UTCDateTime, id::ObjectId},
};
use smtp::queue::spool::SmtpSpool;
use tokio::sync::mpsc::UnboundedSender;
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
    inbuxa_features::ai::explain::schema::embedded()
}

fn server_fail(why: &'static str) -> SetError<P> {
    SetError::new(SetErrorType::ServerFail).with_description(why)
}

fn invalid_subject(why: impl Into<String>) -> SetError<P> {
    SetError::invalid_properties()
        .with_property(P::Subject)
        .with_description(why.into())
}

/// The prepared answers this release ships (EX-26), read once.
fn prepared() -> &'static Prepared {
    static PREPARED: OnceLock<Prepared> = OnceLock::new();
    static PREPARED_JSON: &[u8] =
        include_bytes!("../../../../resources/explain/settings.json.gz");
    PREPARED.get_or_init(|| {
        let mut json = Vec::new();
        match GzDecoder::new(PREPARED_JSON).read_to_end(&mut json) {
            Ok(_) => Prepared::parse(&json),
            Err(_) => Prepared::default(),
        }
    })
}

/// Who may ask (EX-4): server-level administrators holding `sysAiExplain`.
/// JMAP checks the permission by method; the streaming route checks it here.
pub fn assert_allowed(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        return Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Explanations are for server-level administrators."));
    }
    access_token.enforce_permission(Permission::SysAiExplain)
}

/// `inbuxa:Explanation/set`: create only (EX-4, EX-11).
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, Explanation>,
) -> trc::Result<SetResponse<Explanation>> {
    assert_allowed(access_token)?;
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
        let outcome = match subject_of(value) {
            Ok(subject) => match question(server, access_token, &subject).await? {
                Ok(question) => answer(server, access_token, question, None)
                    .await
                    .map(to_value),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        match outcome {
            Ok(created) => {
                response.created.insert(client_id, created);
            }
            Err(error) => response.not_created.append(client_id, error),
        }
    }
    Ok(response)
}

/// The subject of a create; everything else is the server's (EX-5).
fn subject_of(value: Value<'_, P, ExplanationValue>) -> Result<serde_json::Value, SetError<P>> {
    let mut subject = None;
    for (key, value) in value.into_expanded_object() {
        match key {
            Key::Property(P::Subject) => {
                subject = serde_json::to_value(&value).ok();
            }
            key => {
                return Err(SetError::invalid_properties()
                    .with_property(key.into_owned())
                    .with_description("is set by the server"));
            }
        }
    }
    subject.ok_or_else(|| invalid_subject("subject is required"))
}

/// A question, checked and read, ready to answer.
pub struct Question {
    subject: Subject,
    facts: Facts,
    model_id: Id,
    model: AiModel,
    limits: AiLimits,
}

/// Where an answer came from (EX-27).
pub enum Source {
    Model,
    Remembered { answered_at: u64 },
    Prepared { release: String },
}

impl Source {
    pub fn as_str(&self) -> &'static str {
        match self {
            Source::Model => "model",
            Source::Remembered { .. } => "remembered",
            Source::Prepared { .. } => "prepared",
        }
    }
}

/// An explanation, as the console gets it.
pub struct Answer {
    pub text: String,
    pub model: String,
    pub node: String,
    pub elapsed_ms: u64,
    pub grounded: Vec<&'static str>,
    pub source: Source,
}

/// Every check before any answer (EX-1 to EX-9): the subject parses, a model
/// resolves, and the data behind the subject is read. No model call yet.
pub async fn question(
    server: &Server,
    access_token: &AccessToken,
    subject: &serde_json::Value,
) -> trc::Result<Result<Question, SetError<P>>> {
    let subject = match explain::parse(subject) {
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
    Ok(Ok(Question {
        subject,
        facts,
        model_id,
        model,
        limits,
    }))
}

/// Answers a checked question: from the release's prepared answers (EX-26),
/// from this node's memory (EX-24), or from the model, streaming each piece
/// to `stream` when it's set (EX-23).
pub async fn answer(
    server: &Server,
    access_token: &AccessToken,
    question: Question,
    stream: Option<UnboundedSender<String>>,
) -> Result<Answer, SetError<P>> {
    let Question {
        subject,
        facts,
        model_id,
        model,
        limits,
    } = question;
    let kind = subject.kind();
    let node = server.registry().local_hostname().to_string();

    // EX-26: a setting at its default, as this release prepared it
    if kind == explain::Kind::Setting
        && let Some(text) = prepared().answer(kind, &facts)
    {
        let prepared = prepared();
        return Ok(Answer {
            text: text.to_string(),
            model: prepared.model.clone(),
            node,
            elapsed_ms: 0,
            grounded: facts.grounded,
            source: Source::Prepared {
                release: prepared.release.clone(),
            },
        });
    }

    // EX-24, EX-25: the same question, answered before on this node
    let key = memory::key(kind, &facts, &format!("{}@{}", model.name, model_id));
    if let Some(remembered) = Memory::global().get(key) {
        return Ok(Answer {
            text: remembered.text,
            model: remembered.model,
            node: remembered.node,
            elapsed_ms: 0,
            grounded: remembered.grounded,
            source: Source::Remembered {
                answered_at: remembered.answered_at,
            },
        });
    }

    let nonce = format!("{:016x}", rand::random::<u64>());
    let (system, user) = prompts::messages(kind, &facts, &nonce);
    let started = Instant::now();
    let result = server
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
            stream,
        })
        .await;
    let elapsed = started.elapsed();
    let text = match result {
        Ok(answer) => explain::tidy_answer(&answer),
        Err(Failure::Refused(Refused::Busy | Refused::OneAtATime)) => {
            return Err(server_fail("busy"));
        }
        Err(Failure::Refused(Refused::Paused)) => return Err(server_fail("paused")),
        Err(Failure::Refused(Refused::HourlyLimit)) => {
            return Err(SetError::new(SetErrorType::RateLimit).with_description(
                "You've asked for as many explanations as this hour allows.",
            ));
        }
        Err(Failure::Timeout) => return Err(server_fail("timeout")),
        Err(_) => return Err(server_fail("unavailable")),
    };
    if text.is_empty() {
        return Err(server_fail("unavailable"));
    }

    Memory::global().put(
        key,
        Remembered {
            text: text.clone(),
            model: model.name.clone(),
            node: node.clone(),
            answered_at: now(),
            grounded: facts.grounded.clone(),
        },
    );
    Ok(Answer {
        text,
        model: model.name.clone(),
        node,
        elapsed_ms: elapsed.as_millis() as u64,
        grounded: facts.grounded,
        source: Source::Model,
    })
}

/// An answer as `inbuxa:Explanation`.
pub fn to_value(answer: Answer) -> EValue {
    let mut out = Map::with_capacity(9);
    out.insert_unchecked(
        Key::Property(P::Id),
        Value::Element(ExplanationValue::Id(Id::from(rand::random::<u32>() as u64))),
    );
    out.insert_unchecked(Key::Property(P::Text), Value::Str(answer.text.into()));
    out.insert_unchecked(Key::Property(P::Model), Value::Str(answer.model.into()));
    out.insert_unchecked(Key::Property(P::Node), Value::Str(answer.node.into()));
    out.insert_unchecked(
        Key::Property(P::ElapsedMs),
        Value::Number(answer.elapsed_ms.into()),
    );
    out.insert_unchecked(
        Key::Property(P::Grounded),
        Value::Array(
            answer
                .grounded
                .iter()
                .map(|tag| Value::Str((*tag).into()))
                .collect(),
        ),
    );
    out.insert_unchecked(
        Key::Property(P::Source),
        Value::Str(answer.source.as_str().into()),
    );
    match answer.source {
        Source::Remembered { answered_at } => {
            out.insert_unchecked(
                Key::Property(P::AnsweredAt),
                Value::Str(
                    UTCDateTime::from_timestamp(answered_at as i64)
                        .to_string()
                        .into(),
                ),
            );
        }
        Source::Prepared { release } => {
            out.insert_unchecked(Key::Property(P::PreparedFor), Value::Str(release.into()));
        }
        Source::Model => {}
    }
    Value::Object(out)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    /// The settings questions a release prepares answers for (EX-26): every
    /// non-secret property of every settings object, at the object's own
    /// default, built exactly as a live question is.
    fn prepared_questions() -> Vec<(String, String, Facts)> {
        let schema = schema().expect("the embedded schema reads");
        let mut json = Vec::new();
        GzDecoder::new(&include_bytes!("../../../../resources/schema/schema.json.gz")[..])
            .read_to_end(&mut json)
            .unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&json).unwrap();
        let mut out = Vec::new();
        let mut objects = raw["objects"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("x:") && !k.contains('/'))
            .cloned()
            .collect::<Vec<_>>();
        objects.sort();
        for object in objects {
            let Some(object_type) = ObjectType::parse(&object[2..]) else {
                continue;
            };
            if NOT_SETTINGS.contains(&object_type) {
                continue;
            }
            // As a live question reads it: the object, serialized
            let default = serde_json::to_value(Object::from(object_type).into_value())
                .unwrap_or_default();
            let Some(map) = default.as_object() else {
                continue;
            };
            let mut properties = map.keys().cloned().collect::<Vec<_>>();
            properties.sort();
            for property in properties {
                if property == "@type" || property == "id" {
                    continue;
                }
                let Some(info) = schema.property(&object, &property) else {
                    continue;
                };
                if info.secret {
                    continue;
                }
                let mut facts = Facts::default();
                push_setting(&mut facts, &object, &property, &info, &map[&property]);
                out.push((object.clone(), property, facts));
            }
        }
        out
    }

    #[test]
    fn prepared_questions_are_well_formed() {
        let questions = prepared_questions();
        assert!(questions.len() > 500, "found {}", questions.len());
        assert!(questions.iter().any(|(o, p, _)| o == "x:Domain" && p == "dnsManagement"));
        assert!(!questions.iter().any(|(o, p, _)| o == "x:AiModel" && p == "httpAuth"));
    }

    /// Writes `resources/explain/settings.json.gz` (EX-26). Run before a
    /// release, against one or more model servers serving the recommended
    /// model. Each server gets its own workers, all taking from one queue,
    /// so a faster server simply answers more:
    ///
    ///   INBUXA_PREPARE_MODEL_URL=http://127.0.0.1:18182/v1/chat/completions,http://127.0.0.1:18183/v1/chat/completions \
    ///   INBUXA_PREPARE_CONCURRENCY=8,2 \
    ///   INBUXA_PREPARE_MODEL=qwen3-4b-instruct-2507 INBUXA_PREPARE_RELEASE=2026.9.27 \
    ///   cargo test -p jmap --release --lib -- --ignored prepare_setting_explanations --nocapture
    ///
    /// Answers already in the file for the same key are kept, so a rerun only
    /// asks about settings that changed.
    #[test]
    #[ignore]
    fn prepare_setting_explanations() {
        use inbuxa_features::ai::explain::memory::{key, key_hex};
        use std::io::Write;
        let urls = std::env::var("INBUXA_PREPARE_MODEL_URL").expect("INBUXA_PREPARE_MODEL_URL");
        let urls = urls.split(',').map(str::trim).filter(|u| !u.is_empty()).map(String::from).collect::<Vec<_>>();
        let model = std::env::var("INBUXA_PREPARE_MODEL").expect("INBUXA_PREPARE_MODEL");
        let release = std::env::var("INBUXA_PREPARE_RELEASE").expect("INBUXA_PREPARE_RELEASE");
        let concurrency = std::env::var("INBUXA_PREPARE_CONCURRENCY").unwrap_or_else(|_| "4".into());
        let concurrency = concurrency
            .split(',')
            .map(|c| c.trim().parse::<usize>().unwrap_or(4).max(1))
            .collect::<Vec<_>>();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources/explain/settings.json.gz");

        let mut answers = prepared().answers.clone();
        let wanted = prepared_questions()
            .into_iter()
            .map(|(object, property, facts)| {
                let k = key_hex(key(explain::Kind::Setting, &facts, ""));
                (object, property, facts, k)
            })
            .collect::<Vec<_>>();
        let todo = wanted
            .iter()
            .filter(|(_, _, _, k)| !answers.contains_key(k))
            .cloned()
            .collect::<Vec<_>>();
        eprintln!("{} settings, {} to ask about", wanted.len(), todo.len());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let client = reqwest::Client::new();
        let started = Instant::now();
        let queue = std::sync::Arc::new(std::sync::Mutex::new(
            todo.into_iter().collect::<std::collections::VecDeque<_>>(),
        ));
        let results = runtime.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            for (i, url) in urls.iter().enumerate() {
                let workers = concurrency.get(i).or(concurrency.last()).copied().unwrap_or(4);
                for _ in 0..workers {
                    let (client, url, model, queue) =
                        (client.clone(), url.clone(), model.clone(), queue.clone());
                    set.spawn(async move {
                        let mut out = Vec::new();
                        loop {
                            let next = queue.lock().unwrap().pop_front();
                            let Some((object, property, facts, k)) = next else {
                                break;
                            };
                            let nonce = format!("{:016x}", rand::random::<u64>());
                            let (system, user) =
                                prompts::messages(explain::Kind::Setting, &facts, &nonce);
                            let body = inbuxa_features::ai::request::body(
                                inbuxa_features::ai::request::Kind::Chat,
                                &model,
                                Some(&system),
                                &user,
                                0.2,
                                explain::MAX_TOKENS,
                                false,
                            );
                            let reply = match client
                                .post(&url)
                                .header("content-type", "application/json")
                                .body(body.to_string())
                                .send()
                                .await
                            {
                                Ok(response) => response.bytes().await.ok(),
                                Err(_) => None,
                            };
                            let text = reply.and_then(|reply| {
                                inbuxa_features::ai::request::answer(
                                    inbuxa_features::ai::request::Kind::Chat,
                                    &reply,
                                )
                            });
                            match text.map(|t| explain::tidy_answer(&t)) {
                                Some(text) if !text.is_empty() => {
                                    eprintln!("{object}.{property}: {} chars", text.len());
                                    out.push((k, text));
                                }
                                _ => eprintln!("{object}.{property}: no answer"),
                            }
                        }
                        out
                    });
                }
            }
            let mut out = Vec::new();
            while let Some(result) = set.join_next().await {
                if let Ok(pairs) = result {
                    out.extend(pairs);
                }
            }
            out
        });
        let asked = results.len();
        answers.extend(results);
        // Only answers for questions this release still has
        let keep = wanted.iter().map(|(_, _, _, k)| k.clone()).collect::<std::collections::HashSet<_>>();
        answers.retain(|k, _| keep.contains(k));
        let mut sorted = answers.into_iter().collect::<Vec<_>>();
        sorted.sort();
        let json = serde_json::json!({
            "release": release,
            "model": model,
            "promptVersion": prompts::PROMPT_VERSION,
            "answers": sorted.into_iter().map(|(k, v)| (k, serde_json::Value::String(v))).collect::<serde_json::Map<_, _>>(),
        });
        let mut gz = mail_auth::flate2::write::GzEncoder::new(
            std::fs::File::create(path).unwrap(),
            mail_auth::flate2::Compression::best(),
        );
        gz.write_all(serde_json::to_string_pretty(&json).unwrap().as_bytes())
            .unwrap();
        gz.finish().unwrap();
        eprintln!(
            "asked {asked} in {:.0}s; wrote {} answers to {path}",
            started.elapsed().as_secs_f64(),
            json["answers"].as_object().map(|a| a.len()).unwrap_or(0)
        );
    }

    #[test]
    fn not_settings_parse() {
        for object in NOT_SETTINGS {
            assert_eq!(ObjectType::parse(object.as_str()), Some(*object));
        }
    }
}
