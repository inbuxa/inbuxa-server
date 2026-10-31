/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The relay's JMAP methods (spec "The relay's JMAP API").
//!
//! One account, `relay`. No back-references: the downstream doesn't need
//! them. Before the join completes, only `Relay/join`, then `Relay/get` and
//! `Relay/set`, answer; everything else is `forbidden`.

use crate::{app::App, link::tls::cert_pin, outbound::Destroyed, state::JoinStage};
use inbuxa_relay_proto::{
    CAPABILITY, CORE_CAPABILITY, b64,
    jmap::{Invocation, MethodError, Request, Response, method},
    recipient::{RecipientDomain, RecipientHash},
    time, token,
    types::{NewOutbound, RELAY_SINGLETON, RelaySettings, RelayStatus, Verdict, type_name},
};
use rustls_pki_types::{CertificateDer, pem::PemObject};
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub const ACCOUNT_ID: &str = "relay";
pub const MAX_CALLS: usize = 64;
const MAX_CHANGES: usize = 5000;
const CLAIM_LIMIT_MAX: usize = 100;
const LEASE_DEFAULT: u64 = 300;
const LEASE_MAX: u64 = 3600;

/// A request-level failure (RFC 8620 §3.6.1).
#[derive(Debug)]
pub struct RequestError {
    pub kind: &'static str,
    pub status: u16,
    pub detail: String,
}

/// Who is calling: the connection, for leases, and where it comes from.
#[derive(Clone, Copy)]
pub struct Caller {
    pub conn: u64,
    pub peer: std::net::IpAddr,
}

type Failure = (MethodError, Option<String>);
type MethodResult = Result<Value, Failure>;

fn err(kind: MethodError, text: impl Into<String>) -> Failure {
    (kind, Some(text.into()))
}

pub fn handle(app: &App, caller: &Caller, request: Request) -> Result<Response, RequestError> {
    for cap in [CORE_CAPABILITY, CAPABILITY] {
        if !request.using.iter().any(|u| u == cap) {
            return Err(RequestError {
                kind: inbuxa_relay_proto::jmap::request_error::UNKNOWN_CAPABILITY,
                status: 400,
                detail: format!("the request must use {cap}"),
            });
        }
    }
    if request.method_calls.len() > MAX_CALLS {
        return Err(RequestError {
            kind: inbuxa_relay_proto::jmap::request_error::LIMIT,
            status: 400,
            detail: format!("at most {MAX_CALLS} method calls a request"),
        });
    }
    let mut responses = Vec::with_capacity(request.method_calls.len());
    for call in &request.method_calls {
        let result = call_one(app, caller, call);
        responses.push(match result {
            Ok(Value::Object(args)) => {
                Invocation(call.name().to_string(), args, call.call_id().into())
            }
            Ok(_) => call.error(MethodError::ServerFail, None),
            Err((kind, text)) => call.error(kind, text),
        });
    }
    Ok(Response {
        method_responses: responses,
        session_state: "1".into(),
        created_ids: None,
    })
}

fn call_one(app: &App, caller: &Caller, call: &Invocation) -> MethodResult {
    let args = call.args();
    if args.get("accountId").and_then(Value::as_str) != Some(ACCOUNT_ID) {
        return Err(err(MethodError::AccountNotFound, "the account is `relay`"));
    }
    let stage = app.identity.lock().expect("identity").stage;
    let allowed = match stage {
        JoinStage::Joined => true,
        JoinStage::Waiting => call.name() == method::RELAY_JOIN,
        JoinStage::Answered => matches!(call.name(), method::RELAY_GET | method::RELAY_SET),
    };
    if !allowed {
        return Err(err(
            MethodError::Forbidden,
            "the relay has not finished joining",
        ));
    }
    match call.name() {
        method::RELAY_JOIN => relay_join(app, args),
        method::RELAY_GET => relay_get(app, caller, args),
        method::RELAY_SET => relay_set(app, args),
        method::RELAY_UPGRADE => relay_upgrade(app, args),
        method::RECIPIENT_DOMAIN_GET => recipient_domain_get(app),
        method::RECIPIENT_DOMAIN_SET => recipient_domain_set(app, args),
        method::RECIPIENT_SET => recipient_set(app, args),
        method::RECIPIENT_CHANGES => recipient_changes(app, args),
        method::RECIPIENT_REPLACE => recipient_replace(app, args),
        method::INBOUND_GET => inbound_get(app, args),
        method::INBOUND_QUERY => inbound_query(app),
        method::INBOUND_CHANGES => inbound_changes(app, args),
        method::INBOUND_CLAIM => inbound_claim(app, caller, args),
        method::INBOUND_SET => inbound_set(app, args),
        method::OUTBOUND_GET => outbound_get(app, args),
        method::OUTBOUND_CHANGES => outbound_changes(app, args),
        method::OUTBOUND_SET => outbound_set(app, args),
        method::RELAY_EVENT_GET => event_get(app, args),
        method::RELAY_EVENT_CHANGES => event_changes(app, args),
        method::RELAY_EVENT_SET => event_set(app, args),
        _ => Err((MethodError::UnknownMethod, None)),
    }
}

fn string_list(args: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>, Failure> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .map(Some)
            .ok_or_else(|| {
                err(
                    MethodError::InvalidArguments,
                    format!("{key} must be a list of strings"),
                )
            }),
        Some(_) => Err(err(
            MethodError::InvalidArguments,
            format!("{key} must be a list"),
        )),
    }
}

fn object<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, Failure> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(map)) => Ok(Some(map)),
        Some(_) => Err(err(
            MethodError::InvalidArguments,
            format!("{key} must be an object"),
        )),
    }
}

fn set_error(kind: &str, description: impl Into<String>) -> Value {
    json!({ "type": kind, "description": description.into() })
}

// ---- Relay ----------------------------------------------------------------

fn relay_join(app: &App, args: &Map<String, Value>) -> MethodResult {
    let nonce = args
        .get("nonce")
        .and_then(Value::as_str)
        .and_then(b64::decode)
        .filter(|n| (16..=64).contains(&n.len()))
        .ok_or_else(|| {
            err(
                MethodError::InvalidArguments,
                "nonce: 16 to 64 bytes, base64url",
            )
        })?;
    let mut identity = app.identity.lock().expect("identity");
    if identity.stage != JoinStage::Waiting {
        return Err(err(
            MethodError::Forbidden,
            "the relay has already answered a join",
        ));
    }
    if time::now() >= identity.join_expires_at {
        return Err(err(
            MethodError::Forbidden,
            "the join token has expired: reset and join again",
        ));
    }
    let secret = identity
        .join_secret
        .ok_or_else(|| err(MethodError::Forbidden, "no join secret"))?;
    let pin = CertificateDer::from_pem_slice(identity.link_cert_pem.as_bytes())
        .ok()
        .and_then(|der| cert_pin(&der))
        .ok_or_else(|| {
            err(
                MethodError::ServerFail,
                "the link certificate is unreadable",
            )
        })?;
    let proof = token::join_proof(&secret, &nonce, &pin);
    identity.stage = JoinStage::Answered;
    identity
        .save(&app.paths)
        .map_err(|e| err(MethodError::ServerFail, e.to_string()))?;
    drop(identity);
    app.record("relay.join-answered", Map::new());
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "proof": b64::encode(&proof),
        "relayPin": b64::encode(&pin),
    }))
}

fn relay_object(app: &App, caller: &Caller) -> Value {
    let settings = app.settings().map(|s| (*s).clone()).unwrap_or_default();
    let mut value = serde_json::to_value(&settings).expect("settings serialize");
    let obj = value.as_object_mut().expect("object");
    // Secrets the relay holds are never read back.
    obj.remove("recipientKey");
    if let Some(Value::Object(cert)) = obj.get_mut("smtpCertificate") {
        cert.remove("keyPem");
    }
    obj.insert("id".into(), Value::String(RELAY_SINGLETON.into()));
    obj.insert(
        "status".into(),
        serde_json::to_value(RelayStatus {
            link_from: Some(caller.peer.to_string()),
            ..app.status()
        })
        .expect("status serializes"),
    );
    obj.insert(
        "relayVersion".into(),
        Value::String(crate::app::VERSION.into()),
    );
    value
}

fn relay_get(app: &App, caller: &Caller, args: &Map<String, Value>) -> MethodResult {
    let ids = string_list(args, "ids")?;
    let wanted = ids
        .as_ref()
        .is_none_or(|ids| ids.iter().any(|i| i == RELAY_SINGLETON));
    let not_found: Vec<String> = ids
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i != RELAY_SINGLETON)
        .collect();
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "state": app.relay_state(),
        "list": if wanted { vec![relay_object(app, caller)] } else { vec![] },
        "notFound": not_found,
    }))
}

/// Read-only on `Relay`: what only the relay sets.
const RELAY_READ_ONLY: &[&str] = &["id", "status", "relayVersion"];

fn relay_set(app: &App, args: &Map<String, Value>) -> MethodResult {
    let old_state = app.relay_state();
    if let Some(if_in) = args.get("ifInState").and_then(Value::as_str)
        && if_in != old_state
    {
        return Err((MethodError::StateMismatch, None));
    }
    let mut not_updated = Map::new();
    let mut updated = Map::new();
    for key in ["create", "destroy"] {
        if args.get(key).is_some_and(|v| !v.is_null()) {
            return Err(err(
                MethodError::InvalidArguments,
                "Relay can only be updated",
            ));
        }
    }
    if let Some(update) = object(args, "update")? {
        for (id, patch) in update {
            if id != RELAY_SINGLETON {
                not_updated.insert(
                    id.clone(),
                    set_error("notFound", "the only Relay is singleton"),
                );
                continue;
            }
            match apply_settings(app, patch) {
                Ok(()) => {
                    updated.insert(id.clone(), Value::Null);
                }
                Err(e) => {
                    not_updated.insert(id.clone(), e);
                }
            }
        }
    }
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": old_state,
        "newState": app.relay_state(),
        "updated": updated,
        "notUpdated": not_updated,
    }))
}

/// `Relay/upgrade` (RL-29): `{blobId, signature}`, the release binary as
/// an upload and its signature file's text. Answers once the new binary
/// is in place; the relay then exits for its supervisor to restart it.
fn relay_upgrade(app: &App, args: &Map<String, Value>) -> MethodResult {
    use crate::upgrade::{self, Refused};
    use std::sync::atomic::Ordering;
    if !app.self_upgrade {
        return Err(err(
            MethodError::Forbidden,
            "this relay runs in a container image: update the image instead",
        ));
    }
    let blob_id = args
        .get("blobId")
        .and_then(Value::as_str)
        .filter(|id| crate::link::is_blob_id(id))
        .ok_or_else(|| err(MethodError::InvalidArguments, "blobId: an uploaded blob"))?;
    let signature = args
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            err(
                MethodError::InvalidArguments,
                "signature: the release's signature file",
            )
        })?;
    let exe = app
        .exe
        .clone()
        .ok_or_else(|| err(MethodError::ServerFail, "the relay can't find its binary"))?;
    if app.upgrading.swap(true, Ordering::SeqCst) {
        return Err(err(
            MethodError::Forbidden,
            "an upgrade is already on its way",
        ));
    }
    let path = app.paths.blobs().join(blob_id);
    let result = std::fs::read(&path)
        .map_err(|_| Refused::Invalid("no such blob".into()))
        .and_then(|binary| {
            let release =
                upgrade::check(&binary, signature, &app.release_keys, crate::app::VERSION)?;
            upgrade::install(&exe, &binary, &release.version)?;
            Ok(release)
        });
    let _ = std::fs::remove_file(&path);
    let release = match result {
        Ok(release) => release,
        Err(refused) => {
            app.upgrading.store(false, Ordering::SeqCst);
            let (kind, text) = match refused {
                Refused::Invalid(text) => (MethodError::InvalidArguments, text),
                Refused::Failed(text) => (MethodError::ServerFail, text),
            };
            app.record(
                "relay.upgrade-refused",
                crate::events::data([("reason", json!(text))]),
            );
            return Err(err(kind, text));
        }
    };
    app.record(
        "relay.upgraded",
        crate::events::data([
            ("from", json!(crate::app::VERSION)),
            ("to", json!(release.version)),
        ]),
    );
    app.restart.notify_one();
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "relayVersion": release.version,
    }))
}

fn apply_settings(app: &App, patch: &Value) -> Result<(), Value> {
    let Value::Object(patch) = patch else {
        return Err(set_error("invalidPatch", "a patch is an object"));
    };
    let current = app.settings().map(|s| (*s).clone()).unwrap_or_default();
    let mut merged = serde_json::to_value(&current).expect("settings serialize");
    let defaults = serde_json::to_value(RelaySettings::default()).expect("settings serialize");
    let obj = merged.as_object_mut().expect("object");
    for (key, value) in patch {
        if key.contains('/') {
            return Err(set_error("invalidPatch", "set whole properties, not paths"));
        }
        if RELAY_READ_ONLY.contains(&key.as_str()) {
            return Err(set_error(
                "invalidProperties",
                format!("{key} is set by the relay"),
            ));
        }
        if value.is_null() {
            match defaults.get(key) {
                Some(default) => obj.insert(key.clone(), default.clone()),
                None => obj.remove(key),
            };
        } else {
            obj.insert(key.clone(), value.clone());
        }
    }
    // An unchanged key on the certificate keeps the stored one.
    if let (Some(Value::Object(new)), Some(old)) =
        (obj.get_mut("smtpCertificate"), &current.smtp_certificate)
        && new.get("keyPem").is_none_or(|k| k.as_str() == Some(""))
        && new.get("chainPem").and_then(Value::as_str) == Some(old.chain_pem.as_str())
    {
        new.insert("keyPem".into(), Value::String(old.key_pem.clone()));
    }
    let settings: RelaySettings = serde_json::from_value(merged)
        .map_err(|e| set_error("invalidProperties", e.to_string()))?;
    let problems = settings.problems();
    if !problems.is_empty() {
        return Err(set_error("invalidProperties", problems.join("; ")));
    }
    if let Some(cert) = &settings.smtp_certificate
        && let Err(e) = crate::smtp::tls_config(&settings.hostname, Some(cert))
    {
        return Err(set_error(
            "invalidProperties",
            format!("smtpCertificate: {e}"),
        ));
    }
    crate::state::save_settings(&app.paths, &settings)
        .map_err(|e| set_error("serverFail", e.to_string()))?;
    app.link_allow_from_changed(&settings.link_allow_from);
    app.settings.send_replace(Some(Arc::new(settings)));

    // The first Relay/set after the proof completes the join.
    let mut identity = app.identity.lock().expect("identity");
    let joined_now = identity.stage == JoinStage::Answered;
    if joined_now {
        identity.stage = JoinStage::Joined;
        identity.join_secret = None;
        identity
            .save(&app.paths)
            .map_err(|e| set_error("serverFail", e.to_string()))?;
    }
    drop(identity);
    if joined_now {
        app.record("relay.joined", Map::new());
    }
    app.relay_changed();
    Ok(())
}

// ---- Recipients -----------------------------------------------------------

fn recipient_domain_get(app: &App) -> MethodResult {
    let recipients = app.recipients.read().expect("recipients");
    let list: Vec<Value> = recipients
        .domains()
        .map(|d| {
            let mut v = serde_json::to_value(d).expect("domain serializes");
            v["id"] = Value::String(d.domain.clone());
            v
        })
        .collect();
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "state": recipients.state(),
        "list": list,
        "notFound": [],
    }))
}

fn recipient_domain_set(app: &App, args: &Map<String, Value>) -> MethodResult {
    let mut recipients = app.recipients.write().expect("recipients");
    let old_state = recipients.state();
    let mut created = Map::new();
    let mut not_created = Map::new();
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    if let Some(create) = object(args, "create")? {
        for (key, value) in create {
            match serde_json::from_value::<RecipientDomain>(value.clone()) {
                Ok(domain) if !domain.domain.is_empty() => {
                    let id = domain.domain.trim_end_matches('.').to_lowercase();
                    recipients.put_domain(domain);
                    created.insert(key.clone(), json!({ "id": id }));
                }
                Ok(_) => {
                    not_created.insert(
                        key.clone(),
                        set_error("invalidProperties", "domain is required"),
                    );
                }
                Err(e) => {
                    not_created.insert(key.clone(), set_error("invalidProperties", e.to_string()));
                }
            }
        }
    }
    if let Some(update) = object(args, "update")? {
        for (id, patch) in update {
            let Some(current) = recipients.domain(id).cloned() else {
                not_updated.insert(id.clone(), set_error("notFound", "no such domain"));
                continue;
            };
            let mut merged = serde_json::to_value(&current).expect("domain serializes");
            if let (Some(obj), Value::Object(patch)) = (merged.as_object_mut(), patch) {
                for (k, v) in patch {
                    obj.insert(k.clone(), v.clone());
                }
            }
            match serde_json::from_value::<RecipientDomain>(merged) {
                Ok(domain) if domain.domain == current.domain => {
                    recipients.put_domain(domain);
                    updated.insert(id.clone(), Value::Null);
                }
                Ok(_) => {
                    not_updated.insert(
                        id.clone(),
                        set_error("invalidProperties", "domain can't change"),
                    );
                }
                Err(e) => {
                    not_updated.insert(id.clone(), set_error("invalidProperties", e.to_string()));
                }
            }
        }
    }
    for id in string_list(args, "destroy")?.unwrap_or_default() {
        if recipients.remove_domain(&id) {
            destroyed.push(id);
        } else {
            not_destroyed.insert(id, set_error("notFound", "no such domain"));
        }
    }
    let new_state = save_recipients(app, &recipients)?;
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": old_state,
        "newState": new_state,
        "created": created,
        "notCreated": not_created,
        "updated": updated,
        "notUpdated": not_updated,
        "destroyed": destroyed,
        "notDestroyed": not_destroyed,
    }))
}

fn save_recipients(
    app: &App,
    recipients: &crate::recipients::Recipients,
) -> Result<String, Failure> {
    recipients
        .save(&app.paths)
        .map_err(|e| err(MethodError::ServerFail, e.to_string()))?;
    let state = recipients.state();
    app.notify(type_name::RECIPIENT, state.clone());
    app.notify(type_name::RECIPIENT_DOMAIN, state.clone());
    Ok(state)
}

fn parse_hash(text: &str) -> Option<RecipientHash> {
    b64::decode(text).and_then(|b| b.try_into().ok())
}

fn recipient_set(app: &App, args: &Map<String, Value>) -> MethodResult {
    let mut created = Map::new();
    let mut not_created = Map::new();
    let mut add = Vec::new();
    if let Some(create) = object(args, "create")? {
        for (key, value) in create {
            match value
                .get("hash")
                .and_then(Value::as_str)
                .and_then(parse_hash)
            {
                Some(hash) => {
                    add.push(hash);
                    created.insert(key.clone(), json!({ "id": b64::encode(&hash) }));
                }
                None => {
                    not_created.insert(
                        key.clone(),
                        set_error("invalidProperties", "hash: 32 bytes, base64url"),
                    );
                }
            }
        }
    }
    let mut remove = Vec::new();
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    for id in string_list(args, "destroy")?.unwrap_or_default() {
        match parse_hash(&id) {
            Some(hash) => {
                remove.push(hash);
                destroyed.push(id);
            }
            None => {
                not_destroyed.insert(id, set_error("notFound", "not a recipient id"));
            }
        }
    }
    let mut recipients = app.recipients.write().expect("recipients");
    let old_state = recipients.state();
    recipients.apply(&add, &remove);
    let new_state = save_recipients(app, &recipients)?;
    drop(recipients);
    app.relay_changed();
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": old_state,
        "newState": new_state,
        "created": created,
        "notCreated": not_created,
        "updated": {},
        "destroyed": destroyed,
        "notDestroyed": not_destroyed,
    }))
}

fn recipient_changes(app: &App, args: &Map<String, Value>) -> MethodResult {
    let since = args.get("sinceState").and_then(Value::as_str).unwrap_or("");
    let state = app.recipients.read().expect("recipients").state();
    if since != state {
        // The relay doesn't log recipient changes: the downstream holds the
        // set, and sends it again with Recipient/replace.
        return Err((MethodError::CannotCalculateChanges, None));
    }
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": since,
        "newState": state,
        "hasMoreChanges": false,
        "created": [], "updated": [], "destroyed": [],
    }))
}

fn recipient_replace(app: &App, args: &Map<String, Value>) -> MethodResult {
    let blob_id = args
        .get("blobId")
        .and_then(Value::as_str)
        .filter(|id| crate::link::is_blob_id(id))
        .ok_or_else(|| err(MethodError::InvalidArguments, "blobId: an uploaded blob"))?;
    let path = app.paths.blobs().join(blob_id);
    let file =
        std::fs::read(&path).map_err(|_| err(MethodError::InvalidArguments, "no such blob"))?;
    let mut recipients = app.recipients.write().expect("recipients");
    let old_state = recipients.state();
    let count = recipients
        .replace(&file)
        .map_err(|e| err(MethodError::InvalidArguments, e))?;
    let new_state = save_recipients(app, &recipients)?;
    drop(recipients);
    let _ = std::fs::remove_file(path);
    app.record(
        "recipients.replaced",
        crate::events::data([("count", json!(count))]),
    );
    app.relay_changed();
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": old_state,
        "newState": new_state,
        "count": count,
    }))
}

// ---- Inbound --------------------------------------------------------------

fn inbound_get(app: &App, args: &Map<String, Value>) -> MethodResult {
    let ids = string_list(args, "ids")?;
    let now = time::now();
    let spool = app.spool.lock().expect("spool");
    let ids = ids.unwrap_or_else(|| spool.ids(now));
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in ids {
        match spool.get(&id, now) {
            Some(inbound) => list.push(serde_json::to_value(inbound).expect("inbound serializes")),
            None => not_found.push(id),
        }
    }
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "state": spool.state(),
        "list": list,
        "notFound": not_found,
    }))
}

fn inbound_query(app: &App) -> MethodResult {
    let spool = app.spool.lock().expect("spool");
    let ids = spool.ids(time::now());
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "queryState": spool.state(),
        "canCalculateChanges": false,
        "position": 0,
        "total": ids.len(),
        "ids": ids,
    }))
}

fn inbound_changes(app: &App, args: &Map<String, Value>) -> MethodResult {
    let since = args
        .get("sinceState")
        .and_then(Value::as_str)
        .ok_or_else(|| err(MethodError::InvalidArguments, "sinceState is required"))?;
    let max = args
        .get("maxChanges")
        .and_then(Value::as_u64)
        .map_or(MAX_CHANGES, |m| (m as usize).clamp(1, MAX_CHANGES));
    let spool = app.spool.lock().expect("spool");
    let changes = spool
        .changes(since, max)
        .ok_or((MethodError::CannotCalculateChanges, None))?;
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": changes.old_state,
        "newState": changes.new_state,
        "hasMoreChanges": changes.has_more,
        "created": changes.created,
        "updated": changes.updated,
        "destroyed": changes.destroyed,
    }))
}

fn inbound_claim(app: &App, caller: &Caller, args: &Map<String, Value>) -> MethodResult {
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map_or(10, |l| (l as usize).clamp(1, CLAIM_LIMIT_MAX));
    let lease = args
        .get("leaseSeconds")
        .and_then(Value::as_u64)
        .map_or(LEASE_DEFAULT, |l| l.clamp(10, LEASE_MAX));
    let (ids, state) = {
        let mut spool = app.spool.lock().expect("spool");
        let ids = spool.claim(caller.conn, limit, lease, time::now());
        (ids, spool.state())
    };
    if !ids.is_empty() {
        app.notify(type_name::INBOUND, state.clone());
    }
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "ids": ids,
        "newState": state,
    }))
}

fn inbound_set(app: &App, args: &Map<String, Value>) -> MethodResult {
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    if object(args, "create")?.is_some_and(|c| !c.is_empty()) {
        return Err(err(
            MethodError::InvalidArguments,
            "only the relay creates Inbound",
        ));
    }
    let mut spool = app.spool.lock().expect("spool");
    let old_state = spool.state();
    if let Some(update) = object(args, "update")? {
        for (id, patch) in update {
            let verdict = patch
                .get("verdict")
                .cloned()
                .ok_or(())
                .and_then(|v| serde_json::from_value::<Verdict>(v).map_err(|_| ()));
            let only_verdict = patch.as_object().is_some_and(|p| p.len() == 1);
            match verdict {
                Ok(verdict) if only_verdict => match spool.set_verdict(id, verdict) {
                    Ok(()) => {
                        updated.insert(id.clone(), Value::Null);
                    }
                    Err(e) => {
                        let (kind, text) = match e {
                            crate::spool::VerdictError::NotFound => ("notFound", "no such message"),
                            crate::spool::VerdictError::NotPending => (
                                "invalidProperties",
                                "the message isn't waiting for a verdict",
                            ),
                            crate::spool::VerdictError::Invalid => {
                                ("invalidProperties", "the reply doesn't fit the verdict")
                            }
                        };
                        not_updated.insert(id.clone(), set_error(kind, text));
                    }
                },
                _ => {
                    not_updated.insert(
                        id.clone(),
                        set_error("invalidProperties", "only verdict can be set"),
                    );
                }
            }
        }
    }
    for id in string_list(args, "destroy")?.unwrap_or_default() {
        if spool.destroy(&id) {
            destroyed.push(id);
        } else {
            not_destroyed.insert(id, set_error("notFound", "no such message"));
        }
    }
    let new_state = spool.state();
    drop(spool);
    if new_state != old_state {
        app.notify(type_name::INBOUND, new_state.clone());
    }
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": old_state,
        "newState": new_state,
        "updated": updated,
        "notUpdated": not_updated,
        "destroyed": destroyed,
        "notDestroyed": not_destroyed,
    }))
}

// ---- Outbound -------------------------------------------------------------

fn outbound_get(app: &App, args: &Map<String, Value>) -> MethodResult {
    let ids = string_list(args, "ids")?;
    let outbox = app.outbox.lock().expect("outbox");
    let ids = ids.unwrap_or_else(|| outbox.ids());
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in ids {
        match outbox.get(&id) {
            Some(outbound) => {
                list.push(serde_json::to_value(outbound).expect("outbound serializes"))
            }
            None => not_found.push(id),
        }
    }
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "state": outbox.state(),
        "list": list,
        "notFound": not_found,
    }))
}

fn outbound_changes(app: &App, args: &Map<String, Value>) -> MethodResult {
    let since = args
        .get("sinceState")
        .and_then(Value::as_str)
        .ok_or_else(|| err(MethodError::InvalidArguments, "sinceState is required"))?;
    let max = args
        .get("maxChanges")
        .and_then(Value::as_u64)
        .map_or(MAX_CHANGES, |m| (m as usize).clamp(1, MAX_CHANGES));
    let outbox = app.outbox.lock().expect("outbox");
    let changes = outbox
        .changes(since, max)
        .ok_or((MethodError::CannotCalculateChanges, None))?;
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": changes.old_state,
        "newState": changes.new_state,
        "hasMoreChanges": changes.has_more,
        "created": changes.created,
        "updated": changes.updated,
        "destroyed": changes.destroyed,
    }))
}

/// RL-19: the only way mail leaves through the relay.
fn outbound_set(app: &App, args: &Map<String, Value>) -> MethodResult {
    let mut created = Map::new();
    let mut not_created = Map::new();
    let mut not_updated = Map::new();
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    let settings = app.settings();
    let create = object(args, "create")?;
    let full = match (&settings, create) {
        (Some(settings), Some(create)) if !create.is_empty() => app.spool_full(settings),
        _ => false,
    };
    let mut outbox = app.outbox.lock().expect("outbox");
    let old_state = outbox.state();
    for (key, value) in create.into_iter().flatten() {
        let new = match serde_json::from_value::<NewOutbound>(value.clone()) {
            Ok(new) if crate::link::is_blob_id(&new.blob_id) => new,
            Ok(_) => {
                not_created.insert(
                    key.clone(),
                    set_error("invalidProperties", "blobId: an uploaded blob"),
                );
                continue;
            }
            Err(e) => {
                not_created.insert(key.clone(), set_error("invalidProperties", e.to_string()));
                continue;
            }
        };
        let Some(settings) = &settings else {
            not_created.insert(
                key.clone(),
                set_error("forbidden", "the relay has no settings yet"),
            );
            continue;
        };
        let blob = app.paths.blobs().join(&new.blob_id);
        match outbox.create(
            &blob,
            &new.blob_id,
            new.envelope,
            settings,
            full,
            time::now(),
        ) {
            Ok(id) => {
                let object = outbox.get(&id).expect("just created");
                created.insert(
                    key.clone(),
                    serde_json::to_value(object).expect("outbound serializes"),
                );
            }
            Err(refusal) => {
                not_created.insert(key.clone(), set_error(refusal.kind, refusal.description));
            }
        }
    }
    for id in object(args, "update")?
        .into_iter()
        .flatten()
        .map(|(id, _)| id)
    {
        not_updated.insert(
            id.clone(),
            set_error("forbidden", "only the relay changes an Outbound"),
        );
    }
    for id in string_list(args, "destroy")?.unwrap_or_default() {
        match outbox.destroy(&id) {
            Destroyed::Yes => destroyed.push(id),
            Destroyed::NotFound => {
                not_destroyed.insert(id, set_error("notFound", "no such message"));
            }
            Destroyed::InFlight => {
                not_destroyed.insert(
                    id,
                    set_error("forbidden", "a delivery attempt is under way; try again"),
                );
            }
        }
    }
    let new_state = outbox.state();
    drop(outbox);
    if new_state != old_state {
        app.notify(type_name::OUTBOUND, new_state.clone());
        app.relay_changed();
    }
    if !created.is_empty() {
        app.outbound_wake.notify_one();
    }
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": old_state,
        "newState": new_state,
        "created": created,
        "notCreated": not_created,
        "updated": {},
        "notUpdated": not_updated,
        "destroyed": destroyed,
        "notDestroyed": not_destroyed,
    }))
}

// ---- RelayEvent -----------------------------------------------------------

fn event_get(app: &App, args: &Map<String, Value>) -> MethodResult {
    let ids = string_list(args, "ids")?;
    let events = app.events.lock().expect("events");
    let (list, not_found) = events.get(ids.as_deref());
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "state": events.state(),
        "list": list,
        "notFound": not_found,
    }))
}

fn event_changes(app: &App, args: &Map<String, Value>) -> MethodResult {
    let since = args
        .get("sinceState")
        .and_then(Value::as_str)
        .ok_or_else(|| err(MethodError::InvalidArguments, "sinceState is required"))?;
    let events = app.events.lock().expect("events");
    let (created, destroyed) = events
        .changes(since)
        .ok_or((MethodError::CannotCalculateChanges, None))?;
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": since,
        "newState": events.state(),
        "hasMoreChanges": false,
        "created": created,
        "updated": [],
        "destroyed": destroyed,
    }))
}

fn event_set(app: &App, args: &Map<String, Value>) -> MethodResult {
    if object(args, "create")?.is_some_and(|c| !c.is_empty())
        || object(args, "update")?.is_some_and(|u| !u.is_empty())
    {
        return Err(err(
            MethodError::InvalidArguments,
            "events can only be destroyed",
        ));
    }
    let ids = string_list(args, "destroy")?.unwrap_or_default();
    let mut events = app.events.lock().expect("events");
    let old_state = events.state();
    let destroyed = events.acknowledge(&ids);
    let not_destroyed: Map<String, Value> = ids
        .iter()
        .filter(|id| !destroyed.contains(id))
        .map(|id| (id.clone(), set_error("notFound", "no such event")))
        .collect();
    let new_state = events.state();
    drop(events);
    if new_state != old_state {
        app.notify(type_name::RELAY_EVENT, new_state.clone());
    }
    Ok(json!({
        "accountId": ACCOUNT_ID,
        "oldState": old_state,
        "newState": new_state,
        "created": {},
        "updated": {},
        "destroyed": destroyed,
        "notDestroyed": not_destroyed,
    }))
}

/// The state of one type, for `StateChange`s and the session.
pub fn states(app: &App) -> Vec<(&'static str, String)> {
    let recipient = app.recipients.read().expect("recipients").state();
    vec![
        (type_name::RELAY, app.relay_state()),
        (type_name::RECIPIENT, recipient.clone()),
        (type_name::RECIPIENT_DOMAIN, recipient),
        (type_name::INBOUND, app.spool.lock().expect("spool").state()),
        (
            type_name::OUTBOUND,
            app.outbox.lock().expect("outbox").state(),
        ),
        (
            type_name::RELAY_EVENT,
            app.events.lock().expect("events").state(),
        ),
    ]
}
