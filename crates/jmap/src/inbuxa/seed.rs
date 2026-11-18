/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: K-S8: a new store's setup from a file (`--seed`), for installs
//! that are declared rather than clicked through, such as the Helm chart
//! (docs/spec/store-seed.md).
//!
//! The file is a JMAP request body, the same `methodCalls` an administrator
//! would send to `/jmap`, with back-references between calls. It runs once,
//! through the same request handler, as the system administrator. A value
//! written `{"$file": "/path"}` is replaced by that file's contents, so
//! secrets stay in mounted files and out of the seed.

use common::{
    Server,
    auth::AccessToken,
    config::server::{DEFAULT_TLS_TIMEOUT, ServerProtocol},
    network::{ServerInstance, TcpAcceptor, limiter::ConcurrencyLimiter},
};
use http_proto::HttpSessionData;
use jmap_proto::request::Request;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
    sync::Arc,
};
use store::{
    SUBSPACE_INBUXA, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use tokio::sync::watch;
use utils::snowflake::SnowflakeIdGenerator;

use crate::api::request::RequestHandler;

/// Where the store notes that a seed ran: `started <sha256>` while it runs,
/// `applied <sha256>` once every call succeeded.
pub const SEED_MARKER_KEY: &[u8] = b"Ks";

/// A seed has a few dozen calls, not the thousands a client may never send
const MAX_CALLS: usize = 1_000;

#[derive(Debug, PartialEq, Eq)]
pub enum SeedOutcome {
    /// Every call succeeded; `created` objects were created or updated
    Applied { calls: usize, created: usize },
    /// This store was seeded before. `changed`: from a different file, which
    /// isn't applied: after the first run the registry is what counts.
    AlreadyApplied { changed: bool },
    /// Not applied, and nothing written
    Refused(String),
}

pub async fn apply_seed(
    server: &Server,
    path: &Path,
    store_was_new: bool,
) -> Result<SeedOutcome, String> {
    let raw = std::fs::read(path)
        .map_err(|err| format!("Can't read the seed {}: {err}", path.display()))?;
    let digest = hex(&Sha256::digest(&raw));

    let mut request: Value = serde_json::from_slice(&raw)
        .map_err(|err| format!("The seed {} isn't JSON: {err}", path.display()))?;
    resolve_files(&mut request, &mut |file| {
        std::fs::read_to_string(file)
            .map(|contents| contents.trim_end_matches(['\r', '\n']).to_string())
            .map_err(|err| format!("Can't read {file}, named by the seed: {err}"))
    })?;
    let body = serde_json::to_vec(&request).map_err(|err| err.to_string())?;

    let store = server.store();
    let marker = store
        .get_value::<String>(ValueKey::from(marker_class()))
        .await
        .map_err(|err| format!("Can't read the store: {err}"))?;
    match marker.as_deref().and_then(|m| m.split_once(' ')) {
        Some(("applied", previous)) => {
            return Ok(SeedOutcome::AlreadyApplied {
                changed: previous != digest,
            });
        }
        Some(_) => {
            return Ok(SeedOutcome::Refused(
                "An earlier seed run on this store stopped partway, so part of the seed may \
                 already be there. Finish the setup in the console, or start again from an \
                 empty store."
                    .to_string(),
            ));
        }
        None if !store_was_new => {
            return Ok(SeedOutcome::Refused(
                "The store is already set up, so the seed isn't applied: a seed is only for \
                 a new store. Make changes in the console or through the API."
                    .to_string(),
            ));
        }
        None => {}
    }

    let request = Request::parse(&body, MAX_CALLS, body.len() + 1)
        .map_err(|err| format!("The seed isn't a JMAP request: {err}"))?;
    let calls = request.method_calls.len();

    set_marker(server, &format!("started {digest}")).await?;
    let response = server
        .handle_jmap_request(request, &AccessToken::new_admin(), &local_session())
        .await;
    let response = serde_json::to_value(&response).map_err(|err| err.to_string())?;

    let (created, failed) = summarize(&response);
    if !failed.is_empty() {
        return Err(format!(
            "The seed failed, and the store may hold part of it:\n  {}",
            failed.join("\n  ")
        ));
    }
    set_marker(server, &format!("applied {digest}")).await?;

    Ok(SeedOutcome::Applied { calls, created })
}

/// Replaces each `{"$file": "/path"}` with what `read` returns for the path
pub fn resolve_files(
    value: &mut Value,
    read: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            if map.len() == 1
                && let Some(file) = map.get("$file")
            {
                let Value::String(file) = file else {
                    return Err("\"$file\" takes a path, as a string".to_string());
                };
                *value = Value::String(read(file)?);
                return Ok(());
            }
            map.values_mut().try_for_each(|v| resolve_files(v, read))
        }
        Value::Array(items) => items.iter_mut().try_for_each(|v| resolve_files(v, read)),
        _ => Ok(()),
    }
}

/// How many objects the response created or updated, and every failure in
/// it: a method error, or anything not created, updated or destroyed. Only
/// error types and descriptions go into the failures, never the values sent,
/// which may be secrets.
pub fn summarize(response: &Value) -> (usize, Vec<String>) {
    let mut created = 0;
    let mut failed = Vec::new();

    let calls = response
        .get("methodResponses")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for call in calls {
        let (Some(name), Some(args), Some(id)) = (
            call.get(0).and_then(Value::as_str),
            call.get(1),
            call.get(2).and_then(Value::as_str),
        ) else {
            continue;
        };

        if name == "error" {
            failed.push(format!("call \"{id}\": {}", describe(args)));
            continue;
        }

        for key in ["created", "updated"] {
            created += args
                .get(key)
                .and_then(Value::as_object)
                .map_or(0, |m| m.len());
        }
        for key in ["notCreated", "notUpdated", "notDestroyed"] {
            if let Some(errors) = args.get(key).and_then(Value::as_object) {
                for (object, error) in errors {
                    failed.push(format!(
                        "call \"{id}\" ({name}) {key} {object}: {}",
                        describe(error)
                    ));
                }
            }
        }
    }

    (created, failed)
}

fn describe(error: &Value) -> String {
    let kind = error.get("type").and_then(Value::as_str).unwrap_or("error");
    let mut text = kind.to_string();
    if let Some(description) = error.get("description").and_then(Value::as_str) {
        text.push_str(": ");
        text.push_str(description);
    }
    if let Some(properties) = error.get("properties").and_then(Value::as_array) {
        let names = properties
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        if !names.is_empty() {
            text.push_str(&format!(" ({names})"));
        }
    }
    text
}

fn marker_class() -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: SEED_MARKER_KEY.to_vec(),
    })
}

async fn set_marker(server: &Server, value: &str) -> Result<(), String> {
    let mut batch = BatchBuilder::new();
    batch.set(marker_class(), value.as_bytes().to_vec());
    server
        .store()
        .write(batch.build_all())
        .await
        .map(|_| ())
        .map_err(|err| format!("Can't write the seed's note to the store: {err}"))
}

/// The seed is applied in-process: no connection, so a session of its own,
/// as the task manager makes one for alarms. Marked TLS because nothing
/// crosses a network.
fn local_session() -> HttpSessionData {
    HttpSessionData {
        instance: Arc::new(ServerInstance {
            id: "_seed".to_string(),
            protocol: ServerProtocol::Http,
            acceptor: TcpAcceptor::Plain,
            limiter: ConcurrencyLimiter::new(1),
            proxy_networks: vec![],
            tls_timeout: DEFAULT_TLS_TIMEOUT,
            shutdown_rx: watch::channel(false).1,
            span_id_gen: Arc::new(SnowflakeIdGenerator::new()),
        }),
        local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port: 0,
        remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        remote_port: 0,
        is_tls: true,
        session_id: 0,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_secrets_from_files() {
        let mut seed = json!({"methodCalls": [["x:Account/set", {"create": {"a": {
            "name": "admin",
            "credentials": {"0": {"@type": "Password", "secret": {"$file": "/s/admin"}}}
        }}}, "c"]]});
        resolve_files(&mut seed, &mut |path| Ok(format!("pw-from-{path}"))).unwrap();
        assert_eq!(
            seed.pointer("/methodCalls/0/1/create/a/credentials/0/secret"),
            Some(&json!("pw-from-/s/admin"))
        );
    }

    #[test]
    fn leaves_other_objects_alone() {
        let mut seed = json!({"a": {"$file": "/x", "other": 1}, "b": [{"filePath": "/y"}]});
        let before = seed.clone();
        resolve_files(&mut seed, &mut |_| Err("not read".to_string())).unwrap();
        assert_eq!(seed, before);
    }

    #[test]
    fn stops_on_a_file_it_cannot_read() {
        let mut seed = json!([{"$file": "/missing"}]);
        assert_eq!(
            resolve_files(&mut seed, &mut |_| Err("gone".to_string())),
            Err("gone".to_string())
        );
        let mut seed = json!({"$file": 3});
        assert!(resolve_files(&mut seed, &mut |_| Ok(String::new())).is_err());
    }

    #[test]
    fn counts_changes_and_reports_failures_without_values() {
        let response = json!({"methodResponses": [
            ["x:Domain/set", {"created": {"d": {"id": "a1"}}}, "d"],
            ["x:Account/set", {"created": {}, "notCreated": {"a": {
                "type": "invalidProperties", "description": "Bad secret", "properties": ["credentials"]
            }}}, "a"],
            ["x:SystemSettings/set", {"updated": {"singleton": null}}, "s"],
            ["error", {"type": "unknownMethod"}, "x"]
        ]});
        let (created, failed) = summarize(&response);
        assert_eq!(created, 2);
        assert_eq!(
            failed,
            vec![
                "call \"a\" (x:Account/set) notCreated a: invalidProperties: Bad secret (credentials)",
                "call \"x\": unknownMethod",
            ]
        );
    }
}
