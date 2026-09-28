/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `POST /api/directory/test`: try a saved directory before anything signs in
//! through it (settings-reorg, guided setup "Connect a sign-in directory").
//!
//! The body names a directory and an address, and optionally a password:
//!
//! ```json
//! {"directoryId": "b", "address": "jane@corp.example", "password": "…"}
//! ```
//!
//! The answer says whether the directory opened, what a recipient lookup of
//! the address finds, and, when a password is given, whether it signs in.
//! It calls the directory itself, below the sign-in path, so a test never
//! creates or updates an account (DIR-14), never counts toward the sign-in
//! ban, and doesn't mind which domains use the directory (DIR-6). Nothing is
//! cached (DIR-32). A password hash a directory hands back is never returned.
//!
//! For server-level administrators who may change directories.

use common::{Server, auth::AccessToken};
use directory::{Credentials, Directory, Recipient};
use registry::schema::enums::Permission;
use serde_json::{Value, json};
use std::str::FromStr;
use types::id::Id;

fn message(err: &trc::Error) -> String {
    err.value_as_str(trc::Key::Reason)
        .or_else(|| err.value_as_str(trc::Key::Details))
        .map(str::to_string)
        .unwrap_or_else(|| err.to_string())
}

fn kind(directory: &Directory) -> &'static str {
    match directory {
        Directory::Ldap(_) => "ldap",
        Directory::Sql(_) => "sql",
        Directory::OpenId(_) => "oidc",
        Directory::Unavailable(d) => match d.directory_type() {
            registry::schema::enums::DirectoryType::Ldap => "ldap",
            registry::schema::enums::DirectoryType::Sql => "sql",
            registry::schema::enums::DirectoryType::Oidc => "oidc",
        },
    }
}

pub fn assert_allowed(access_token: &AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        return Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Directory tests are for server-level administrators."));
    }
    access_token.enforce_permission(Permission::SysDirectoryUpdate)
}

fn bad(details: &'static str) -> trc::Error {
    trc::ResourceEvent::BadParameters.into_err().details(details)
}

pub async fn test(server: &Server, body: &Value) -> trc::Result<Value> {
    let directory_id = body
        .get("directoryId")
        .and_then(Value::as_str)
        .and_then(|id| Id::from_str(id).ok())
        .ok_or_else(|| bad("Expected {\"directoryId\": …, \"address\": …}"))?;
    let address = body
        .get("address")
        .and_then(Value::as_str)
        .map(|a| a.trim().to_lowercase())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| bad("Expected an address to look up"))?;
    let password = body
        .get("password")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty());

    let Some(directory) = server
        .core
        .storage
        .directories
        .get(&(directory_id.id() as u32))
        .cloned()
    else {
        return Ok(json!({
            "opened": false,
            "error": "The server hasn't loaded this directory. Save it, and try again in a few seconds.",
        }));
    };

    let mut out = json!({ "kind": kind(&directory) });
    if let Directory::Unavailable(d) = directory.as_ref() {
        out["opened"] = json!(false);
        out["error"] = json!(message(&d.error()));
        return Ok(out);
    }
    out["opened"] = json!(true);

    if let Some(discovery) = directory.oidc_discovery_document() {
        out["oidc"] = json!({
            "issuer": discovery.document.issuer,
            "jwksUri": discovery.document.jwks_uri,
        });
    }

    // What mail for this address would find.
    if directory.can_lookup_recipients() {
        out["lookup"] = match directory.recipient(&address).await {
            Ok(Recipient::Account(a)) => json!({
                "found": "account",
                "email": a.email,
                "aliases": a.email_aliases,
                "groups": a.groups.unwrap_or_default(),
                "description": a.description,
            }),
            Ok(Recipient::Group(g)) => json!({
                "found": "group",
                "email": g.email,
                "aliases": g.email_aliases,
                "description": g.description,
            }),
            Ok(Recipient::Invalid) => json!({ "found": "none" }),
            Err(err) => json!({ "error": message(&err) }),
        };
    }

    // Whether this person could sign in. OIDC takes tokens, not passwords
    // (DIR-29), so there's nothing to try there.
    if let Some(password) = password
        && !matches!(directory.as_ref(), Directory::OpenId(_))
    {
        let credentials = Credentials::Basic {
            username: address.clone(),
            secret: password.to_string(),
            mfa_token: None,
        };
        out["signIn"] = match directory.authenticate(&credentials).await {
            Ok(a) => json!({
                "ok": true,
                "email": a.email,
                "groups": a.groups.unwrap_or_default(),
                "description": a.description,
            }),
            Err(err) if matches!(err.as_ref(), trc::EventType::Auth(trc::AuthEvent::Failed)) => {
                json!({ "ok": false, "wrongPassword": true })
            }
            Err(err) => json!({ "ok": false, "error": message(&err) }),
        };
    }

    Ok(out)
}
