/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What an audit entry holds (AU-4). Stored as JSON, so entries written by
//! one version of the fork read back in the next.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

/// Longest value kept for one side of a change; longer ones are cut, with
/// their original length noted.
pub const MAX_VALUE_LEN: usize = 2048;

/// One thing that happened.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    /// Milliseconds since the epoch.
    pub at: u64,
    pub actor: Actor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<Via>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<IpAddr>,
    pub action: Action,
    pub target: Target,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<Change>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Why, as the actor gave it: required for holds, locks and exports,
    /// optional for everything else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub outcome: Outcome,
}

/// Who acted: an account, named as it was then, or the server itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Actor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<u32>,
    /// The account's name, or `system:<subsystem>`.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<u32>,
}

impl Actor {
    pub fn account(account_id: u32, name: impl Into<String>, tenant_id: Option<u32>) -> Self {
        Actor {
            account_id: Some(account_id),
            name: name.into(),
            tenant_id,
        }
    }

    pub fn system(subsystem: &str) -> Self {
        Actor {
            account_id: None,
            name: format!("system:{subsystem}"),
            tenant_id: None,
        }
    }

    pub fn is_system(&self) -> bool {
        self.account_id.is_none()
    }
}

/// How the actor signed in (AU-5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Via {
    Password,
    AppPassword {
        id: u32,
    },
    ApiKey {
        id: u32,
    },
    #[serde(rename = "oauth")]
    OAuth {
        client: String,
    },
    /// A token from an external directory (OIDC).
    Directory,
    /// Signed in as someone else with a master user's password.
    #[serde(rename_all = "camelCase")]
    Master {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account_id: Option<u32>,
        name: String,
    },
    /// The recovery administrator from the server's own configuration.
    Recovery,
}

/// What kind of thing happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    Create,
    Update,
    Destroy,
    SignIn,
    SignInFailed,
    /// JMAP access to another account through `Impersonate`.
    AccountAccess,
    /// A blob of another account read through `FetchAnyBlob`.
    BlobAccess,
    Export,
    Verify,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Update => "update",
            Action::Destroy => "destroy",
            Action::SignIn => "signIn",
            Action::SignInFailed => "signInFailed",
            Action::AccountAccess => "accountAccess",
            Action::BlobAccess => "blobAccess",
            Action::Export => "export",
            Action::Verify => "verify",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "create" => Action::Create,
            "update" => Action::Update,
            "destroy" => Action::Destroy,
            "signIn" => Action::SignIn,
            "signInFailed" => Action::SignInFailed,
            "accountAccess" => Action::AccountAccess,
            "blobAccess" => Action::BlobAccess,
            "export" => Action::Export,
            "verify" => Action::Verify,
            _ => return None,
        })
    }
}

/// What it happened to.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    /// An object type (`x:Domain`, `inbuxa:ProtocolPolicy`), or `account`
    /// for sign-ins and access.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The account the object belongs to, when it belongs to one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<u32>,
}

/// One property's change. A secret is never stored: `redacted` says it
/// changed, and both sides are left out (AU-4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub redacted: bool,
}

impl Change {
    pub fn new(field: impl Into<String>, before: Option<Value>, after: Option<Value>) -> Self {
        Change {
            field: field.into(),
            before: before.map(shorten),
            after: after.map(shorten),
            redacted: false,
        }
    }

    pub fn redacted(field: impl Into<String>) -> Self {
        Change {
            field: field.into(),
            before: None,
            after: None,
            redacted: true,
        }
    }
}

/// How it ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Outcome {
    Success {
        /// The id a create was given.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        created_id: Option<String>,
    },
    Refused {
        /// The JMAP error type (`forbidden`, `invalidProperties`, …).
        error: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },
    /// Written before the change was tried; its outcome follows in a later
    /// entry, or never if the server stopped in between (AU-3).
    Pending,
}

impl Outcome {
    pub fn success() -> Self {
        Outcome::Success { created_id: None }
    }

    pub fn refused(error: impl Into<String>, description: Option<String>) -> Self {
        Outcome::Refused {
            error: error.into(),
            description: description.map(|d| shorten_str(d, 500)),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Success { .. } => "success",
            Outcome::Refused { .. } => "refused",
            Outcome::Pending => "pending",
        }
    }
}

/// Cuts a long value, keeping it valid JSON.
pub fn shorten(value: Value) -> Value {
    match value {
        Value::String(s) if s.len() > MAX_VALUE_LEN => Value::String(shorten_str(s, MAX_VALUE_LEN)),
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => value,
        other => {
            let text = other.to_string();
            if text.len() > MAX_VALUE_LEN {
                Value::String(shorten_str(text, MAX_VALUE_LEN))
            } else {
                other
            }
        }
    }
}

fn shorten_str(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes in all)", &s[..end], s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_back_as_written() {
        let record = Record {
            at: 1_800_000_000_000,
            actor: Actor::account(3, "admin@example.com", None),
            via: Some(Via::OAuth {
                client: "inbuxa-admin".into(),
            }),
            remote_ip: Some("192.0.2.1".parse().unwrap()),
            action: Action::Update,
            target: Target {
                kind: "x:Domain".into(),
                id: Some("b".into()),
                name: Some("example.com".into()),
                ..Default::default()
            },
            changes: vec![
                Change::new("isEnabled", Some(true.into()), Some(false.into())),
                Change::redacted("secret"),
            ],
            details: None,
            reason: Some("Ticket 42".into()),
            outcome: Outcome::Pending,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"kind\":\"oauth\""));
        let created = serde_json::to_string(&Outcome::Success {
            created_id: Some("c".into()),
        })
        .unwrap();
        assert_eq!(created, r#"{"status":"success","createdId":"c"}"#);
        assert!(json.contains("\"redacted\":true"));
        assert!(!json.contains("\"details\""));
        assert_eq!(serde_json::from_str::<Record>(&json).unwrap(), record);
    }

    #[test]
    fn long_values_are_cut() {
        let long = "é".repeat(MAX_VALUE_LEN);
        let Value::String(cut) = shorten(Value::String(long.clone())) else {
            panic!()
        };
        assert!(cut.len() < long.len());
        assert!(cut.ends_with(&format!("({} bytes in all)", long.len())));
        let array = Value::Array((0..2000).map(Value::from).collect());
        assert!(shorten(array).is_string());
        assert_eq!(shorten(Value::from(5)), Value::from(5));
    }

    #[test]
    fn actions_round_trip() {
        for action in [
            Action::Create,
            Action::Update,
            Action::Destroy,
            Action::SignIn,
            Action::SignInFailed,
            Action::AccountAccess,
            Action::BlobAccess,
            Action::Export,
            Action::Verify,
        ] {
            assert_eq!(Action::parse(action.as_str()), Some(action));
            assert_eq!(
                serde_json::to_value(action).unwrap(),
                Value::String(action.as_str().into())
            );
        }
    }
}
