/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The JMAP envelope the link uses: requests and responses (RFC 8620 §3),
//! the WebSocket frames (RFC 8887 §4), and the session resource. Method
//! arguments stay as JSON values; each side parses the ones it handles.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Method names, beyond the standard `/get`, `/set` and `/changes`.
pub mod method {
    pub const RELAY_GET: &str = "Relay/get";
    pub const RELAY_SET: &str = "Relay/set";
    pub const RELAY_JOIN: &str = "Relay/join";
    pub const RELAY_UPGRADE: &str = "Relay/upgrade";
    pub const RECIPIENT_DOMAIN_GET: &str = "RecipientDomain/get";
    pub const RECIPIENT_DOMAIN_SET: &str = "RecipientDomain/set";
    pub const RECIPIENT_SET: &str = "Recipient/set";
    pub const RECIPIENT_CHANGES: &str = "Recipient/changes";
    pub const RECIPIENT_REPLACE: &str = "Recipient/replace";
    pub const INBOUND_GET: &str = "Inbound/get";
    pub const INBOUND_CHANGES: &str = "Inbound/changes";
    pub const INBOUND_QUERY: &str = "Inbound/query";
    pub const INBOUND_CLAIM: &str = "Inbound/claim";
    pub const INBOUND_SET: &str = "Inbound/set";
    pub const OUTBOUND_GET: &str = "Outbound/get";
    pub const OUTBOUND_CHANGES: &str = "Outbound/changes";
    pub const OUTBOUND_SET: &str = "Outbound/set";
    pub const RELAY_EVENT_GET: &str = "RelayEvent/get";
    pub const RELAY_EVENT_CHANGES: &str = "RelayEvent/changes";
    pub const RELAY_EVENT_SET: &str = "RelayEvent/set";
}

/// One method call: `[name, arguments, callId]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invocation(pub String, pub Map<String, Value>, pub String);

impl Invocation {
    pub fn new(name: impl Into<String>, args: Value, call_id: impl Into<String>) -> Self {
        let args = match args {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        Invocation(name.into(), args, call_id.into())
    }

    pub fn name(&self) -> &str {
        &self.0
    }

    pub fn args(&self) -> &Map<String, Value> {
        &self.1
    }

    pub fn call_id(&self) -> &str {
        &self.2
    }

    /// A method-level error response for this call (RFC 8620 §3.6.2).
    pub fn error(&self, kind: MethodError, description: Option<String>) -> Invocation {
        let mut args = Map::new();
        args.insert("type".into(), Value::String(kind.as_str().into()));
        if let Some(description) = description {
            args.insert("description".into(), Value::String(description));
        }
        Invocation("error".into(), args, self.2.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub using: Vec<String>,
    pub method_calls: Vec<Invocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ids: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub method_responses: Vec<Invocation>,
    pub session_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ids: Option<BTreeMap<String, String>>,
}

/// The method-level errors the relay gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodError {
    UnknownMethod,
    InvalidArguments,
    AccountNotFound,
    Forbidden,
    ServerFail,
    StateMismatch,
    CannotCalculateChanges,
    /// The relay has no room: the spool is full (spec "The spool").
    OverQuota,
}

impl MethodError {
    pub fn as_str(&self) -> &'static str {
        match self {
            MethodError::UnknownMethod => "unknownMethod",
            MethodError::InvalidArguments => "invalidArguments",
            MethodError::AccountNotFound => "accountNotFound",
            MethodError::Forbidden => "forbidden",
            MethodError::ServerFail => "serverFail",
            MethodError::StateMismatch => "stateMismatch",
            MethodError::CannotCalculateChanges => "cannotCalculateChanges",
            MethodError::OverQuota => "overQuota",
        }
    }
}

/// Request-level problem types (RFC 8620 §3.6.1).
pub mod request_error {
    pub const UNKNOWN_CAPABILITY: &str = "urn:ietf:params:jmap:error:unknownCapability";
    pub const NOT_JSON: &str = "urn:ietf:params:jmap:error:notJSON";
    pub const NOT_REQUEST: &str = "urn:ietf:params:jmap:error:notRequest";
    pub const LIMIT: &str = "urn:ietf:params:jmap:error:limit";
}

/// A client-to-server WebSocket frame (RFC 8887 §4.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum ClientFrame {
    Request {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(flatten)]
        request: Request,
    },
    WebSocketPushEnable {
        #[serde(rename = "dataTypes", default)]
        data_types: Option<Vec<String>>,
        #[serde(rename = "pushState", default, skip_serializing_if = "Option::is_none")]
        push_state: Option<String>,
    },
    WebSocketPushDisable,
}

/// A server-to-client WebSocket frame (RFC 8887 §4.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum ServerFrame {
    Response {
        #[serde(rename = "requestId", default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        #[serde(flatten)]
        response: Response,
    },
    RequestError {
        #[serde(rename = "requestId", default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        #[serde(rename = "type")]
        kind: String,
        status: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    StateChange {
        /// accountId → type name → state.
        changed: BTreeMap<String, BTreeMap<String, String>>,
        #[serde(rename = "pushState", default, skip_serializing_if = "Option::is_none")]
        push_state: Option<String>,
    },
}

/// The session resource (RFC 8620 §2), trimmed to what the link needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub capabilities: BTreeMap<String, Value>,
    pub accounts: BTreeMap<String, Account>,
    pub primary_accounts: BTreeMap<String, String>,
    pub username: String,
    pub api_url: String,
    pub download_url: String,
    pub upload_url: String,
    pub event_source_url: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub name: String,
    pub is_personal: bool,
    pub is_read_only: bool,
    pub account_capabilities: BTreeMap<String, Value>,
}

/// The WebSocket capability object (RFC 8887 §4.1).
pub fn websocket_capability(url: &str) -> Value {
    serde_json::json!({ "url": url, "supportsPush": true })
}

/// The WebSocket capability's URI.
pub const WEBSOCKET_CAPABILITY: &str = "urn:ietf:params:jmap:websocket";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frames_match_rfc8887() {
        let frame: ClientFrame = serde_json::from_value(json!({
            "@type": "Request",
            "id": "r1",
            "using": ["urn:ietf:params:jmap:core", "urn:inbuxa:jmap:relay"],
            "methodCalls": [["Relay/get", {"accountId": "relay"}, "c0"]]
        }))
        .unwrap();
        let ClientFrame::Request { id, request } = frame else {
            panic!("not a request")
        };
        assert_eq!(id.as_deref(), Some("r1"));
        assert_eq!(request.method_calls[0].name(), "Relay/get");

        let frame: ClientFrame =
            serde_json::from_value(json!({"@type": "WebSocketPushEnable", "dataTypes": null}))
                .unwrap();
        assert_eq!(
            frame,
            ClientFrame::WebSocketPushEnable {
                data_types: None,
                push_state: None
            }
        );

        let change = ServerFrame::StateChange {
            changed: [(
                "relay".to_string(),
                [("Inbound".to_string(), "s7".to_string())].into(),
            )]
            .into(),
            push_state: None,
        };
        assert_eq!(
            serde_json::to_value(&change).unwrap(),
            json!({"@type": "StateChange", "changed": {"relay": {"Inbound": "s7"}}})
        );
    }

    #[test]
    fn method_errors() {
        let call = Invocation::new("Nope/get", json!({}), "c1");
        let err = call.error(MethodError::UnknownMethod, None);
        assert_eq!(
            serde_json::to_value(&err).unwrap(),
            json!(["error", {"type": "unknownMethod"}, "c1"])
        );
    }
}
