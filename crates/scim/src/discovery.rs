/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The discovery endpoints (SCIM-3 to SCIM-6): fixed documents, no account
//! data.

use crate::{
    CURSOR_TIMEOUT, DEFAULT_PAGE_SIZE, MAX_OPERATIONS, MAX_PAYLOAD, MAX_RESULTS, ScimResponse,
};
use scim_proto::{
    MESSAGE_LIST_RESPONSE, SCHEMA_GROUP, SCHEMA_RESOURCE_TYPE, SCHEMA_SCHEMA,
    SCHEMA_SERVICE_PROVIDER_CONFIG, SCHEMA_USER, ScimError,
};
use serde_json::{Value, json};

/// INBUXA's own documentation, never upstream's (SCIM-4).
const DOCUMENTATION: &str = "https://inbuxa.org";

pub fn service_provider_config(base: &str) -> Value {
    json!({
        "schemas": [SCHEMA_SERVICE_PROVIDER_CONFIG],
        "documentationUri": DOCUMENTATION,
        "patch": {"supported": true},
        "bulk": {
            "supported": true,
            "maxOperations": MAX_OPERATIONS,
            "maxPayloadSize": MAX_PAYLOAD,
        },
        "filter": {"supported": true, "maxResults": MAX_RESULTS},
        "changePassword": {"supported": false},
        "sort": {"supported": true},
        "etag": {"supported": true},
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "API key",
            "description": "An API key of the service principal's, sent as an Authorization: Bearer token",
            "documentationUri": DOCUMENTATION,
            "primary": true,
        }],
        "pagination": {
            "cursor": true,
            "index": true,
            "defaultPaginationMethod": "index",
            "defaultPageSize": DEFAULT_PAGE_SIZE,
            "maxPageSize": MAX_RESULTS,
            "cursorTimeout": CURSOR_TIMEOUT,
        },
        "interopProfileConformant": false,
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": format!("{base}/ServiceProviderConfig"),
        },
    })
}

fn resource_type(base: &str, name: &str) -> Option<Value> {
    let (endpoint, schema, description) = match name {
        "User" => ("/Users", SCHEMA_USER, "A mailbox account"),
        "Group" => ("/Groups", SCHEMA_GROUP, "A group of users"),
        _ => return None,
    };
    Some(json!({
        "schemas": [SCHEMA_RESOURCE_TYPE],
        "id": name,
        "name": name,
        "endpoint": endpoint,
        "description": description,
        "schema": schema,
        "meta": {
            "resourceType": "ResourceType",
            "location": format!("{base}/ResourceTypes/{name}"),
        },
    }))
}

fn list(items: Vec<Value>) -> Value {
    json!({
        "schemas": [MESSAGE_LIST_RESPONSE],
        "totalResults": items.len(),
        "itemsPerPage": items.len(),
        "startIndex": 1,
        "Resources": items,
    })
}

pub fn resource_types(base: &str, id: Option<&str>) -> ScimResponse {
    match id {
        Some(id) => match ["User", "Group"]
            .into_iter()
            .find(|name| name.eq_ignore_ascii_case(id))
            .and_then(|name| resource_type(base, name))
        {
            Some(value) => ScimResponse::json(200, value),
            None => ScimError::not_found(format!("There is no resource type '{id}'")).into(),
        },
        None => ScimResponse::json(
            200,
            list(
                ["User", "Group"]
                    .into_iter()
                    .filter_map(|name| resource_type(base, name))
                    .collect(),
            ),
        ),
    }
}

pub fn schemas(base: &str, id: Option<&str>) -> ScimResponse {
    let all = [user_schema(base), group_schema(base)];
    match id {
        Some(id) => match all.into_iter().find(|schema| {
            schema["id"]
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case(id))
        }) {
            Some(value) => ScimResponse::json(200, value),
            None => ScimError::not_found(format!("There is no schema '{id}'")).into(),
        },
        None => ScimResponse::json(200, list(all.into_iter().collect())),
    }
}

/// One attribute definition (RFC 7643 §7).
struct Attr {
    name: &'static str,
    kind: &'static str,
    multi: bool,
    required: bool,
    case_exact: bool,
    mutability: &'static str,
    returned: &'static str,
    uniqueness: &'static str,
    sub: Vec<Attr>,
    canonical: &'static [&'static str],
    reference_types: &'static [&'static str],
}

impl Attr {
    fn new(name: &'static str, kind: &'static str) -> Self {
        Attr {
            name,
            kind,
            multi: false,
            required: false,
            case_exact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none",
            sub: Vec::new(),
            canonical: &[],
            reference_types: &[],
        }
    }

    fn multi(mut self) -> Self {
        self.multi = true;
        self
    }

    fn required(mut self) -> Self {
        self.required = true;
        self
    }

    fn case_exact(mut self) -> Self {
        self.case_exact = true;
        self
    }

    fn read_only(mut self) -> Self {
        self.mutability = "readOnly";
        self
    }

    fn immutable(mut self) -> Self {
        self.mutability = "immutable";
        self
    }

    fn unique(mut self) -> Self {
        self.uniqueness = "server";
        self
    }

    fn with(mut self, sub: Vec<Attr>) -> Self {
        self.sub = sub;
        self
    }

    fn canonical(mut self, values: &'static [&'static str]) -> Self {
        self.canonical = values;
        self
    }

    fn refs(mut self, types: &'static [&'static str]) -> Self {
        self.reference_types = types;
        self
    }

    fn to_json(&self) -> Value {
        let mut value = json!({
            "name": self.name,
            "type": self.kind,
            "multiValued": self.multi,
            "description": "",
            "required": self.required,
            "caseExact": self.case_exact,
            "mutability": self.mutability,
            "returned": self.returned,
            "uniqueness": self.uniqueness,
        });
        if !self.sub.is_empty() {
            value["subAttributes"] = Value::Array(self.sub.iter().map(Attr::to_json).collect());
        }
        if !self.canonical.is_empty() {
            value["canonicalValues"] = json!(self.canonical);
        }
        if !self.reference_types.is_empty() {
            value["referenceTypes"] = json!(self.reference_types);
        }
        value
    }
}

fn schema(base: &str, id: &str, name: &str, description: &str, attributes: Vec<Attr>) -> Value {
    json!({
        "schemas": [SCHEMA_SCHEMA],
        "id": id,
        "name": name,
        "description": description,
        "attributes": attributes.iter().map(Attr::to_json).collect::<Vec<_>>(),
        "meta": {
            "resourceType": "Schema",
            "location": format!("{base}/Schemas/{id}"),
        },
    })
}

/// The User attributes of the mapping table (SCIM-6); `password` isn't
/// published.
pub fn user_schema(base: &str) -> Value {
    schema(
        base,
        SCHEMA_USER,
        "User",
        "A mailbox account",
        vec![
            Attr::new("userName", "string").required().unique(),
            Attr::new("externalId", "string").case_exact(),
            Attr::new("displayName", "string"),
            Attr::new("name", "complex").with(vec![Attr::new("formatted", "string")]),
            Attr::new("active", "boolean"),
            Attr::new("emails", "complex").multi().with(vec![
                Attr::new("value", "string"),
                Attr::new("type", "string").canonical(&["work"]),
                Attr::new("primary", "boolean"),
            ]),
            Attr::new("locale", "string"),
            Attr::new("preferredLanguage", "string"),
            Attr::new("timezone", "string"),
            Attr::new("groups", "complex")
                .multi()
                .read_only()
                .with(vec![
                    Attr::new("value", "string").read_only(),
                    Attr::new("display", "string").read_only(),
                    Attr::new("$ref", "reference").read_only().refs(&["Group"]),
                ]),
        ],
    )
}

/// The Group attributes of the mapping table (SCIM-6).
pub fn group_schema(base: &str) -> Value {
    schema(
        base,
        SCHEMA_GROUP,
        "Group",
        "A group of users",
        vec![
            Attr::new("displayName", "string").required().unique(),
            Attr::new("externalId", "string").case_exact(),
            Attr::new("members", "complex").multi().with(vec![
                Attr::new("value", "string").immutable(),
                Attr::new("display", "string").read_only(),
                Attr::new("type", "string").immutable().canonical(&["User"]),
                Attr::new("$ref", "reference").immutable().refs(&["User"]),
            ]),
        ],
    )
}
