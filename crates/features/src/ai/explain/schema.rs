/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Reference text from the registry schema (EX-7, EX-9): what an event
//! means, and what a setting is, its default and allowed values, and whether
//! it holds a secret anywhere inside it.

use serde_json::Value;
use std::{collections::HashSet, io::Read, sync::OnceLock};

/// The registry schema, as the console downloads it.
pub struct Schema(Value);

/// The schema built into the server, read once. Also used by the audit log,
/// to know which properties hold secrets (AU-4).
pub fn embedded() -> Option<&'static Schema> {
    static SCHEMA: OnceLock<Option<Schema>> = OnceLock::new();
    static SCHEMA_JSON: &[u8] = include_bytes!("../../../../../resources/schema/schema.json.gz");
    SCHEMA
        .get_or_init(|| {
            let mut json = Vec::new();
            flate2::read::GzDecoder::new(SCHEMA_JSON)
                .read_to_end(&mut json)
                .ok()?;
            serde_json::from_slice(&json).ok().map(Schema::new)
        })
        .as_ref()
}

/// What the schema says about one property of one object.
#[derive(Debug, Clone, PartialEq)]
pub struct PropertyInfo {
    pub description: String,
    pub label: Option<String>,
    pub default: Option<Value>,
    /// Allowed values of an enum, as "name (label)".
    pub allowed: Vec<String>,
    /// The property is a secret, or an object with a secret inside (EX-9).
    pub secret: bool,
}

impl Schema {
    pub fn new(json: Value) -> Self {
        Schema(json)
    }

    /// An event's label and explanation, by its name (`smtp.spf-ehlo-fail`).
    pub fn event(&self, name: &str) -> Option<(String, String)> {
        self.0["enums"]["EventType"]
            .as_array()?
            .iter()
            .find(|e| e["name"] == name)
            .map(|e| {
                (
                    e["label"].as_str().unwrap_or_default().to_string(),
                    e["explanation"].as_str().unwrap_or_default().to_string(),
                )
            })
    }

    /// The field sets an object's properties are defined in: its own, or
    /// those of each of its variants.
    fn field_sets(&self, object: &str) -> Vec<String> {
        let schema = &self.0["schemas"][object];
        let mut names = Vec::new();
        match schema["type"].as_str() {
            Some("single") => {
                if let Some(name) = schema["schemaName"].as_str() {
                    names.push(name.to_string());
                }
            }
            Some("multiple") => {
                for variant in schema["variants"].as_array().into_iter().flatten() {
                    if let Some(name) = variant["schemaName"].as_str()
                        && !names.iter().any(|n| n == name)
                    {
                        names.push(name.to_string());
                    }
                }
            }
            _ => {}
        }
        if names.is_empty() {
            names.push(object.to_string());
        }
        names
    }

    /// One property of one object (`x:Domain`, `dnsManagement`).
    pub fn property(&self, object: &str, property: &str) -> Option<PropertyInfo> {
        for set in self.field_sets(object) {
            let fields = &self.0["fields"][&set];
            let Some(definition) = fields["properties"].get(property) else {
                continue;
            };
            let kind = &definition["type"];
            let allowed = match kind["enumName"].as_str() {
                Some(name) if kind["type"] == "enum" => self.0["enums"][name]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| {
                        let name = e["name"].as_str()?;
                        Some(match e["label"].as_str() {
                            Some(label) => format!("{name} ({label})"),
                            None => name.to_string(),
                        })
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let label = [object, set.as_str()]
                .iter()
                .find_map(|form| self.label(form, property));
            return Some(PropertyInfo {
                description: definition["description"].as_str().unwrap_or_default().to_string(),
                label,
                default: fields["defaults"].get(property).cloned(),
                allowed,
                secret: self.holds_secret(kind, &mut HashSet::new()),
            });
        }
        None
    }

    fn label(&self, form: &str, property: &str) -> Option<String> {
        self.0["forms"][form]["sections"]
            .as_array()?
            .iter()
            .flat_map(|section| section["fields"].as_array().into_iter().flatten())
            .find(|field| field["name"] == property)
            .and_then(|field| field["label"].as_str())
            .map(str::to_string)
    }

    /// Whether a type is a secret or embeds one, following embedded objects
    /// (not references to other records).
    fn holds_secret(&self, kind: &Value, seen: &mut HashSet<String>) -> bool {
        match kind {
            Value::Object(map) => {
                if map.get("format").and_then(Value::as_str) == Some("secret") {
                    return true;
                }
                let embeds = matches!(
                    map.get("type").and_then(Value::as_str),
                    Some("object" | "objectList")
                );
                if embeds
                    && let Some(name) = map.get("objectName").and_then(Value::as_str)
                    && seen.insert(name.to_string())
                {
                    for set in self.field_sets(name) {
                        let properties = &self.0["fields"][&set]["properties"];
                        for definition in properties.as_object().into_iter().flat_map(|p| p.values()) {
                            if self.holds_secret(&definition["type"], seen) {
                                return true;
                            }
                        }
                    }
                }
                map.iter()
                    .filter(|(key, _)| key.as_str() != "objectName")
                    .any(|(_, value)| self.holds_secret(value, seen))
            }
            Value::Array(items) => items.iter().any(|item| self.holds_secret(item, seen)),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema() -> Schema {
        Schema::new(json!({
            "schemas": {
                "x:Domain": {"type": "single", "schemaName": "x:Domain"},
                "x:HttpAuth": {"type": "multiple", "variants": [
                    {"name": "Unauthenticated"},
                    {"name": "Bearer", "schemaName": "x:HttpAuthBearer"}]},
                "x:AiModel": {"type": "single", "schemaName": "x:AiModel"}
            },
            "fields": {
                "x:Domain": {"properties": {
                    "isEnabled": {"description": "Whether the domain is on", "type": {"type": "boolean"}},
                    "dnsManagement": {"description": "How DNS is managed",
                        "type": {"type": "enum", "enumName": "DnsManagement"}},
                    "tenantId": {"description": "Owner", "type": {"type": "objectId", "objectName": "x:AiModel"}}
                }, "defaults": {"isEnabled": true}},
                "x:HttpAuthBearer": {"properties": {
                    "bearerToken": {"description": "Token", "type": {"type": "string", "format": "secret"}}}},
                "x:AiModel": {"properties": {
                    "httpAuth": {"description": "Auth", "type": {"type": "object", "objectName": "x:HttpAuth"}},
                    "apiKey": {"description": "Key", "type": {"type": "string", "format": "secret", "nullable": true}},
                    "name": {"description": "Name", "type": {"type": "string"}}
                }}
            },
            "forms": {"x:Domain": {"sections": [{"fields": [{"name": "isEnabled", "label": "Enabled"}]}]}},
            "enums": {
                "DnsManagement": [{"name": "Manual", "label": "Manual"}, {"name": "Automatic"}],
                "EventType": [{"name": "smtp.spf-ehlo-fail", "label": "SPF EHLO check failed",
                    "explanation": "The EHLO name failed SPF."}]
            }
        }))
    }

    #[test]
    fn describes_a_property() {
        let s = schema();
        let enabled = s.property("x:Domain", "isEnabled").unwrap();
        assert_eq!(enabled.label.as_deref(), Some("Enabled"));
        assert_eq!(enabled.default, Some(json!(true)));
        assert!(!enabled.secret);
        let dns = s.property("x:Domain", "dnsManagement").unwrap();
        assert_eq!(dns.allowed, vec!["Manual (Manual)", "Automatic"]);
        assert!(s.property("x:Domain", "nothing").is_none());
        assert!(s.property("x:Nothing", "isEnabled").is_none());
    }

    #[test]
    fn finds_secrets_even_nested() {
        let s = schema();
        assert!(s.property("x:AiModel", "apiKey").unwrap().secret);
        // A secret inside one variant of an embedded object
        assert!(s.property("x:AiModel", "httpAuth").unwrap().secret);
        assert!(!s.property("x:AiModel", "name").unwrap().secret);
        // A reference to another record isn't followed
        assert!(!s.property("x:Domain", "tenantId").unwrap().secret);
    }

    #[test]
    fn describes_an_event() {
        let (label, text) = schema().event("smtp.spf-ehlo-fail").unwrap();
        assert_eq!(label, "SPF EHLO check failed");
        assert!(text.contains("SPF"));
        assert!(schema().event("nope").is_none());
    }
}
