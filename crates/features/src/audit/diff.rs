/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What changed in an object, as audit changes (AU-4). Objects are compared
//! as their JMAP JSON, one top-level property at a time. A property that is
//! a secret, or holds one anywhere inside it, is recorded as changed and
//! never with its value: the registry schema says which those are, and a few
//! names are treated as secret whatever it says.

use crate::{ai::explain::schema, audit::record::Change};
use serde_json::{Map, Value};
use std::str::FromStr;
use types::id::Id;

/// Properties never recorded with a value, even if the schema lacks them.
const ALWAYS_SECRET: &[&str] = &[
    "secret",
    "password",
    "credentials",
    "apiKey",
    "token",
    "privateKey",
    "otpAuth",
];

/// Whether `property` of `object` (`x:AiModel`, `apiKey`) holds a secret.
pub fn is_secret(object: &str, property: &str) -> bool {
    let lower = property.to_ascii_lowercase();
    ALWAYS_SECRET
        .iter()
        .any(|name| lower == name.to_ascii_lowercase())
        || lower.ends_with("secret")
        || lower.ends_with("password")
        || schema::embedded()
            .and_then(|schema| schema.property(object, property))
            .is_some_and(|info| info.secret)
}

/// The changes between two versions of an object; `None` for a side that
/// doesn't exist (a create or a destroy).
pub fn diff(object: &str, before: Option<&Value>, after: Option<&Value>) -> Vec<Change> {
    let empty = Map::new();
    let before = before.and_then(Value::as_object).unwrap_or(&empty);
    let after = after.and_then(Value::as_object).unwrap_or(&empty);
    let mut fields = before.keys().chain(after.keys()).collect::<Vec<_>>();
    fields.sort();
    fields.dedup();

    let mut changes = Vec::new();
    for field in fields {
        if field == "id" {
            continue;
        }
        let old = before.get(field).filter(|v| !v.is_null());
        let new = after.get(field).filter(|v| !v.is_null());
        if old == new {
            continue;
        }
        changes.push(if is_secret(object, field) {
            Change::redacted(field.as_str())
        } else {
            Change::new(field.as_str(), old.cloned(), new.cloned())
        });
    }
    changes
}

/// The changes a JMAP patch asks for, with what each place held before when
/// the old object is known. Patch keys are properties or JSON pointers
/// (`sections/0/enabled`); the property is the pointer's first part.
pub fn patch(object: &str, before: Option<&Value>, patch: &Map<String, Value>) -> Vec<Change> {
    let mut changes = Vec::new();
    for (pointer, value) in patch {
        let property = pointer.split('/').next().unwrap_or(pointer);
        if property == "id" {
            continue;
        }
        if is_secret(object, property) {
            changes.push(Change::redacted(pointer.as_str()));
            continue;
        }
        let old = before
            .and_then(|before| before.pointer(&format!("/{pointer}")))
            .filter(|v| !v.is_null())
            .cloned();
        let new = Some(value.clone()).filter(|v| !v.is_null());
        if old == new {
            continue;
        }
        changes.push(Change::new(pointer.as_str(), old, new));
    }
    changes
}

/// What an object is called, and whose it is, for an audit target.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Described {
    pub name: Option<String>,
    pub account_id: Option<u32>,
    pub tenant_id: Option<u32>,
}

/// Reads a target's name and owners from its JSON.
pub fn describe(value: &Value) -> Described {
    let name = [
        "name",
        "email",
        "address",
        "hostname",
        "domain",
        "description",
    ]
    .iter()
    .find_map(|key| value.get(key)?.as_str())
    .map(|name| name.chars().take(200).collect());
    let id = |key: &str| {
        value
            .get(key)?
            .as_str()
            .and_then(|id| Id::from_str(id).ok())
            .map(|id| id.document_id())
    };
    Described {
        name,
        account_id: id("accountId"),
        tenant_id: id("memberTenantId"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diffs_by_property() {
        let before = json!({"id": "a", "name": "x", "enabled": true, "gone": 1});
        let after = json!({"id": "b", "name": "y", "enabled": true, "added": [1]});
        let changes = diff("x:Thing", Some(&before), Some(&after));
        assert_eq!(
            changes,
            vec![
                Change::new("added", None, Some(json!([1]))),
                Change::new("gone", Some(json!(1)), None),
                Change::new("name", Some(json!("x")), Some(json!("y"))),
            ]
        );
        // A create lists everything that is set
        assert_eq!(diff("x:Thing", None, Some(&after)).len(), 3);
    }

    #[test]
    fn secrets_are_never_kept() {
        let before = json!({"apiKey": "old-key", "userPassword": "a", "name": "m"});
        let after = json!({"apiKey": "new-key", "userPassword": "b", "name": "m"});
        let changes = diff("x:AiModel", Some(&before), Some(&after));
        assert_eq!(
            changes,
            vec![Change::redacted("apiKey"), Change::redacted("userPassword")]
        );
        let text = serde_json::to_string(&changes).unwrap();
        assert!(!text.contains("new-key"));
        assert!(!text.contains("old-key"));
        // Unchanged secrets aren't mentioned at all
        assert!(diff("x:AiModel", Some(&before), Some(&before)).is_empty());
    }

    #[test]
    fn secrets_the_schema_knows() {
        // x:AiModel's httpAuth holds a secret inside one of its variants
        if schema::embedded().is_some() {
            assert!(is_secret("x:AiModel", "httpAuth"));
            assert!(!is_secret("x:AiModel", "name"));
        }
    }

    #[test]
    fn patches_with_their_old_values() {
        let before = json!({"name": "a", "list": [{"on": false}], "secret": "s"});
        let patch_value = json!({"name": "b", "list/0/on": true, "secret": "t", "new": 3});
        let changes = patch("x:Thing", Some(&before), patch_value.as_object().unwrap());
        assert!(changes.contains(&Change::new("name", Some(json!("a")), Some(json!("b")))));
        assert!(changes.contains(&Change::new(
            "list/0/on",
            Some(json!(false)),
            Some(json!(true))
        )));
        assert!(changes.contains(&Change::redacted("secret")));
        assert!(changes.contains(&Change::new("new", None, Some(json!(3)))));
        // Nothing to nothing isn't a change
        let nulls = json!({"description": null});
        assert!(patch("x:Thing", None, nulls.as_object().unwrap()).is_empty());
    }

    #[test]
    fn describes_targets() {
        let d = describe(&json!({
            "name": "example.com",
            "memberTenantId": Id::from(5u32).to_string(),
            "accountId": Id::from(9u32).to_string(),
        }));
        assert_eq!(
            d,
            Described {
                name: Some("example.com".into()),
                account_id: Some(9),
                tenant_id: Some(5)
            }
        );
        assert_eq!(describe(&json!({"n": 1})), Described::default());
    }
}
