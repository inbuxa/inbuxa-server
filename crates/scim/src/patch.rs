/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `PATCH` (SCIM-42). The operations are applied, in order, to the
//! resource as it is now; the result is then written the way a `PUT` is.
//! So either every operation takes effect or none does.

use crate::{ResourceKind, resource::get, users::parse_bool};
use scim_proto::{Filter, MESSAGE_PATCH_OP, PatchPath, ScimError, filter::CompareOp};
use serde_json::{Map, Value};

/// Attributes of the core schemas accepted and discarded (SCIM-33).
const IGNORED_USER: &[&str] = &[
    "password",
    "phoneNumbers",
    "addresses",
    "photos",
    "ims",
    "title",
    "userType",
    "nickName",
    "profileUrl",
    "entitlements",
    "roles",
    "x509Certificates",
];
const IGNORED_GROUP: &[&str] = &["description"];

const USER_ATTRS: &[&str] = &[
    "userName",
    "displayName",
    "name",
    "active",
    "emails",
    "locale",
    "preferredLanguage",
    "timezone",
    "externalId",
];
const GROUP_ATTRS: &[&str] = &["displayName", "externalId", "members"];
const READ_ONLY: &[&str] = &["id", "meta", "groups", "schemas"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Remove,
    Replace,
}

pub fn apply(
    kind: ResourceKind,
    current: &Value,
    body: &Map<String, Value>,
) -> Result<Map<String, Value>, ScimError> {
    let schemas = get(body, "schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| ScimError::invalid_syntax("The 'schemas' attribute is missing"))?;
    if !schemas.iter().any(|s| {
        s.as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(MESSAGE_PATCH_OP))
    }) {
        return Err(ScimError::invalid_syntax(format!(
            "'schemas' must include '{MESSAGE_PATCH_OP}'"
        )));
    }
    let operations = get(body, "Operations")
        .and_then(Value::as_array)
        .filter(|ops| !ops.is_empty())
        .ok_or_else(|| ScimError::invalid_syntax("'Operations' must be a non-empty list"))?;

    let mut doc = current.as_object().cloned().unwrap_or_default();
    doc.remove("meta");
    let mut state = State::default();
    for operation in operations {
        let operation = operation
            .as_object()
            .ok_or_else(|| ScimError::invalid_syntax("Each operation must be an object"))?;
        let op = match get(operation, "op")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("add") => Op::Add,
            Some("remove") => Op::Remove,
            Some("replace") => Op::Replace,
            other => {
                return Err(ScimError::invalid_syntax(format!(
                    "'{}' isn't a PATCH operation",
                    other.unwrap_or_default()
                )));
            }
        };
        let value = get(operation, "value").cloned().unwrap_or(Value::Null);
        match get(operation, "path").and_then(Value::as_str) {
            Some(path) => {
                let path = PatchPath::parse(path)?;
                apply_path(kind, &mut doc, &mut state, op, &path, value)?;
            }
            None if op == Op::Remove => {
                return Err(ScimError::bad_request(
                    scim_proto::ScimType::NoTarget,
                    "'remove' needs a 'path'",
                ));
            }
            None => {
                // No path: the value is an object of attributes (Keycloak)
                let Value::Object(attributes) = value else {
                    return Err(ScimError::invalid_value(
                        "Without a 'path', the value must be an object of attributes",
                    ));
                };
                for (name, value) in attributes {
                    if is_extension(kind, &name) {
                        continue;
                    }
                    let path = PatchPath::parse(&name)?;
                    apply_path(kind, &mut doc, &mut state, op, &path, value)?;
                }
            }
        }
    }
    state.finish(kind, &mut doc);

    // The primary entry is derived from userName: drop it, so a renamed
    // account doesn't keep its old address as an alias (SCIM-23)
    if let Some(original) = current.get("userName").and_then(Value::as_str)
        && let Some(Value::Array(emails)) = doc.get_mut("emails")
    {
        emails.retain(|email| {
            !(is_primary(email)
                && email
                    .get("value")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case(original)))
        });
    }
    Ok(doc)
}

fn is_extension(kind: ResourceKind, name: &str) -> bool {
    kind == ResourceKind::User && name.eq_ignore_ascii_case(scim_proto::SCHEMA_ENTERPRISE_USER)
}

/// Keeps the pairs that store one value in step.
#[derive(Default)]
struct State {
    display: Option<Option<Value>>,
    formatted: Option<Option<Value>>,
    locale: Option<Option<Value>>,
    language: Option<Option<Value>>,
}

impl State {
    fn finish(self, kind: ResourceKind, doc: &mut Map<String, Value>) {
        // SCIM-24: displayName and name.formatted are one stored value
        if let Some(display) = self.display.or(self.formatted) {
            if kind == ResourceKind::User {
                set_formatted(doc, display.clone());
            }
            match display {
                Some(display) => doc.insert("displayName".into(), display),
                None => doc.remove("displayName"),
            };
        }
        // SCIM-26: locale and preferredLanguage are one stored value
        if let Some(locale) = self.locale.or(self.language) {
            match locale {
                Some(locale) => {
                    doc.insert("locale".into(), locale.clone());
                    doc.insert("preferredLanguage".into(), locale);
                }
                None => {
                    doc.remove("locale");
                    doc.remove("preferredLanguage");
                }
            }
        }
    }
}

fn set_formatted(doc: &mut Map<String, Value>, value: Option<Value>) {
    let name = doc
        .entry("name")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(name) = name {
        name.retain(|k, _| !k.eq_ignore_ascii_case("formatted"));
        if let Some(value) = value {
            name.insert("formatted".into(), value);
        }
    }
}

fn key_of(doc: &Map<String, Value>, name: &str) -> Option<String> {
    doc.keys().find(|k| k.eq_ignore_ascii_case(name)).cloned()
}

fn apply_path(
    kind: ResourceKind,
    doc: &mut Map<String, Value>,
    state: &mut State,
    op: Op,
    path: &PatchPath,
    value: Value,
) -> Result<(), ScimError> {
    let attr = &path.attr;
    if let Some(urn) = &attr.urn {
        if kind == ResourceKind::User
            && urn.eq_ignore_ascii_case(scim_proto::SCHEMA_ENTERPRISE_USER)
        {
            return Ok(());
        }
        if !urn.eq_ignore_ascii_case(kind.schema()) {
            return Err(ScimError::invalid_path(format!(
                "The schema '{urn}' isn't supported"
            )));
        }
    }
    let (attrs, ignored) = match kind {
        ResourceKind::User => (USER_ATTRS, IGNORED_USER),
        ResourceKind::Group => (GROUP_ATTRS, IGNORED_GROUP),
    };
    if READ_ONLY.iter().any(|a| attr.name.eq_ignore_ascii_case(a)) {
        return Err(ScimError::mutability(format!(
            "'{}' is read-only",
            attr.name
        )));
    }
    if ignored.iter().any(|a| attr.name.eq_ignore_ascii_case(a)) {
        return Ok(());
    }
    let Some(name) = attrs
        .iter()
        .find(|a| attr.name.eq_ignore_ascii_case(a))
        .copied()
    else {
        return Err(ScimError::invalid_path(format!(
            "'{}' isn't a supported path",
            attr.name
        )));
    };
    let set = |value: Value| {
        if op == Op::Remove || value.is_null() {
            None
        } else {
            Some(value)
        }
    };

    match name {
        "emails" | "members" => list_op(doc, name, op, path, value),
        "name" => match attr.sub.as_deref() {
            Some(sub) if sub.eq_ignore_ascii_case("formatted") => {
                state.formatted = Some(set(value));
                Ok(())
            }
            Some(sub) => {
                // The other parts are accepted and discarded (SCIM-33)
                let _ = sub;
                Ok(())
            }
            None => {
                let formatted = value
                    .as_object()
                    .and_then(|name| get(name, "formatted"))
                    .cloned();
                if op == Op::Remove {
                    state.formatted = Some(None);
                } else if let Some(formatted) = formatted {
                    state.formatted = Some(Some(formatted));
                }
                Ok(())
            }
        },
        _ if attr.sub.is_some() || path.filter.is_some() => Err(ScimError::invalid_path(format!(
            "'{name}' has no sub-attributes"
        ))),
        "displayName" => {
            state.display = Some(set(value));
            Ok(())
        }
        "locale" => {
            state.locale = Some(set(value));
            Ok(())
        }
        "preferredLanguage" => {
            state.language = Some(set(value));
            Ok(())
        }
        "active" => {
            match set(value) {
                Some(value) => {
                    let active = parse_bool(&value)
                        .ok_or_else(|| ScimError::invalid_value("'active' must be a boolean"))?;
                    doc.insert("active".into(), Value::Bool(active));
                }
                None => {
                    doc.remove("active");
                }
            }
            Ok(())
        }
        _ => {
            if let Some(key) = key_of(doc, name) {
                doc.remove(&key);
            }
            if let Some(value) = set(value) {
                doc.insert(name.to_string(), value);
            }
            Ok(())
        }
    }
}

fn items(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items,
        Value::Null => vec![],
        item => vec![item],
    }
}

fn is_primary(item: &Value) -> bool {
    item.get("primary") == Some(&Value::Bool(true))
}

/// `emails` and `members`: whole-list and value-filtered operations.
fn list_op(
    doc: &mut Map<String, Value>,
    name: &str,
    op: Op,
    path: &PatchPath,
    value: Value,
) -> Result<(), ScimError> {
    let is_emails = name == "emails";
    if path.attr.sub.is_some() {
        return Err(ScimError::invalid_path(format!(
            "Use a value filter to change one of '{name}'"
        )));
    }
    let mut list = doc.remove(name).map(items).unwrap_or_default();

    match (&path.filter, op) {
        (None, Op::Add) => {
            for item in items(value) {
                if !list.iter().any(|i| same_value(i, &item)) {
                    list.push(item);
                }
            }
        }
        (None, Op::Replace) => {
            let primary = list.iter().filter(|i| is_emails && is_primary(i)).cloned();
            let mut new = primary.collect::<Vec<_>>();
            new.extend(items(value));
            list = new;
        }
        (None, Op::Remove) => {
            // SCIM-25: the primary address stays; SCIM-36: every member goes
            list.retain(|i| is_emails && is_primary(i));
        }
        (Some(_), Op::Add) => {
            return Err(ScimError::invalid_path("'add' can't take a value filter"));
        }
        (Some(filter), op) => {
            let matched = list.iter().map(|i| matches(filter, i)).collect::<Vec<_>>();
            if is_emails
                && list
                    .iter()
                    .zip(&matched)
                    .any(|(item, hit)| *hit && is_primary(item))
            {
                let unchanged = op == Op::Replace
                    && match &path.sub_after_filter {
                        Some(sub) => list.iter().zip(&matched).all(|(item, hit)| {
                            !*hit || !is_primary(item) || item.get(sub.as_str()) == Some(&value)
                        }),
                        None => false,
                    };
                if !unchanged {
                    return Err(ScimError::mutability(
                        "The primary email is set by 'userName' and can't be changed through 'emails'",
                    ));
                }
            }
            match op {
                Op::Remove => {
                    let mut hits = matched.iter();
                    // Removing what isn't there succeeds, since clients retry
                    list.retain(|_| !*hits.next().unwrap_or(&false));
                }
                Op::Replace => {
                    if !matched.iter().any(|hit| *hit) {
                        return Err(ScimError::bad_request(
                            scim_proto::ScimType::NoTarget,
                            format!("No entry of '{name}' matches the filter"),
                        ));
                    }
                    for (item, hit) in list.iter_mut().zip(&matched) {
                        if !*hit {
                            continue;
                        }
                        match &path.sub_after_filter {
                            Some(sub) => {
                                if let Value::Object(item) = item {
                                    item.insert(sub.clone(), value.clone());
                                }
                            }
                            None => *item = value.clone(),
                        }
                    }
                }
                Op::Add => unreachable!(),
            }
        }
    }
    doc.insert(name.to_string(), Value::Array(list));
    Ok(())
}

fn same_value(a: &Value, b: &Value) -> bool {
    match (
        a.get("value").and_then(Value::as_str),
        b.get("value").and_then(Value::as_str),
    ) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

/// A value filter against one entry of a multi-valued attribute.
pub fn matches(filter: &Filter, item: &Value) -> bool {
    match filter {
        Filter::And(a, b) => matches(a, item) && matches(b, item),
        Filter::Or(a, b) => matches(a, item) || matches(b, item),
        Filter::Not(inner) => !matches(inner, item),
        Filter::Present(path) => item
            .as_object()
            .and_then(|item| get(item, &path.name))
            .is_some(),
        Filter::Compare { path, op, value } => {
            let Some(actual) = item.as_object().and_then(|item| get(item, &path.name)) else {
                return false;
            };
            match (actual, value) {
                (Value::String(actual), Value::String(wanted)) => {
                    let (actual, wanted) = (actual.to_lowercase(), wanted.to_lowercase());
                    match op {
                        CompareOp::Eq => actual == wanted,
                        CompareOp::Ne => actual != wanted,
                        CompareOp::Co => actual.contains(&wanted),
                        CompareOp::Sw => actual.starts_with(&wanted),
                        CompareOp::Ew => actual.ends_with(&wanted),
                        _ => false,
                    }
                }
                (actual, wanted) => match op {
                    CompareOp::Eq => parse_bool(actual)
                        .zip(parse_bool(wanted))
                        .map_or(actual == wanted, |(a, b)| a == b),
                    CompareOp::Ne => actual != wanted,
                    _ => false,
                },
            }
        }
        Filter::ValuePath { .. } => false,
    }
}
