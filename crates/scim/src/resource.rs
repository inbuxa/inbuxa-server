/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What users and groups share: body parsing (SCIM-33), attribute
//! projection (SCIM-40), versions and conditional requests (SCIM-44), the
//! audit event (SCIM-54), and the per-resource operations (SCIM-39 to
//! SCIM-43).

use crate::{ResourceKind, Route, ScimResponse, context::Ctx, groups, patch, users};
use hyper::HeaderMap;
use registry::schema::enums::Permission;
use scim_proto::ScimError;
use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;
use types::id::Id;

/// Parses a JSON object, refusing duplicated attributes, exact or in
/// another case (SCIM-33).
pub fn parse_body(body: &[u8]) -> Result<Map<String, Value>, ScimError> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = deserializer
        .deserialize_any(StrictValue)
        .map_err(|err| ScimError::invalid_syntax(format!("The body isn't valid JSON: {err}")))?;
    deserializer
        .end()
        .map_err(|err| ScimError::invalid_syntax(format!("The body isn't valid JSON: {err}")))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(ScimError::invalid_syntax("The body must be a JSON object")),
    }
}

struct StrictValue;

impl<'de> serde::de::DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for StrictValue {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictValue)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.keys().any(|k: &String| k.eq_ignore_ascii_case(&key)) {
                return Err(serde::de::Error::custom(format!(
                    "the attribute '{key}' appears twice"
                )));
            }
            let value = access.next_value_seed(StrictValue)?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}

/// An attribute, whatever case it was sent in (RFC 7643 §2.1).
pub fn get<'x>(map: &'x Map<String, Value>, name: &str) -> Option<&'x Value> {
    map.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
        .filter(|v| !v.is_null())
}

/// Checks `schemas` and every attribute name against what the resource
/// knows (SCIM-33).
pub fn check_attributes(
    map: &Map<String, Value>,
    kind: ResourceKind,
    known: &[&str],
) -> Result<(), ScimError> {
    let schemas = get(map, "schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| ScimError::invalid_syntax("The 'schemas' attribute is missing"))?;
    let mut has_core = false;
    for schema in schemas {
        let schema = schema
            .as_str()
            .ok_or_else(|| ScimError::invalid_syntax("'schemas' must hold strings"))?;
        if schema.eq_ignore_ascii_case(kind.schema()) {
            has_core = true;
        } else if !(kind == ResourceKind::User
            && schema.eq_ignore_ascii_case(scim_proto::SCHEMA_ENTERPRISE_USER))
        {
            return Err(ScimError::invalid_syntax(format!(
                "The schema '{schema}' isn't known"
            )));
        }
    }
    if !has_core {
        return Err(ScimError::invalid_syntax(format!(
            "'schemas' must include '{}'",
            kind.schema()
        )));
    }
    for key in map.keys() {
        let is_known = known.iter().any(|k| k.eq_ignore_ascii_case(key))
            || (kind == ResourceKind::User
                && key.eq_ignore_ascii_case(scim_proto::SCHEMA_ENTERPRISE_USER));
        if !is_known {
            return Err(ScimError::invalid_syntax(format!(
                "The attribute '{key}' isn't known"
            )));
        }
    }
    Ok(())
}

/// A weak version computed from the resource's content (SCIM-44).
pub fn version_of(doc: &Value) -> String {
    let mut doc = doc.clone();
    if let Some(meta) = doc.get_mut("meta").and_then(Value::as_object_mut) {
        meta.remove("version");
    }
    format!(
        "W/\"{:016x}\"",
        xxhash_rust::xxh3::xxh3_64(doc.to_string().as_bytes())
    )
}

/// Sets `meta.version` on a rendered resource.
pub fn stamp(mut doc: Value) -> Value {
    let version = version_of(&doc);
    if let Some(meta) = doc.get_mut("meta").and_then(Value::as_object_mut) {
        meta.insert("version".to_string(), Value::String(version));
    }
    doc
}

pub fn version(doc: &Value) -> String {
    doc.pointer("/meta/version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn opaque(tag: &str) -> &str {
    tag.trim().trim_start_matches("W/").trim_matches('"')
}

fn header<'x>(headers: &'x HeaderMap, name: &str) -> Option<&'x str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// `If-Match` on a write: `412` when the resource has changed (SCIM-44).
pub fn check_if_match(headers: &HeaderMap, current: &str) -> Result<(), ScimError> {
    match header(headers, "if-match") {
        Some(tags)
            if !tags
                .split(',')
                .any(|tag| tag.trim() == "*" || opaque(tag) == opaque(current)) =>
        {
            Err(ScimError::new(
                412,
                "The resource has changed since that version",
            ))
        }
        _ => Ok(()),
    }
}

fn not_modified(headers: &HeaderMap, current: &str) -> bool {
    header(headers, "if-none-match").is_some_and(|tags| {
        tags.split(',')
            .any(|tag| tag.trim() == "*" || opaque(tag) == opaque(current))
    })
}

/// `attributes` and `excludedAttributes` (RFC 7644 §3.9, SCIM-40). `id`,
/// `schemas` and `meta` always stay.
#[derive(Debug, Clone, Default)]
pub struct Projection {
    pub attributes: Vec<String>,
    pub excluded: Vec<String>,
}

impl Projection {
    pub fn parse(attributes: Option<&str>, excluded: Option<&str>) -> Self {
        let split = |list: Option<&str>| {
            list.map(|list| {
                list.split(',')
                    .map(|s| {
                        let s = s.trim();
                        // A fully qualified name keeps only its attribute part
                        match s.len() > 4 && s[..4].eq_ignore_ascii_case("urn:") {
                            true => s.rsplit(':').next().unwrap_or(s).to_string(),
                            false => s.to_string(),
                        }
                    })
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
        };
        Projection {
            attributes: split(attributes),
            excluded: split(excluded),
        }
    }

    /// Whether the rendered resource will hold `name` (SCIM-37).
    pub fn includes(&self, name: &str) -> bool {
        let matches = |list: &[String]| {
            list.iter().any(|a| {
                a.eq_ignore_ascii_case(name)
                    || a.split_once('.')
                        .is_some_and(|(top, _)| top.eq_ignore_ascii_case(name))
            })
        };
        if !self.attributes.is_empty() && !matches(&self.attributes) {
            return false;
        }
        !self.excluded.iter().any(|a| a.eq_ignore_ascii_case(name))
    }

    pub fn apply(&self, doc: Value) -> Value {
        let Value::Object(mut map) = doc else {
            return doc;
        };
        const ALWAYS: [&str; 3] = ["id", "schemas", "meta"];
        if !self.attributes.is_empty() {
            map.retain(|key, value| {
                if ALWAYS.iter().any(|a| a.eq_ignore_ascii_case(key)) {
                    return true;
                }
                let mut keep = false;
                let mut subs = Vec::new();
                for attr in &self.attributes {
                    match attr.split_once('.') {
                        Some((top, sub)) if top.eq_ignore_ascii_case(key) => subs.push(sub),
                        None if attr.eq_ignore_ascii_case(key) => keep = true,
                        _ => {}
                    }
                }
                if keep {
                    return true;
                }
                if subs.is_empty() {
                    return false;
                }
                let only = |item: &mut Value| {
                    if let Value::Object(item) = item {
                        item.retain(|k, _| subs.iter().any(|s| s.eq_ignore_ascii_case(k)));
                    }
                };
                match value {
                    Value::Array(items) => items.iter_mut().for_each(only),
                    item => only(item),
                }
                true
            });
        }
        for attr in &self.excluded {
            if ALWAYS.iter().any(|a| a.eq_ignore_ascii_case(attr)) {
                continue;
            }
            match attr.split_once('.') {
                None => map.retain(|key, _| !key.eq_ignore_ascii_case(attr)),
                Some((top, sub)) => {
                    for (key, value) in map.iter_mut() {
                        if !key.eq_ignore_ascii_case(top) {
                            continue;
                        }
                        let drop = |item: &mut Value| {
                            if let Value::Object(item) = item {
                                item.retain(|k, _| !k.eq_ignore_ascii_case(sub));
                            }
                        };
                        match value {
                            Value::Array(items) => items.iter_mut().for_each(drop),
                            item => drop(item),
                        }
                    }
                }
            }
        }
        Value::Object(map)
    }
}

/// A query parameter, in any case.
pub fn param<'x>(query: Option<&'x str>, name: &str) -> Option<String> {
    query.and_then(|query| {
        http_proto::form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.into_owned())
    })
}

/// A rendered resource with its `Location` and `ETag` headers.
pub fn resource_response(status: u16, doc: Value, projection: &Projection) -> ScimResponse {
    let version = version(&doc);
    let location = doc
        .pointer("/meta/location")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut response =
        ScimResponse::json(status, projection.apply(doc)).with_header("ETag", version);
    if status == 201 {
        response = response.with_header("Location", location);
    }
    response
}

/// The audit event of every write (SCIM-54).
pub fn audit(
    ctx: &Ctx<'_>,
    event: trc::ScimEvent,
    kind: ResourceKind,
    id: Id,
    external_id: Option<&str>,
) {
    trc::event!(
        Scim(event),
        AccountId = ctx.principal_id(),
        Id = id.document_id(),
        Type = kind.name(),
        Details = external_id.unwrap_or_default().to_string(),
    );
}

/// The resource as it is now, rendered in full.
pub async fn render(ctx: &Ctx<'_>, kind: ResourceKind, id: Id) -> Result<Value, ScimError> {
    let (id, account) = ctx.load(kind, &id.to_string()).await?;
    match kind {
        ResourceKind::User => users::render(ctx, id, &account).await,
        ResourceKind::Group => groups::render(ctx, id, &account, None).await,
    }
}

/// How the new state of a resource was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    Create,
    Replace,
    Patch,
}

/// Create, read, replace, modify and delete of one resource.
pub async fn dispatch(
    ctx: &Ctx<'_>,
    kind: ResourceKind,
    route: &Route,
    query: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<ScimResponse, ScimError> {
    let projection = Projection::parse(
        param(query, "attributes").as_deref(),
        param(query, "excludedAttributes").as_deref(),
    );
    match route {
        Route::Create(_) => {
            ctx.require(Permission::SysAccountCreate)?;
            let body = parse_body(body)?;
            let id = match kind {
                ResourceKind::User => users::create(ctx, &body).await?,
                ResourceKind::Group => groups::create(ctx, &body).await?,
            };
            let doc = render(ctx, kind, id).await?;
            Ok(resource_response(201, doc, &projection))
        }
        Route::Get(_, id) => {
            ctx.require(Permission::SysAccountGet)?;
            let (id, account) = ctx.load(kind, id).await?;
            let doc = match kind {
                ResourceKind::User => users::render(ctx, id, &account).await?,
                ResourceKind::Group => groups::render(ctx, id, &account, Some(&projection)).await?,
            };
            if not_modified(headers, &version(&doc)) {
                return Ok(ScimResponse::empty(304).with_header("ETag", version(&doc)));
            }
            Ok(resource_response(200, doc, &projection))
        }
        Route::Replace(_, id) | Route::Modify(_, id) => {
            ctx.require(Permission::SysAccountUpdate)?;
            let (id, account) = ctx.load(kind, id).await?;
            let current = match kind {
                ResourceKind::User => users::render(ctx, id, &account).await?,
                ResourceKind::Group => groups::render(ctx, id, &account, None).await?,
            };
            check_if_match(headers, &version(&current))?;
            let body = parse_body(body)?;
            let (doc, mode) = if matches!(route, Route::Replace(..)) {
                (body, WriteMode::Replace)
            } else {
                (patch::apply(kind, &current, &body)?, WriteMode::Patch)
            };
            match kind {
                ResourceKind::User => {
                    users::replace(ctx, id, &account, &current, &doc, mode).await?
                }
                ResourceKind::Group => {
                    groups::replace(ctx, id, &account, &current, &doc, mode).await?
                }
            }
            let doc = render(ctx, kind, id).await?;
            Ok(resource_response(200, doc, &projection))
        }
        Route::Delete(_, id) => {
            ctx.require(Permission::SysAccountDestroy)?;
            let (id, account) = ctx.load(kind, id).await?;
            if id.document_id() == ctx.principal_id() {
                return Err(ScimError::forbidden(
                    "The service principal can't delete itself",
                ));
            }
            let current = match kind {
                ResourceKind::User => users::render(ctx, id, &account).await?,
                ResourceKind::Group => groups::render(ctx, id, &account, None).await?,
            };
            check_if_match(headers, &version(&current))?;
            if kind == ResourceKind::Group {
                groups::remove_all_members(ctx, id).await?;
            }
            ctx.destroy(id).await?;
            audit(
                ctx,
                trc::ScimEvent::ResourceDeleted,
                kind,
                id,
                current.get("externalId").and_then(Value::as_str),
            );
            Ok(ScimResponse::empty(204))
        }
        _ => Err(ScimError::not_found("There is no such SCIM endpoint")),
    }
}
