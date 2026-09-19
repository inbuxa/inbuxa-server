/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `POST /Bulk` (SCIM-51). Operations run in the order sent, each
//! authorized and scoped as it would be alone. A later operation may name
//! a resource created earlier as `bulkId:<id>`. Not atomic.

use crate::{
    MAX_OPERATIONS, ResourceKind, Route, ScimResponse,
    context::Ctx,
    resource::{dispatch, get, parse_body},
};
use ahash::AHashMap;
use hyper::{HeaderMap, Method, header::HeaderValue};
use scim_proto::{MESSAGE_BULK_REQUEST, MESSAGE_BULK_RESPONSE, ScimError};
use serde_json::{Map, Value, json};

/// Replaces `bulkId:<id>` references; `Err` names the first unresolved.
fn resolve(value: &mut Value, created: &AHashMap<String, String>) -> Result<(), String> {
    match value {
        Value::String(text) => {
            if let Some(reference) = text.strip_prefix("bulkId:") {
                *text = created
                    .get(reference)
                    .cloned()
                    .ok_or_else(|| reference.to_string())?;
            }
            Ok(())
        }
        Value::Array(items) => items.iter_mut().try_for_each(|item| resolve(item, created)),
        Value::Object(map) => map.values_mut().try_for_each(|item| resolve(item, created)),
        _ => Ok(()),
    }
}

fn resolve_path(path: &str, created: &AHashMap<String, String>) -> Result<String, String> {
    path.split('/')
        .map(|segment| match segment.strip_prefix("bulkId:") {
            Some(reference) => created
                .get(reference)
                .cloned()
                .ok_or_else(|| reference.to_string()),
            None => Ok(segment.to_string()),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|segments| segments.join("/"))
}

pub async fn bulk(ctx: &Ctx<'_>, body: &[u8]) -> Result<ScimResponse, ScimError> {
    let body = parse_body(body)?;
    let schemas = get(&body, "schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| ScimError::invalid_syntax("The 'schemas' attribute is missing"))?;
    if !schemas.iter().any(|s| {
        s.as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(MESSAGE_BULK_REQUEST))
    }) {
        return Err(ScimError::invalid_syntax(format!(
            "'schemas' must include '{MESSAGE_BULK_REQUEST}'"
        )));
    }
    let operations = get(&body, "Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| ScimError::invalid_syntax("'Operations' must be a list"))?;
    if operations.len() > MAX_OPERATIONS {
        return Err(ScimError::new(
            413,
            format!("A bulk request takes at most {MAX_OPERATIONS} operations"),
        ));
    }
    let fail_on_errors =
        match get(&body, "failOnErrors") {
            Some(value) => Some(value.as_u64().filter(|n| *n > 0).ok_or_else(|| {
                ScimError::invalid_value("'failOnErrors' must be a positive number")
            })? as usize),
            None => None,
        };

    let mut created: AHashMap<String, String> = AHashMap::new();
    let mut results = Vec::with_capacity(operations.len());
    let mut errors = 0;
    for operation in operations {
        if fail_on_errors.is_some_and(|limit| errors >= limit) {
            break;
        }
        let Some(operation) = operation.as_object() else {
            return Err(ScimError::invalid_syntax(
                "Each operation must be an object",
            ));
        };
        let (result, created_id) = run_one(ctx, operation, &created).await;
        let bulk_id = get(operation, "bulkId").and_then(Value::as_str);
        if let (Some(bulk_id), Some(id)) = (bulk_id, created_id) {
            created.insert(bulk_id.to_string(), id);
        }
        if result
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.starts_with('2'))
        {
            errors += 1;
        }
        results.push(result);
    }

    Ok(ScimResponse::json(
        200,
        json!({
            "schemas": [MESSAGE_BULK_RESPONSE],
            "Operations": results,
        }),
    ))
}

/// One operation's result, and the id it created, if any.
async fn run_one(
    ctx: &Ctx<'_>,
    operation: &Map<String, Value>,
    created: &AHashMap<String, String>,
) -> (Value, Option<String>) {
    let method_text = get(operation, "method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_uppercase();
    let bulk_id = get(operation, "bulkId").and_then(Value::as_str);
    let mut result = Map::new();
    result.insert("method".into(), json!(method_text));
    if let Some(bulk_id) = bulk_id {
        result.insert("bulkId".into(), json!(bulk_id));
    }
    let fail = |mut result: Map<String, Value>, error: ScimError| {
        result.insert("status".into(), json!(error.status.to_string()));
        result.insert("response".into(), error.to_json());
        (Value::Object(result), None)
    };

    let method = match method_text.as_str() {
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "PATCH" => Method::PATCH,
        "DELETE" => Method::DELETE,
        _ => {
            return fail(
                result,
                ScimError::invalid_syntax(format!("'{method_text}' isn't a bulk method")),
            );
        }
    };
    if method == Method::POST && bulk_id.is_none() {
        return fail(result, ScimError::invalid_syntax("A POST needs a 'bulkId'"));
    }
    let Some(path) = get(operation, "path").and_then(Value::as_str) else {
        return fail(
            result,
            ScimError::invalid_syntax("Each operation needs a 'path'"),
        );
    };
    let unresolved = |reference: String| ScimError {
        status: 409,
        scim_type: Some(scim_proto::ScimType::InvalidValue),
        detail: format!("The reference 'bulkId:{reference}' can't be resolved"),
    };
    let path = match resolve_path(path, created) {
        Ok(path) => path,
        Err(reference) => return fail(result, unresolved(reference)),
    };
    let mut data = get(operation, "data").cloned().unwrap_or(Value::Null);
    if let Err(reference) = resolve(&mut data, created) {
        return fail(result, unresolved(reference));
    }

    let segments = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let route = match Route::parse(&method, &segments) {
        Ok(
            route @ (Route::Create(_) | Route::Replace(..) | Route::Modify(..) | Route::Delete(..)),
        ) => route,
        _ => {
            return fail(
                result,
                ScimError::invalid_value(format!("'{method_text} {path}' isn't a bulk operation")),
            );
        }
    };
    let kind = match &route {
        Route::Create(kind)
        | Route::Replace(kind, _)
        | Route::Modify(kind, _)
        | Route::Delete(kind, _) => *kind,
        _ => ResourceKind::User,
    };
    let mut headers = HeaderMap::new();
    if let Some(version) = get(operation, "version").and_then(Value::as_str)
        && let Ok(value) = HeaderValue::from_str(version)
    {
        headers.insert("if-match", value);
    }
    let body = if data.is_null() {
        Vec::new()
    } else {
        data.to_string().into_bytes()
    };

    match dispatch(ctx, kind, &route, None, &headers, &body).await {
        Ok(response) => {
            let location = response
                .body
                .as_ref()
                .and_then(|b| b.pointer("/meta/location"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let id = response
                .body
                .as_ref()
                .and_then(|b| b.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let version = response
                .body
                .as_ref()
                .and_then(|b| b.pointer("/meta/version"))
                .and_then(Value::as_str)
                .map(str::to_string);
            result.insert("status".into(), json!(response.status.to_string()));
            if let Some(location) = location {
                result.insert("location".into(), json!(location));
            }
            if let Some(version) = version {
                result.insert("version".into(), json!(version));
            }
            let created_id = if matches!(route, Route::Create(_)) {
                id
            } else {
                None
            };
            (Value::Object(result), created_id)
        }
        Err(error) => fail(result, error),
    }
}
