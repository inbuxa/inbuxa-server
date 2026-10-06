/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The SCIM error document (RFC 7644 §3.12, RFC 9865 for the cursor types).

use crate::MESSAGE_ERROR;
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimType {
    InvalidFilter,
    TooMany,
    Uniqueness,
    Mutability,
    InvalidSyntax,
    InvalidPath,
    NoTarget,
    InvalidValue,
    InvalidVers,
    Sensitive,
    InvalidCursor,
    ExpiredCursor,
    InvalidCount,
}

impl ScimType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScimType::InvalidFilter => "invalidFilter",
            ScimType::TooMany => "tooMany",
            ScimType::Uniqueness => "uniqueness",
            ScimType::Mutability => "mutability",
            ScimType::InvalidSyntax => "invalidSyntax",
            ScimType::InvalidPath => "invalidPath",
            ScimType::NoTarget => "noTarget",
            ScimType::InvalidValue => "invalidValue",
            ScimType::InvalidVers => "invalidVers",
            ScimType::Sensitive => "sensitive",
            ScimType::InvalidCursor => "invalidCursor",
            ScimType::ExpiredCursor => "expiredCursor",
            ScimType::InvalidCount => "invalidCount",
        }
    }
}

/// An error answer: status, optional `scimType`, and a `detail`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimError {
    pub status: u16,
    pub scim_type: Option<ScimType>,
    pub detail: String,
}

impl ScimError {
    pub fn new(status: u16, detail: impl Into<String>) -> Self {
        ScimError {
            status,
            scim_type: None,
            detail: detail.into(),
        }
    }

    pub fn bad_request(scim_type: ScimType, detail: impl Into<String>) -> Self {
        ScimError {
            status: 400,
            scim_type: Some(scim_type),
            detail: detail.into(),
        }
    }

    pub fn conflict(detail: impl Into<String>) -> Self {
        ScimError {
            status: 409,
            scim_type: Some(ScimType::Uniqueness),
            detail: detail.into(),
        }
    }

    pub fn invalid_syntax(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidSyntax, detail)
    }

    pub fn invalid_value(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidValue, detail)
    }

    pub fn invalid_filter(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidFilter, detail)
    }

    pub fn invalid_path(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidPath, detail)
    }

    pub fn mutability(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::Mutability, detail)
    }

    pub fn too_many(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::TooMany, detail)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(404, detail)
    }

    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(403, detail)
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(401, detail)
    }

    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "schemas": [MESSAGE_ERROR],
            "status": self.status.to_string(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            value["scimType"] = Value::String(scim_type.as_str().to_string());
        }
        value
    }
}

impl std::fmt::Display for ScimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.scim_type {
            Some(scim_type) => write!(f, "{} {}: {}", self.status, scim_type.as_str(), self.detail),
            None => write!(f, "{}: {}", self.status, self.detail),
        }
    }
}

impl std::error::Error for ScimError {}
