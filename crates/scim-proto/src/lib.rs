/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The SCIM 2.0 wire contract (RFC 7643, RFC 7644, RFC 9865): schema and
//! message URNs, the error document, and the filter and PATCH path grammars.
//! No server behavior lives here; see `docs/spec/features/scim.md`.

pub mod error;
pub mod filter;
pub mod path;

pub use error::{ScimError, ScimType};
pub use filter::{AttrPath, CompareOp, Filter};
pub use path::PatchPath;

pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCHEMA_ENTERPRISE_USER: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const SCHEMA_SERVICE_PROVIDER_CONFIG: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const SCHEMA_RESOURCE_TYPE: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
pub const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

pub const MESSAGE_LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const MESSAGE_SEARCH_REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
pub const MESSAGE_PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const MESSAGE_BULK_REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
pub const MESSAGE_BULK_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
pub const MESSAGE_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

pub const CONTENT_TYPE: &str = "application/scim+json";
