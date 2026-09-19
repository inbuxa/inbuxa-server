/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! SCIM 2.0 provisioning (`docs/spec/features/scim.md`). inbuxa-server is the
//! service provider: an identity provider pushes users and groups to
//! `/scim/v2`, and each request becomes the same `x:Account` reads and
//! writes JMAP makes, so permissions, tenancy, address uniqueness and quotas
//! are enforced in one place. The HTTP crate authenticates the caller; this
//! crate routes and translates.

pub mod bulk;
pub mod context;
pub mod cursor;
pub mod discovery;
pub mod groups;
pub mod patch;
pub mod query;
pub mod resource;
pub mod users;

use common::{Server, auth::AccessToken};
use context::Ctx;
use http_proto::{HttpResponse, HttpSessionData};
use hyper::{HeaderMap, Method, StatusCode};
use scim_proto::{CONTENT_TYPE, ScimError};
use serde_json::Value;

/// The largest body accepted, `/Bulk` included (SCIM-51).
pub const MAX_PAYLOAD: usize = 1024 * 1024;
/// `/Bulk` operations per request (SCIM-51).
pub const MAX_OPERATIONS: usize = 1000;
/// The most results a page, a filter or a group's members may hold (SCIM-4).
pub const MAX_RESULTS: usize = 200;
/// A page's size when `count` isn't given (SCIM-48).
pub const DEFAULT_PAGE_SIZE: usize = 100;
/// How long a cursor stays good, in seconds (SCIM-49).
pub const CURSOR_TIMEOUT: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    User,
    Group,
}

impl ResourceKind {
    pub fn endpoint(&self) -> &'static str {
        match self {
            ResourceKind::User => "Users",
            ResourceKind::Group => "Groups",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ResourceKind::User => "User",
            ResourceKind::Group => "Group",
        }
    }

    pub fn schema(&self) -> &'static str {
        match self {
            ResourceKind::User => scim_proto::SCHEMA_USER,
            ResourceKind::Group => scim_proto::SCHEMA_GROUP,
        }
    }
}

/// What a path and method ask for (SCIM-2, "Interfaces").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Options,
    ServiceProviderConfig,
    ResourceTypes(Option<String>),
    Schemas(Option<String>),
    Me,
    List(ResourceKind),
    Create(ResourceKind),
    Search(Option<ResourceKind>),
    Get(ResourceKind, String),
    Replace(ResourceKind, String),
    Modify(ResourceKind, String),
    Delete(ResourceKind, String),
    Bulk,
}

impl Route {
    /// Routes the path segments after `/scim/v2`.
    pub fn parse(method: &Method, segments: &[String]) -> Result<Route, ScimResponse> {
        if method == Method::OPTIONS {
            return Ok(Route::Options);
        }
        let not_allowed = |allow: &str| Err(ScimResponse::method_not_allowed(allow));
        let segments = segments
            .iter()
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        let kind = |name: &str| {
            if name.eq_ignore_ascii_case("Users") {
                Some(ResourceKind::User)
            } else if name.eq_ignore_ascii_case("Groups") {
                Some(ResourceKind::Group)
            } else {
                None
            }
        };
        match segments.as_slice() {
            [name] if name.eq_ignore_ascii_case("ServiceProviderConfig") => match *method {
                Method::GET => Ok(Route::ServiceProviderConfig),
                _ => not_allowed("GET, OPTIONS"),
            },
            [name, rest @ ..] if name.eq_ignore_ascii_case("ResourceTypes") && rest.len() <= 1 => {
                match *method {
                    Method::GET => Ok(Route::ResourceTypes(rest.first().map(|s| s.to_string()))),
                    _ => not_allowed("GET, OPTIONS"),
                }
            }
            [name, rest @ ..] if name.eq_ignore_ascii_case("Schemas") && rest.len() <= 1 => {
                match *method {
                    Method::GET => Ok(Route::Schemas(rest.first().map(|s| s.to_string()))),
                    _ => not_allowed("GET, OPTIONS"),
                }
            }
            [name, ..] if name.eq_ignore_ascii_case("Me") => Ok(Route::Me),
            [name] if name.eq_ignore_ascii_case("Bulk") => match *method {
                Method::POST => Ok(Route::Bulk),
                _ => not_allowed("POST, OPTIONS"),
            },
            [".search"] => match *method {
                Method::POST => Ok(Route::Search(None)),
                _ => not_allowed("POST, OPTIONS"),
            },
            [name] if kind(name).is_some() => {
                let kind = kind(name).unwrap();
                match *method {
                    Method::GET => Ok(Route::List(kind)),
                    Method::POST => Ok(Route::Create(kind)),
                    _ => not_allowed("GET, POST, OPTIONS"),
                }
            }
            [name, ".search"] if kind(name).is_some() => match *method {
                Method::POST => Ok(Route::Search(kind(name))),
                _ => not_allowed("POST, OPTIONS"),
            },
            [name, id] if kind(name).is_some() => {
                let kind = kind(name).unwrap();
                let id = id.to_string();
                match *method {
                    Method::GET => Ok(Route::Get(kind, id)),
                    Method::PUT => Ok(Route::Replace(kind, id)),
                    Method::PATCH => Ok(Route::Modify(kind, id)),
                    Method::DELETE => Ok(Route::Delete(kind, id)),
                    _ => not_allowed("GET, PUT, PATCH, DELETE, OPTIONS"),
                }
            }
            _ => Err(ScimResponse::error(ScimError::not_found(
                "There is no such SCIM endpoint",
            ))),
        }
    }

    /// Discovery, `OPTIONS` and `/Me` need no credential (SCIM-2, SCIM-3).
    pub fn is_anonymous(&self) -> bool {
        matches!(
            self,
            Route::Options
                | Route::ServiceProviderConfig
                | Route::ResourceTypes(_)
                | Route::Schemas(_)
                | Route::Me
        )
    }
}

/// A SCIM answer, turned into an HTTP response at the edge.
#[derive(Debug, Clone)]
pub struct ScimResponse {
    pub status: u16,
    pub body: Option<Value>,
    pub headers: Vec<(&'static str, String)>,
}

impl ScimResponse {
    pub fn json(status: u16, body: Value) -> Self {
        ScimResponse {
            status,
            body: Some(body),
            headers: Vec::new(),
        }
    }

    pub fn empty(status: u16) -> Self {
        ScimResponse {
            status,
            body: None,
            headers: Vec::new(),
        }
    }

    pub fn error(error: ScimError) -> Self {
        let mut response = ScimResponse::json(error.status, error.to_json());
        if error.status == 401 {
            response.headers.push((
                "WWW-Authenticate",
                "Bearer realm=\"INBUXA SCIM\"".to_string(),
            ));
        }
        response
    }

    pub fn method_not_allowed(allow: &str) -> Self {
        let mut response = ScimResponse::error(ScimError::new(
            405,
            format!("This endpoint accepts {allow}"),
        ));
        response.headers.push(("Allow", allow.to_string()));
        response
    }

    pub fn with_header(mut self, name: &'static str, value: String) -> Self {
        self.headers.push((name, value));
        self
    }

    pub fn into_http_response(self) -> HttpResponse {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = HttpResponse::new(status);
        for (name, value) in self.headers {
            response = response.with_header(name, value);
        }
        match self.body {
            Some(body) => response
                .with_content_type(CONTENT_TYPE)
                .with_text_body(body.to_string()),
            None => response,
        }
    }
}

impl From<ScimError> for ScimResponse {
    fn from(error: ScimError) -> Self {
        ScimResponse::error(error)
    }
}

/// A request that has passed authentication.
pub struct ScimRequest<'x> {
    pub route: Route,
    pub query: Option<&'x str>,
    pub headers: &'x HeaderMap,
    pub body: Vec<u8>,
}

/// An internal failure as a SCIM answer. Details stay in the log.
pub fn server_error(err: trc::Error) -> ScimError {
    trc::error!(err.clone().details("SCIM request failed"));
    ScimError::new(500, "The request couldn't be completed")
}

/// Answers an anonymous route (SCIM-2, SCIM-3).
pub fn handle_anonymous(server: &Server, route: &Route, query: Option<&str>) -> ScimResponse {
    let base = context::base_url(server);
    if query.is_some_and(|query| {
        query.split('&').any(|pair| {
            pair.split('=')
                .next()
                .is_some_and(|k| k.eq_ignore_ascii_case("filter"))
        })
    }) && !matches!(route, Route::Options | Route::Me)
    {
        return ScimError::forbidden("Discovery endpoints don't take a filter").into();
    }
    match route {
        Route::Options => ScimResponse::empty(204),
        Route::Me => ScimError::new(
            501,
            "/Me isn't supported: the caller is a service account, not a provisioned user",
        )
        .into(),
        Route::ServiceProviderConfig => {
            ScimResponse::json(200, discovery::service_provider_config(&base))
        }
        Route::ResourceTypes(id) => discovery::resource_types(&base, id.as_deref()),
        Route::Schemas(id) => discovery::schemas(&base, id.as_deref()),
        _ => ScimError::not_found("There is no such SCIM endpoint").into(),
    }
}

/// Answers an authenticated route.
pub async fn handle(
    server: &Server,
    access_token: &AccessToken,
    session: &HttpSessionData,
    request: ScimRequest<'_>,
) -> ScimResponse {
    let ctx = match Ctx::new(server, access_token, session).await {
        Ok(ctx) => ctx,
        Err(err) => return err.into(),
    };
    let ScimRequest {
        route,
        query,
        headers,
        body,
    } = request;
    let result = match &route {
        Route::List(kind) => query::list(&ctx, *kind, query).await,
        Route::Search(kind) => match resource::parse_body(&body) {
            Ok(body) => query::search(&ctx, *kind, &body).await,
            Err(err) => Err(err),
        },
        Route::Bulk => bulk::bulk(&ctx, &body).await,
        Route::Create(kind)
        | Route::Get(kind, _)
        | Route::Replace(kind, _)
        | Route::Modify(kind, _)
        | Route::Delete(kind, _) => {
            resource::dispatch(&ctx, *kind, &route, query, headers, &body).await
        }
        _ => Err(ScimError::not_found("There is no such SCIM endpoint")),
    };
    match result {
        Ok(response) => response,
        Err(err) => err.into(),
    }
}
