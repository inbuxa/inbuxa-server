/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:FrontEnds/get` and `/set`: where the server's front ends are
//! (contract C-4). A server setting, so a server administrator's only: the
//! HTTP settings' permissions, and `sysOAuthClientUpdate` to change it, since
//! setting it registers OAuth clients. Inside a tenant it doesn't exist.
//!
//! Setting it registers the front ends' OAuth clients at once (C-6) and
//! reloads the HTTP settings here and on every node, which is what puts the
//! new origins on the cross-origin allowlist (C-14). The environment
//! variables keep working beside it; `get` shows what they say, so whoever
//! reads it can tell which address came from where.
//!
//! It's stored in the registry's store, which is the one start-up and every
//! reload read it from.

use common::{Server, auth::AccessToken, manager::first_party};
use directory::core::secret::hash_secret;
use inbuxa_features::security::front_ends::{self, FrontEnds as Stored, invalid_url};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_front_ends::{FrontEnds, FrontEndsProperty as P, FrontEndsValue},
    request::IntoValid,
};
use jmap_tools::{Key, Map, Value};
use registry::schema::{
    enums::{PasswordHashAlgorithm, Permission},
    prelude::ObjectType,
};
use store::registry::bootstrap::Bootstrap;
use trc::AddContext;
use types::id::Id;

type PValue = Value<'static, P, FrontEndsValue>;

const ALL: &[P] = &[
    P::Id,
    P::AdminUrl,
    P::WebmailUrl,
    P::WebmailClientSecret,
    P::WebmailClientSecretSet,
    P::ExtraOrigins,
    P::EnvironmentAdminUrl,
    P::EnvironmentWebmailUrl,
    P::EnvironmentWebmailClientSecret,
    P::ChangedAt,
    P::ChangedBy,
];

fn env(name: &str) -> Option<String> {
    types::branding::env_var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn opt_str(value: Option<&String>) -> PValue {
    value
        .map(|v| Value::Str(v.clone().into()))
        .unwrap_or(Value::Null)
}

fn to_value(stored: &Stored, properties: &[P]) -> PValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(FrontEndsValue::Id(Id::singleton())),
            P::AdminUrl => opt_str(stored.admin_url.as_ref()),
            P::WebmailUrl => opt_str(stored.webmail_url.as_ref()),
            // Write-only: the stored form is a hash, and even that stays in
            P::WebmailClientSecret => Value::Null,
            P::WebmailClientSecretSet => Value::Bool(stored.webmail_secret_hash.is_some()),
            P::ExtraOrigins => Value::Array(
                stored
                    .extra_origins
                    .iter()
                    .map(|o| Value::Str(o.clone().into()))
                    .collect(),
            ),
            P::EnvironmentAdminUrl => opt_str(env("ADMIN_URL").as_ref()),
            P::EnvironmentWebmailUrl => opt_str(env("WEBMAIL_URL").as_ref()),
            P::EnvironmentWebmailClientSecret => {
                Value::Bool(first_party::webmail_secret_from_environment())
            }
            P::ChangedAt => stored
                .changed_at
                .map(|at| Value::Number(at.into()))
                .unwrap_or(Value::Null),
            P::ChangedBy => opt_str(stored.changed_by.as_ref()),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// `inbuxa:FrontEnds/get`.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<FrontEnds>,
) -> trc::Result<GetResponse<FrontEnds>> {
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let wanted = ids.unwrap_or_else(|| vec![Id::singleton()]);
    let bp = Bootstrap::new(server.registry().clone()).await;
    for id in wanted {
        if id.is_singleton() && access_token.tenant_id().is_none() {
            let stored = front_ends::get(&bp.data_store).await?;
            response.list.push(to_value(&stored, &properties));
        } else {
            response.push_not_found(id);
        }
    }
    Ok(response)
}

fn invalid(key: Key<'_, P>, why: impl Into<String>) -> SetError<P> {
    SetError::invalid_properties()
        .with_property(key.into_owned())
        .with_description(why.into())
}

/// A URL property: a front end's address, or null to clear it.
fn parse_url(
    key: &Key<'_, P>,
    value: &Value<'_, P, FrontEndsValue>,
) -> Result<Option<String>, SetError<P>> {
    match value {
        Value::Null => Ok(None),
        Value::Str(s) => match invalid_url(s) {
            None => Ok(Some(s.trim().trim_end_matches('/').to_string())),
            Some(why) => Err(invalid(key.clone(), why)),
        },
        _ => Err(invalid(key.clone(), "must be a URL or null")),
    }
}

/// `inbuxa:FrontEnds/set`: updates the singleton. `null` clears a property.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, FrontEnds>,
) -> trc::Result<SetResponse<FrontEnds>> {
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (client_id, _) in request.unwrap_create() {
        response.not_created.append(
            client_id,
            SetError::forbidden()
                .with_description("inbuxa:FrontEnds is a singleton that always exists."),
        );
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(
            id,
            SetError::forbidden()
                .with_description("inbuxa:FrontEnds is a singleton that always exists."),
        );
    }

    let mut bp = Bootstrap::new(server.registry().clone()).await;
    let mut changed = false;
    for (id, value) in request.unwrap_update().into_valid() {
        if !id.is_singleton() || access_token.tenant_id().is_some() {
            response.not_updated.append(id, SetError::not_found());
            continue;
        }
        // Setting it registers OAuth clients, so it takes that permission too
        if !access_token.has_permission(Permission::SysOAuthClientUpdate) {
            response.not_updated.append(
                id,
                SetError::forbidden().with_description(
                    "Changing the front ends registers OAuth clients, which needs sysOAuthClientUpdate.",
                ),
            );
            continue;
        }

        let previous = front_ends::get(&bp.data_store).await?;
        let mut next = previous.clone();
        let mut error = None;
        for (key, value) in value.into_expanded_object() {
            let result: Result<(), SetError<P>> = match &key {
                Key::Property(P::AdminUrl) => parse_url(&key, &value).map(|v| next.admin_url = v),
                Key::Property(P::WebmailUrl) => {
                    parse_url(&key, &value).map(|v| next.webmail_url = v)
                }
                Key::Property(P::WebmailClientSecret) => match &value {
                    Value::Null => {
                        next.webmail_secret_hash = None;
                        Ok(())
                    }
                    Value::Str(_) if first_party::webmail_secret_from_environment() => {
                        Err(SetError::forbidden().with_description(
                            "This server takes the webmail's client secret from \
                             INBUXA_WEBMAIL_CLIENT_SECRET, which would replace this one at \
                             every start. Remove it from the server's environment first.",
                        ))
                    }
                    Value::Str(s) if s.len() >= 32 => {
                        next.webmail_secret_hash = Some(
                            hash_secret(
                                &server.inner.data.password_verifier,
                                PasswordHashAlgorithm::Argon2id,
                                s.as_bytes().to_vec(),
                            )
                            .await?,
                        );
                        Ok(())
                    }
                    Value::Str(_) => Err(invalid(key.clone(), "must be at least 32 characters")),
                    _ => Err(invalid(key.clone(), "must be a string or null")),
                },
                Key::Property(P::ExtraOrigins) => match value {
                    Value::Null => {
                        next.extra_origins.clear();
                        Ok(())
                    }
                    Value::Array(items) => {
                        let mut origins = Vec::with_capacity(items.len());
                        let mut bad = None;
                        for item in items {
                            match item {
                                Value::Str(s) => match first_party::origin_of(&s) {
                                    Some(origin) if !origins.contains(&origin) => {
                                        origins.push(origin)
                                    }
                                    Some(_) => {}
                                    None => {
                                        bad = Some(format!("{s:?} is not an http or https origin"))
                                    }
                                },
                                _ => bad = Some("must be a list of origins".to_string()),
                            }
                        }
                        match bad {
                            Some(why) => Err(invalid(key.clone(), why)),
                            None => {
                                next.extra_origins = origins;
                                Ok(())
                            }
                        }
                    }
                    _ => Err(invalid(key.clone(), "must be a list of origins or null")),
                },
                Key::Property(P::Id) => Err(invalid(key.clone(), "is immutable")),
                Key::Property(property) if property.is_server_set() => {
                    Err(invalid(key.clone(), "is set by the server"))
                }
                _ => Err(invalid(
                    key.clone(),
                    "is not a property of inbuxa:FrontEnds",
                )),
            };
            if let Err(err) = result {
                error = Some(err);
                break;
            }
        }
        if let Some(error) = error {
            response.not_updated.append(id, error);
            continue;
        }
        if next.webmail_url.is_some()
            && next.webmail_secret_hash.is_none()
            && !first_party::webmail_secret_from_environment()
        {
            response.not_updated.append(
                id,
                SetError::invalid_properties()
                    .with_property(Key::Property(P::WebmailClientSecret))
                    .with_description("The webmail needs a client secret to be registered."),
            );
            continue;
        }

        let mut compare = previous.clone();
        compare.changed_at = next.changed_at;
        compare.changed_by = next.changed_by.clone();
        if compare != next {
            next.changed_at = Some(store::write::now());
            next.changed_by = Some(Id::from(access_token.account_id()).to_string());
            front_ends::set(&bp.data_store, &next)
                .await
                .caused_by(trc::location!())?;
            changed = true;
        }
        response.updated.append(id, None);
    }

    if changed {
        // The OAuth clients now, so the front end can sign in at once (C-6)
        first_party::ensure_first_party_clients(&mut bp)
            .await
            .caused_by(trc::location!())?;
        // The allowlist is built with the HTTP settings, here and on every
        // node (C-14). The value is stored whatever the reload says, as for
        // any registry write; a refused reload is logged by the reload.
        let _ = server.reload_after_write(ObjectType::Http).await;
    }
    Ok(response)
}
