/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:SharingPolicy/get` and `/set`: whether people may share their own
//! mail and add other accounts to the webmail (multi-account spec, MA-C).
//!
//! The server's policy has the singleton id; each tenant's has the tenant's
//! id. At server level `/get` with no ids answers with the server's and every
//! tenant's; inside a tenant, with the server's (to read) and its own tenant's
//! (MT-1). Only a server administrator holding `sysSharingUpdate` changes the
//! server's; a tenant's administrator changes their tenant's, and can only be
//! stricter than the server.
//!
//! A change rebuilds every access token, here and on every node: what a share
//! still gives is worked out when a token is built.

use common::{Server, auth::AccessToken, ipc::BroadcastEvent};
use inbuxa_features::{
    security::sharing_policy::{self, SharingPolicy as Policy, looser_than_server},
    tenancy::quota::all_tenants,
};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_sharing_policy::{SharingPolicy, SharingPolicyProperty as P, SharingPolicyValue},
    request::IntoValid,
};
use jmap_tools::{Key, Map, Value};
use registry::schema::enums::Permission;
use types::id::Id;

type PValue = Value<'static, P, SharingPolicyValue>;

const ALL: &[P] = &[P::Id, P::TenantId, P::MailSharing, P::AddAccounts, P::ChangedAt, P::ChangedBy];

fn switch_str(on: Option<bool>) -> &'static str {
    if on.unwrap_or(true) { "enabled" } else { "disabled" }
}

fn to_value(tenant_id: Option<u32>, policy: &Policy, properties: &[P]) -> PValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id => Value::Element(SharingPolicyValue::Id(
                tenant_id.map_or_else(Id::singleton, Id::from),
            )),
            P::TenantId => tenant_id
                .map(|t| Value::Element(SharingPolicyValue::Id(Id::from(t))))
                .unwrap_or(Value::Null),
            P::MailSharing => Value::Str(switch_str(policy.mail_sharing).into()),
            P::AddAccounts => Value::Str(switch_str(policy.add_accounts).into()),
            P::ChangedAt => policy
                .changed_at
                .map(|at| Value::Number(at.into()))
                .unwrap_or(Value::Null),
            P::ChangedBy => policy
                .changed_by
                .as_ref()
                .map(|by| Value::Str(by.clone().into()))
                .unwrap_or(Value::Null),
        };
        out.insert_unchecked(Key::Property(property.clone()), value);
    }
    Value::Object(out)
}

/// The tenants this principal may reach: its own inside a tenant (MT-1),
/// every tenant at server level.
async fn reachable(server: &Server, access_token: &AccessToken) -> trc::Result<Vec<u32>> {
    match access_token.tenant_id() {
        Some(tenant_id) => Ok(vec![tenant_id]),
        None => all_tenants(server.registry()).await,
    }
}

/// Which policy an id names: `None` for the server's.
fn target(id: Id) -> Option<u32> {
    if id.is_singleton() { None } else { Some(id.document_id()) }
}

/// `inbuxa:SharingPolicy/get`.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<SharingPolicy>,
) -> trc::Result<GetResponse<SharingPolicy>> {
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };
    let reachable = reachable(server, access_token).await?;
    let wanted: Vec<Id> = match ids {
        None => std::iter::once(Id::singleton())
            .chain(reachable.iter().map(|t| Id::from(*t)))
            .collect(),
        Some(ids) => ids,
    };
    let data = &server.core.storage.data;
    for id in wanted {
        match target(id) {
            None => {
                let policy = sharing_policy::get(data, None).await?;
                response.list.push(to_value(None, &policy, &properties));
            }
            Some(tenant_id) if reachable.contains(&tenant_id) => {
                let policy = sharing_policy::get(data, Some(tenant_id)).await?;
                response.list.push(to_value(Some(tenant_id), &policy, &properties));
            }
            Some(_) => response.push_not_found(id),
        }
    }
    Ok(response)
}

/// `inbuxa:SharingPolicy/set`: turns switches. `null` puts one back to its
/// default, on (as far as the server allows).
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, SharingPolicy>,
) -> trc::Result<SetResponse<SharingPolicy>> {
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    for (client_id, _) in request.unwrap_create() {
        response.not_created.append(
            client_id,
            SetError::forbidden().with_description("A sharing policy exists with the server or the tenant."),
        );
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(
            id,
            SetError::forbidden().with_description("A sharing policy exists with the server or the tenant."),
        );
    }

    let reachable = reachable(server, access_token).await?;
    let data = &server.core.storage.data;
    let mut changed = false;
    for (id, value) in request.unwrap_update().into_valid() {
        let tenant_id = target(id);
        match tenant_id {
            None if access_token.tenant_id().is_some()
                || !access_token.has_permission(Permission::SysSharingUpdate) =>
            {
                response.not_updated.append(
                    id,
                    SetError::forbidden()
                        .with_description("Only a server administrator changes the server's sharing policy."),
                );
                continue;
            }
            Some(tenant_id) if !reachable.contains(&tenant_id) => {
                response.not_updated.append(id, SetError::not_found());
                continue;
            }
            _ => {}
        }

        let previous = sharing_policy::get(data, tenant_id).await?;
        let mut policy = previous.clone();
        let mut error = None;
        for (key, value) in value.into_expanded_object() {
            let parsed = match value {
                Value::Null => Ok(None),
                Value::Str(s) if s == "enabled" => Ok(Some(true)),
                Value::Str(s) if s == "disabled" => Ok(Some(false)),
                _ => Err("must be enabled or disabled".to_string()),
            };
            let result = match &key {
                Key::Property(P::MailSharing) => parsed.map(|v| policy.mail_sharing = v),
                Key::Property(P::AddAccounts) => parsed.map(|v| policy.add_accounts = v),
                Key::Property(P::Id) => Err("is immutable".to_string()),
                Key::Property(_) => Err("is set by the server".to_string()),
                _ => Err("is not a property of inbuxa:SharingPolicy".to_string()),
            };
            if let Err(why) = result {
                error = Some(
                    SetError::invalid_properties()
                        .with_property(key.into_owned())
                        .with_description(why),
                );
                break;
            }
        }
        if let Some(error) = error {
            response.not_updated.append(id, error);
            continue;
        }

        // A tenant can only be stricter than the server
        if tenant_id.is_some()
            && let Some(why) = looser_than_server(&sharing_policy::get(data, None).await?, &policy)
        {
            response
                .not_updated
                .append(id, SetError::forbidden().with_description(why));
            continue;
        }

        if policy.mail_sharing != previous.mail_sharing || policy.add_accounts != previous.add_accounts {
            policy.changed_at = Some(store::write::now() * 1000);
            policy.changed_by = Some(Id::from(access_token.account_id()).to_string());
            sharing_policy::set(data, tenant_id, &policy).await?;
            changed = true;
        }
        response.updated.append(id, None);
    }

    if changed {
        // Shares are honored, or not, as tokens are built
        server.invalidate_all_local_caches();
        server.cluster_broadcast(BroadcastEvent::CacheInvalidateAll).await;
    }
    Ok(response)
}
