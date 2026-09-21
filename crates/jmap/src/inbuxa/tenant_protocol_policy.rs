/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:TenantProtocolPolicy/get` and `/set`: one tenant's legacy mail
//! protocols switch (legacy-protocols spec, LP-9 to LP-14). There is one per
//! tenant, and its id is the tenant's.
//!
//! Inside a tenant, a principal reaches only its own tenant's (MT-1): `/get`
//! with no ids answers with it, and any other id is `notFound`. At server
//! level, `/get` with no ids answers with every tenant's.
//!
//! Turning it off never needs the server's leave; turning it back on is
//! refused with `forbidden` while the server has legacy protocols off (LP-9).
//! A tenant's switch closes no port (LP-13) -- sign-in and client
//! configuration read it (LP-10, LP-14a).

use common::{Server, auth::AccessToken};
use inbuxa_features::{
    security::{
        protocol_policy::LegacyProtocols,
        tenant_protocol_policy::{self, TenantProtocolPolicy as Policy, refusal},
    },
    tenancy::quota::all_tenants,
};
use jmap_proto::{
    error::set::SetError,
    method::{
        get::{GetRequest, GetResponse},
        set::{SetRequest, SetResponse},
    },
    object::inbuxa_tenant_protocol_policy::{
        TenantProtocolPolicy, TenantProtocolPolicyProperty as P, TenantProtocolPolicyValue,
    },
    request::IntoValid,
};
use jmap_tools::{Key, Map, Value};
use types::id::Id;

type PValue = Value<'static, P, TenantProtocolPolicyValue>;

const ALL: &[P] = &[
    P::Id,
    P::TenantId,
    P::LegacyProtocols,
    P::ChangedAt,
    P::ChangedBy,
];

/// The tenants this principal may reach: its own inside a tenant (MT-1),
/// every tenant at server level.
async fn reachable(server: &Server, access_token: &AccessToken) -> trc::Result<Vec<u32>> {
    match access_token.tenant_id() {
        Some(tenant_id) => Ok(vec![tenant_id]),
        None => all_tenants(server.registry()).await,
    }
}

fn to_value(tenant_id: u32, policy: &Policy, properties: &[P]) -> PValue {
    let mut out = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            P::Id | P::TenantId => {
                Value::Element(TenantProtocolPolicyValue::Id(Id::from(tenant_id)))
            }
            P::LegacyProtocols => Value::Str(
                match policy.legacy_protocols {
                    LegacyProtocols::Enabled => "enabled",
                    LegacyProtocols::Disabled => "disabled",
                }
                .into(),
            ),
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

/// `inbuxa:TenantProtocolPolicy/get`.
pub async fn get(
    server: &Server,
    access_token: &AccessToken,
    mut request: GetRequest<TenantProtocolPolicy>,
) -> trc::Result<GetResponse<TenantProtocolPolicy>> {
    let properties = request.unwrap_properties(ALL);
    let (ids, not_found) = request.unwrap_ids(server.core.jmap.get_max_objects)?;
    let mut response = GetResponse {
        account_id: request.account_id.into(),
        state: None,
        list: Vec::new(),
        not_found,
    };

    let reachable = reachable(server, access_token).await?;
    let wanted = match ids {
        None => reachable.iter().map(|id| Id::from(*id)).collect(),
        Some(ids) => ids,
    };
    for id in wanted {
        let tenant_id = id.document_id();
        if reachable.contains(&tenant_id) {
            let policy = tenant_protocol_policy::get(&server.core.storage.data, tenant_id).await?;
            response
                .list
                .push(to_value(tenant_id, &policy, &properties));
        } else {
            response.push_not_found(id);
        }
    }
    Ok(response)
}

/// `inbuxa:TenantProtocolPolicy/set`: turns one tenant's switch. Unset
/// (`null`) puts legacy protocols back on, which LP-9 may refuse.
pub async fn set(
    server: &Server,
    access_token: &AccessToken,
    mut request: SetRequest<'_, TenantProtocolPolicy>,
) -> trc::Result<SetResponse<TenantProtocolPolicy>> {
    let mut response = SetResponse::from_request(&request, server.core.jmap.set_max_objects)?;
    // A tenant's switch comes and goes with the tenant; it is only turned.
    for (client_id, _) in request.unwrap_create() {
        response.not_created.append(
            client_id,
            SetError::forbidden().with_description("A tenant's switch exists with the tenant."),
        );
    }
    for id in request.unwrap_destroy().into_valid() {
        response.not_destroyed.append(
            id,
            SetError::forbidden().with_description("A tenant's switch exists with the tenant."),
        );
    }

    let reachable = reachable(server, access_token).await?;
    for (id, value) in request.unwrap_update().into_valid() {
        let tenant_id = id.document_id();
        if !reachable.contains(&tenant_id) {
            response.not_updated.append(id, SetError::not_found());
            continue;
        }

        let data = &server.core.storage.data;
        let previous = tenant_protocol_policy::get(data, tenant_id).await?;
        let mut policy = previous.clone();
        let mut error = None;
        for (key, value) in value.into_expanded_object() {
            let result = match &key {
                Key::Property(P::LegacyProtocols) => match value {
                    Value::Null => {
                        policy.legacy_protocols = LegacyProtocols::Enabled;
                        Ok(())
                    }
                    value => match value.as_str().as_deref() {
                        Some("enabled") => {
                            policy.legacy_protocols = LegacyProtocols::Enabled;
                            Ok(())
                        }
                        Some("disabled") => {
                            policy.legacy_protocols = LegacyProtocols::Disabled;
                            Ok(())
                        }
                        _ => Err(r#"must be "enabled" or "disabled""#),
                    },
                },
                Key::Property(P::Id) => Err("is immutable"),
                Key::Property(_) => Err("is set by the server"),
                _ => Err("is not a property of inbuxa:TenantProtocolPolicy"),
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

        // LP-9: server off means off for everyone.
        if let Some(why) = refusal(&server.protocol_policy().await?, policy.legacy_protocols) {
            response
                .not_updated
                .append(id, SetError::forbidden().with_description(why));
            continue;
        }

        if policy.legacy_protocols != previous.legacy_protocols {
            policy.changed_at = Some(store::write::now() * 1000);
            policy.changed_by = Some(Id::from(access_token.account_id()).to_string());
            tenant_protocol_policy::set(data, tenant_id, &policy).await?;

            // LP-14. A tenant's switch closes and reopens nothing (LP-13).
            trc::event!(
                Security(trc::SecurityEvent::LegacyProtocolsChanged),
                Policy = "tenant",
                Id = tenant_id,
                Value = if policy.legacy_protocols.is_disabled() {
                    "disabled"
                } else {
                    "enabled"
                },
                AccountId = policy.changed_by.clone(),
            );
        }
        response.updated.append(id, None);
    }
    Ok(response)
}
