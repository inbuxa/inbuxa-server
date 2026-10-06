/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The caller and its scope (SCIM-11 to SCIM-20), and the `x:Account`
//! reads and writes every resource operation goes through.

use crate::{ResourceKind, server_error};
use common::{
    Server,
    auth::{AccessToken, DomainCache},
};
use http_proto::HttpSessionData;
use jmap::registry::set::RegistrySet;
use jmap_proto::{method::set::SetRequest, object::registry::Registry};
use registry::{
    schema::{
        enums::Permission,
        prelude::{ObjectType, Property},
        structs::Account,
    },
    types::EnumImpl,
};
use scim_proto::ScimError;
use serde_json::{Value, json};
use std::{str::FromStr, sync::Arc};
use store::registry::RegistryQuery;
use types::id::Id;

/// The server's public address with `/scim/v2` (SCIM-30).
pub fn base_url(server: &Server) -> String {
    format!(
        "{}/scim/v2",
        server.core.network.http.url_https.trim_end_matches('/')
    )
}

pub struct Ctx<'x> {
    pub server: &'x Server,
    pub token: &'x AccessToken,
    pub session: &'x HttpSessionData,
    pub base: String,
}

impl<'x> Ctx<'x> {
    /// Checks the two gates every non-discovery request passes (SCIM-11).
    pub async fn new(
        server: &'x Server,
        token: &'x AccessToken,
        session: &'x HttpSessionData,
    ) -> Result<Ctx<'x>, ScimError> {
        let ctx = Ctx {
            server,
            token,
            session,
            base: base_url(server),
        };
        ctx.require(Permission::Authenticate)?;
        ctx.require(Permission::ScimAccess)?;
        Ok(ctx)
    }

    /// A `403` naming the missing permission (SCIM-11).
    pub fn require(&self, permission: Permission) -> Result<(), ScimError> {
        if self.token.has_permission(permission) {
            Ok(())
        } else {
            Err(ScimError::forbidden(format!(
                "The credential lacks the '{}' permission",
                permission.as_str()
            )))
        }
    }

    pub fn tenant_id(&self) -> Option<u32> {
        self.token.tenant_id()
    }

    /// The service principal's own id (SCIM-13).
    pub fn principal_id(&self) -> u32 {
        self.token.account_id()
    }

    pub fn location(&self, kind: ResourceKind, id: Id) -> String {
        format!("{}/{}/{id}", self.base, kind.endpoint())
    }

    /// A domain a write may put an address on (SCIM-15, SCIM-17).
    pub async fn writable_domain(&self, name: &str) -> Result<Arc<DomainCache>, ScimError> {
        let not_open = || {
            ScimError::invalid_value(format!(
                "The domain '{name}' isn't open to SCIM provisioning"
            ))
        };
        let domain = self
            .server
            .domain(name)
            .await
            .map_err(server_error)?
            .ok_or_else(not_open)?;
        if let Some(tenant_id) = self.tenant_id()
            && domain.id_tenant != Some(tenant_id)
        {
            return Err(ScimError::not_found(format!(
                "The domain '{name}' isn't in your tenant"
            )));
        }
        if !domain.allows_scim() {
            return Err(not_open());
        }
        Ok(domain)
    }

    /// The domain, when it's in the caller's SCIM scope (SCIM-16).
    pub async fn scoped_domain(
        &self,
        domain_id: u32,
    ) -> Result<Option<Arc<DomainCache>>, ScimError> {
        Ok(self
            .server
            .domain_by_id(domain_id)
            .await
            .map_err(server_error)?
            .filter(|domain| {
                domain.allows_scim()
                    && self
                        .tenant_id()
                        .is_none_or(|tenant_id| domain.id_tenant == Some(tenant_id))
            }))
    }

    /// Every domain in the caller's SCIM scope (SCIM-16).
    pub async fn scoped_domains(&self) -> Result<Vec<Arc<DomainCache>>, ScimError> {
        let ids = self
            .server
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Domain).with_tenant(self.tenant_id()))
            .await
            .map_err(server_error)?;
        let mut domains = Vec::new();
        for id in ids {
            if let Some(domain) = self.scoped_domain(id.document_id()).await? {
                domains.push(domain);
            }
        }
        Ok(domains)
    }

    /// Whether an account is in the caller's scope (SCIM-16, SCIM-17).
    pub async fn in_scope(&self, account: &Account) -> Result<bool, ScimError> {
        let (domain_id, tenant_id) = match account {
            Account::User(user) => (user.domain_id, user.member_tenant_id),
            Account::Group(group) => (group.domain_id, group.member_tenant_id),
        };
        if let Some(caller) = self.tenant_id()
            && tenant_id.map(|id| id.document_id()) != Some(caller)
        {
            return Ok(false);
        }
        Ok(self.scoped_domain(domain_id.document_id()).await?.is_some())
    }

    /// Reads an account of that kind in scope. Anything else, another
    /// tenant's included, is `404` (SCIM-17, SCIM-40).
    pub async fn load(&self, kind: ResourceKind, id: &str) -> Result<(Id, Account), ScimError> {
        let not_found = || ScimError::not_found(format!("{} {id} not found", kind.name()));
        let id = Id::from_str(id).map_err(|_| not_found())?;
        let account = self.load_id(id).await?.ok_or_else(not_found)?;
        let matches = matches!(
            (&account, kind),
            (Account::User(_), ResourceKind::User) | (Account::Group(_), ResourceKind::Group)
        );
        if matches && self.in_scope(&account).await? {
            Ok((id, account))
        } else {
            Err(not_found())
        }
    }

    /// Reads any account, in scope or not.
    pub async fn load_id(&self, id: Id) -> Result<Option<Account>, ScimError> {
        self.server
            .registry()
            .object::<Account>(id)
            .await
            .map_err(server_error)
    }

    /// Account ids matching `query`, within the caller's tenant.
    pub async fn query_ids(&self, query: RegistryQuery) -> Result<Vec<Id>, ScimError> {
        self.server
            .registry()
            .query::<Vec<Id>>(query.with_tenant(self.tenant_id()))
            .await
            .map_err(server_error)
    }

    /// Accounts of one kind on one domain.
    pub fn accounts_query(kind: ResourceKind) -> RegistryQuery {
        RegistryQuery::new(ObjectType::Account).equal(
            Property::Type,
            match kind {
                ResourceKind::User => registry::schema::enums::AccountType::User,
                ResourceKind::Group => registry::schema::enums::AccountType::Group,
            }
            .to_id(),
        )
    }

    /// An `x:Account/set` as the caller, through the same path JMAP takes,
    /// so every registry check applies. Returns the response as JSON.
    async fn account_set(&self, request: Value) -> Result<Value, ScimError> {
        let text = request.to_string();
        let request = serde_json::from_str::<SetRequest<'_, Registry>>(&text)
            .map_err(|err| server_error(trc::JmapEvent::InvalidArguments.into_err().reason(err)))?;
        let response = self
            .server
            .registry_set(ObjectType::Account, request, self.token, self.session)
            .await
            .map_err(|err| {
                if matches!(
                    err.event_type(),
                    trc::EventType::Jmap(trc::JmapEvent::Forbidden)
                        | trc::EventType::Security(trc::SecurityEvent::Unauthorized)
                ) {
                    ScimError::forbidden(
                        err.value_as_str(trc::Key::Details)
                            .unwrap_or("The request isn't allowed")
                            .to_string(),
                    )
                } else {
                    server_error(err)
                }
            })?;
        serde_json::to_value(&response)
            .map_err(|err| server_error(trc::JmapEvent::InvalidArguments.into_err().reason(err)))
    }

    fn account_id(&self) -> String {
        Id::from(self.token.account_id()).to_string()
    }

    /// Creates an account; the new id, or the registry's refusal.
    pub async fn create(&self, object: Value) -> Result<Id, ScimError> {
        let response = self
            .account_set(json!({
                "accountId": self.account_id(),
                "create": {"scim": object},
            }))
            .await?;
        if let Some(error) = response.pointer("/notCreated/scim") {
            return Err(set_error(error));
        }
        response
            .pointer("/created/scim/id")
            .and_then(Value::as_str)
            .and_then(|id| Id::from_str(id).ok())
            .ok_or_else(|| ScimError::new(500, "The account wasn't created"))
    }

    /// Updates an account with a JMAP patch object.
    pub async fn update(&self, id: Id, patch: Value) -> Result<(), ScimError> {
        let key = id.to_string();
        let response = self
            .account_set(json!({
                "accountId": self.account_id(),
                "update": {key.clone(): patch},
            }))
            .await?;
        match response.get("notUpdated").and_then(|v| v.get(&key)) {
            Some(error) => Err(set_error(error)),
            None => Ok(()),
        }
    }

    /// Destroys an account, the way an administrator's destroy does
    /// (SCIM-52, SCIM-53).
    pub async fn destroy(&self, id: Id) -> Result<(), ScimError> {
        let key = id.to_string();
        let response = self
            .account_set(json!({
                "accountId": self.account_id(),
                "destroy": [key.clone()],
            }))
            .await?;
        match response.get("notDestroyed").and_then(|v| v.get(&key)) {
            Some(error) => Err(set_error(error)),
            None => Ok(()),
        }
    }
}

/// A registry refusal as a SCIM error. Only the description is passed on,
/// never another object's id.
pub fn set_error(error: &Value) -> ScimError {
    let description = error
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let with = |fallback: &str| {
        if description.is_empty() {
            fallback.to_string()
        } else {
            description.clone()
        }
    };
    match error
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "primaryKeyViolation" | "alreadyExists" => {
            ScimError::conflict(with("The address or name is already in use"))
        }
        "forbidden" => ScimError::forbidden(with("The change isn't allowed")),
        // SCIM-20: a tenant limit, named in the description
        "overQuota" => ScimError::forbidden(with("A tenant limit is reached")),
        "notFound" => ScimError::not_found(with("The resource wasn't found")),
        "invalidForeignKey" => ScimError::invalid_value(with(
            "A referenced resource is in a different tenant or doesn't exist",
        )),
        "objectIsLinked" => ScimError::invalid_value(with("Other objects still refer to it")),
        _ => {
            let mut detail = with("The value isn't valid");
            if let Some(errors) = error.get("validationErrors") {
                detail = format!("{detail}: {errors}");
            }
            ScimError::invalid_value(detail)
        }
    }
}
