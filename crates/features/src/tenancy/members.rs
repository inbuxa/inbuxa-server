/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Who a change to a tenant affects (MT-16).
//!
//! A principal's permissions are cached. A change to its tenant's roles,
//! permissions or quotas has to reach it on its next request, so the cached
//! permissions of everyone in the tenant are dropped with the change.

use registry::{
    schema::{
        prelude::ObjectType,
        structs::{Roles, Tenant},
    },
    types::id::ObjectId,
};
use store::{RegistryStore, registry::RegistryQuery};
use trc::AddContext;
use types::id::Id;

/// The accounts that belong to a tenant.
pub async fn accounts(registry: &RegistryStore, tenant_id: u32) -> trc::Result<Vec<u32>> {
    registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Account).with_tenant(Some(tenant_id)))
        .await
        .map(|ids| ids.into_iter().map(|id| id.document_id()).collect())
        .caused_by(trc::location!())
}

/// The tenants whose ceiling a role takes part in, given the objects that
/// link to the role. A tenant names the role itself when its roles are
/// `Custom`; `Authentication` names it for every tenant whose roles are
/// `Default`.
pub async fn tenants_using_role(
    registry: &RegistryStore,
    linked: &[ObjectId],
) -> trc::Result<Vec<u32>> {
    let mut tenants = Vec::new();
    let mut by_default = false;

    for object_id in linked {
        match object_id.object() {
            ObjectType::Tenant => tenants.push(object_id.id().document_id()),
            ObjectType::Authentication => by_default = true,
            _ => {}
        }
    }

    if by_default {
        for id in registry
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Tenant))
            .await
            .caused_by(trc::location!())?
        {
            if let Some(tenant) = registry.object::<Tenant>(id).await?
                && matches!(tenant.roles, Roles::Default)
                && !tenants.contains(&id.document_id())
            {
                tenants.push(id.document_id());
            }
        }
    }

    Ok(tenants)
}
