/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The compliance roles (personal-data catalog spec, §7; settled
//! 2026-09-28): a server-level Compliance Officer, and one Compliance
//! Officer role in each tenant. A tenant's accounts can hold only roles of
//! their own tenant (MT-3), so the tenant role is made per tenant: once for
//! each tenant a server already has, and whenever a tenant is created.
//!
//! Each creation is recorded under `P` `c` in the fork's subspace, so a
//! role an administrator deletes stays deleted. A tenant's role, while
//! nobody holds it, is removed with the tenant so it doesn't block the
//! delete.
//!
//! Both read what compliance work needs and change no server setting. The
//! server-level officer also places, widens, releases and exports legal
//! holds: that is the job, and each is audited with its reason. A tenant's
//! role has no holds, which are server-level only (LH-13), and the tenant
//! ceiling keeps it within the tenant. Each role carries a user's own
//! permissions too (signing in, mail), since roles given to a person replace
//! the default user role, and a tenant's accounts can't hold the
//! server-level User role.

use registry::schema::{
    enums::Permission,
    prelude::ObjectType,
    structs::{Role, Tenant},
};
use registry::types::map::Map;
use store::{
    RegistryStore, SUBSPACE_INBUXA, Store, ValueKey,
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::id::Id;

/// The role's name, in the server's roles and in each tenant's.
pub const NAME: &str = "Compliance Officer";

/// Reading who and what records refer to, for both roles.
const READS: &[Permission] = &[
    Permission::SysAccountGet,
    Permission::SysAccountQuery,
    Permission::SysMailingListGet,
    Permission::SysMailingListQuery,
    Permission::SysDomainGet,
    Permission::SysDomainQuery,
    Permission::SysTenantGet,
    Permission::SysTenantQuery,
    Permission::SysRoleGet,
    Permission::SysRoleQuery,
];

/// What the server-level officer holds besides [`READS`].
const OFFICER: &[Permission] = &[
    Permission::SysComplianceGet,
    Permission::SysAuditGet,
    Permission::SysAuditExport,
    Permission::SysLegalHoldGet,
    Permission::SysLegalHoldCreate,
    Permission::SysLegalHoldUpdate,
    Permission::SysLegalHoldExport,
    Permission::SysAccountLockGet,
    // dlp-and-mail-flow-rules spec, §2.8: see DLP rules, review held mail
    Permission::SysDlpPolicyGet,
    Permission::SysDlpReviewGet,
    Permission::SysDlpReviewUpdate,
];

/// What a tenant's officer holds besides [`READS`].
const TENANT_OFFICER: &[Permission] = &[
    Permission::SysComplianceGet,
    Permission::SysAuditGet,
    Permission::SysAuditExport,
    Permission::SysAccountLockGet,
];

fn role(own: &[Permission], tenant: Option<Id>) -> Role {
    let mut permissions = crate::auth::permissions::DefaultPermissions::default().user;
    for permission in own.iter().chain(READS) {
        if !permissions.contains(permission) {
            permissions.push(*permission);
        }
    }
    Role {
        description: NAME.into(),
        enabled_permissions: Map::new(permissions),
        member_tenant_id: tenant,
        ..Default::default()
    }
}

/// The server-level Compliance Officer role.
pub fn officer_role() -> Role {
    role(OFFICER, None)
}

/// A tenant's Compliance Officer role.
pub fn tenant_role(tenant: Id) -> Role {
    role(TENANT_OFFICER, Some(tenant))
}

/// Where a creation is recorded: the server's role, or a tenant's. The value
/// is the role's id.
fn created_key(tenant: Option<Id>) -> ValueClass {
    let mut key = b"Pc".to_vec();
    if let Some(tenant) = tenant {
        key.extend_from_slice(&tenant.id().to_be_bytes());
    }
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

/// The server-level Compliance Officer role the server made, if it has.
pub async fn server_role(data: &Store) -> trc::Result<Option<Id>> {
    recorded(data, None).await
}

async fn recorded(data: &Store, tenant: Option<Id>) -> trc::Result<Option<Id>> {
    Ok(data
        .get_value::<u64>(ValueKey::from(created_key(tenant)))
        .await
        .caused_by(trc::location!())?
        .map(Id::from))
}

async fn record(data: &Store, tenant: Option<Id>, role: Option<Id>) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    match role {
        Some(role) => batch.set(created_key(tenant), role.id().to_be_bytes().to_vec()),
        None => batch.clear(created_key(tenant)),
    };
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// Creates a role, unless one was created for this place before, and records
/// it. Returns the new role's id.
async fn create_once(
    registry: &RegistryStore,
    data: &Store,
    tenant: Option<Id>,
    role: Role,
) -> trc::Result<Option<Id>> {
    if recorded(data, tenant).await?.is_some() {
        return Ok(None);
    }
    match registry.write(RegistryWrite::insert(&role.into())).await? {
        RegistryWriteResult::Success(id) => {
            record(data, tenant, Some(id)).await?;
            Ok(Some(id))
        }
        err => {
            trc::error!(
                trc::EventType::Registry(trc::RegistryEvent::ValidationError)
                    .into_err()
                    .details(format!("Failed to create the {NAME} role: {err}"))
            );
            Ok(None)
        }
    }
}

/// Once per server: the officer role, and one in each tenant it already has.
pub async fn ensure_compliance_roles(registry: &RegistryStore, data: &Store) -> trc::Result<()> {
    create_once(registry, data, None, officer_role()).await?;
    for tenant in registry.list::<Tenant>().await? {
        let tenant = Id::from(tenant.id.id());
        create_once(registry, data, Some(tenant), tenant_role(tenant)).await?;
    }
    Ok(())
}

/// A new tenant gets its Compliance Officer role.
pub async fn tenant_created(registry: &RegistryStore, data: &Store, tenant: Id) -> trc::Result<()> {
    create_once(registry, data, Some(tenant), tenant_role(tenant))
        .await
        .map(|_| ())
}

/// Before a tenant is deleted: removes its Compliance Officer role if nobody
/// holds it, so the role doesn't block the delete. Returns whether it did,
/// so a delete refused for another reason can put it back.
pub async fn tenant_deleting(
    registry: &RegistryStore,
    data: &Store,
    tenant: Id,
) -> trc::Result<bool> {
    let Some(role) = recorded(data, Some(tenant)).await? else {
        return Ok(false);
    };
    match registry
        .write(RegistryWrite::delete(ObjectType::Role.id(role)))
        .await?
    {
        RegistryWriteResult::Success(_) | RegistryWriteResult::NotFound { .. } => {
            record(data, Some(tenant), None).await?;
            Ok(true)
        }
        // Held by someone: the tenant's delete is refused for that anyway
        _ => Ok(false),
    }
}

/// A tenant's delete was refused after its role went: the role comes back.
pub async fn tenant_kept(registry: &RegistryStore, data: &Store, tenant: Id) -> trc::Result<()> {
    tenant_created(registry, data, tenant).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry::types::EnumImpl;

    fn permissions(role: &Role) -> Vec<Permission> {
        role.enabled_permissions.iter().copied().collect()
    }

    #[test]
    fn neither_role_changes_a_setting() {
        let user = crate::auth::permissions::DefaultPermissions::default().user;
        for role in [officer_role(), tenant_role(Id::from(7u64))] {
            let all = permissions(&role);
            for permission in user.iter() {
                assert!(all.contains(permission), "a user's own {permission:?}");
            }
            // Beyond what any user holds for their own account
            for permission in all.into_iter().filter(|p| !user.contains(p)) {
                let name = permission.as_str();
                // Placing holds and reviewing held mail are the officer's
                // job, not settings (settled answers 2 and 4)
                let holds = name.starts_with("sysLegalHold") || name.starts_with("sysDlpReview");
                assert!(
                    !(name.ends_with("Update") && !holds)
                        && !(name.ends_with("Create") && !holds)
                        && !name.ends_with("Destroy")
                        && permission != Permission::Impersonate
                        && permission != Permission::FetchAnyBlob,
                    "{} holds {name}",
                    role.description
                );
            }
        }
    }

    #[test]
    fn the_officer_places_and_releases_holds_a_tenants_does_not() {
        let officer = permissions(&officer_role());
        let tenant = tenant_role(Id::from(7u64));
        assert_eq!(tenant.member_tenant_id, Some(Id::from(7u64)));
        let tenant = permissions(&tenant);
        for hold in [
            Permission::SysLegalHoldGet,
            Permission::SysLegalHoldCreate,
            Permission::SysLegalHoldUpdate,
            Permission::SysLegalHoldExport,
        ] {
            assert!(officer.contains(&hold));
            assert!(!tenant.contains(&hold));
        }
        for both in [
            Permission::SysComplianceGet,
            Permission::SysAuditGet,
            Permission::SysAccountGet,
        ] {
            assert!(officer.contains(&both) && tenant.contains(&both));
        }
        assert!(!officer.contains(&Permission::SysAuditSettingsUpdate));
    }

    #[test]
    fn records_are_per_place() {
        let ValueClass::Any(server) = created_key(None) else {
            panic!()
        };
        let ValueClass::Any(a) = created_key(Some(Id::from(1u64))) else {
            panic!()
        };
        let ValueClass::Any(b) = created_key(Some(Id::from(2u64))) else {
            panic!()
        };
        assert_eq!(server.key, b"Pc");
        assert_ne!(a.key, b.key);
        assert!(a.key.starts_with(b"Pc"));
    }
}
