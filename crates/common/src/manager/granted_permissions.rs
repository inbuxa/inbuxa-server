/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Permissions the fork adds after an install's roles were stored. A new
//! install's roles take them from `DefaultPermissions`; an older install's
//! administrator roles were written once, before the permission existed, so
//! each is added to them here, once. An operator who takes one away later
//! keeps it away: the grant is recorded and never repeated.

use registry::schema::{
    enums::Permission,
    prelude::ObjectType,
    structs::{Authentication, Role},
};
use registry::types::EnumImpl;
use registry::types::id::ObjectId;
use store::{
    SUBSPACE_INBUXA, ValueKey,
    registry::{
        bootstrap::Bootstrap,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::id::Id;

/// Granted to the default administrator roles: "Explain this"
/// (ai-explain spec, EX-4: superuser by default), and the audit log
/// (audit-hold-lock spec, AU-9).
const ADMIN_GRANTS: &[Permission] = &[
    Permission::SysAiExplain,
    Permission::SysAuditGet,
    Permission::SysAuditExport,
    Permission::SysAuditSettingsUpdate,
    Permission::SysAccountLockGet,
    Permission::SysAccountLockCreate,
    Permission::SysAccountLockUpdate,
    Permission::SysAccountLockDestroy,
];

/// Granted to the default tenant administrator roles: reading and exporting
/// the tenant's audit log (AU-9), and locking and delegating its accounts
/// (AL-12).
const TENANT_GRANTS: &[Permission] = &[
    Permission::SysAuditGet,
    Permission::SysAuditExport,
    Permission::SysAccountLockGet,
    Permission::SysAccountLockCreate,
    Permission::SysAccountLockUpdate,
    Permission::SysAccountLockDestroy,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Audience {
    Admin,
    Tenant,
}

fn granted_key(permission: Permission, audience: Audience) -> ValueClass {
    let mut key = b"Pg".to_vec();
    // Admin grants keep the key they were first recorded under
    if audience == Audience::Tenant {
        key.extend_from_slice(b"tenant:");
    }
    key.extend_from_slice(permission.as_str().as_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

pub(crate) async fn grant_new_admin_permissions(bp: &mut Bootstrap) -> trc::Result<()> {
    grant(bp, Audience::Admin, ADMIN_GRANTS).await?;
    grant(bp, Audience::Tenant, TENANT_GRANTS).await
}

async fn grant(bp: &mut Bootstrap, audience: Audience, grants: &[Permission]) -> trc::Result<()> {
    let mut pending = Vec::new();
    for permission in grants {
        if bp
            .data_store
            .get_value::<String>(ValueKey::from(granted_key(*permission, audience)))
            .await
            .caused_by(trc::location!())?
            .is_none()
        {
            pending.push(*permission);
        }
    }
    if pending.is_empty() {
        return Ok(());
    }
    // An administrator's default roles include the plain User role, which
    // every user also holds; only roles that are the audience's alone get it
    let admin_roles: Vec<Id> = bp
        .registry
        .object::<Authentication>(Id::singleton())
        .await?
        .map(|auth| {
            let (own, shared) = match audience {
                Audience::Admin => (
                    auth.default_admin_role_ids.as_slice(),
                    [
                        auth.default_user_role_ids.as_slice(),
                        auth.default_group_role_ids.as_slice(),
                        auth.default_tenant_role_ids.as_slice(),
                    ]
                    .concat(),
                ),
                Audience::Tenant => (
                    auth.default_tenant_role_ids.as_slice(),
                    [
                        auth.default_user_role_ids.as_slice(),
                        auth.default_group_role_ids.as_slice(),
                        auth.default_admin_role_ids.as_slice(),
                    ]
                    .concat(),
                ),
            };
            own.iter()
                .filter(|id| !shared.contains(id))
                .copied()
                .collect()
        })
        .unwrap_or_default();
    // Fetched by id: the registry's listing doesn't reach stored roles
    for role_id in admin_roles {
        let Some(stored) = bp
            .registry
            .get(ObjectId::new(ObjectType::Role, role_id))
            .await?
        else {
            continue;
        };
        let role = Role::from(stored.clone());
        let mut updated = role.clone();
        for permission in &pending {
            // A role that disables it outright keeps it disabled
            if !updated.enabled_permissions.as_slice().contains(permission)
                && !updated.disabled_permissions.as_slice().contains(permission)
            {
                updated.enabled_permissions.push(*permission);
            }
        }
        if updated == role {
            continue;
        }
        let result = bp
            .registry
            .write(RegistryWrite::update(role_id, &updated.into(), &stored))
            .await?;
        if !matches!(result, RegistryWriteResult::Success(_)) {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to add a new permission to an administrator role.")
                .reason(result.to_string())
                .caused_by(trc::location!()));
        }
    }
    let mut batch = BatchBuilder::new();
    for permission in pending {
        batch.set(granted_key(permission, audience), b"granted".to_vec());
    }
    bp.data_store
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}
