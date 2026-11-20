/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Tenancy checks on a registry write over JMAP, before it's saved.
//!
//! - MT-3: no link crosses a tenant boundary.
//! - MT-7: a principal created without a tenant takes its domain's.
//! - MT-8: a domain moves only through no tenant, taking its principals and
//!   keys in with it, and only when its people let it out.
//! - MT-17: creating an object, or moving a domain in, stays within the
//!   tenant's count limits, and the server emits `limit.tenant-quota` when
//!   it doesn't.
//! - An account's disk quota fits within its tenant's (inbuxa-admin#257),
//!   checked by `check_disk_quota` on JMAP and SCIM writes.

use crate::tenancy::{
    domain_move::{self, Move, Refusal},
    links,
    quota::{self, LimitReached},
};
use ahash::AHashSet;
use jmap_proto::error::set::{SetError, SetErrorType};
use registry::{
    schema::{
        enums::{StorageQuota, TenantStorageQuota},
        prelude::{Object, ObjectInner, Property},
        structs::{Account, DkimManagement, Domain, Tenant},
    },
    types::{EnumImpl, id::ObjectId},
};
use store::RegistryStore;
use types::id::Id;

/// What a checked write still has to do once it's saved.
#[derive(Debug, Default)]
pub struct AfterSave {
    /// A domain's move, whose principals and keys follow it (MT-8).
    pub domain_move: Option<Move>,
}

/// The domain a principal lives on.
fn principal_domain(object: &ObjectInner) -> Option<Id> {
    match object {
        ObjectInner::Account(Account::User(obj)) => Some(obj.domain_id),
        ObjectInner::Account(Account::Group(obj)) => Some(obj.domain_id),
        ObjectInner::MailingList(obj) => Some(obj.domain_id),
        _ => None,
    }
}

/// MT-7: a principal created without a tenant takes its domain's. Called
/// only for a server-level writer, since one in a tenant always creates in
/// its own.
pub async fn default_tenant(registry: &RegistryStore, object: &mut Object) -> trc::Result<()> {
    if object.inner.member_tenant_id().is_none()
        && let Some(domain_id) = principal_domain(&object.inner)
        && let Some(domain) = registry.object::<Domain>(domain_id).await?
        && let Some(tenant_id) = domain.member_tenant_id
    {
        object.inner.set_member_tenant_id(tenant_id);
    }
    Ok(())
}

/// An account's own disk quota, `None` when it has none (0 is none too).
fn account_disk_quota(object: &ObjectInner) -> Option<u64> {
    let quotas = match object {
        ObjectInner::Account(Account::User(obj)) => &obj.quotas,
        ObjectInner::Account(Account::Group(obj)) => &obj.quotas,
        _ => return None,
    };
    quotas
        .get(&StorageQuota::MaxDiskQuota)
        .copied()
        .filter(|quota| *quota > 0)
}

/// A tenant's count limit, `None` when it has none.
async fn limits(
    registry: &RegistryStore,
    tenant_id: Id,
) -> trc::Result<impl Fn(TenantStorageQuota) -> Option<u64>> {
    let quotas = registry
        .object::<Tenant>(tenant_id)
        .await?
        .map(|tenant| tenant.quotas)
        .unwrap_or_default();
    Ok(move |quota: TenantStorageQuota| quotas.get(&quota).copied())
}

/// Runs the tenancy checks on a write. `id` and `old` are the stored object
/// on an update, `None` on a create.
pub async fn check(
    registry: &RegistryStore,
    id: Option<Id>,
    old: Option<&Object>,
    new: &Object,
) -> trc::Result<Result<AfterSave, SetError<Property>>> {
    let tenant = new.inner.member_tenant_id();
    let mut after = AfterSave::default();

    // MT-8: a domain changing tenant
    if let (Some(id), Some(old), ObjectInner::Domain(_)) = (id, old, &new.inner)
        && old.inner.member_tenant_id() != tenant
    {
        let limit = match tenant {
            Some(tenant_id) => Some(limits(registry, tenant_id).await?),
            None => None,
        };
        let planned = domain_move::plan(
            registry,
            id,
            old.inner.member_tenant_id(),
            tenant,
            |quota| limit.as_ref().and_then(|limit| limit(quota)),
        )
        .await?;
        match planned {
            Ok(planned) => after.domain_move = Some(planned),
            Err(refusal) => return Ok(Err(refused_move(refusal, tenant))),
        }
    }

    // MT-3: no link across a tenant boundary
    if let Some(foreign) = links::foreign_link(registry, new, tenant, old, &AHashSet::new()).await?
    {
        return Ok(Err(foreign_key(foreign)));
    }

    // MT-17: count limits on a new object
    if old.is_none()
        && let Some(tenant_id) = tenant
        && let Some(quota) = quota::limit_for(&new.inner)
    {
        let limit = limits(registry, tenant_id).await?;
        if let Err(reached) =
            quota::check(registry, tenant_id.document_id(), quota, limit(quota), 1).await?
        {
            return Ok(Err(over_quota(reached, tenant_id)));
        }

        // A new domain's generated DKIM keys, one per algorithm, count too (MT-9)
        if let ObjectInner::Domain(Domain {
            dkim_management: DkimManagement::Automatic(dkim),
            ..
        }) = &new.inner
        {
            let quota = TenantStorageQuota::MaxDkimKeys;
            let keys = dkim.algorithms.iter().count() as u64;
            if let Err(reached) =
                quota::check(registry, tenant_id.document_id(), quota, limit(quota), keys).await?
            {
                return Ok(Err(over_quota(reached, tenant_id)));
            }
        }
    }

    Ok(Ok(after))
}

/// inbuxa-admin#257: an account's disk quota fits within its tenant's, so no
/// member gets more space than the whole tenant has. Run on a JMAP or SCIM
/// write, after `check`. Checked when the quota is set or changed, or the
/// account changes tenant; an account already over a lowered tenant limit
/// keeps its quota until someone changes it, like the count limits (MT-18).
/// No quota at all is fine: the account shares the tenant's space. Not run
/// for accounts a directory creates at sign-in or for a restored account,
/// which would otherwise be refused for a setting nobody can edit first.
pub async fn check_disk_quota(
    registry: &RegistryStore,
    old: Option<&Object>,
    new: &Object,
) -> trc::Result<Result<(), SetError<Property>>> {
    let tenant = new.inner.member_tenant_id();
    if let Some(tenant_id) = tenant
        && let Some(quota) = account_disk_quota(&new.inner)
        && old.is_none_or(|old| {
            account_disk_quota(&old.inner) != Some(quota) || old.inner.member_tenant_id() != tenant
        })
        && let Some(tenant_quota) =
            (limits(registry, tenant_id).await?)(TenantStorageQuota::MaxDiskQuota)
                .filter(|limit| *limit > 0)
        && quota > tenant_quota
    {
        return Ok(Err(over_tenant_disk_quota(quota, tenant_quota)));
    }
    Ok(Ok(()))
}

/// Finishes a checked write once it's saved. Returns each other object it
/// changed, as it was and as it is now, for cache invalidation.
pub async fn after_save(
    data: &store::Store,
    registry: &RegistryStore,
    after: AfterSave,
) -> trc::Result<Vec<(Id, Object, Object)>> {
    let Some(planned) = after.domain_move else {
        return Ok(vec![]);
    };
    let changed = domain_move::apply(registry, &planned).await?;

    // MT-20: the members who moved in bring their usage with them
    if let Some(tenant_id) = planned.to
        && !changed.is_empty()
    {
        quota::recalculate(data, registry, tenant_id.document_id()).await?;
    }

    Ok(changed)
}

fn foreign_key(object_id: ObjectId) -> SetError<Property> {
    SetError::new(SetErrorType::InvalidForeignKey)
        .with_object_id(object_id)
        .with_description(format!(
            "{} {} belongs to a different tenant.",
            object_id.object().as_str(),
            object_id.id()
        ))
}

/// Refuses with `overQuota`, naming the limit, and emits
/// `limit.tenant-quota` (MT-17).
fn over_quota(reached: LimitReached, tenant_id: Id) -> SetError<Property> {
    let name = reached.quota.as_str();
    trc::event!(
        Limit(trc::LimitEvent::TenantQuota),
        Id = tenant_id.document_id(),
        Limit = reached.limit,
        Total = reached.count,
        Details = name,
    );

    SetError::new(SetErrorType::OverQuota).with_description(format!(
        "The tenant's {name} limit of {} is reached.",
        reached.limit
    ))
}

/// Refuses an account disk quota bigger than its tenant's (inbuxa-admin#257).
fn over_tenant_disk_quota(quota: u64, tenant_quota: u64) -> SetError<Property> {
    SetError::invalid_properties()
        .with_property(Property::Quotas)
        .with_description(format!(
            "The account's disk quota of {quota} bytes ({}) is more than its tenant's \
             maxDiskQuota of {tenant_quota} bytes ({}). Set it to {tenant_quota} or less, \
             or leave it empty to share the tenant's space.",
            readable_size(quota),
            readable_size(tenant_quota),
        ))
}

/// A byte count in binary units, for people reading an error: "50 GiB".
fn readable_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 || value.fract() == 0.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod disk_quota_tests {
    use super::*;

    #[test]
    fn readable_sizes() {
        assert_eq!(readable_size(512), "512 bytes");
        assert_eq!(readable_size(5 * 1024 * 1024 * 1024), "5 GiB");
        assert_eq!(readable_size(1536 * 1024 * 1024), "1.5 GiB");
    }

    #[test]
    fn zero_quota_is_no_quota() {
        let user = |quota: u64| {
            ObjectInner::Account(Account::User(registry::schema::structs::UserAccount {
                quotas: [(StorageQuota::MaxDiskQuota, quota)].into_iter().collect(),
                ..Default::default()
            }))
        };
        assert_eq!(account_disk_quota(&user(0)), None);
        assert_eq!(account_disk_quota(&user(10)), Some(10));
    }
}

fn refused_move(refusal: Refusal, tenant: Option<Id>) -> SetError<Property> {
    match refusal {
        Refusal::Across => SetError::invalid_properties()
            .with_property(Property::MemberTenantId)
            .with_description(
                "A domain moves between tenants only by leaving one for no tenant first.",
            ),
        Refusal::PrincipalsRemain { example, count } => SetError::invalid_properties()
            .with_property(Property::MemberTenantId)
            .with_object_id(example)
            .with_description(format!(
                "{count} principal(s) on this domain belong to a tenant it would leave."
            )),
        Refusal::ForeignLink(object_id) => foreign_key(object_id),
        Refusal::Limit(reached) => over_quota(reached, tenant.unwrap_or_default()),
    }
}
