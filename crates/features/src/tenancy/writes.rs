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
//! - A tenant's accounts' disk quotas add up to no more than the tenant's
//!   (inbuxa-admin#257), checked by `check_disk_quota` on JMAP and SCIM
//!   writes and on a restore, and by the domain-move plan. A write that
//!   could grow the total holds the tenant's disk-quota lock
//!   (`disk_quota_tenant`) from the check until it's saved.

use crate::tenancy::{
    domain_move::{self, Move, Refusal},
    links,
    quota::{self, LimitReached, account_disk_quota},
};
use ahash::AHashSet;
use jmap_proto::error::set::{SetError, SetErrorType};
use registry::{
    schema::{
        enums::TenantStorageQuota,
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

/// The tenant whose allocated disk space this write could grow, if any
/// (inbuxa-admin#257): an account given a disk quota, or a bigger one, or
/// joining a tenant with one; or a domain moving into a tenant, which brings
/// its accounts. Such a write takes the tenant's disk-quota lock before its
/// checks and keeps it until it's saved, so two writes at once can't each
/// fit the space left and together pass it. Lowering or clearing a quota,
/// or any other change, needs no lock.
pub fn disk_quota_tenant(old: Option<&Object>, new: &Object) -> Option<Id> {
    let tenant = new.inner.member_tenant_id()?;
    let moved_in = old.is_none_or(|old| old.inner.member_tenant_id() != Some(tenant));
    match &new.inner {
        ObjectInner::Account(_) => {
            let quota = account_disk_quota(&new.inner)?;
            let grows = moved_in
                || old.is_some_and(|old| {
                    account_disk_quota(&old.inner).is_none_or(|before| quota > before)
                });
            grows.then_some(tenant)
        }
        ObjectInner::Domain(_) if old.is_some() && moved_in => Some(tenant),
        _ => None,
    }
}

/// inbuxa-admin#257: a tenant's accounts' disk quotas add up to no more than
/// the tenant's own, so it can't give out more space than it has, in one
/// account or across many. Run on a JMAP or SCIM write and on a restore,
/// after `check`, holding the lock `disk_quota_tenant` names. `id` is the
/// account on an update; `restoring` words the refusal for a restore,
/// whose quota can't be edited first. Only a write that grows the total is checked, so a
/// tenant already over a lowered limit can still edit its accounts and
/// lower their quotas, like the count limits (MT-18). No quota at all is
/// fine: the account shares what's left of the tenant's space. Not run for
/// accounts a directory creates at sign-in, which never carry a quota.
pub async fn check_disk_quota(
    registry: &RegistryStore,
    id: Option<Id>,
    old: Option<&Object>,
    new: &Object,
    restoring: bool,
) -> trc::Result<Result<(), SetError<Property>>> {
    if let ObjectInner::Account(_) = &new.inner
        && let Some(tenant_id) = disk_quota_tenant(old, new)
        && let Some(quota) = account_disk_quota(&new.inner)
        && let Some(tenant_quota) =
            (limits(registry, tenant_id).await?)(TenantStorageQuota::MaxDiskQuota)
                .filter(|limit| *limit > 0)
    {
        let except = id.into_iter().collect::<AHashSet<_>>();
        let others = quota::allocated_disk(registry, tenant_id.document_id(), &except).await?;
        if others.saturating_add(quota) > tenant_quota {
            return Ok(Err(over_tenant_disk_quota(
                quota,
                others,
                tenant_quota,
                restoring,
            )));
        }
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

/// Refuses an account disk quota that doesn't fit in what its tenant has
/// left to give (inbuxa-admin#257).
fn over_tenant_disk_quota(
    quota: u64,
    others: u64,
    tenant_quota: u64,
    restoring: bool,
) -> SetError<Property> {
    SetError::invalid_properties()
        .with_property(Property::Quotas)
        .with_description(disk_quota_message(quota, others, tenant_quota, restoring))
}

/// Why a disk quota doesn't fit: the tenant's limit, what its other
/// accounts already have, and what's left.
fn disk_quota_message(quota: u64, others: u64, tenant_quota: u64, restoring: bool) -> String {
    let left = tenant_quota.saturating_sub(others);
    let given = if others > 0 {
        format!(
            " Its other accounts already have {others} bytes ({}) of it, so {left} bytes ({}) \
             is left to give.",
            readable_size(others),
            readable_size(left),
        )
    } else {
        String::new()
    };
    if restoring {
        return format!(
            "The account's disk quota of {quota} bytes ({}) doesn't fit in its tenant's \
             maxDiskQuota of {tenant_quota} bytes ({}).{given} It comes back with that quota, \
             so lower other accounts' quotas first, then restore it.",
            readable_size(quota),
            readable_size(tenant_quota),
        );
    }
    let fix = if left > 0 {
        format!("Set it to {left} or less, lower another account's,")
    } else {
        "Lower another account's quota,".to_string()
    };
    format!(
        "The account's disk quota of {quota} bytes ({}) doesn't fit in its tenant's \
         maxDiskQuota of {tenant_quota} bytes ({}).{given} {fix} or leave it empty to share \
         the tenant's space.",
        readable_size(quota),
        readable_size(tenant_quota),
    )
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
    use registry::schema::{
        enums::StorageQuota,
        structs::{Domain, UserAccount},
    };

    fn account(tenant: Option<u64>, quota: u64) -> Object {
        Object::from(Account::User(UserAccount {
            member_tenant_id: tenant.map(Id::from),
            quotas: [(StorageQuota::MaxDiskQuota, quota)].into_iter().collect(),
            ..Default::default()
        }))
    }

    fn domain(tenant: Option<u64>) -> Object {
        Object::from(Domain {
            member_tenant_id: tenant.map(Id::from),
            ..Default::default()
        })
    }

    #[test]
    fn writes_that_grow_a_tenants_disk_space_take_its_lock() {
        let tenant = Some(Id::from(7u64));
        // A new account with a quota, and one without
        assert_eq!(disk_quota_tenant(None, &account(Some(7), 10)), tenant);
        assert_eq!(disk_quota_tenant(None, &account(Some(7), 0)), None);
        assert_eq!(disk_quota_tenant(None, &account(None, 10)), None);
        // Raised, set for the first time, lowered, cleared, unchanged
        let old = account(Some(7), 10);
        assert_eq!(disk_quota_tenant(Some(&old), &account(Some(7), 11)), tenant);
        assert_eq!(disk_quota_tenant(Some(&account(Some(7), 0)), &old), tenant);
        assert_eq!(disk_quota_tenant(Some(&old), &account(Some(7), 9)), None);
        assert_eq!(disk_quota_tenant(Some(&old), &account(Some(7), 0)), None);
        assert_eq!(disk_quota_tenant(Some(&old), &old), None);
        // Joining a tenant with a quota, even a smaller one
        assert_eq!(
            disk_quota_tenant(Some(&account(None, 10)), &account(Some(7), 5)),
            tenant
        );
        assert_eq!(
            disk_quota_tenant(Some(&account(Some(8), 10)), &account(Some(7), 5)),
            tenant
        );
        // A domain moving in brings its accounts; a new or staying one doesn't
        assert_eq!(
            disk_quota_tenant(Some(&domain(None)), &domain(Some(7))),
            tenant
        );
        assert_eq!(disk_quota_tenant(None, &domain(Some(7))), None);
        assert_eq!(
            disk_quota_tenant(Some(&domain(Some(7))), &domain(Some(7))),
            None
        );
        assert_eq!(
            disk_quota_tenant(Some(&domain(Some(7))), &domain(None)),
            None
        );
    }

    #[test]
    fn the_refusal_says_what_is_left() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let message = disk_quota_message(5 * GIB, 15 * GIB, 5 * GIB, false);
        assert!(
            message.contains("already have 16106127360 bytes (15 GiB)"),
            "{message}"
        );
        assert!(
            message.contains("so 0 bytes (0 bytes) is left"),
            "{message}"
        );
        assert!(
            message.contains(" Lower another account's quota, or leave"),
            "{message}"
        );
        let message = disk_quota_message(4 * GIB, GIB, 4 * GIB, false);
        assert!(
            message.contains("so 3221225472 bytes (3 GiB) is left"),
            "{message}"
        );
        let message = disk_quota_message(3 * GIB, 4 * GIB, 5 * GIB, true);
        assert!(message.contains("then restore it"), "{message}");
        assert!(!message.contains("Set it to"), "{message}");
        let message = disk_quota_message(6 * GIB, 0, 5 * GIB, false);
        assert!(!message.contains("already have"), "{message}");
        assert!(
            message.contains("Set it to 5368709120 or less"),
            "{message}"
        );
    }

    #[test]
    fn readable_sizes() {
        assert_eq!(readable_size(512), "512 bytes");
        assert_eq!(readable_size(5 * 1024 * 1024 * 1024), "5 GiB");
        assert_eq!(readable_size(1536 * 1024 * 1024), "1.5 GiB");
    }

    #[test]
    fn zero_quota_is_no_quota() {
        let user = |quota: u64| {
            ObjectInner::Account(Account::User(UserAccount {
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
        Refusal::DiskQuota {
            allocated,
            adding,
            limit,
        } => SetError::new(SetErrorType::OverQuota).with_description(format!(
            "The accounts on this domain have {adding} bytes ({}) of disk quota between them, \
             and the tenant has {} ({}) of its maxDiskQuota of {limit} bytes ({}) left to give.",
            readable_size(adding),
            limit.saturating_sub(allocated),
            readable_size(limit.saturating_sub(allocated)),
            readable_size(limit),
        )),
    }
}
