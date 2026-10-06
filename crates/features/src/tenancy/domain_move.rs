/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Moving a domain into or out of a tenant (MT-8, MT-17).
//!
//! A domain moves into a tenant only from no tenant, and out of one only back
//! to no tenant. Moving in, its principals (accounts, groups, mailing lists)
//! and DKIM keys move with it, after the tenant's limits are checked. Moving
//! out is refused while any principal on it is in the tenant; with none, its
//! DKIM keys move out with it. A principal on it in a third tenant blocks
//! either move, and so does any link the move would carry across a tenant
//! boundary (MT-3).

use crate::tenancy::{
    links,
    quota::{self, LimitReached},
};
use ahash::{AHashMap, AHashSet};
use registry::{
    schema::{
        enums::TenantStorageQuota,
        prelude::{OBJ_FILTER_TENANT, Object, ObjectInner, ObjectType},
        structs::{Account, DkimSignature},
    },
    types::id::ObjectId,
};
use store::{
    RegistryStore,
    registry::write::{RegistryWrite, RegistryWriteResult},
};
use types::id::Id;

/// Why a domain can't move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Straight from one tenant to another.
    Across,
    /// Principals on the domain belong somewhere other than the destination.
    PrincipalsRemain { example: ObjectId, count: usize },
    /// The move would leave this object linked across a tenant boundary.
    ForeignLink(ObjectId),
    /// The destination tenant's limit would be crossed.
    Limit(LimitReached),
}

/// A move that passed every check, ready to apply once the domain itself is
/// saved.
#[derive(Debug, Clone, Default)]
pub struct Move {
    /// The domain's new tenant.
    pub to: Option<Id>,
    /// The principals and keys that move with the domain.
    pub carried: Vec<ObjectId>,
}

/// Whether a type moves with its domain.
fn moves_with_domain(object_type: ObjectType) -> bool {
    matches!(
        object_type,
        ObjectType::Account | ObjectType::MailingList | ObjectType::DkimSignature
    )
}

/// Checks a domain's move from `from` to `to` (MT-8), counting what moves
/// with it against the destination's limits (MT-17). `limit` gives the
/// destination's limit for each kind, `None` for no limit.
pub async fn plan(
    registry: &RegistryStore,
    domain_id: Id,
    from: Option<Id>,
    to: Option<Id>,
    limit: impl Fn(TenantStorageQuota) -> Option<u64>,
) -> trc::Result<Result<Move, Refusal>> {
    let domain = ObjectId::new(ObjectType::Domain, domain_id);
    if from == to {
        return Ok(Ok(Move {
            to,
            carried: vec![],
        }));
    }
    if from.is_some() && to.is_some() {
        return Ok(Err(Refusal::Across));
    }

    // Sort out what links to the domain
    let mut carried = Vec::new();
    let mut adding: AHashMap<TenantStorageQuota, u64> = AHashMap::new();
    let mut blocking = Vec::new();
    let mut seen = AHashSet::new();
    for referrer in registry.linked_objects(domain).await? {
        let object_type = referrer.object();
        // An account links to its domain once more for each alias on it
        if object_type.flags() & OBJ_FILTER_TENANT == 0 || !seen.insert(referrer) {
            continue;
        }
        let Some(object) = registry.get(referrer).await? else {
            continue;
        };
        let tenant = object.inner.member_tenant_id();
        if tenant == to {
            continue;
        }

        if moves_with_domain(object_type) && tenant == from {
            let is_principal = object_type != ObjectType::DkimSignature;
            if to.is_none() && is_principal {
                // Moving out: the tenant's people stay, so the domain can't go
                blocking.push(referrer);
            } else {
                let kind = match &object.inner {
                    ObjectInner::Account(Account::Group(_)) => Some(1),
                    _ => None,
                };
                if let Some(quota) = quota::limit_for_id(referrer, kind) {
                    *adding.entry(quota).or_default() += 1;
                }
                carried.push(referrer);
            }
        } else if moves_with_domain(object_type) && object_type != ObjectType::DkimSignature {
            // A principal in a third tenant
            blocking.push(referrer);
        } else {
            return Ok(Err(Refusal::ForeignLink(referrer)));
        }
    }
    if let Some(example) = blocking.first() {
        return Ok(Err(Refusal::PrincipalsRemain {
            example: *example,
            count: blocking.len(),
        }));
    }

    // Nothing may be left linked across the boundary
    let moving = carried
        .iter()
        .copied()
        .chain([domain])
        .collect::<AHashSet<_>>();
    for object_id in &carried {
        if let Some(object) = registry.get(*object_id).await?
            && let Some(foreign) = links::foreign_link(registry, &object, to, None, &moving).await?
        {
            return Ok(Err(Refusal::ForeignLink(foreign)));
        }
        if let Some(foreign) = links::foreign_referrer(registry, *object_id, to, &moving).await? {
            return Ok(Err(Refusal::ForeignLink(foreign)));
        }
    }

    // The destination's limits, the domain itself included
    if let Some(tenant_id) = to {
        *adding.entry(TenantStorageQuota::MaxDomains).or_default() += 1;
        let mut quotas = adding.into_iter().collect::<Vec<_>>();
        quotas.sort_unstable_by_key(|(quota, _)| *quota as u16);
        for (quota, count) in quotas {
            if let Err(reached) = quota::check(
                registry,
                tenant_id.document_id(),
                quota,
                limit(quota),
                count,
            )
            .await?
            {
                return Ok(Err(Refusal::Limit(reached)));
            }
        }
    }

    Ok(Ok(Move { to, carried }))
}

/// Moves what travels with a domain into its new tenant, once the domain is
/// saved. Returns each object changed, as it was and as it is now, for cache
/// invalidation. An object that changed or vanished since `plan` is skipped.
pub async fn apply(
    registry: &RegistryStore,
    planned: &Move,
) -> trc::Result<Vec<(Id, Object, Object)>> {
    let mut changed = Vec::with_capacity(planned.carried.len());
    for object_id in &planned.carried {
        let Some(old) = registry.get(*object_id).await? else {
            continue;
        };
        let mut new = old.clone();
        set_tenant(&mut new.inner, planned.to);
        if new.inner == old.inner {
            continue;
        }
        if let RegistryWriteResult::Success(_) = registry
            .write(RegistryWrite::update(object_id.id(), &new, &old))
            .await?
        {
            changed.push((object_id.id(), old, new));
        }
    }
    Ok(changed)
}

/// Sets or clears the tenant of an object that moves with its domain.
fn set_tenant(object: &mut ObjectInner, tenant: Option<Id>) {
    match object {
        ObjectInner::Account(Account::User(obj)) => obj.member_tenant_id = tenant,
        ObjectInner::Account(Account::Group(obj)) => obj.member_tenant_id = tenant,
        ObjectInner::MailingList(obj) => obj.member_tenant_id = tenant,
        ObjectInner::DkimSignature(DkimSignature::Dkim1Ed25519Sha256(obj)) => {
            obj.member_tenant_id = tenant
        }
        ObjectInner::DkimSignature(DkimSignature::Dkim1RsaSha256(obj)) => {
            obj.member_tenant_id = tenant
        }
        ObjectInner::DkimSignature(DkimSignature::Dkim2Ed25519Sha256(obj)) => {
            obj.member_tenant_id = tenant
        }
        ObjectInner::DkimSignature(DkimSignature::Dkim2RsaSha256(obj)) => {
            obj.member_tenant_id = tenant
        }
        _ => {}
    }
}
