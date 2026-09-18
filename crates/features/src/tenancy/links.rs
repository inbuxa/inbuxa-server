/*
 * SPDX-FileCopyrightText: 2026 John Coffey
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Links between objects never cross a tenant boundary (MT-3).
//!
//! The registry store already refuses a link from an object in a tenant to
//! one outside it. This covers the other direction, a link from an object in
//! no tenant to one inside a tenant, which MT-3 counts as a different tenant
//! too. It also re-checks every link, not only new ones, when an object's
//! tenant changes, since a move can strand links that were fine before.

use ahash::AHashSet;
use registry::{
    schema::prelude::{OBJ_FILTER_TENANT, Object, ObjectType},
    types::{
        id::ObjectId,
        index::{IndexBuilder, IndexKey},
    },
};
use store::RegistryStore;
use types::id::Id;

/// Whether an object of this type can hold links that MT-3 governs: every
/// type that can belong to a tenant, plus the two server-level objects that
/// name roles for tenants.
fn is_governed(object_type: ObjectType) -> bool {
    object_type.flags() & OBJ_FILTER_TENANT != 0
        || matches!(object_type, ObjectType::Tenant | ObjectType::Authentication)
}

/// The objects this object links to that can belong to a tenant.
pub fn tenant_links(object: &Object) -> Vec<ObjectId> {
    let mut index = IndexBuilder::default();
    object.index(&mut index);
    index
        .keys
        .iter()
        .filter_map(|key| match key {
            IndexKey::ForeignKey { object_id, .. }
                if object_id.object().flags() & OBJ_FILTER_TENANT != 0 =>
            {
                Some(*object_id)
            }
            _ => None,
        })
        .collect()
}

/// Finds a link from `object` to an object in a different tenant, "no
/// tenant" included (MT-3), and returns the object it can't link to.
///
/// `tenant` is the tenant `object` will belong to. On an update, `old` is the
/// object as stored: links it already had are checked again only if the
/// tenant changes. Links to objects in `moving` are skipped, because those
/// objects are moving into `tenant` together with this one (MT-8).
pub async fn foreign_link(
    registry: &RegistryStore,
    object: &Object,
    tenant: Option<Id>,
    old: Option<&Object>,
    moving: &AHashSet<ObjectId>,
) -> trc::Result<Option<ObjectId>> {
    if !is_governed(object.object_type()) {
        return Ok(None);
    }

    let existing = match old {
        Some(old) if old.inner.member_tenant_id() == tenant => tenant_links(old),
        _ => Vec::new(),
    };

    for target in tenant_links(object) {
        if existing.contains(&target) || moving.contains(&target) {
            continue;
        }
        // A missing target is left to the store, which names it as an
        // invalid foreign key in the same way.
        if let Some(linked) = registry.get(target).await?
            && linked.inner.member_tenant_id() != tenant
        {
            return Ok(Some(target));
        }
    }

    Ok(None)
}

/// Finds an object outside `moving` that links to `object_id` from a tenant
/// other than `tenant` (MT-3, MT-8). Used before `object_id` moves into
/// `tenant`, since the link would then cross a tenant boundary.
pub async fn foreign_referrer(
    registry: &RegistryStore,
    object_id: ObjectId,
    tenant: Option<Id>,
    moving: &AHashSet<ObjectId>,
) -> trc::Result<Option<ObjectId>> {
    for referrer in registry.linked_objects(object_id).await? {
        if moving.contains(&referrer) || !is_governed(referrer.object()) {
            continue;
        }
        if let Some(object) = registry.get(referrer).await?
            && object.inner.member_tenant_id() != tenant
        {
            return Ok(Some(referrer));
        }
    }

    Ok(None)
}
