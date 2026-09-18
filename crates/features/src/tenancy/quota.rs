/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Tenant limits: how many of each kind of object a tenant may hold
//! (MT-17, MT-18) and how much storage its members use (MT-20, MT-21).

use registry::{
    schema::{
        enums::TenantStorageQuota,
        prelude::{ObjectInner, ObjectType, Property},
        structs::Account,
    },
    types::id::ObjectId,
};
use store::{
    RegistryStore, Store, ValueKey,
    registry::RegistryQuery,
    write::{BatchBuilder, ValueClass},
};
use trc::AddContext;

use types::id::Id;

/// The count limit that applies to an object, if any (MT-17).
pub fn limit_for(object: &ObjectInner) -> Option<TenantStorageQuota> {
    Some(match object {
        ObjectInner::Account(Account::User(_)) => TenantStorageQuota::MaxAccounts,
        ObjectInner::Account(Account::Group(_)) => TenantStorageQuota::MaxGroups,
        ObjectInner::Domain(_) => TenantStorageQuota::MaxDomains,
        ObjectInner::MailingList(_) => TenantStorageQuota::MaxMailingLists,
        ObjectInner::Role(_) => TenantStorageQuota::MaxRoles,
        ObjectInner::OAuthClient(_) => TenantStorageQuota::MaxOauthClients,
        ObjectInner::DkimSignature(_) => TenantStorageQuota::MaxDkimKeys,
        ObjectInner::DnsServer(_) => TenantStorageQuota::MaxDnsServers,
        ObjectInner::Directory(_) => TenantStorageQuota::MaxDirectories,
        ObjectInner::AcmeProvider(_) => TenantStorageQuota::MaxAcmeProviders,
        _ => return None,
    })
}

/// The object type a count limit counts, and for accounts, which kind.
fn counted(quota: TenantStorageQuota) -> Option<(ObjectType, Option<u16>)> {
    Some(match quota {
        TenantStorageQuota::MaxAccounts => (ObjectType::Account, Some(0)),
        TenantStorageQuota::MaxGroups => (ObjectType::Account, Some(1)),
        TenantStorageQuota::MaxDomains => (ObjectType::Domain, None),
        TenantStorageQuota::MaxMailingLists => (ObjectType::MailingList, None),
        TenantStorageQuota::MaxRoles => (ObjectType::Role, None),
        TenantStorageQuota::MaxOauthClients => (ObjectType::OAuthClient, None),
        TenantStorageQuota::MaxDkimKeys => (ObjectType::DkimSignature, None),
        TenantStorageQuota::MaxDnsServers => (ObjectType::DnsServer, None),
        TenantStorageQuota::MaxDirectories => (ObjectType::Directory, None),
        TenantStorageQuota::MaxAcmeProviders => (ObjectType::AcmeProvider, None),
        TenantStorageQuota::MaxDiskQuota => return None,
    })
}

/// Which count limit an object of this type and kind counts against. The
/// inverse of `counted`, for objects known only by id.
pub fn limit_for_id(object_id: ObjectId, account_kind: Option<u16>) -> Option<TenantStorageQuota> {
    Some(match object_id.object() {
        ObjectType::Account => match account_kind {
            Some(1) => TenantStorageQuota::MaxGroups,
            _ => TenantStorageQuota::MaxAccounts,
        },
        ObjectType::Domain => TenantStorageQuota::MaxDomains,
        ObjectType::MailingList => TenantStorageQuota::MaxMailingLists,
        ObjectType::Role => TenantStorageQuota::MaxRoles,
        ObjectType::OAuthClient => TenantStorageQuota::MaxOauthClients,
        ObjectType::DkimSignature => TenantStorageQuota::MaxDkimKeys,
        ObjectType::DnsServer => TenantStorageQuota::MaxDnsServers,
        ObjectType::Directory => TenantStorageQuota::MaxDirectories,
        ObjectType::AcmeProvider => TenantStorageQuota::MaxAcmeProviders,
        _ => return None,
    })
}

/// How many objects a tenant holds that count against `quota`.
pub async fn count(
    registry: &RegistryStore,
    tenant_id: u32,
    quota: TenantStorageQuota,
) -> trc::Result<u64> {
    let Some((object_type, kind)) = counted(quota) else {
        return Ok(0);
    };
    let mut query = RegistryQuery::new(object_type).with_tenant(Some(tenant_id));
    if let Some(kind) = kind {
        query = query.equal(Property::Type, kind);
    }
    registry
        .query::<Vec<Id>>(query)
        .await
        .map(|ids| ids.len() as u64)
        .caused_by(trc::location!())
}

/// A count limit that adding objects would cross.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitReached {
    pub quota: TenantStorageQuota,
    pub limit: u64,
    pub count: u64,
}

/// Checks that a tenant can take `adding` more objects that count against
/// `quota`, given its `limit` (`None` is no limit). Objects already over a
/// lowered limit stay: only new ones are refused (MT-18).
pub async fn check(
    registry: &RegistryStore,
    tenant_id: u32,
    quota: TenantStorageQuota,
    limit: Option<u64>,
    adding: u64,
) -> trc::Result<Result<(), LimitReached>> {
    let Some(limit) = limit else {
        return Ok(Ok(()));
    };
    let count = count(registry, tenant_id, quota).await?;
    if count + adding > limit {
        Ok(Err(LimitReached {
            quota,
            limit,
            count,
        }))
    } else {
        Ok(Ok(()))
    }
}

/// The key of a tenant's storage usage counter.
fn usage_key(tenant_id: u32) -> ValueKey<ValueClass> {
    ValueKey::from(ValueClass::TenantQuota(tenant_id))
}

/// Storage used by all a tenant's members together, in bytes (MT-20).
pub async fn used(data: &Store, tenant_id: u32) -> trc::Result<i64> {
    data.get_counter(usage_key(tenant_id))
        .await
        .caused_by(trc::location!())
}

/// Recomputes a tenant's storage usage from its members' own usage
/// (MT-21). Safe on a live server: the stored figure is corrected by the
/// difference, so deliveries counted while this runs aren't lost. One that
/// lands between reading the members and reading the total can leave the
/// figure off by that message until the next run.
pub async fn recalculate(
    data: &Store,
    registry: &RegistryStore,
    tenant_id: u32,
) -> trc::Result<i64> {
    let members = registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Account).with_tenant(Some(tenant_id)))
        .await
        .caused_by(trc::location!())?;

    let mut total = 0i64;
    for member in members {
        total += data
            .get_counter(ValueKey {
                account_id: member.document_id(),
                collection: 0,
                document_id: 0,
                class: ValueClass::Quota,
            })
            .await
            .caused_by(trc::location!())?
            .max(0);
    }

    let stored = used(data, tenant_id).await?;
    if stored != total {
        let mut batch = BatchBuilder::new();
        batch.add(ValueClass::TenantQuota(tenant_id), total - stored);
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(total)
}

/// Every tenant's id, for recomputing all of them (MT-21,
/// `resetTenantQuotas`).
pub async fn all_tenants(registry: &RegistryStore) -> trc::Result<Vec<u32>> {
    registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Tenant))
        .await
        .map(|ids| ids.into_iter().map(|id| id.document_id()).collect())
        .caused_by(trc::location!())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_count_limit_counts_something() {
        for quota in [
            TenantStorageQuota::MaxAccounts,
            TenantStorageQuota::MaxGroups,
            TenantStorageQuota::MaxDomains,
            TenantStorageQuota::MaxMailingLists,
            TenantStorageQuota::MaxRoles,
            TenantStorageQuota::MaxOauthClients,
            TenantStorageQuota::MaxDkimKeys,
            TenantStorageQuota::MaxDnsServers,
            TenantStorageQuota::MaxDirectories,
            TenantStorageQuota::MaxAcmeProviders,
        ] {
            let (object_type, kind) = counted(quota).unwrap();
            let id = ObjectId::new(object_type, Id::new(1));
            assert_eq!(limit_for_id(id, kind), Some(quota));
        }
        assert!(counted(TenantStorageQuota::MaxDiskQuota).is_none());
    }
}
