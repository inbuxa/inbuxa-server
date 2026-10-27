/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    Server,
    auth::AccountCache,
    storage::{ObjectQuota, TenantQuota},
};
use registry::{
    schema::enums::{StorageQuota, TenantStorageQuota},
    types::EnumImpl,
};
use store::{
    ValueKey,
    write::{AccountCounter, BatchBuilder, ValueClass},
};
use trc::AddContext;

impl Server {
    pub async fn get_used_quota_account(&self, account_id: u32) -> trc::Result<i64> {
        self.core
            .storage
            .data
            .get_counter(ValueKey {
                account_id,
                collection: 0,
                document_id: 0,
                class: ValueClass::Quota,
            })
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(account_id))
    }

    // inbuxa: MT-20: storage used by all a tenant's members together
    pub async fn get_used_quota_tenant(&self, tenant_id: u32) -> trc::Result<i64> {
        inbuxa_features::tenancy::quota::used(&self.core.storage.data, tenant_id).await
    }

    pub async fn has_available_quota(
        &self,
        account: &AccountCache,
        item_size: u64,
    ) -> trc::Result<()> {
        if account.quota_disk != 0 {
            let used_quota = self.get_used_quota_account(account.id).await?.max(0) as u64;

            if used_quota + item_size > account.quota_disk {
                return Err(trc::LimitEvent::Quota
                    .into_err()
                    .ctx(trc::Key::Limit, account.quota_disk)
                    .ctx(trc::Key::Used, used_quota));
            }
        }

        // inbuxa: MT-19: the tenant's limit applies too, whichever is reached first
        if let Some(tenant_id) = account.id_tenant {
            let tenant = self.tenant(tenant_id).await?;
            if tenant.quota_disk != 0 {
                let used_quota = self.get_used_quota_tenant(tenant_id).await?.max(0) as u64;

                if used_quota + item_size > tenant.quota_disk {
                    return Err(trc::LimitEvent::TenantQuota
                        .into_err()
                        .ctx(trc::Key::Id, tenant_id)
                        .ctx(trc::Key::Limit, tenant.quota_disk)
                        .ctx(trc::Key::Used, used_quota));
                }
            }
        }

        Ok(())
    }


    pub fn limit_disk_quota(&self, batch: &mut BatchBuilder, account: &AccountCache) {
        if account.quota_disk != 0 {
            batch.limit_counter(AccountCounter::Quota, account.quota_disk);
        }
    }

    pub fn limit_object_quota(
        &self,
        batch: &mut BatchBuilder,
        account: &AccountCache,
        object: StorageQuota,
    ) {
        if let Some(limit) = self.object_quota_limit(account, object) {
            batch.limit_counter(AccountCounter::ObjectCount(object), limit as u64);
        }
    }

    pub async fn object_count(&self, account_id: u32, object: StorageQuota) -> trc::Result<usize> {
        self.core
            .storage
            .data
            .get_counter(ValueKey {
                account_id,
                collection: 0,
                document_id: 0,
                class: ValueClass::ObjectCount(object),
            })
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(account_id))
            .map(|count| usize::try_from(count).unwrap_or_default())
    }

    pub async fn disk_quota_budget(&self, account: &AccountCache) -> trc::Result<DiskQuotaBudget> {
        let mut budget = DiskQuotaBudget::unlimited();
        if account.quota_disk != 0 {
            let used_quota = self.get_used_quota_account(account.id).await?.max(0) as u64;
            budget.limit_to(
                account.quota_disk.saturating_sub(used_quota),
                trc::LimitEvent::Quota,
            );
        }

        // inbuxa: MT-19: and the tenant's
        if let Some(tenant_id) = account.id_tenant {
            let tenant = self.tenant(tenant_id).await?;
            if tenant.quota_disk != 0 {
                let used_quota = self.get_used_quota_tenant(tenant_id).await?.max(0) as u64;
                budget.limit_to(
                    tenant.quota_disk.saturating_sub(used_quota),
                    trc::LimitEvent::TenantQuota,
                );
            }
        }

        Ok(budget)
    }


    #[inline(always)]
    pub fn object_quota(&self, user_quotas: Option<&ObjectQuota>, object: StorageQuota) -> u32 {
        user_quotas.unwrap_or(&self.core.email.max_objects).0[object as usize]
    }

    #[inline(always)]
    pub fn object_quota_limit(
        &self,
        account: &AccountCache,
        object: StorageQuota,
    ) -> Option<usize> {
        let limit = self.object_quota(account.object_quotas(), object);
        (limit != u32::MAX).then_some(limit as usize)
    }

    pub fn object_quota_usage(
        &self,
        account: &AccountCache,
        object: StorageQuota,
        used: impl FnOnce() -> usize,
    ) -> ObjectQuotaUsage {
        self.object_quota_limit(account, object)
            .map_or_else(ObjectQuotaUsage::unlimited, |limit| ObjectQuotaUsage {
                used: used(),
                limit,
            })
    }

    pub fn assert_object_quota(
        &self,
        account: &AccountCache,
        object: StorageQuota,
        requested: usize,
        used: impl FnOnce() -> usize,
    ) -> trc::Result<()> {
        let Some(limit) = self.object_quota_limit(account, object) else {
            return Ok(());
        };
        let used = used();
        if used.saturating_add(requested) <= limit {
            Ok(())
        } else {
            Err(trc::LimitEvent::Quota
                .into_err()
                .account_id(account.id)
                .ctx(trc::Key::ObjectType, object.as_str())
                .ctx(trc::Key::Limit, limit)
                .ctx(trc::Key::Used, used))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ObjectQuotaUsage {
    pub used: usize,
    pub limit: usize,
}

impl ObjectQuotaUsage {
    pub fn unlimited() -> Self {
        Self {
            used: 0,
            limit: usize::MAX,
        }
    }

    #[inline(always)]
    pub fn has_room(&self, pending: usize) -> bool {
        self.used.saturating_add(pending) < self.limit
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DiskQuotaBudget {
    available: Option<i64>,
    binding: trc::LimitEvent,
}

impl DiskQuotaBudget {
    pub const fn unlimited() -> Self {
        Self {
            available: None,
            binding: trc::LimitEvent::Quota,
        }
    }

    pub fn limited(available: u64, binding: trc::LimitEvent) -> Self {
        Self {
            available: Some(saturating_i64(available)),
            binding,
        }
    }

    fn limit_to(&mut self, available: u64, binding: trc::LimitEvent) {
        let available = saturating_i64(available);
        if self.available.is_none_or(|current| available < current) {
            self.available = Some(available);
            self.binding = binding;
        }
    }

    #[inline(always)]
    pub fn check(&self, bytes: u64) -> Result<(), trc::LimitEvent> {
        match self.available {
            Some(available) if bytes > 0 && saturating_i64(bytes) > available => Err(self.binding),
            _ => Ok(()),
        }
    }

    #[inline(always)]
    pub fn try_reserve(&mut self, bytes: u64) -> Result<(), trc::LimitEvent> {
        self.check(bytes)?;
        self.reserve(bytes);
        Ok(())
    }

    #[inline(always)]
    pub fn reserve(&mut self, bytes: u64) {
        if let Some(available) = &mut self.available {
            *available = available.saturating_sub(saturating_i64(bytes));
        }
    }

    #[inline(always)]
    pub fn release(&mut self, bytes: u64) {
        if let Some(available) = &mut self.available {
            *available = available.saturating_add(saturating_i64(bytes));
        }
    }
}

#[inline(always)]
fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl ObjectQuota {
    #[inline(always)]
    pub fn set(&mut self, item: StorageQuota, max: u32) {
        self.0[item as usize] = max;
    }

    #[inline(always)]
    pub fn get(&self, item: StorageQuota) -> u32 {
        self.0[item as usize]
    }
}

// inbuxa: MT: per-tenant quotas, which 1.0 dropped
impl TenantQuota {
    #[inline(always)]
    pub fn set(&mut self, item: TenantStorageQuota, max: u32) {
        self.0[item as usize] = max;
    }

    #[inline(always)]
    pub fn get(&self, item: TenantStorageQuota) -> u32 {
        self.0[item as usize]
    }
}

impl Default for ObjectQuota {
    fn default() -> Self {
        Self([u32::MAX; StorageQuota::COUNT - 1])
    }
}

impl Default for TenantQuota {
    fn default() -> Self {
        Self([u32::MAX; TenantStorageQuota::COUNT - 1])
    }
}


