/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{
    Batch, BatchBuilder, ChangedCollection, IntoOperations, Operation, TENANT_OF_ACCOUNT,
    ValueClass, ValueOp, assert::ToAssertValue, log::VanishedItem,
};
use crate::{
    SerializeInfallible, U32_LEN,
    write::{
        LogCollection, MergeFnc, MergeOperation, Params, SetFnc, SetOperation, TaskQueueClass,
    },
};
use registry::{
    schema::structs::Task,
    types::{EnumImpl, ObjectImpl},
};
use types::{
    collection::{Collection, SyncCollection, VanishedCollection},
    field::FieldType,
};
use utils::{map::vec_map::VecMap, snowflake::SnowflakeIdGenerator};

/// inbuxa: MT-20: sets each tenant storage change's tenant from the account
/// it's under; one with no tenant becomes a repeat of its account switch,
/// which writes nothing.
fn retarget_tenant_quota(ops: &mut [Operation], tenant_of: impl Fn(u32) -> Option<u32>) {
    let mut current = None;
    for op in ops.iter_mut() {
        let account_id = match op {
            Operation::AccountId { account_id } => {
                current = Some(*account_id);
                continue;
            }
            Operation::Value {
                class: ValueClass::TenantQuota(_),
                ..
            } => match current {
                Some(account_id) => account_id,
                None => continue,
            },
            _ => continue,
        };
        match tenant_of(account_id) {
            Some(tenant_id) => {
                if let Operation::Value {
                    class: ValueClass::TenantQuota(tenant),
                    ..
                } = op
                {
                    *tenant = tenant_id;
                }
            }
            None => *op = Operation::AccountId { account_id },
        }
    }
}

/// inbuxa: MT-20: a tenant storage change never resolved is dropped rather
/// than written under the placeholder.
fn drop_unresolved_tenant_quota(ops: &mut [Operation]) {
    let mut current = None;
    for op in ops.iter_mut() {
        match op {
            Operation::AccountId { account_id } => current = Some(*account_id),
            Operation::Value {
                class: ValueClass::TenantQuota(TENANT_OF_ACCOUNT),
                ..
            } => {
                if let Some(account_id) = current {
                    *op = Operation::AccountId { account_id };
                }
            }
            _ => {}
        }
    }
}

impl BatchBuilder {
    pub fn new() -> Self {
        Self {
            ops: Vec::with_capacity(32),
            current_account_id: None,
            current_collection: None,
            current_document_id: None,
            changes: Default::default(),
            changed_collections: Default::default(),
            batch_size: 0,
            batch_ops: 0,
            has_assertions: false,
            commit_points: Vec::new(),
        }
    }

    pub fn with_account_id(&mut self, account_id: u32) -> &mut Self {
        if self
            .current_account_id
            .is_none_or(|current_account_id| current_account_id != account_id)
        {
            self.current_account_id = account_id.into();
            self.ops.push(Operation::AccountId { account_id });
        }
        self
    }

    pub fn with_collection(&mut self, collection: Collection) -> &mut Self {
        let collection_ = Some(collection);
        if collection_ != self.current_collection {
            self.current_collection = collection_;
            self.ops.push(Operation::Collection { collection });
        }
        self
    }

    pub fn with_document(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });
        self.current_document_id = Some(document_id);
        self.has_assertions = false;
        self
    }

    pub fn assert_value(
        &mut self,
        class: impl Into<ValueClass>,
        value: impl ToAssertValue,
    ) -> &mut Self {
        self.ops.push(Operation::AssertValue {
            class: class.into(),
            assert_value: value.to_assert_value(),
        });
        self.batch_ops += 1;
        self.has_assertions = true;
        self
    }

    pub fn index(&mut self, field: impl FieldType, value: impl Into<Vec<u8>>) -> &mut Self {
        let field = field.into();
        let value = value.into();
        let value_len = value.len();

        self.ops.push(Operation::Index {
            field,
            key: value,
            set: true,
        });
        self.batch_size += (U32_LEN * 3) + value_len;
        self.batch_ops += 1;
        self
    }

    pub fn unindex(&mut self, field: impl FieldType, value: impl Into<Vec<u8>>) -> &mut Self {
        let field = field.into();
        let value = value.into();
        let value_len = value.len();

        self.ops.push(Operation::Index {
            field,
            key: value,
            set: false,
        });
        self.batch_size += (U32_LEN * 3) + value_len;
        self.batch_ops += 1;
        self
    }

    #[inline(always)]
    pub fn tag(&mut self, field: impl FieldType) -> &mut Self {
        self.index(field, vec![])
    }

    #[inline(always)]
    pub fn untag(&mut self, field: impl FieldType) -> &mut Self {
        self.unindex(field, vec![])
    }

    pub fn add(&mut self, class: impl Into<ValueClass>, value: i64) -> &mut Self {
        let class = class.into();
        self.batch_size += class.serialized_size() + std::mem::size_of::<i64>();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::AtomicAdd(value),
        });
        self.batch_ops += 1;
        self
    }

    pub fn add_and_get(&mut self, class: impl Into<ValueClass>, value: i64) -> &mut Self {
        let class = class.into();
        self.batch_size += class.serialized_size() + (std::mem::size_of::<i64>() * 2);
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::AddAndGet(value),
        });
        self.batch_ops += 1;
        self
    }

    pub fn set(&mut self, class: impl Into<ValueClass>, value: impl Into<Vec<u8>>) -> &mut Self {
        let class = class.into();
        let value = value.into();
        self.batch_size += class.serialized_size() + value.len();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::Set(value),
        });
        self.batch_ops += 1;
        self
    }

    pub fn set_fnc(
        &mut self,
        class: impl Into<ValueClass>,
        params: Params,
        fnc: SetFnc,
    ) -> &mut Self {
        self.ops.push(Operation::Value {
            class: class.into(),
            op: ValueOp::SetFnc(SetOperation { fnc, params }),
        });
        self
    }

    pub fn merge_fnc(
        &mut self,
        class: impl Into<ValueClass>,
        params: Params,
        fnc: MergeFnc,
    ) -> &mut Self {
        self.ops.push(Operation::Value {
            class: class.into(),
            op: ValueOp::MergeFnc(MergeOperation { fnc, params }),
        });
        self
    }

    pub fn clear(&mut self, class: impl Into<ValueClass>) -> &mut Self {
        let class = class.into();
        self.batch_size += class.serialized_size();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::Clear,
        });
        self.batch_ops += 1;
        self
    }

    pub fn acl_grant(&mut self, grant_account_id: u32, op: Vec<u8>) -> &mut Self {
        self.batch_size += (U32_LEN * 3) + op.len();
        self.ops.push(Operation::Value {
            class: ValueClass::Acl(grant_account_id),
            op: ValueOp::Set(op),
        });
        self.batch_ops += 1;
        self
    }

    pub fn acl_revoke(&mut self, grant_account_id: u32) -> &mut Self {
        self.batch_size += U32_LEN * 3;
        self.ops.push(Operation::Value {
            class: ValueClass::Acl(grant_account_id),
            op: ValueOp::Clear,
        });
        self.batch_ops += 1;
        self
    }

    pub fn log_item_insert(
        &mut self,
        collection: SyncCollection,
        prefix: Option<u32>,
    ) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes.get_mut_or_insert(account_id).log_item_insert(
                collection,
                prefix,
                document_id,
            );
        }
        self
    }

    pub fn log_item_update(
        &mut self,
        collection: SyncCollection,
        prefix: Option<u32>,
    ) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes.get_mut_or_insert(account_id).log_item_update(
                collection,
                prefix,
                document_id,
            );
        }
        self
    }

    pub fn log_item_delete(
        &mut self,
        collection: SyncCollection,
        prefix: Option<u32>,
    ) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes.get_mut_or_insert(account_id).log_item_delete(
                collection,
                prefix,
                document_id,
            );
        }
        self
    }

    pub fn log_container_insert(&mut self, collection: SyncCollection) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_insert(collection, document_id);
        }
        self
    }

    pub fn log_container_update(&mut self, collection: SyncCollection) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_update(collection, document_id);
        }
        self
    }

    pub fn log_container_delete(&mut self, collection: SyncCollection) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_delete(collection, document_id);
        }
        self
    }

    pub fn log_container_property_change(
        &mut self,
        collection: SyncCollection,
        document_id: u32,
    ) -> &mut Self {
        if let Some(account_id) = self.current_account_id {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_property_update(collection, document_id);
        }
        self
    }

    pub fn log_vanished_item(
        &mut self,
        collection: VanishedCollection,
        item: impl Into<VanishedItem>,
    ) -> &mut Self {
        if let Some(account_id) = self.current_account_id {
            let item = item.into();
            self.batch_size += item.serialized_size();
            self.changes
                .get_mut_or_insert(account_id)
                .log_vanished_item(collection, item);
        }
        self
    }

    pub fn log_share_notification(
        &mut self,
        notification_id: u64,
        notify_account_id: u32,
        value: impl SerializeInfallible,
    ) -> &mut Self {
        self.changed_collections
            .get_mut_or_insert(notify_account_id)
            .share_notification_id = Some(notification_id);
        self.set(
            ValueClass::ShareNotification {
                notification_id,
                notify_account_id,
            },
            value.serialize(),
        )
    }

    fn serialize_changes(&mut self) {
        if !self.changes.is_empty() {
            for (account_id, changelog) in std::mem::take(&mut self.changes) {
                self.with_account_id(account_id);

                // Serialize changes
                for (collection, changes) in changelog.changes.into_iter() {
                    let cc = self.changed_collections.get_mut_or_insert(account_id);
                    if changes.has_container_changes() {
                        cc.changed_containers.insert(collection);
                    }
                    if changes.has_item_changes() {
                        cc.changed_items.insert(collection);
                    }

                    self.ops.push(Operation::Log {
                        collection: LogCollection::Sync(collection),
                        set: changes.serialize(),
                    });
                }

                // Serialize vanished items
                for (collection, vanished) in changelog.vanished.into_iter() {
                    self.ops.push(Operation::Log {
                        collection: LogCollection::Vanished(collection),
                        set: vanished.serialize(),
                    });
                }
            }
        }
    }

    pub fn commit_point(&mut self) -> &mut Self {
        if self.is_large_batch() {
            self.serialize_changes();
            self.commit_points.push(self.ops.len());
            self.batch_ops = 0;
            self.batch_size = 0;
            if let Some(account_id) = self.current_account_id {
                self.ops.push(Operation::AccountId { account_id });
            }
            if let Some(collection) = self.current_collection {
                self.ops.push(Operation::Collection { collection });
            }
        }
        self
    }

    #[inline]
    pub fn is_large_batch(&self) -> bool {
        self.batch_size > 5_000_000 || self.batch_ops > 1000
    }

    pub fn any_op(&mut self, op: Operation) -> &mut Self {
        if let Operation::Value { class, op } = &op {
            self.batch_size += class.serialized_size();
            if let ValueOp::Set(value) = op {
                self.batch_size += value.len();
            }
        }

        self.ops.push(op);
        self.batch_ops += 1;
        self
    }

    pub fn custom(&mut self, value: impl IntoOperations) -> trc::Result<&mut Self> {
        value.build(self)?;
        Ok(self)
    }

    pub fn last_account_id(&self) -> Option<u32> {
        self.current_account_id
    }

    pub fn last_collection(&self) -> Option<Collection> {
        self.current_collection
    }

    pub fn last_document_id(&self) -> Option<u32> {
        self.current_document_id
    }

    pub fn commit_points(&mut self) -> CommitPointIterator {
        self.serialize_changes();
        CommitPointIterator {
            commit_points: std::mem::take(&mut self.commit_points),
            commit_point_last: self.ops.len(),
            offset_start: 0,
        }
    }

    /// inbuxa: MT-20: the accounts whose data this batch's tenant storage
    /// changes are for, so their tenants can be looked up.
    pub fn tenant_quota_accounts(&self) -> Vec<u32> {
        let mut accounts = Vec::new();
        let mut current = None;
        for op in &self.ops {
            match op {
                Operation::AccountId { account_id } => current = Some(*account_id),
                Operation::Value {
                    class: ValueClass::TenantQuota(_),
                    ..
                } => {
                    if let Some(account_id) = current
                        && !accounts.contains(&account_id)
                    {
                        accounts.push(account_id);
                    }
                }
                _ => {}
            }
        }
        accounts
    }

    /// inbuxa: MT-20: points each tenant storage change at the tenant of the
    /// account whose data it is, whoever made the change, so an account's
    /// usage and its tenant's always move together. A change for an account
    /// with no tenant is dropped.
    pub fn retarget_tenant_quota(&mut self, tenant_of: impl Fn(u32) -> Option<u32>) {
        retarget_tenant_quota(&mut self.ops, tenant_of);
    }

    pub fn build_one(&mut self, commit_point: CommitPoint) -> Batch<'_> {
        drop_unresolved_tenant_quota(
            &mut self.ops[commit_point.offset_start..commit_point.offset_end],
        );
        Batch {
            changes: &self.changed_collections,
            ops: &mut self.ops[commit_point.offset_start..commit_point.offset_end],
        }
    }

    pub fn build_all(&mut self) -> Batch<'_> {
        self.serialize_changes();
        drop_unresolved_tenant_quota(&mut self.ops);
        Batch {
            changes: &self.changed_collections,
            ops: self.ops.as_mut_slice(),
        }
    }

    pub fn changes(self) -> Option<VecMap<u32, ChangedCollection>> {
        if self.has_changes() {
            Some(self.changed_collections)
        } else {
            None
        }
    }

    pub fn has_changes(&self) -> bool {
        !self.changed_collections.is_empty()
    }

    pub fn ops(&self) -> &[Operation] {
        self.ops.as_slice()
    }

    pub fn len(&self) -> usize {
        self.batch_size
    }

    pub fn is_empty(&self) -> bool {
        self.batch_ops == 0
    }

    pub fn schedule_task(&mut self, task: Task) -> &mut Self {
        let due = task.due_timestamp();
        let class = task.object_type().to_id();
        let task = task.to_pickled_vec();
        let id = SnowflakeIdGenerator::global_id().unwrap_or_default();

        self.set(ValueClass::TaskQueue(TaskQueueClass::Task { id }), task)
            .set(
                ValueClass::TaskQueue(TaskQueueClass::Due { id, due }),
                class.serialize(),
            )
    }

    pub fn schedule_task_with_id(&mut self, id: u64, task: Task) -> &mut Self {
        let due = task.due_timestamp();
        let class = task.object_type().to_id();
        let task = task.to_pickled_vec();

        self.set(ValueClass::TaskQueue(TaskQueueClass::Task { id }), task)
            .set(
                ValueClass::TaskQueue(TaskQueueClass::Due { id, due }),
                class.serialize(),
            )
    }
}

pub struct CommitPointIterator {
    commit_points: Vec<usize>,
    commit_point_last: usize,
    offset_start: usize,
}

pub struct CommitPoint {
    pub offset_start: usize,
    pub offset_end: usize,
}

impl CommitPointIterator {
    pub fn iter(&mut self) -> impl Iterator<Item = CommitPoint> {
        self.commit_points
            .iter()
            .copied()
            .chain([self.commit_point_last])
            .map(|offset_end| {
                let point = CommitPoint {
                    offset_start: self.offset_start,
                    offset_end,
                };
                self.offset_start = offset_end;
                point
            })
    }
}

impl Batch<'_> {
    pub fn is_atomic(&self) -> bool {
        !self.ops.iter().any(|op| {
            matches!(
                op,
                Operation::AssertValue { .. }
                    | Operation::Value {
                        op: ValueOp::AddAndGet(_) | ValueOp::AddAndGetExpiring(..),
                        ..
                    }
            )
        })
    }

    pub fn first_account_id(&self) -> Option<u32> {
        self.ops.iter().find_map(|op| match op {
            Operation::AccountId { account_id } => Some(*account_id),
            _ => None,
        })
    }
}

impl Default for BatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tenant_quota_tests {
    use super::*;

    fn tenant_changes(batch: &mut BatchBuilder) -> Vec<(u32, i64)> {
        let mut out = Vec::new();
        for op in batch.build_all().ops.iter() {
            if let Operation::Value {
                class: ValueClass::TenantQuota(tenant),
                op: ValueOp::AtomicAdd(by),
            } = op
            {
                out.push((*tenant, *by));
            }
        }
        out
    }

    #[test]
    fn tenant_changes_follow_the_owner() {
        let mut batch = BatchBuilder::new();
        // A writer in tenant 5 into account 1 (tenant 7); a writer with no
        // tenant into account 2 (tenant 8); account 3 has none
        batch
            .with_account_id(1)
            .add(ValueClass::Quota, 10)
            .add(ValueClass::TenantQuota(5), 10)
            .with_account_id(2)
            .add(ValueClass::Quota, -4)
            .add(ValueClass::TenantQuota(TENANT_OF_ACCOUNT), -4)
            .with_account_id(3)
            .add(ValueClass::Quota, 6)
            .add(ValueClass::TenantQuota(5), 6);
        assert_eq!(batch.tenant_quota_accounts(), vec![1, 2, 3]);
        batch.retarget_tenant_quota(|account| match account {
            1 => Some(7),
            2 => Some(8),
            _ => None,
        });
        assert_eq!(tenant_changes(&mut batch), vec![(7, 10), (8, -4)]);
    }

    #[test]
    fn an_unresolved_change_is_dropped() {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(1)
            .add(ValueClass::Quota, 10)
            .add(ValueClass::TenantQuota(TENANT_OF_ACCOUNT), 10)
            .add(ValueClass::TenantQuota(4), 10);
        assert_eq!(tenant_changes(&mut batch), vec![(4, 10)]);
    }
}
