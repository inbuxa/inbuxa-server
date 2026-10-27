/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{IndexValue, RevokeCleanup};
use crate::sharing::notification::ShareNotification;
use registry::schema::{
    enums::SharedObjectType,
    structs::{Task, TaskShareRevokeCleanup, TaskStatus},
};
use store::{
    SerializeInfallible, U32_LEN,
    write::{
        BatchBuilder, BlobLink, BlobOp, Patch, PatchSource, PendingId, QueueDocumentId, SetValue,
        SizedSetValue, Slot, TaskId, ValueClass, blob::BlobLinkValue, now,
    },
};
use types::collection::Collection;
use utils::{map::bitmap::Bitmap, snowflake::SnowflakeIdGenerator};

pub(crate) fn build_index(
    batch: &mut BatchBuilder,
    item: IndexValue<'_>,
    changed_by: u32,
    set: bool,
    pending_id: Option<Slot>,
) {
    match item {
        IndexValue::Index { field, value } => {
            if !value.is_empty() {
                if set {
                    batch.index(field, value.into_owned());
                } else {
                    batch.unindex(field, value.into_owned());
                }
            }
        }
        IndexValue::ParentProperty { field, value } => {
            if set {
                batch.set(field, parent_property(value, pending_id));
            } else {
                batch.clear(field);
            }
        }
        IndexValue::SearchIndex { index, .. } => {
            let account_id = batch.last_account_id().unwrap();

            if set {
                batch.queue_document_index(index, account_id, QueueDocumentId::Current);
            } else {
                batch.queue_document_unindex(index, account_id, QueueDocumentId::Current);
            }
        }
        IndexValue::Property { field, value } => {
            if !value.is_none() {
                if set {
                    batch.set(field, value.into_owned());
                } else {
                    batch.clear(field);
                }
            }
        }
        IndexValue::Blob { value, size } => {
            if set {
                batch.set(
                    BlobOp::Link {
                        hash: value,
                        to: BlobLink::Document,
                    },
                    BlobLinkValue::new(size),
                );
            } else {
                batch.clear(BlobOp::Link {
                    hash: value,
                    to: BlobLink::Document,
                });
            }
        }
        IndexValue::Acl { value } => {
            let object_account_id = batch.last_account_id().unwrap_or_default();
            let object_type = batch.last_collection().unwrap_or(Collection::None);
            let object_id = batch.last_document_id().unwrap_or(PendingId::Assigned(0));
            let notification_id = SnowflakeIdGenerator::global_id().unwrap_or_default();

            for item in value.as_ref() {
                if set {
                    batch.acl_grant(item.account_id, item.grants.bitmap.serialize());
                    batch.log_share_notification(
                        notification_id,
                        item.account_id,
                        ShareNotification {
                            object_account_id,
                            object_type,
                            changed_by,
                            old_rights: Default::default(),
                            new_rights: item.grants,
                            ..Default::default()
                        }
                        .into_value(object_id),
                    );
                } else {
                    batch.acl_revoke(item.account_id);
                    batch.log_share_notification(
                        notification_id,
                        item.account_id,
                        ShareNotification {
                            object_account_id,
                            object_type,
                            changed_by,
                            old_rights: item.grants,
                            new_rights: Default::default(),
                            ..Default::default()
                        }
                        .into_value(object_id),
                    );
                }
            }
        }
        IndexValue::Quota { used } => {
            let value = if set { used as i64 } else { -(used as i64) };

            batch.add(ValueClass::Quota, value);

        }
        IndexValue::ObjectCount(kind) => {
            batch.add(ValueClass::ObjectCount(kind), if set { 1 } else { -1 });
        }
        IndexValue::LogItem {
            sync_collection,
            prefix,
        } => {
            if set {
                batch.log_item_insert(sync_collection, prefix);
            } else {
                batch.log_item_delete(sync_collection, prefix);
            }
        }
        IndexValue::LogContainer { sync_collection } => {
            if set {
                batch.log_container_insert(sync_collection);
            } else {
                batch.log_container_delete(sync_collection);
            }
        }
        IndexValue::LogContainerProperty {
            sync_collection,
            ids,
        } => {
            for parent_id in ids {
                batch.log_container_property_change(sync_collection, parent_id);
            }
        }
    }
}

pub(crate) fn merge_index(
    batch: &mut BatchBuilder,
    current: IndexValue<'_>,
    change: IndexValue<'_>,
    changed_by: u32,
    revoke_cleanup: RevokeCleanup,
    pending_id: Option<Slot>,
) -> trc::Result<()> {
    match (current, change) {
        (
            IndexValue::Index {
                field,
                value: old_value,
            },
            IndexValue::Index {
                value: new_value, ..
            },
        ) => {
            if !old_value.is_empty() {
                batch.unindex(field, old_value.into_owned());
            }

            if !new_value.is_empty() {
                batch.index(field, new_value.into_owned());
            }
        }
        (
            IndexValue::ParentProperty {
                field: old_field, ..
            },
            IndexValue::ParentProperty { field, value },
        ) => {
            if old_field != field {
                batch.clear(old_field);
            }
            batch.set(field, parent_property(value, pending_id));
        }
        (IndexValue::SearchIndex { index, .. }, IndexValue::SearchIndex { .. }) => {
            batch.queue_document_index(
                index,
                batch.last_account_id().unwrap(),
                QueueDocumentId::Current,
            );
        }
        (
            IndexValue::Property {
                field: old_field,
                value: old_value,
            },
            IndexValue::Property {
                field: new_field,
                value: new_value,
                ..
            },
        ) => {
            if old_field != new_field {
                batch.clear(old_field);
                batch.set(new_field, new_value.into_owned());
            } else if new_value != old_value {
                if new_value.is_some() {
                    batch.set(old_field, new_value.into_owned());
                } else {
                    batch.clear(old_field);
                }
            }
        }
        (
            IndexValue::Blob {
                value: old_hash, ..
            },
            IndexValue::Blob {
                value: new_hash,
                size,
            },
        ) => {
            batch.clear(BlobOp::Link {
                hash: old_hash,
                to: BlobLink::Document,
            });
            batch.set(
                BlobOp::Link {
                    hash: new_hash,
                    to: BlobLink::Document,
                },
                BlobLinkValue::new(size),
            );
        }
        (IndexValue::Acl { value: old_acl }, IndexValue::Acl { value: new_acl }) => {
            let has_old_acl = !old_acl.is_empty();
            let has_new_acl = !new_acl.is_empty();

            if !has_old_acl && !has_new_acl {
                return Ok(());
            }

            let object_account_id = batch.last_account_id().unwrap_or_default();
            let object_type = batch.last_collection().unwrap_or(Collection::None);
            let object_id = batch.last_document_id().unwrap_or(PendingId::Assigned(0));
            let notification_id = SnowflakeIdGenerator::global_id().unwrap_or_default();
            let mut cleanup_type = match (revoke_cleanup, object_id) {
                (RevokeCleanup::Scheduled, PendingId::Assigned(document_id)) => {
                    SharedObjectType::from_collection(object_type)
                        .map(|shared_type| (shared_type, document_id))
                }
                _ => None,
            };

            match (has_old_acl, has_new_acl) {
                (true, true) => {
                    // Remove deleted ACLs
                    for current_item in old_acl.as_ref() {
                        if !new_acl
                            .iter()
                            .any(|item| item.account_id == current_item.account_id)
                        {
                            batch.acl_revoke(current_item.account_id);
                            if let Some((shared_type, document_id)) = cleanup_type.take() {
                                schedule_revoke_cleanup(
                                    batch,
                                    object_account_id,
                                    shared_type,
                                    document_id,
                                );
                            }
                            batch.log_share_notification(
                                notification_id,
                                current_item.account_id,
                                ShareNotification {
                                    object_account_id,
                                    object_type,
                                    changed_by,
                                    old_rights: current_item.grants,
                                    new_rights: Default::default(),
                                    ..Default::default()
                                }
                                .into_value(object_id),
                            );
                        }
                    }

                    // Update ACLs
                    for item in new_acl.as_ref() {
                        let mut add_item = true;
                        let mut old_rights = Bitmap::default();
                        for current_item in old_acl.as_ref() {
                            if item.account_id == current_item.account_id {
                                if item.grants == current_item.grants {
                                    add_item = false;
                                } else {
                                    old_rights = current_item.grants;
                                }
                                break;
                            }
                        }
                        if add_item {
                            batch.acl_grant(item.account_id, item.grants.bitmap.serialize());
                            batch.log_share_notification(
                                notification_id,
                                item.account_id,
                                ShareNotification {
                                    object_account_id,
                                    object_type,
                                    changed_by,
                                    old_rights,
                                    new_rights: item.grants,
                                    ..Default::default()
                                }
                                .into_value(object_id),
                            );
                        }
                    }
                }
                (false, true) => {
                    // Add all ACLs
                    for item in new_acl.as_ref() {
                        batch.acl_grant(item.account_id, item.grants.bitmap.serialize());
                        batch.log_share_notification(
                            notification_id,
                            item.account_id,
                            ShareNotification {
                                object_account_id,
                                object_type,
                                changed_by,
                                old_rights: Default::default(),
                                new_rights: item.grants,
                                ..Default::default()
                            }
                            .into_value(object_id),
                        );
                    }
                }
                (true, false) => {
                    // Remove all ACLs
                    for item in old_acl.as_ref() {
                        batch.acl_revoke(item.account_id);
                        if let Some((shared_type, document_id)) = cleanup_type.take() {
                            schedule_revoke_cleanup(
                                batch,
                                object_account_id,
                                shared_type,
                                document_id,
                            );
                        }
                        batch.log_share_notification(
                            notification_id,
                            item.account_id,
                            ShareNotification {
                                object_account_id,
                                object_type,
                                changed_by,
                                old_rights: item.grants,
                                new_rights: Default::default(),
                                ..Default::default()
                            }
                            .into_value(object_id),
                        );
                    }
                }
                _ => {}
            }
        }
        (IndexValue::Quota { used: old_used }, IndexValue::Quota { used: new_used }) => {
            let value = new_used as i64 - old_used as i64;
            batch.add(ValueClass::Quota, value);

        }
        (IndexValue::ObjectCount(old_kind), IndexValue::ObjectCount(new_kind)) => {
            batch
                .add(ValueClass::ObjectCount(old_kind), -1)
                .add(ValueClass::ObjectCount(new_kind), 1);
        }
        (
            IndexValue::LogItem {
                sync_collection,
                prefix: old_prefix,
            },
            IndexValue::LogItem {
                prefix: new_prefix, ..
            },
        ) => {
            batch.log_item_delete(sync_collection, old_prefix);
            batch.log_item_insert(sync_collection, new_prefix);
        }
        (
            IndexValue::LogContainerProperty {
                sync_collection,
                ids: old_ids,
            },
            IndexValue::LogContainerProperty { ids: new_ids, .. },
        ) => {
            for parent_id in &old_ids {
                if !new_ids.contains(parent_id) {
                    batch.log_container_property_change(sync_collection, *parent_id);
                }
            }
            for parent_id in new_ids {
                if !old_ids.contains(&parent_id) {
                    batch.log_container_property_change(sync_collection, parent_id);
                }
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn parent_property(value: Vec<u8>, pending_id: Option<Slot>) -> SizedSetValue {
    match pending_id {
        Some(slot) if value.len() >= U32_LEN => SetValue::patched(
            value,
            vec![Patch {
                offset: 0,
                source: PatchSource::SlotBeU32(slot),
            }],
        ),
        _ => SetValue::fixed(value),
    }
}

#[cfg(not(stalwart_tests))]
pub(crate) const REVOKE_CLEANUP_WINDOW: u64 = 300;
#[cfg(stalwart_tests)]
pub(crate) const REVOKE_CLEANUP_WINDOW: u64 = 1;

pub(crate) fn revoke_cleanup_schedule(now: u64) -> (u64, u64) {
    let window = now / REVOKE_CLEANUP_WINDOW;
    (window, (window + 2) * REVOKE_CLEANUP_WINDOW)
}

fn schedule_revoke_cleanup(
    batch: &mut BatchBuilder,
    account_id: u32,
    object_type: SharedObjectType,
    document_id: u32,
) {
    let (window, due) = revoke_cleanup_schedule(now());
    batch.schedule_task_with_id(
        TaskId::shared_object(account_id, object_type.collection(), document_id, window),
        Task::ShareRevokeCleanup(TaskShareRevokeCleanup {
            account_id: account_id.into(),
            document_id: document_id.into(),
            object_type,
            status: TaskStatus::at(due as i64),
        }),
    );
}
