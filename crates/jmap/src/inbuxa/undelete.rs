/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Undelete over JMAP: `x:ArchivedItem` (`docs/spec/features/undelete.md`).
//! The rules themselves are in `inbuxa_features::undelete`.

use crate::{
    api::query::QueryResponseBuilder,
    inbuxa::access::assert_can_manage,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse},
        query::RegistryQueryFilters,
    },
};
use common::{Server, auth::AccessToken};
use inbuxa_features::{masked_email::ops::collapse, undelete};
use jmap_proto::{error::set::SetError, types::state::State as JmapState};
use jmap_tools::Key;
use registry::{
    jmap::{IntoValue, JmapValue},
    schema::{
        enums::ArchivedItemType,
        prelude::Property,
        structs::{ArchivedItem, Task, TaskRestoreArchivedItem, TaskStatus},
    },
    types::datetime::UTCDateTime,
};
use std::str::FromStr;
use store::{registry::RegistryFilterOp, write::BatchBuilder};
use types::id::Id;

fn kind(item: &ArchivedItem) -> (ArchivedItemType, &'static str) {
    match item {
        ArchivedItem::Email(_) => (ArchivedItemType::Email, "Email"),
        ArchivedItem::FileNode(_) => (ArchivedItemType::FileNode, "FileNode"),
        ArchivedItem::CalendarEvent(_) => (ArchivedItemType::CalendarEvent, "CalendarEvent"),
        ArchivedItem::ContactCard(_) => (ArchivedItemType::ContactCard, "ContactCard"),
        ArchivedItem::SieveScript(_) => (ArchivedItemType::SieveScript, "SieveScript"),
    }
}

/// The item's original date: when a message was received, or when anything
/// else was created. Restore gives it back.
fn original_date(item: &ArchivedItem) -> UTCDateTime {
    match item {
        ArchivedItem::Email(item) => item.received_at,
        ArchivedItem::FileNode(item) => item.created_at,
        ArchivedItem::CalendarEvent(item) => item.created_at,
        ArchivedItem::ContactCard(item) => item.created_at,
        ArchivedItem::SieveScript(item) => item.created_at,
    }
}

/// When the item was archived.
fn archived_at(item: &ArchivedItem) -> i64 {
    match item {
        ArchivedItem::Email(item) => item.archived_at,
        ArchivedItem::FileNode(item) => item.archived_at,
        ArchivedItem::CalendarEvent(item) => item.archived_at,
        ArchivedItem::ContactCard(item) => item.archived_at,
        ArchivedItem::SieveScript(item) => item.archived_at,
    }
    .timestamp()
}

/// Text a search matches: the summary fields (a fork addition).
fn summary_text(item: &ArchivedItem) -> String {
    match item {
        ArchivedItem::Email(item) => format!("{} {}", item.from, item.subject),
        ArchivedItem::FileNode(item) => item.name.clone(),
        ArchivedItem::CalendarEvent(item) => item.title.clone(),
        ArchivedItem::ContactCard(item) => item.name.clone().unwrap_or_default(),
        ArchivedItem::SieveScript(item) => item.name.clone(),
    }
    .to_lowercase()
}

/// The archive's state, for `/get` and `/changes`.
pub async fn state(server: &Server, account_id: u32) -> trc::Result<JmapState> {
    let latest = undelete::data::latest_change(&server.core.storage.data, account_id).await?;
    Ok(if latest == 0 {
        JmapState::Initial
    } else {
        JmapState::Exact(latest)
    })
}

/// The item as `/get` shows it: every property, `status` and `accountId`
/// included (upstream omits them).
async fn to_value(server: &Server, id: Id, item: ArchivedItem) -> trc::Result<JmapValue<'static>> {
    let requested = undelete::data::is_restore_requested(&server.core.storage.data, id).await?;
    let mut value = item.into_value();
    if let JmapValue::Object(object) = &mut value {
        object.insert_unchecked(Key::Property(Property::Id), JmapValue::Element(id.into()));
        object.insert_unchecked(
            Key::Property(Property::Status),
            JmapValue::Str(
                if requested {
                    "requestRestore"
                } else {
                    "archived"
                }
                .into(),
            ),
        );
    }
    Ok(value)
}

/// `x:ArchivedItem/get` (UD-7). Items past their deadline aren't returned
/// (UD-13).
pub(crate) async fn get(mut get: RegistryGetResponse<'_>) -> trc::Result<RegistryGetResponse<'_>> {
    let account_id = get.account_id;
    assert_can_manage(get.server, get.access_token, account_id).await?;
    let data = &get.server.core.storage.data;
    let registry = get.server.registry();

    match get.ids.take() {
        None => {
            for (id, item) in undelete::records::of_account(data, registry, account_id).await? {
                let value = to_value(get.server, id, item).await?;
                get.response.list.push(value);
            }
        }
        Some(ids) => {
            for id in ids {
                match undelete::records::get(data, registry, account_id, id).await? {
                    Some(item) => {
                        let value = to_value(get.server, id, item).await?;
                        get.response.list.push(value);
                    }
                    None => get.not_found(id),
                }
            }
        }
    }
    get.response.state = Some(state(get.server, account_id).await?);
    Ok(get)
}

/// `x:ArchivedItem/query`, filtering on `@type`, `archivedAt` and text over
/// the summary fields (a fork addition). Newest first.
pub(crate) async fn query(mut req: RegistryQueryResponse<'_>) -> trc::Result<QueryResponseBuilder> {
    let account_id = req.request.account_id.document_id();
    assert_can_manage(req.server, req.access_token, account_id).await?;

    let mut typ = None;
    let mut after = None;
    let mut before = None;
    let mut text = None;
    req.request
        .extract_filters(|property, op, value| match (property, op, value) {
            (Property::Type, RegistryFilterOp::Equal, serde_json::Value::String(v)) => {
                typ = Some(v);
                true
            }
            (Property::ArchivedAt, op, serde_json::Value::String(v)) => {
                let Ok(at) = UTCDateTime::from_str(&v) else {
                    return false;
                };
                match op {
                    RegistryFilterOp::GreaterThan | RegistryFilterOp::GreaterEqualThan => {
                        after = Some(at.timestamp());
                        true
                    }
                    RegistryFilterOp::LowerThan | RegistryFilterOp::LowerEqualThan => {
                        before = Some(at.timestamp());
                        true
                    }
                    _ => false,
                }
            }
            (Property::Text, _, serde_json::Value::String(v)) => {
                text = Some(v.to_lowercase());
                true
            }
            (Property::AccountId, _, _) => true,
            _ => false,
        })?;
    req.request
        .extract_parameters(req.server.core.jmap.query_max_results, Some(Property::Id))?;

    let mut items = undelete::records::of_account(
        &req.server.core.storage.data,
        req.server.registry(),
        account_id,
    )
    .await?
    .into_iter()
    .filter(|(_, item)| {
        let archived_at = archived_at(item);
        typ.as_deref().is_none_or(|t| kind(item).1 == t)
            && after.is_none_or(|at| archived_at >= at)
            && before.is_none_or(|at| archived_at <= at)
            && text
                .as_deref()
                .is_none_or(|t| summary_text(item).contains(t))
    })
    .collect::<Vec<_>>();
    items.sort_by(|(a_id, a), (b_id, b)| archived_at(b).cmp(&archived_at(a)).then(b_id.cmp(a_id)));

    let mut response = QueryResponseBuilder::new(
        items.len(),
        req.server.core.jmap.query_max_results,
        JmapState::Initial,
        &req.request,
    );
    for (id, _) in items {
        if !response.add_id(id) {
            break;
        }
    }
    Ok(response)
}

/// Asks for an item's restore: the server schedules the restore task, once
/// (UD-8, UD-11).
async fn request_restore(
    server: &Server,
    account_id: u32,
    id: Id,
    item: &ArchivedItem,
) -> trc::Result<()> {
    let data = &server.core.storage.data;
    if undelete::data::is_restore_requested(data, id).await? {
        return Ok(());
    }
    let mut batch = BatchBuilder::new();
    batch.schedule_task(Task::RestoreArchivedItem(TaskRestoreArchivedItem {
        account_id: Id::from(account_id),
        archived_item_type: kind(item).0,
        blob_id: item.blob_id().clone(),
        created_at: original_date(item),
        archived_until: item.archived_until(),
        status: TaskStatus::now(),
    }));
    undelete::data::set_restore_requested(&mut batch, id);
    undelete::data::log_change(
        &mut batch,
        account_id,
        server.registry().assign_id(),
        id,
        undelete::data::Change::Updated,
    );
    server.store().write(batch.build_all()).await?;
    server.notify_task_queue();
    Ok(())
}

/// `x:ArchivedItem/set`: `status: requestRestore` restores (UD-8), destroy
/// removes for good (UD-12). Items are never created over the API.
pub(crate) async fn set(mut set: RegistrySetResponse<'_>) -> trc::Result<RegistrySetResponse<'_>> {
    let account_id = set.account_id;
    assert_can_manage(set.server, set.access_token, account_id).await?;
    let data = &set.server.core.storage.data;
    let registry = set.server.registry();

    set.fail_all_create("Archived items are created by deleting things, not directly.");

    for (id, value) in std::mem::take(&mut set.update) {
        let Some(item) = undelete::records::get(data, registry, account_id, id).await? else {
            set.response.not_updated.append(id, SetError::not_found());
            continue;
        };
        let mut restore = false;
        let mut invalid = None;
        for (key, value) in value.into_expanded_object() {
            match (key, value.as_str().as_deref()) {
                (Key::Property(Property::Status), Some("requestRestore")) => restore = true,
                (Key::Property(Property::Status), Some("archived")) => {}
                (Key::Property(property), _) => {
                    invalid = Some(property);
                    break;
                }
                _ => {
                    invalid = Some(Property::Status);
                    break;
                }
            }
        }
        if let Some(property) = invalid {
            set.response.not_updated.append(
                id,
                SetError::invalid_properties()
                    .with_property(property)
                    .with_description("Only status can be set, to requestRestore."),
            );
            continue;
        }
        if restore {
            request_restore(set.server, account_id, id, &item).await?;
        }
        set.response.updated.append(id, None);
    }

    for id in std::mem::take(&mut set.destroy) {
        match undelete::records::get(data, registry, account_id, id).await? {
            // inbuxa: LH-7: a held item can't be destroyed; restoring it
            // still can. The hold is named only to those who may see holds.
            Some(item)
                if inbuxa_features::hold::is_held_until(
                    item.archived_until().timestamp().max(0) as u64,
                ) =>
            {
                let mut why = "A legal hold applies to this item, so it can't be deleted.".to_string();
                if set
                    .access_token
                    .has_permission(registry::schema::enums::Permission::SysLegalHoldGet)
                {
                    let names = set
                        .server
                        .holds_on(account_id)
                        .await?
                        .into_iter()
                        .map(|hold| hold.name)
                        .collect::<Vec<_>>();
                    if !names.is_empty() {
                        why = format!("Held by {}, so it can't be deleted.", names.join(", "));
                    }
                }
                set.response
                    .not_destroyed
                    .append(id, SetError::forbidden().with_description(why));
            }
            Some(item) => {
                undelete::records::remove(data, registry, id, &item).await?;
                set.response.destroyed.push(id);
            }
            None => set.response.not_destroyed.append(id, SetError::not_found()),
        }
    }

    Ok(set)
}

/// `x:ArchivedItem/changes` (a fork addition).
pub async fn changes(
    server: &Server,
    access_token: &AccessToken,
    request: jmap_proto::method::changes::ChangesRequest,
) -> trc::Result<jmap_proto::response::ResponseMethod<'static>> {
    use jmap_proto::{
        method::changes::ChangesResponse,
        response::{ChangesResponseMethod, ResponseMethod},
    };

    let account_id = request.account_id.document_id();
    assert_can_manage(server, access_token, account_id).await?;
    let since = match &request.since_state {
        JmapState::Initial => 0,
        JmapState::Exact(change_id) => *change_id,
        JmapState::Intermediate(_) => {
            return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
        }
    };
    let max = request
        .max_changes
        .filter(|max| *max != 0)
        .unwrap_or(usize::MAX)
        .min(server.core.jmap.changes_max_results);
    let entries = undelete::data::changes_since(&server.core.storage.data, account_id, since)
        .await?
        .into_iter()
        .map(|(change_id, id, change)| {
            (
                change_id,
                id,
                match change {
                    undelete::data::Change::Created => {
                        inbuxa_features::masked_email::data::Change::Created
                    }
                    undelete::data::Change::Updated => {
                        inbuxa_features::masked_email::data::Change::Updated
                    }
                    undelete::data::Change::Destroyed => {
                        inbuxa_features::masked_email::data::Change::Destroyed
                    }
                },
            )
        })
        .collect::<Vec<_>>();
    let changes = collapse(since, &entries, max);

    Ok(ResponseMethod::Changes(ChangesResponseMethod::Registry(
        Box::new(ChangesResponse {
            account_id: request.account_id,
            old_state: request.since_state,
            new_state: if changes.new_state == 0 {
                JmapState::Initial
            } else {
                JmapState::Exact(changes.new_state)
            },
            has_more_changes: changes.has_more,
            created: changes.created,
            updated: changes.updated,
            destroyed: changes.destroyed,
            updated_properties: None,
        }),
    )))
}
