/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Restoring archived files, calendar events, contacts and Sieve scripts
//! (`docs/spec/features/undelete.md`, UD-8 to UD-11). Email restores in
//! `restore_item.rs`.

use crate::task_manager::TaskResult;
use calcard::{Entry, Parser, common::timezone::Tz};
use common::{DavName, Server, auth::BuildAccessToken};
use email::sieve::{SieveScript, ingest::SieveScriptIngest};
use groupware::{
    cache::GroupwareCache,
    calendar::{CalendarEvent, CalendarEventData},
    contact::ContactCard,
    file::{FileNode, FileProperties},
};
use inbuxa_features::undelete::{self, data::Extra, groupware::candidates};
use registry::schema::structs::{ArchivedItem, TaskRestoreArchivedItem};
use store::write::BatchBuilder;
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    id::Id,
};

/// The names already used under a parent in an account's resources.
fn names_under(resources: &common::DavResources, parent: Option<u32>) -> Vec<String> {
    resources
        .paths
        .iter()
        .filter(|path| path.parent_id == parent)
        .map(|path| {
            path.path
                .rsplit('/')
                .next()
                .unwrap_or(&path.path)
                .to_string()
        })
        .collect()
}

fn free(name: &str, taken: &[String]) -> String {
    let name = if name.is_empty() { "restored" } else { name };
    candidates(name)
        .find(|candidate| !taken.iter().any(|t| t.eq_ignore_ascii_case(candidate)))
        .unwrap()
}

/// Restores a file, event, contact or script. `Ok(None)` once restored;
/// `Ok(Some(reason))` when it can't be, and stays archived.
pub(crate) async fn restore_other(
    server: &Server,
    task: &TaskRestoreArchivedItem,
    item_id: Id,
    item: &ArchivedItem,
    extra: Option<Extra>,
) -> trc::Result<Option<String>> {
    let account_id = task.account_id.document_id();
    let access_token = server.access_token(account_id).await?.build();
    let account = server.account(account_id).await?;
    let changed_by = access_token.account_tenant_ids();
    let hash = &task.blob_id.hash;

    let Some(bytes) = server
        .blob_store()
        .get_blob(hash.as_slice(), 0..usize::MAX)
        .await?
    else {
        return Ok(Some("The kept copy is gone.".into()));
    };

    // UD-10: a restore counts against quota like anything new
    if server
        .has_available_quota(&account, bytes.len() as u64)
        .await
        .is_err()
    {
        return Ok(Some(
            "Not restored: the account or its tenant is over quota.".into(),
        ));
    }

    let mut batch = BatchBuilder::new();
    match (item, extra) {
        (ArchivedItem::FileNode(archived), extra) => {
            let (parent_id, name, media_type) = match extra {
                Some(Extra::FileNode {
                    parent_id,
                    name,
                    media_type,
                    ..
                }) => (parent_id.unwrap_or(0), name, media_type),
                _ => (0, archived.name.clone(), None),
            };
            let resources = server
                .fetch_dav_resources(account_id, account_id, SyncCollection::FileNode)
                .await?;
            // Back to its folder if that still exists, else the root
            let parent_id = if parent_id > 0
                && resources.container_resource_by_id(parent_id - 1).is_some()
            {
                parent_id
            } else {
                0
            };
            let parent = parent_id.checked_sub(1);
            let name = free(&name, &names_under(&resources, parent));
            let document_id = server
                .store()
                .assign_document_ids(account_id, Collection::FileNode, 1)
                .await?;
            FileNode {
                parent_id,
                name,
                file: Some(FileProperties {
                    blob_hash: hash.clone(),
                    size: bytes.len() as u32,
                    media_type,
                    executable: false,
                }),
                created: archived.created_at.timestamp(),
                ..Default::default()
            }
            .insert(changed_by, account_id, document_id, false, true, &mut batch)?;
        }
        (ArchivedItem::CalendarEvent(_), extra) => {
            let Entry::ICalendar(ical) = Parser::new(&String::from_utf8_lossy(&bytes)).entry()
            else {
                return Ok(Some("The kept event can't be read.".into()));
            };
            let (calendar_ids, name) = match extra {
                Some(Extra::CalendarEvent { calendar_ids, name }) => (calendar_ids, name),
                _ => (vec![], String::new()),
            };
            let resources = server
                .fetch_dav_resources(account_id, account_id, SyncCollection::Calendar)
                .await?;
            // Back to its calendar if that still exists, else the default
            let calendar_id = match calendar_ids
                .into_iter()
                .find(|id| resources.container_resource_by_id(*id).is_some())
            {
                Some(id) => id,
                None => match server
                    .get_or_create_default_calendar(account_id, account_id)
                    .await?
                {
                    Some(id) => id,
                    None => return Ok(Some("The account has no calendar.".into())),
                },
            };
            let name = free(&name, &names_under(&resources, Some(calendar_id)));
            let mut next_alarm = None;
            let event = CalendarEvent {
                names: vec![DavName {
                    name,
                    parent_id: calendar_id,
                }],
                data: CalendarEventData::new(
                    ical,
                    Tz::Floating,
                    server.core.groupware.max_ical_instances,
                    &mut next_alarm,
                ),
                size: bytes.len() as u32,
                ..Default::default()
            };
            let document_id = server
                .store()
                .assign_document_ids(account_id, Collection::CalendarEvent, 1)
                .await?;
            event.insert(changed_by, account_id, document_id, next_alarm, &mut batch)?;
        }
        (ArchivedItem::ContactCard(_), extra) => {
            let Entry::VCard(card) = Parser::new(&String::from_utf8_lossy(&bytes)).entry() else {
                return Ok(Some("The kept contact can't be read.".into()));
            };
            let (address_book_ids, name) = match extra {
                Some(Extra::ContactCard {
                    address_book_ids,
                    name,
                }) => (address_book_ids, name),
                _ => (vec![], String::new()),
            };
            let resources = server
                .fetch_dav_resources(account_id, account_id, SyncCollection::AddressBook)
                .await?;
            // Back to its address book if that still exists, else the first
            let book_id = match address_book_ids
                .into_iter()
                .find(|id| resources.container_resource_by_id(*id).is_some())
            {
                Some(id) => id,
                None => match resources.document_ids(true).next() {
                    Some(id) => id,
                    None => match server.create_default_addressbook(&account, &account).await? {
                        Some(id) => id,
                        None => return Ok(Some("The account has no address book.".into())),
                    },
                },
            };
            let name = free(&name, &names_under(&resources, Some(book_id)));
            let document_id = server
                .store()
                .assign_document_ids(account_id, Collection::ContactCard, 1)
                .await?;
            ContactCard {
                names: vec![DavName {
                    name,
                    parent_id: book_id,
                }],
                card,
                size: bytes.len() as u32,
                ..Default::default()
            }
            .insert(changed_by, account_id, document_id, &mut batch)?;
        }
        (ArchivedItem::SieveScript(archived), _) => {
            // Back as an inactive script, never activated (UD-8)
            let mut name = None;
            for candidate in candidates(&archived.name).take(100) {
                if server
                    .sieve_script_get_by_name(account_id, &candidate)
                    .await?
                    .is_none()
                {
                    name = Some(candidate);
                    break;
                }
            }
            let Some(name) = name else {
                return Ok(Some("No free script name.".into()));
            };
            let document_id = server
                .store()
                .assign_document_ids(account_id, Collection::SieveScript, 1)
                .await?;
            batch
                .with_account_id(account_id)
                .with_collection(Collection::SieveScript)
                .with_document(document_id)
                .custom(
                    common::storage::index::ObjectIndexBuilder::<(), _>::new()
                        .with_changes(
                            SieveScript::new(name, hash.clone()).with_size(bytes.len() as u32),
                        )
                        .with_changed_by(changed_by),
                )
                .caused_by(trc::location!())?;
        }
        (ArchivedItem::Email(_), _) => return Ok(Some("Not an email restore.".into())),
    }
    server.commit_batch(batch).await?;

    // UD-9: the record goes once the item is back
    undelete::records::remove(&server.core.storage.data, server.registry(), item_id, item)
        .await?;
    Ok(None)
}

/// The result of a restore that couldn't happen: the item stays archived,
/// and a new request can try again (UD-10).
pub(crate) async fn not_restored(server: &Server, item_id: Id, reason: String) -> trc::Result<TaskResult> {
    let mut batch = BatchBuilder::new();
    undelete::data::clear_restore_requested(&mut batch, item_id);
    server.core.storage.data.write(batch.build_all()).await?;
    Ok(TaskResult::permanent(reason))
}
