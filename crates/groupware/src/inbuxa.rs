/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Undelete notes for files, calendar events and contacts deleted for good
//! (`docs/spec/features/undelete.md`, UD-1). The rules are in
//! `inbuxa_features::undelete`.

use crate::{calendar::CalendarEvent, contact::ContactCard, file::FileNode};
use inbuxa_features::undelete::{
    data::Extra,
    groupware::{Kind, Note, note},
};
use registry::schema::{
    enums::IndexDocumentType,
    structs::{Task, TaskIndexDocument, TaskStatus},
};
use store::write::BatchBuilder;

/// A file (not a folder) deleted for good.
pub fn note_file(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    node: &FileNode,
) -> trc::Result<()> {
    let Some(file) = &node.file else {
        return Ok(());
    };
    // Files aren't search-indexed, so nothing else schedules the task that
    // archives the note: schedule it here
    batch.schedule_task(Task::UnindexDocument(TaskIndexDocument {
        account_id: account_id.into(),
        document_id: document_id.into(),
        document_type: IndexDocumentType::File,
        status: TaskStatus::now(),
    }));
    note(
        batch,
        Kind::File,
        account_id,
        document_id,
        Note {
            deleted_at: 0,
            created_at: node.created,
            content: None,
            blob_hash: Some(file.blob_hash.as_slice().to_vec()),
            extra: Extra::FileNode {
                parent_id: Some(node.parent_id),
                name: node.name.clone(),
                media_type: file.media_type.clone(),
                size: file.size,
            },
        },
    )
}

/// A calendar event deleted for good.
pub fn note_event(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    event: &CalendarEvent,
) -> trc::Result<()> {
    note(
        batch,
        Kind::CalendarEvent,
        account_id,
        document_id,
        Note {
            deleted_at: 0,
            created_at: event.created,
            content: Some(event.data.event.to_string()),
            blob_hash: None,
            extra: Extra::CalendarEvent {
                calendar_ids: event.names.iter().map(|n| n.parent_id).collect(),
                name: event.names.first().map(|n| n.name.clone()).unwrap_or_default(),
            },
        },
    )
}

/// A contact deleted for good.
pub fn note_card(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    card: &ContactCard,
) -> trc::Result<()> {
    note(
        batch,
        Kind::ContactCard,
        account_id,
        document_id,
        Note {
            deleted_at: 0,
            created_at: card.created,
            content: Some(card.card.to_string()),
            blob_hash: None,
            extra: Extra::ContactCard {
                address_book_ids: card.names.iter().map(|n| n.parent_id).collect(),
                name: card.names.first().map(|n| n.name.clone()).unwrap_or_default(),
            },
        },
    )
}
