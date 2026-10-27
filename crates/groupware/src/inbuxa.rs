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
use store::write::BatchBuilder;

/// A file (not a folder) deleted for good.
pub fn note_file(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    node: &FileNode,
) -> trc::Result<()> {
    let Some(file) = node.file() else {
        return Ok(());
    };
    // 1.0 search-indexes files, so deleting one queues the unindex that
    // archives the note
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

/// A calendar event deleted for good. `ical` is its content, which 1.0
/// keeps apart from the event's record.
pub fn note_event(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    event: &CalendarEvent,
    ical: Option<String>,
) -> trc::Result<()> {
    note(
        batch,
        Kind::CalendarEvent,
        account_id,
        document_id,
        Note {
            deleted_at: 0,
            created_at: event.created,
            content: ical,
            blob_hash: None,
            extra: Extra::CalendarEvent {
                calendar_ids: event.names.iter().map(|n| n.parent_id).collect(),
                name: event.names.first().map(|n| n.name.clone()).unwrap_or_default(),
            },
        },
    )
}

/// A contact deleted for good. `vcard` is its content, which 1.0 keeps
/// apart from the card's record.
pub fn note_card(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    card: &ContactCard,
    vcard: Option<String>,
) -> trc::Result<()> {
    note(
        batch,
        Kind::ContactCard,
        account_id,
        document_id,
        Note {
            deleted_at: 0,
            created_at: card.created,
            content: vcard,
            blob_hash: None,
            extra: Extra::ContactCard {
                address_book_ids: card.names.iter().map(|n| n.parent_id).collect(),
                name: card.names.first().map(|n| n.name.clone()).unwrap_or_default(),
            },
        },
    )
}
