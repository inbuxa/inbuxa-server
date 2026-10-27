/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Core, Server};
use email::message::metadata::MetadataRow;
use groupware::{calendar::CalendarEventContent, contact::ContactCardContent};
use store::{
    ValueKey,
    search::IndexDocument,
    write::{Archive, ArchiveBytes, SearchIndex},
};
use trc::AddContext;
use types::{
    collection::Collection,
    field::{CalendarEventField, ContactField},
};

pub(crate) fn is_email_indexed(server: &Server) -> bool {
    server
        .core
        .email
        .index_fields
        .contains_key(&SearchIndex::Email)
}

pub(crate) async fn build_email_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
    row: MetadataRow,
) -> trc::Result<IndexDocument> {
    let metadata = row.unarchive().caused_by(trc::location!())?;
    let raw_message = server
        .blob_store()
        .get_blob(metadata.blob_hash().as_slice(), 0..usize::MAX)
        .await
        .caused_by(trc::location!())?
        .ok_or_else(|| {
            trc::StoreEvent::NotFound
                .into_err()
                .details("Blob not found")
        })?;

    if !metadata.has_extractable_attachments() {
        return email_document(&server.core, &row, account_id, document_id, &raw_message);
    }

    let core = server.core.clone();
    tokio::task::spawn_blocking(move || {
        email_document(&core, &row, account_id, document_id, &raw_message)
    })
    .await
    .map_err(|err| {
        trc::EventType::Server(trc::ServerEvent::ThreadError)
            .reason(err)
            .details("Email indexing task failed")
            .caused_by(trc::location!())
    })?
}

fn email_document(
    core: &Core,
    row: &MetadataRow,
    account_id: u32,
    document_id: u32,
    raw_message: &[u8],
) -> trc::Result<IndexDocument> {
    let index_fields = core
        .email
        .index_fields
        .get(&SearchIndex::Email)
        .ok_or_else(|| trc::StoreEvent::UnexpectedError.into_err())?;
    let headers = row.raw_headers().caused_by(trc::location!())?;
    Ok(row.unarchive().caused_by(trc::location!())?.index_document(
        account_id,
        document_id,
        &headers,
        raw_message,
        index_fields,
        core.email.default_language,
        &core.email.extract_limits,
    ))
}

pub(crate) async fn build_calendar_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Calendar) else {
        return Ok(None);
    };

    match server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
            account_id,
            Collection::CalendarEvent,
            document_id,
            CalendarEventField::Content,
        ))
        .await?
    {
        Some(metadata_) => Ok(Some(
            metadata_
                .unarchive::<CalendarEventContent>()
                .caused_by(trc::location!())?
                .index_document(
                    account_id,
                    document_id,
                    index_fields,
                    server.core.email.default_language,
                ),
        )),
        None => Ok(None),
    }
}

pub(crate) async fn build_contact_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Contacts) else {
        return Ok(None);
    };

    match server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
            account_id,
            Collection::ContactCard,
            document_id,
            ContactField::Content,
        ))
        .await?
    {
        Some(metadata_) => Ok(Some(
            metadata_
                .unarchive::<ContactCardContent>()
                .caused_by(trc::location!())?
                .index_document(
                    account_id,
                    document_id,
                    index_fields,
                    server.core.email.default_language,
                ),
        )),
        None => Ok(None),
    }
}


#[cfg(not(feature = "enterprise"))]
pub(crate) async fn build_tracing_span_document(
    _: &Server,
    _: u64,
) -> trc::Result<Option<IndexDocument>> {
    Ok(None)
}
