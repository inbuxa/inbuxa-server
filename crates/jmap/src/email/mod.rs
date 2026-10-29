/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use email::message::ingest::IngestedEmail;
use jmap_proto::{
    error::set::SetError,
    object::email::{EmailProperty, EmailValue},
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map, Value};
use types::{id::Id, keyword::Keyword};

pub mod copy;
pub mod get;
pub mod import;
pub mod parse;
pub mod query;
pub mod set;
pub mod snippet;

fn ingested_into_object(email: IngestedEmail) -> Map<'static, EmailProperty, EmailValue> {
    Map::with_capacity(3)
        .with_key_value(
            EmailProperty::Id,
            Id::from_parts(email.thread_id, email.document_id),
        )
        .with_key_value(EmailProperty::ThreadId, Id::from(email.thread_id))
        .with_key_value(EmailProperty::BlobId, email.blob_id)
        .with_key_value(EmailProperty::Size, email.size)
}

pub(crate) enum PatchResult<'x> {
    SetKeyword(&'x Keyword),
    RemoveKeyword(&'x Keyword),
    AddMailbox(u32),
    RemoveMailbox(u32),
    Invalid(SetError<EmailProperty>),
}

/// inbuxa: the error for a keyword that is not a valid name (RFC 8621
/// section 4.1.1), which would otherwise reach IMAP clients unescaped
pub(crate) fn invalid_keyword() -> SetError<EmailProperty> {
    SetError::invalid_properties()
        .with_property(EmailProperty::Keywords)
        .with_description("Keywords must be 1 to 255 printable ASCII characters without spaces or ( ) { ] % * \" \\.")
}

pub(crate) fn handle_email_patch<'x>(
    pointer: &'x JsonPointer<EmailProperty>,
    value: Value<'_, EmailProperty, EmailValue>,
) -> PatchResult<'x> {
    let mut pointer_iter = pointer.iter();

    match (pointer_iter.next(), pointer_iter.next()) {
        (
            Some(JsonPointerItem::Key(Key::Property(EmailProperty::Keywords))),
            Some(JsonPointerItem::Key(Key::Property(EmailProperty::Keyword(keyword)))),
        ) => match value {
            Value::Bool(true) => return PatchResult::SetKeyword(keyword),
            Value::Bool(false) | Value::Null => return PatchResult::RemoveKeyword(keyword),
            _ => (),
        },
        (
            Some(JsonPointerItem::Key(Key::Property(EmailProperty::MailboxIds))),
            Some(JsonPointerItem::Key(Key::Property(EmailProperty::IdValue(id)))),
        ) => match value {
            Value::Bool(true) => return PatchResult::AddMailbox(id.document_id()),
            Value::Bool(false) | Value::Null => {
                return PatchResult::RemoveMailbox(id.document_id());
            }
            _ => (),
        },
        _ => (),
    }

    PatchResult::Invalid(
        SetError::invalid_properties()
            .with_property(EmailProperty::Pointer(pointer.clone()))
            .with_description("Invalid patch value".to_string()),
    )
}
