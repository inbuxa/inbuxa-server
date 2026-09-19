/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Deleted email (UD-1, UD-4, UD-5).
//!
//! Every way of deleting mail for good (JMAP, IMAP, POP3, Trash emptying,
//! mailbox removal) ends by scheduling the message's data for removal. At the
//! deletion itself, while its mailboxes and keywords are still known, a note
//! is made if archiving is on, fixing the deadline then. When the data is
//! finally removed, a noted message becomes an archived item.

use crate::undelete::{
    data::{self, EmailNote, Extra},
    records,
};
use registry::{
    schema::structs::{ArchivedEmail, ArchivedItem},
    types::datetime::UTCDateTime,
};
use store::{
    RegistryStore, Store,
    write::{BatchBuilder, now},
};
use types::{blob::BlobId, blob_hash::BlobHash};

/// Notes a deleted message, when archiving is on (`retention` seconds).
pub fn note(
    batch: &mut BatchBuilder,
    retention: u64,
    account_id: u32,
    document_id: u32,
    size: u64,
    mailboxes: Vec<u32>,
    keywords: Vec<String>,
) -> trc::Result<()> {
    let archived_at = now();
    data::note_email(
        batch,
        account_id,
        document_id,
        &EmailNote {
            archived_at,
            archived_until: archived_at + retention,
            size,
            mailboxes,
            keywords,
        },
    )
}

/// The keywords a restored message gets back: all it had, except
/// `$deleted`, which would only have it expunged again.
pub fn keywords_to_keep(keywords: impl IntoIterator<Item = String>) -> Vec<String> {
    keywords
        .into_iter()
        .filter(|keyword| !keyword.eq_ignore_ascii_case("$deleted"))
        .collect()
}

/// What the message's stored summary says, for the archived record.
pub struct Summary<'x> {
    pub blob_hash: BlobHash,
    pub from: Option<&'x str>,
    pub subject: Option<&'x str>,
    pub received_at: u64,
}

/// A message's data is being removed: if it was noted at deletion, it
/// becomes an archived item, and its kept copy is held until the deadline.
/// Returns whether it was archived.
pub async fn archive(
    data: &Store,
    registry: &RegistryStore,
    account_id: u32,
    document_id: u32,
    summary: Summary<'_>,
) -> trc::Result<bool> {
    let Some(note) = data::email_note(data, account_id, document_id).await? else {
        return Ok(false);
    };
    let item = ArchivedItem::Email(ArchivedEmail {
        from: summary.from.unwrap_or_default().to_string(),
        subject: summary.subject.unwrap_or_default().to_string(),
        received_at: UTCDateTime::from_timestamp(summary.received_at as i64),
        size: note.size,
        account_id: types::id::Id::from(account_id),
        archived_at: UTCDateTime::from_timestamp(note.archived_at as i64),
        archived_until: UTCDateTime::from_timestamp(note.archived_until as i64),
        blob_id: BlobId::new(summary.blob_hash, Default::default()),
    });
    records::insert(
        data,
        registry,
        &item,
        &Extra::Email {
            mailboxes: note.mailboxes,
            keywords: note.keywords,
        },
    )
    .await?;

    let mut batch = BatchBuilder::new();
    data::clear_email_note(&mut batch, account_id, document_id);
    data.write(batch.build_all()).await.map(|_| true)
}

/// Where a restored message goes (UD-8): back into the mailboxes it was in
/// that still exist. Trash only if Trash is all it was in; otherwise the
/// others. Into `inbox` if none are left.
pub fn restore_mailboxes(
    original: &[u32],
    exists: impl Fn(u32) -> bool,
    inbox: u32,
    trash: u32,
) -> Vec<u32> {
    let only_trash = original.len() == 1 && original[0] == trash;
    let mailboxes = original
        .iter()
        .copied()
        .filter(|id| exists(*id) && (only_trash || *id != trash))
        .collect::<Vec<_>>();
    if mailboxes.is_empty() {
        vec![inbox]
    } else {
        mailboxes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INBOX: u32 = 0;
    const TRASH: u32 = 1;

    #[test]
    fn back_where_it_was() {
        // Acceptance test 4: both labels come back
        assert_eq!(
            restore_mailboxes(&[0, 7], |_| true, INBOX, TRASH),
            vec![0, 7]
        );
        // Acceptance test 5: mailboxes gone, so Inbox
        assert_eq!(
            restore_mailboxes(&[7, 8], |_| false, INBOX, TRASH),
            vec![INBOX]
        );
        assert_eq!(
            restore_mailboxes(&[7, 8], |id| id == 8, INBOX, TRASH),
            vec![8]
        );
    }

    #[test]
    fn trash_only_if_that_was_all() {
        assert_eq!(
            restore_mailboxes(&[TRASH], |_| true, INBOX, TRASH),
            vec![TRASH]
        );
        assert_eq!(
            restore_mailboxes(&[TRASH, 7], |_| true, INBOX, TRASH),
            vec![7]
        );
        assert_eq!(restore_mailboxes(&[], |_| true, INBOX, TRASH), vec![INBOX]);
    }

    #[test]
    fn deleted_keyword_isnt_kept() {
        assert_eq!(
            keywords_to_keep(["$seen".to_string(), "$Deleted".to_string()]),
            vec!["$seen".to_string()]
        );
    }
}
