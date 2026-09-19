/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Deleted files, calendar events and contacts (UD-1, a deliberate
//! extension: upstream archives only email).
//!
//! The code that deletes them for good (over JMAP and WebDAV alike) builds
//! its changes without reaching the settings, so it notes every deletion:
//! the content (a calendar or contact's text, or a file's blob) and where
//! the item lived. The task that then removes the item from the search index
//! archives the note if archiving is on, or drops it.

use crate::undelete::{
    data::{Extra, Json},
    records,
};
use registry::{
    schema::structs::{ArchivedCalendarEvent, ArchivedContactCard, ArchivedFileNode, ArchivedItem},
    types::datetime::UTCDateTime,
};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    RegistryStore, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, now},
};
use types::{blob::BlobId, blob_hash::BlobHash, id::Id};

/// The kinds noted here, as stored in the note's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    File = 0,
    CalendarEvent = 1,
    ContactCard = 2,
}

/// A deleted item, noted at deletion.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
pub struct Note {
    pub deleted_at: u64,
    pub created_at: i64,
    /// A calendar event or contact's text.
    pub content: Option<String>,
    /// A file's content, already a blob.
    pub blob_hash: Option<Vec<u8>>,
    pub extra: Extra,
}

fn note_class(kind: Kind, account_id: u32, document_id: u32) -> ValueClass {
    let mut key = Vec::with_capacity(11);
    key.extend_from_slice(b"Ug");
    key.push(kind as u8);
    key.extend_from_slice(&account_id.to_be_bytes());
    key.extend_from_slice(&document_id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: store::SUBSPACE_INBUXA,
        key,
    })
}

/// Notes an item deleted for good (UD-1).
pub fn note(
    batch: &mut BatchBuilder,
    kind: Kind,
    account_id: u32,
    document_id: u32,
    mut note: Note,
) -> trc::Result<()> {
    note.deleted_at = now();
    batch.set(
        note_class(kind, account_id, document_id),
        Json(&note).serialize()?,
    );
    Ok(())
}

/// Takes an item's note, if it has one.
pub async fn take(
    data: &Store,
    kind: Kind,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<Note>> {
    let class = note_class(kind, account_id, document_id);
    let Some(Json(note)) = data
        .get_value::<Json<Note>>(ValueKey::from(class.clone()))
        .await?
    else {
        return Ok(None);
    };
    let mut batch = BatchBuilder::new();
    batch.clear(class);
    data.write(batch.build_all()).await?;
    Ok(Some(note))
}

/// The value of the first line starting with `name` (as `NAME:` or
/// `NAME;params:`) in iCalendar or vCard text, unfolded.
fn property(text: &str, name: &str) -> Option<String> {
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n')).peekable();
    while let Some(line) = lines.next() {
        let Some(rest) = line
            .get(..name.len())
            .filter(|head| head.eq_ignore_ascii_case(name))
            .map(|_| &line[name.len()..])
        else {
            continue;
        };
        if !(rest.starts_with(':') || rest.starts_with(';')) {
            continue;
        }
        let mut value = rest.split_once(':')?.1.to_string();
        while let Some(next) = lines.peek() {
            if let Some(continued) = next.strip_prefix(' ').or_else(|| next.strip_prefix('\t')) {
                value.push_str(continued);
                lines.next();
            } else {
                break;
            }
        }
        return Some(value.replace("\\,", ",").replace("\\;", ";").replace("\\n", " "));
    }
    None
}

/// An iCalendar date or date-time (`20260918`, `20260918T100000Z`) as a
/// Unix timestamp, read as UTC.
fn ical_time(value: &str) -> Option<i64> {
    let digits = value.trim().trim_end_matches('Z');
    let (date, time) = digits.split_once('T').unwrap_or((digits, "000000"));
    if date.len() != 8 || time.len() < 6 {
        return None;
    }
    let n = |s: &str| s.parse::<i64>().ok();
    let (y, m, d) = (n(&date[..4])?, n(&date[4..6])?, n(&date[6..8])?);
    let (hh, mm, ss) = (n(&time[..2])?, n(&time[2..4])?, n(&time[4..6])?);
    // Days from the civil date (Howard Hinnant's algorithm)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Archives a noted item: holds its kept copy (`blob_hash`) until the
/// deadline and writes its record (UD-1, UD-4, UD-5).
pub async fn archive(
    data: &Store,
    registry: &RegistryStore,
    account_id: u32,
    note: Note,
    blob_hash: BlobHash,
    retention: u64,
) -> trc::Result<Id> {
    let archived_at = now();
    let common = (
        types::id::Id::from(account_id),
        UTCDateTime::from_timestamp(archived_at as i64),
        UTCDateTime::from_timestamp((archived_at + retention) as i64),
        BlobId::new(blob_hash, Default::default()),
        UTCDateTime::from_timestamp(note.created_at),
    );
    let text = note.content.as_deref().unwrap_or_default();
    let item = match &note.extra {
        Extra::FileNode { name, .. } => ArchivedItem::FileNode(ArchivedFileNode {
            name: name.clone(),
            created_at: common.4,
            account_id: common.0,
            archived_at: common.1,
            archived_until: common.2,
            blob_id: common.3,
        }),
        Extra::CalendarEvent { .. } => ArchivedItem::CalendarEvent(ArchivedCalendarEvent {
            title: property(text, "SUMMARY").unwrap_or_default(),
            start_time: property(text, "DTSTART")
                .and_then(|v| ical_time(&v))
                .map(UTCDateTime::from_timestamp),
            created_at: common.4,
            account_id: common.0,
            archived_at: common.1,
            archived_until: common.2,
            blob_id: common.3,
        }),
        Extra::ContactCard { .. } => ArchivedItem::ContactCard(ArchivedContactCard {
            name: property(text, "FN"),
            created_at: common.4,
            account_id: common.0,
            archived_at: common.1,
            archived_until: common.2,
            blob_id: common.3,
        }),
        Extra::Email { .. } | Extra::SieveScript { .. } => {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Not a groupware item"));
        }
    };
    records::insert(data, registry, &item, &note.extra).await
}

/// The names a restored item tries, in order: the original, then with
/// ` (restored)`, then numbered (UD-8).
pub fn candidates(name: &str) -> impl Iterator<Item = String> + '_ {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{ext}")),
        _ => (name, String::new()),
    };
    std::iter::once(name.to_string())
        .chain(std::iter::once(format!("{stem} (restored){ext}")))
        .chain((2u32..).map(move |n| format!("{stem} (restored {n}){ext}")))
}

/// The first free name for a restored item (UD-8).
pub fn free_name(name: &str, is_taken: impl Fn(&str) -> bool) -> String {
    candidates(name).find(|candidate| !is_taken(candidate)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_ical_and_vcard() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Team\r\n  lunch\r\nDTSTART;TZID=X:20260918T120000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert_eq!(property(ics, "SUMMARY").as_deref(), Some("Team lunch"));
        assert_eq!(
            property(ics, "DTSTART").and_then(|v| ical_time(&v)),
            Some(1_789_732_800)
        );
        let vcf = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Jane Doe\r\nEND:VCARD\r\n";
        assert_eq!(property(vcf, "FN").as_deref(), Some("Jane Doe"));
        assert_eq!(property(vcf, "N"), None);
    }

    #[test]
    fn restored_names() {
        assert_eq!(free_name("a.txt", |_| false), "a.txt");
        assert_eq!(free_name("a.txt", |n| n == "a.txt"), "a (restored).txt");
        assert_eq!(
            free_name("a.txt", |n| n == "a.txt" || n == "a (restored).txt"),
            "a (restored 2).txt"
        );
        assert_eq!(free_name("script", |n| n == "script"), "script (restored)");
    }
}

/// Archives a Sieve script deleted for good (UD-1). Its content is already
/// a blob, held from now until the deadline.
pub async fn archive_sieve(
    data: &Store,
    registry: &RegistryStore,
    account_id: u32,
    name: &str,
    content: String,
    blob_hash: BlobHash,
    retention: u64,
) -> trc::Result<Id> {
    let archived_at = now();
    let item = ArchivedItem::SieveScript(registry::schema::structs::ArchivedSieveScript {
        name: name.to_string(),
        created_at: UTCDateTime::from_timestamp(archived_at as i64),
        content,
        account_id: types::id::Id::from(account_id),
        archived_at: UTCDateTime::from_timestamp(archived_at as i64),
        archived_until: UTCDateTime::from_timestamp((archived_at + retention) as i64),
        blob_id: BlobId::new(blob_hash, Default::default()),
    });
    records::insert(
        data,
        registry,
        &item,
        &Extra::SieveScript {
            name: name.to_string(),
        },
    )
    .await
}
