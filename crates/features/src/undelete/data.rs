/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What undelete keeps in the fork's own subspace (`store::SUBSPACE_INBUXA`).
//! Every key starts with `U`, then one byte for the kind:
//!
//! - `n` + account + document: a deleted email waiting for its archive
//!   record, with what only the deletion knows (mailboxes, keywords, size)
//!   and the deadline fixed then (UD-4, UD-5).
//! - `x` + item id: what restoring an archived item needs beyond the kept
//!   copy (UD-4, UD-8).
//! - `b` + account + blob hash: the item a kept copy belongs to, since the
//!   restore task names only the blob.
//! - `r` + item id: present while a restore is asked for (UD-11).
//! - `c` + account + change id: one change to the account's archive, for
//!   `/changes`.
//! - `k` + account id: a deleted account kept for its period (UD-15a).
//! - `a` + address: an address a kept account holds reserved (UD-16).
//!
//! Values are JSON, so they read back across versions of the fork.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize, de::DeserializeOwned};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::id::Id;

const FEATURE: u8 = b'U';
const KIND_NOTE: u8 = b'n';
const KIND_EXTRA: u8 = b'x';
const KIND_BLOB: u8 = b'b';
const KIND_RESTORE: u8 = b'r';
const KIND_CHANGE: u8 = b'c';
const KIND_KEPT: u8 = b'k';
const KIND_RESERVED: u8 = b'a';

fn class(kind: u8, rest: &[u8]) -> ValueClass {
    let mut key = Vec::with_capacity(2 + rest.len());
    key.push(FEATURE);
    key.push(kind);
    key.extend_from_slice(rest);
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

fn key(kind: u8, rest: &[u8]) -> ValueKey<ValueClass> {
    ValueKey::from(class(kind, rest))
}

/// A value stored as JSON.
pub struct Json<T>(pub T);

impl<T: SerdeSerialize> Serialize for Json<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(&self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to serialize undelete record")
                .reason(err)
        })
    }
}

impl<T: DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid undelete record")
                .reason(err)
        })
    }
}

async fn get<T: DeserializeOwned + Sync + Send + 'static>(
    data: &Store,
    key: ValueKey<ValueClass>,
) -> trc::Result<Option<T>> {
    data.get_value::<Json<T>>(key)
        .await
        .map(|value| value.map(|Json(value)| value))
        .caused_by(trc::location!())
}

fn set<T: SerdeSerialize>(
    batch: &mut BatchBuilder,
    class: ValueClass,
    value: &T,
) -> trc::Result<()> {
    batch.set(class, Json(value).serialize()?);
    Ok(())
}

fn account_document(account_id: u32, document_id: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&account_id.to_be_bytes());
    out[4..].copy_from_slice(&document_id.to_be_bytes());
    out
}

fn account_blob(account_id: u32, blob_hash: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + blob_hash.len());
    out.extend_from_slice(&account_id.to_be_bytes());
    out.extend_from_slice(blob_hash);
    out
}

/// A deleted email, noted at deletion for the archive record made when its
/// data is finally removed.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
pub struct EmailNote {
    /// When it was deleted, as a Unix timestamp.
    pub archived_at: u64,
    /// When the kept copy goes, fixed at deletion (UD-5).
    pub archived_until: u64,
    pub size: u64,
    pub mailboxes: Vec<u32>,
    pub keywords: Vec<String>,
}

/// What restore needs beyond the kept copy (UD-4, UD-8).
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(tag = "kind")]
pub enum Extra {
    Email {
        mailboxes: Vec<u32>,
        keywords: Vec<String>,
    },
    FileNode {
        parent_id: Option<u32>,
        name: String,
        media_type: Option<String>,
        #[serde(default)]
        size: u32,
    },
    CalendarEvent {
        calendar_ids: Vec<u32>,
        name: String,
    },
    ContactCard {
        address_book_ids: Vec<u32>,
        name: String,
    },
    SieveScript {
        name: String,
    },
}

/// A deleted account, kept for its period (UD-15a).
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
pub struct KeptAccount {
    /// The `x:Account` record as it was, pickled.
    pub record: Vec<u8>,
    pub name: String,
    pub addresses: Vec<String>,
    pub member_tenant_id: Option<u64>,
    pub deleted_at: u64,
    pub kept_until: u64,
}

pub fn note_email(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: u32,
    note: &EmailNote,
) -> trc::Result<()> {
    set(
        batch,
        class(KIND_NOTE, &account_document(account_id, document_id)),
        note,
    )
}

pub async fn email_note(
    data: &Store,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<EmailNote>> {
    get(
        data,
        key(KIND_NOTE, &account_document(account_id, document_id)),
    )
    .await
}

pub fn clear_email_note(batch: &mut BatchBuilder, account_id: u32, document_id: u32) {
    batch.clear(class(KIND_NOTE, &account_document(account_id, document_id)));
}

pub fn set_extra(batch: &mut BatchBuilder, item_id: Id, extra: &Extra) -> trc::Result<()> {
    set(batch, class(KIND_EXTRA, &item_id.id().to_be_bytes()), extra)
}

pub async fn extra(data: &Store, item_id: Id) -> trc::Result<Option<Extra>> {
    get(data, key(KIND_EXTRA, &item_id.id().to_be_bytes())).await
}

pub fn clear_extra(batch: &mut BatchBuilder, item_id: Id) {
    batch.clear(class(KIND_EXTRA, &item_id.id().to_be_bytes()));
}

pub fn set_blob_item(batch: &mut BatchBuilder, account_id: u32, blob_hash: &[u8], item_id: Id) {
    batch.set(
        class(KIND_BLOB, &account_blob(account_id, blob_hash)),
        item_id.id().to_be_bytes().to_vec(),
    );
}

pub async fn blob_item(data: &Store, account_id: u32, blob_hash: &[u8]) -> trc::Result<Option<Id>> {
    data.get_value::<u64>(key(KIND_BLOB, &account_blob(account_id, blob_hash)))
        .await
        .map(|id| id.map(Id::new))
        .caused_by(trc::location!())
}

pub fn clear_blob_item(batch: &mut BatchBuilder, account_id: u32, blob_hash: &[u8]) {
    batch.clear(class(KIND_BLOB, &account_blob(account_id, blob_hash)));
}

pub fn set_restore_requested(batch: &mut BatchBuilder, item_id: Id) {
    batch.set(class(KIND_RESTORE, &item_id.id().to_be_bytes()), vec![1]);
}

pub async fn is_restore_requested(data: &Store, item_id: Id) -> trc::Result<bool> {
    data.key_exists(key(KIND_RESTORE, &item_id.id().to_be_bytes()))
        .await
        .caused_by(trc::location!())
}

pub fn clear_restore_requested(batch: &mut BatchBuilder, item_id: Id) {
    batch.clear(class(KIND_RESTORE, &item_id.id().to_be_bytes()));
}

/// What a change did to an archived item, for `/changes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Change {
    Created = 0,
    Updated = 1,
    Destroyed = 2,
}

fn change_rest(account_id: u32, change_id: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&account_id.to_be_bytes());
    out[4..].copy_from_slice(&change_id.to_be_bytes());
    out
}

pub fn log_change(
    batch: &mut BatchBuilder,
    account_id: u32,
    change_id: u64,
    item_id: Id,
    change: Change,
) {
    let mut value = Vec::with_capacity(9);
    value.extend_from_slice(&item_id.id().to_be_bytes());
    value.push(change as u8);
    batch.set(
        class(KIND_CHANGE, &change_rest(account_id, change_id)),
        value,
    );
}

/// The account's changes after `since`, oldest first, each with its id.
pub async fn changes_since(
    data: &Store,
    account_id: u32,
    since: u64,
) -> trc::Result<Vec<(u64, Id, Change)>> {
    let mut changes = Vec::new();
    data.iterate(
        IterateParams::new(
            key(
                KIND_CHANGE,
                &change_rest(account_id, since.saturating_add(1)),
            ),
            key(KIND_CHANGE, &change_rest(account_id, u64::MAX)),
        )
        .ascending(),
        |key, value| {
            if key.len() >= 8 && value.len() == 9 {
                let change = match value[8] {
                    0 => Change::Created,
                    1 => Change::Updated,
                    _ => Change::Destroyed,
                };
                changes.push((
                    u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap()),
                    Id::new(u64::from_be_bytes(value[0..8].try_into().unwrap())),
                    change,
                ));
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(changes)
}

/// The account's latest change id, 0 when there's none.
pub async fn latest_change(data: &Store, account_id: u32) -> trc::Result<u64> {
    let mut latest = 0;
    data.iterate(
        IterateParams::new(
            key(KIND_CHANGE, &change_rest(account_id, 0)),
            key(KIND_CHANGE, &change_rest(account_id, u64::MAX)),
        )
        .descending()
        .only_first()
        .no_values(),
        |key, _| {
            if key.len() >= 8 {
                latest = u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap());
            }
            Ok(false)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(latest)
}

pub fn set_kept_account(
    batch: &mut BatchBuilder,
    account_id: u32,
    kept: &KeptAccount,
) -> trc::Result<()> {
    set(batch, class(KIND_KEPT, &account_id.to_be_bytes()), kept)?;
    for address in &kept.addresses {
        batch.set(
            class(KIND_RESERVED, address.to_lowercase().as_bytes()),
            account_id.to_be_bytes().to_vec(),
        );
    }
    Ok(())
}

pub async fn kept_account(data: &Store, account_id: u32) -> trc::Result<Option<KeptAccount>> {
    get(data, key(KIND_KEPT, &account_id.to_be_bytes())).await
}

pub fn clear_kept_account(batch: &mut BatchBuilder, account_id: u32, kept: &KeptAccount) {
    batch.clear(class(KIND_KEPT, &account_id.to_be_bytes()));
    for address in &kept.addresses {
        batch.clear(class(KIND_RESERVED, address.to_lowercase().as_bytes()));
    }
}

/// Every kept account, as (id, kept).
pub async fn kept_accounts(data: &Store) -> trc::Result<Vec<(u32, KeptAccount)>> {
    let mut kept = Vec::new();
    data.iterate(
        IterateParams::new(
            key(KIND_KEPT, &0u32.to_be_bytes()),
            key(KIND_KEPT, &u32::MAX.to_be_bytes()),
        )
        .ascending(),
        |key, value| {
            if key.len() >= 4
                && let Ok(Json(account)) = Json::<KeptAccount>::deserialize(value)
            {
                kept.push((
                    u32::from_be_bytes(key[key.len() - 4..].try_into().unwrap()),
                    account,
                ));
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(kept)
}

/// The kept account an address is reserved for (UD-16).
pub async fn reserved_by(data: &Store, address: &str) -> trc::Result<Option<u32>> {
    data.get_value::<u32>(key(KIND_RESERVED, address.to_lowercase().as_bytes()))
        .await
        .caused_by(trc::location!())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip() {
        let extra = Extra::Email {
            mailboxes: vec![0, 7],
            keywords: vec!["$seen".into(), "$flagged".into()],
        };
        let bytes = Json(&extra).serialize().unwrap();
        assert_eq!(Json::<Extra>::deserialize(&bytes).unwrap().0, extra);

        let note = EmailNote {
            archived_at: 1,
            archived_until: 2,
            size: 3,
            mailboxes: vec![1],
            keywords: vec![],
        };
        let bytes = Json(&note).serialize().unwrap();
        assert_eq!(Json::<EmailNote>::deserialize(&bytes).unwrap().0, note);
    }
}
