/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What the fork keeps beside upstream's `x:MaskedEmail` record, in its own
//! subspace (`store::SUBSPACE_INBUXA`). Every key starts with `M`, so other
//! fork features can share the subspace. After it, one byte names the kind:
//!
//! - `m` + mask id: the mask's `Record` (state, last mail, pending deadline).
//!   Missing for masks written before the fork, whose state comes from
//!   upstream's `enabled`.
//! - `a` + address: `AddressEntry`, the mask an address belongs to. Kept
//!   after the mask is destroyed, as a tombstone, so the address is never
//!   issued again (ME-3, ME-13).
//! - `c` + account id + change id: one change to one of the account's masks,
//!   for `/changes`.
//! - `i`: present once masks written before the fork are indexed.

use crate::masked_email::State;
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::id::Id;

const FEATURE: u8 = b'M';
const KIND_RECORD: u8 = b'm';
const KIND_ADDRESS: u8 = b'a';
const KIND_CHANGE: u8 = b'c';
const KIND_INDEXED: u8 = b'i';

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

/// The fork's record of one mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub state: State,
    /// When mail last arrived through the mask, as a Unix timestamp (ME-7).
    pub last_message_at: Option<u64>,
    /// For a pending mask, when it's removed if no mail arrives (ME-8).
    pub pending_until: Option<u64>,
}

impl Serialize for Record {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(17);
        out.push(self.state as u8);
        out.extend_from_slice(&self.last_message_at.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.pending_until.unwrap_or(0).to_be_bytes());
        Ok(out)
    }
}

impl Deserialize for Record {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let corrupt = || {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid masked email record")
                .caused_by(trc::location!())
        };
        if bytes.len() != 17 {
            return Err(corrupt());
        }
        let state = State::from_u8(bytes[0]).ok_or_else(corrupt)?;
        let u64_at = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
        Ok(Record {
            state,
            last_message_at: Some(u64_at(1)).filter(|v| *v != 0),
            pending_until: Some(u64_at(9)).filter(|v| *v != 0),
        })
    }
}

/// The mask an address belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressEntry {
    pub mask_id: Id,
    pub account_id: u32,
    /// False once the mask is destroyed: the entry is then a tombstone.
    pub live: bool,
}

impl Serialize for AddressEntry {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(13);
        out.extend_from_slice(&self.mask_id.id().to_be_bytes());
        out.extend_from_slice(&self.account_id.to_be_bytes());
        out.push(self.live as u8);
        Ok(out)
    }
}

impl Deserialize for AddressEntry {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        if bytes.len() != 13 {
            return Err(trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid masked email address entry")
                .caused_by(trc::location!()));
        }
        Ok(AddressEntry {
            mask_id: Id::new(u64::from_be_bytes(bytes[0..8].try_into().unwrap())),
            account_id: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            live: bytes[12] != 0,
        })
    }
}

/// What a change did to a mask, for `/changes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Change {
    Created = 0,
    Updated = 1,
    Destroyed = 2,
}

/// An address as the index keys it: lowercased.
pub fn normalize(address: &str) -> String {
    address.trim().to_lowercase()
}

pub async fn record(data: &Store, mask_id: Id) -> trc::Result<Option<Record>> {
    data.get_value::<Record>(key(KIND_RECORD, &mask_id.id().to_be_bytes()))
        .await
        .caused_by(trc::location!())
}

pub fn set_record(batch: &mut BatchBuilder, mask_id: Id, record: &Record) -> trc::Result<()> {
    batch.set(
        class(KIND_RECORD, &mask_id.id().to_be_bytes()),
        record.serialize()?,
    );
    Ok(())
}

pub fn clear_record(batch: &mut BatchBuilder, mask_id: Id) {
    batch.clear(class(KIND_RECORD, &mask_id.id().to_be_bytes()));
}

pub async fn address(data: &Store, address: &str) -> trc::Result<Option<AddressEntry>> {
    data.get_value::<AddressEntry>(key(KIND_ADDRESS, normalize(address).as_bytes()))
        .await
        .caused_by(trc::location!())
}

pub fn set_address(
    batch: &mut BatchBuilder,
    address: &str,
    entry: &AddressEntry,
) -> trc::Result<()> {
    batch.set(
        class(KIND_ADDRESS, normalize(address).as_bytes()),
        entry.serialize()?,
    );
    Ok(())
}

pub fn log_change(
    batch: &mut BatchBuilder,
    account_id: u32,
    change_id: u64,
    mask_id: Id,
    change: Change,
) {
    let mut rest = Vec::with_capacity(12);
    rest.extend_from_slice(&account_id.to_be_bytes());
    rest.extend_from_slice(&change_id.to_be_bytes());
    let mut value = Vec::with_capacity(9);
    value.extend_from_slice(&mask_id.id().to_be_bytes());
    value.push(change as u8);
    batch.set(class(KIND_CHANGE, &rest), value);
}

fn change_key(account_id: u32, change_id: u64) -> ValueKey<ValueClass> {
    let mut rest = Vec::with_capacity(12);
    rest.extend_from_slice(&account_id.to_be_bytes());
    rest.extend_from_slice(&change_id.to_be_bytes());
    key(KIND_CHANGE, &rest)
}

/// The account's changes after `since`, oldest first, each with its change
/// id.
pub async fn changes_since(
    data: &Store,
    account_id: u32,
    since: u64,
) -> trc::Result<Vec<(u64, Id, Change)>> {
    let mut changes = Vec::new();
    data.iterate(
        IterateParams::new(
            change_key(account_id, since.saturating_add(1)),
            change_key(account_id, u64::MAX),
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
        IterateParams::new(change_key(account_id, 0), change_key(account_id, u64::MAX))
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

pub async fn is_indexed(data: &Store) -> trc::Result<bool> {
    data.key_exists(key(KIND_INDEXED, &[]))
        .await
        .caused_by(trc::location!())
}

pub fn set_indexed(batch: &mut BatchBuilder) {
    batch.set(class(KIND_INDEXED, &[]), vec![1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip() {
        for record in [
            Record {
                state: State::Pending,
                last_message_at: None,
                pending_until: Some(1_800_000_000),
            },
            Record {
                state: State::Disabled,
                last_message_at: Some(1_700_000_000),
                pending_until: None,
            },
        ] {
            assert_eq!(
                Record::deserialize(&record.serialize().unwrap()).unwrap(),
                record
            );
        }
        let entry = AddressEntry {
            mask_id: Id::new(123456789),
            account_id: 42,
            live: false,
        };
        assert_eq!(
            AddressEntry::deserialize(&entry.serialize().unwrap()).unwrap(),
            entry
        );
    }

    #[test]
    fn addresses_are_lowercased() {
        assert_eq!(
            normalize(" Shop_ab12@Example.ORG "),
            "shop_ab12@example.org"
        );
    }
}
