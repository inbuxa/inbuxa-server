/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Operations on masks that combine upstream's record with the fork's.

use crate::masked_email::{
    State,
    data::{self, AddressEntry, Change, Record},
};
use registry::{
    schema::{prelude::ObjectType, structs::MaskedEmail},
    types::id::ObjectId,
};
use store::{
    RegistryStore, Store,
    registry::{
        RegistryQuery,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::{BatchBuilder, now},
};
use trc::AddContext;
use types::id::Id;

/// How long a pending mask waits for its first message (ME-8).
pub const PENDING_FOR_SECS: u64 = 24 * 60 * 60;

/// A mask as both APIs see it.
#[derive(Debug, Clone)]
pub struct Mask {
    pub id: Id,
    pub object: MaskedEmail,
    pub state: State,
    pub expired: bool,
    pub last_message_at: Option<u64>,
}

impl Mask {
    /// Whether mail to it is accepted (ME-4, ME-6).
    pub fn accepts_mail(&self) -> bool {
        self.state.is_live() && !self.expired
    }

    /// Whether it counts against `maxMaskedAddresses` (ME-14).
    pub fn is_counted(&self) -> bool {
        self.accepts_mail()
    }
}

fn is_expired(object: &MaskedEmail, now: u64) -> bool {
    object
        .expires_at
        .is_some_and(|expires| expires.timestamp() <= now as i64)
}

/// Reads a mask, removing it first if it's pending and past its deadline
/// (ME-8). `None` if it doesn't exist or was just removed.
pub async fn load(data: &Store, registry: &RegistryStore, id: Id) -> trc::Result<Option<Mask>> {
    let Some(object) = registry.object::<MaskedEmail>(id).await? else {
        return Ok(None);
    };
    let record = data::record(data, id).await?;
    let state = record
        .map(|r| r.state)
        .unwrap_or_else(|| State::from_upstream(object.enabled));
    let now = now();

    if state == State::Pending
        && record
            .and_then(|r| r.pending_until)
            .is_some_and(|until| until <= now)
    {
        destroy(data, registry, id, &object).await?;
        return Ok(None);
    }

    Ok(Some(Mask {
        id,
        expired: is_expired(&object, now),
        state,
        last_message_at: record.and_then(|r| r.last_message_at),
        object,
    }))
}

/// Every mask an account owns, pending ones past their deadline removed.
pub async fn of_account(
    data: &Store,
    registry: &RegistryStore,
    account_id: u32,
) -> trc::Result<Vec<Mask>> {
    let mut masks = Vec::new();
    for id in registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::MaskedEmail).with_account(account_id))
        .await
        .caused_by(trc::location!())?
    {
        if let Some(mask) = load(data, registry, id).await? {
            masks.push(mask);
        }
    }
    Ok(masks)
}

/// How many masks count against the account's limit (ME-14).
pub async fn live_count(
    data: &Store,
    registry: &RegistryStore,
    account_id: u32,
) -> trc::Result<u64> {
    Ok(of_account(data, registry, account_id)
        .await?
        .iter()
        .filter(|mask| mask.is_counted())
        .count() as u64)
}

/// The mask an address reaches, if mail to it is accepted (ME-4). Masks
/// written before the fork are indexed the first time this runs.
pub async fn resolve(
    data: &Store,
    registry: &RegistryStore,
    address: &str,
) -> trc::Result<Option<Mask>> {
    ensure_indexed(data, registry).await?;
    let Some(entry) = data::address(data, address).await? else {
        return Ok(None);
    };
    if !entry.live {
        return Ok(None);
    }
    match load(data, registry, entry.mask_id).await? {
        Some(mask) if mask.accepts_mail() => Ok(Some(mask)),
        Some(_) => Ok(None),
        None => {
            // Removed without the fork seeing it, e.g. with its account
            let mut batch = BatchBuilder::new();
            data::set_address(
                &mut batch,
                address,
                &AddressEntry {
                    live: false,
                    ..entry
                },
            )?;
            data::clear_record(&mut batch, entry.mask_id);
            data.write(batch.build_all()).await?;
            Ok(None)
        }
    }
}

/// Mail arrived through a mask: `lastMessageAt` moves, and a pending mask
/// becomes enabled (ME-7).
pub async fn delivered(data: &Store, registry: &RegistryStore, mask: &Mask) -> trc::Result<()> {
    let state = if mask.state == State::Pending {
        State::Enabled
    } else {
        mask.state
    };
    let mut batch = BatchBuilder::new();
    data::set_record(
        &mut batch,
        mask.id,
        &Record {
            state,
            last_message_at: Some(now()),
            pending_until: None,
        },
    )?;
    data::log_change(
        &mut batch,
        mask.object.account_id.document_id(),
        registry.assign_id(),
        mask.id,
        Change::Updated,
    );
    data.write(batch.build_all()).await.map(|_| ())
}

/// Records a new mask: its state, its address and the change (ME-7a, ME-8).
pub async fn created(
    data: &Store,
    registry: &RegistryStore,
    id: Id,
    object: &MaskedEmail,
    state: State,
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    data::set_record(
        &mut batch,
        id,
        &Record {
            state,
            last_message_at: None,
            pending_until: (state == State::Pending).then(|| now() + PENDING_FOR_SECS),
        },
    )?;
    data::set_address(
        &mut batch,
        &object.email,
        &AddressEntry {
            mask_id: id,
            account_id: object.account_id.document_id(),
            live: true,
        },
    )?;
    data::log_change(
        &mut batch,
        object.account_id.document_id(),
        registry.assign_id(),
        id,
        Change::Created,
    );
    data.write(batch.build_all()).await.map(|_| ())
}

/// Records a changed mask, and its new state if it has one (ME-1, ME-2).
pub async fn updated(
    data: &Store,
    registry: &RegistryStore,
    mask: &Mask,
    state: State,
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    data::set_record(
        &mut batch,
        mask.id,
        &Record {
            state,
            last_message_at: mask.last_message_at,
            pending_until: if state == State::Pending {
                data::record(data, mask.id)
                    .await?
                    .and_then(|r| r.pending_until)
            } else {
                None
            },
        },
    )?;
    data::log_change(
        &mut batch,
        mask.object.account_id.document_id(),
        registry.assign_id(),
        mask.id,
        Change::Updated,
    );
    data.write(batch.build_all()).await.map(|_| ())
}

/// Records a destroyed mask: its address becomes a tombstone (ME-3).
pub async fn destroyed(
    data: &Store,
    registry: &RegistryStore,
    id: Id,
    object: &MaskedEmail,
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    data::clear_record(&mut batch, id);
    data::set_address(
        &mut batch,
        &object.email,
        &AddressEntry {
            mask_id: id,
            account_id: object.account_id.document_id(),
            live: false,
        },
    )?;
    data::log_change(
        &mut batch,
        object.account_id.document_id(),
        registry.assign_id(),
        id,
        Change::Destroyed,
    );
    data.write(batch.build_all()).await.map(|_| ())
}

/// Removes a mask and tombstones its address (ME-8).
async fn destroy(
    data: &Store,
    registry: &RegistryStore,
    id: Id,
    object: &MaskedEmail,
) -> trc::Result<()> {
    match registry
        .write(RegistryWrite::delete(ObjectId::new(
            ObjectType::MaskedEmail,
            id,
        )))
        .await?
    {
        RegistryWriteResult::Success(_) | RegistryWriteResult::NotFound { .. } => {
            destroyed(data, registry, id, object).await
        }
        _ => Ok(()),
    }
}

/// Indexes the addresses of masks written before the fork, once (the key
/// fact for compatibility: delivery finds a mask by its stored address).
pub async fn ensure_indexed(data: &Store, registry: &RegistryStore) -> trc::Result<()> {
    if data::is_indexed(data).await? {
        return Ok(());
    }
    let mut batch = BatchBuilder::new();
    for id in registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::MaskedEmail))
        .await
        .caused_by(trc::location!())?
    {
        if let Some(object) = registry.object::<MaskedEmail>(id).await?
            && data::address(data, &object.email).await?.is_none()
        {
            data::set_address(
                &mut batch,
                &object.email,
                &AddressEntry {
                    mask_id: id,
                    account_id: object.account_id.document_id(),
                    live: true,
                },
            )?;
        }
        if batch.is_large_batch() {
            data.write(std::mem::take(&mut batch).build_all()).await?;
        }
    }
    data::set_indexed(&mut batch);
    data.write(batch.build_all()).await.map(|_| ())
}

/// Whether an account may send as an address because it's one of the
/// account's live masks (ME-11).
pub async fn sends_as(
    data: &Store,
    registry: &RegistryStore,
    account_id: u32,
    address: &str,
) -> trc::Result<bool> {
    Ok(resolve(data, registry, address)
        .await?
        .is_some_and(|mask| mask.object.account_id.document_id() == account_id))
}

/// Changes to an account's masks since a state, for `/changes`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub created: Vec<Id>,
    pub updated: Vec<Id>,
    pub destroyed: Vec<Id>,
    /// The state after the changes returned.
    pub new_state: u64,
    pub has_more: bool,
}

/// The changes since `since`, at most `max` masks' worth. A mask created and
/// destroyed within the window isn't reported; one created and changed is
/// reported as created.
pub fn collapse(since: u64, entries: &[(u64, Id, Change)], max: usize) -> Changes {
    use ahash::AHashMap;
    let mut state: AHashMap<Id, (bool, bool)> = AHashMap::new(); // (created, destroyed)
    let mut order = Vec::new();
    let mut result = Changes {
        new_state: since,
        ..Default::default()
    };
    for (change_id, id, change) in entries {
        if !state.contains_key(id) {
            if order.len() == max {
                result.has_more = true;
                break;
            }
            order.push(*id);
        }
        let entry = state.entry(*id).or_insert((false, false));
        match change {
            Change::Created => entry.0 = true,
            Change::Destroyed => entry.1 = true,
            Change::Updated => {}
        }
        result.new_state = *change_id;
    }
    for id in order {
        match state[&id] {
            (true, true) => {}
            (true, false) => result.created.push(id),
            (false, true) => result.destroyed.push(id),
            (false, false) => result.updated.push(id),
        }
    }
    result
}

/// What an address is, as far as masks go.
#[derive(Debug)]
pub enum Lookup {
    /// A mask that accepts mail.
    Accepts(Mask),
    /// A live mask that refuses mail now (deleted or expired), which may
    /// accept it again later, so a refusal mustn't be cached (ME-6).
    Refuses,
    /// Not a mask, or a destroyed one.
    Unknown,
}

/// Looks an address up among masks, for accepting a recipient.
pub async fn lookup(data: &Store, registry: &RegistryStore, address: &str) -> trc::Result<Lookup> {
    if let Some(mask) = resolve(data, registry, address).await? {
        Ok(Lookup::Accepts(mask))
    } else if data::address(data, address)
        .await?
        .is_some_and(|entry| entry.live)
    {
        Ok(Lookup::Refuses)
    } else {
        Ok(Lookup::Unknown)
    }
}

/// The mask a recipient reaches, as written or with a `+tag` sub-address
/// removed, since a mask takes sub-addresses as the account's own addresses
/// do (ME-10).
pub async fn resolve_recipient(
    data: &Store,
    registry: &RegistryStore,
    recipient: &str,
) -> trc::Result<Option<Mask>> {
    if let Some(mask) = resolve(data, registry, recipient).await? {
        return Ok(Some(mask));
    }
    if let Some((local, domain)) = recipient.rsplit_once('@')
        && let Some((base, _)) = local.split_once('+')
    {
        return resolve(data, registry, &format!("{base}@{domain}")).await;
    }
    Ok(None)
}

/// The message as delivered through a mask: an `X-Masked-Email` header
/// names the mask, so the user can tell even when it was only BCC'd (ME-9).
/// Nothing else in the message changes.
pub fn with_header(address: &str, message: &[u8]) -> Vec<u8> {
    let header = format!("X-Masked-Email: {address}\r\n");
    let mut out = Vec::with_capacity(header.len() + message.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(message);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_collapse() {
        let (a, b, c) = (Id::new(1), Id::new(2), Id::new(3));
        let entries = [
            (10, a, Change::Created),
            (11, a, Change::Updated),
            (12, b, Change::Updated),
            (13, c, Change::Created),
            (14, c, Change::Destroyed),
            (15, b, Change::Destroyed),
        ];
        let all = collapse(9, &entries, 100);
        assert_eq!(all.created, vec![a]);
        assert_eq!(all.destroyed, vec![b]);
        assert!(all.updated.is_empty());
        assert_eq!(all.new_state, 15);
        assert!(!all.has_more);

        let first = collapse(9, &entries, 1);
        assert_eq!(first.created, vec![a]);
        assert_eq!(first.new_state, 11);
        assert!(first.has_more);
    }

    #[test]
    fn header_goes_first() {
        let out = with_header("shop_ab12@example.org", b"Subject: hi\r\n\r\nbody");
        assert_eq!(
            out,
            b"X-Masked-Email: shop_ab12@example.org\r\nSubject: hi\r\n\r\nbody".to_vec()
        );
    }
}
