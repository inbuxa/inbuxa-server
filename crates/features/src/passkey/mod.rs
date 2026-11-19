/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Passkeys (passkeys spec, inbuxa-server #334): what the server keeps for
//! each one, in the fork's subspace (`store::SUBSPACE_INBUXA`). Every key
//! starts with `N`, then one byte names the kind:
//!
//! - `p` + account id + number: the passkey's `Passkey` record.
//! - `c` + credential id: the account and number it belongs to, so sign-in
//!   finds a passkey without loading accounts.
//! - `h` + account id: the account's user handle, 32 random bytes the
//!   authenticator keeps as the user id.
//! - `u` + user handle: the account it belongs to.
//! - `t` + SHA-256 of a registration ticket: the pending passkey it opens
//!   (PK-6).
//! - `e` + account id: how many times the account's passkeys were removed.
//!   It's part of the account's credential version, so a removal ends every
//!   session (PK-15).
//!
//! Kept apart from the account's credentials, so a server that doesn't know
//! passkeys still reads every account.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use sha2::{Digest, Sha256};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;

const FEATURE: u8 = b'N';
const KIND_PASSKEY: u8 = b'p';
const KIND_CREDENTIAL: u8 = b'c';
const KIND_HANDLE: u8 = b'h';
const KIND_HANDLE_ACCOUNT: u8 = b'u';
const KIND_TICKET: u8 = b't';
const KIND_EPOCH: u8 = b'e';

/// Passkeys per account, pending ones included (PK-5).
pub const MAX_PASSKEYS: usize = 10;
/// How long a registration ticket stays good (PK-6).
pub const TICKET_SECONDS: u64 = 600;
/// The longest name (PK-5).
pub const MAX_NAME: usize = 64;
/// The length of a user handle.
pub const HANDLE_LEN: usize = 32;
const CREATE_ATTEMPTS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum State {
    /// Made, waiting for the browser part of registration.
    Pending,
    /// Registered and usable for sign-in.
    Active,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Active => "active",
        }
    }
}

/// One passkey.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    pub account_id: u32,
    /// Unique within the account.
    pub number: u32,
    pub name: String,
    pub state: State,
    /// For a pending passkey, when its ticket runs out.
    #[serde(default)]
    pub ticket_expires: u64,
    /// The relying-party id it was registered for (PK-3, PK-4).
    #[serde(default)]
    pub rp_id: String,
    /// The authenticator's credential id.
    #[serde(default)]
    pub credential_id: Vec<u8>,
    /// The public key, as COSE.
    #[serde(default)]
    pub public_key: Vec<u8>,
    #[serde(default)]
    pub sign_count: u32,
    #[serde(default)]
    pub transports: Vec<String>,
    /// The authenticator said the key is synced.
    #[serde(default)]
    pub backed_up: bool,
    #[serde(default)]
    pub aaguid: Vec<u8>,
    /// When it was made: for a pending one, when registration started.
    pub created_at: u64,
    #[serde(default)]
    pub last_used_at: Option<u64>,
}

impl Passkey {
    /// The JMAP id: the account id over the number.
    pub fn id(&self) -> u64 {
        passkey_id(self.account_id, self.number)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.state == State::Pending && self.ticket_expires <= now
    }
}

/// A passkey's JMAP id.
pub fn passkey_id(account_id: u32, number: u32) -> u64 {
    ((account_id as u64) << 32) | number as u64
}

/// The account id and number in a JMAP id.
pub fn split_id(id: u64) -> (u32, u32) {
    ((id >> 32) as u32, id as u32)
}

/// A name as a person typed it, trimmed, or why it can't be used.
pub fn clean_name(name: &str) -> Result<String, &'static str> {
    let name = name.trim();
    if name.is_empty() {
        Err("Give the passkey a name, such as the device it's on.")
    } else if name.chars().count() > MAX_NAME {
        Err("At most 64 characters.")
    } else if name.chars().any(char::is_control) {
        Err("A name can't hold control characters.")
    } else {
        Ok(name.to_string())
    }
}

/// What a ticket is stored under.
pub fn ticket_hash(ticket: &str) -> [u8; 32] {
    Sha256::digest(ticket.as_bytes()).into()
}

struct Json<T>(T);

impl Deserialize for Json<Passkey> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid passkey")
                .reason(err)
        })
    }
}

fn to_json(passkey: &Passkey) -> trc::Result<Vec<u8>> {
    serde_json::to_vec(passkey).map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Failed to serialize a passkey")
            .reason(err)
    })
}

struct Raw(Vec<u8>);

impl Deserialize for Raw {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Raw(bytes.to_vec()))
    }
}

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

fn pair(account_id: u32, number: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&account_id.to_be_bytes());
    out[4..].copy_from_slice(&number.to_be_bytes());
    out
}

fn unpair(bytes: &[u8]) -> Option<(u32, u32)> {
    let account = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?);
    let number = u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?);
    Some((account, number))
}

/// One passkey, expired pending ones included.
pub async fn get(data: &Store, account_id: u32, number: u32) -> trc::Result<Option<Passkey>> {
    Ok(data
        .get_value::<Json<Passkey>>(key(KIND_PASSKEY, &pair(account_id, number)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(passkey)| passkey))
}

/// Every passkey of the account, expired pending ones included, by number.
pub async fn all(data: &Store, account_id: u32) -> trc::Result<Vec<Passkey>> {
    let mut out = Vec::new();
    data.iterate(
        IterateParams::new(
            key(KIND_PASSKEY, &pair(account_id, 0)),
            key(KIND_PASSKEY, &pair(account_id, u32::MAX)),
        ),
        |_, value| {
            if let Ok(Json(passkey)) = Json::<Passkey>::deserialize(value) {
                out.push(passkey);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    out.sort_by_key(|p| p.number);
    Ok(out)
}

/// Every passkey of the account a person can see: active ones, and pending
/// ones whose ticket is still good. Expired pending ones are removed.
pub async fn list(data: &Store, account_id: u32, now: u64) -> trc::Result<Vec<Passkey>> {
    let mut out = Vec::new();
    for passkey in all(data, account_id).await? {
        if passkey.is_expired(now) {
            remove(data, &passkey).await?;
        } else {
            out.push(passkey);
        }
    }
    Ok(out)
}

pub enum Created {
    Pending(Passkey),
    Full,
}

/// Starts registering a passkey (PK-5): a pending record opened by `ticket`.
pub async fn create_pending(
    data: &Store,
    account_id: u32,
    name: String,
    ticket: &str,
    now: u64,
) -> trc::Result<Created> {
    for attempt in 1..=CREATE_ATTEMPTS {
        let existing = list(data, account_id, now).await?;
        if existing.len() >= MAX_PASSKEYS {
            return Ok(Created::Full);
        }
        let number = existing.iter().map(|p| p.number).max().unwrap_or(0) + 1;
        let passkey = Passkey {
            account_id,
            number,
            name: name.clone(),
            state: State::Pending,
            ticket_expires: now + TICKET_SECONDS,
            rp_id: String::new(),
            credential_id: Vec::new(),
            public_key: Vec::new(),
            sign_count: 0,
            transports: Vec::new(),
            backed_up: false,
            aaguid: Vec::new(),
            created_at: now,
            last_used_at: None,
        };
        let record = class(KIND_PASSKEY, &pair(account_id, number));
        let mut batch = BatchBuilder::new();
        batch.assert_value(record.clone(), AssertValue::None);
        batch.set(record, to_json(&passkey)?);
        batch.set(
            class(KIND_TICKET, &ticket_hash(ticket)),
            pair(account_id, number).to_vec(),
        );
        match data.write(batch.build_all()).await {
            Ok(_) => return Ok(Created::Pending(passkey)),
            Err(err)
                if attempt < CREATE_ATTEMPTS
                    && matches!(
                        err.as_ref(),
                        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                    ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
    Ok(Created::Full)
}

/// The pending passkey a ticket opens, while the ticket is good.
pub async fn by_ticket(data: &Store, ticket: &str, now: u64) -> trc::Result<Option<Passkey>> {
    let Some(Raw(target)) = data
        .get_value::<Raw>(key(KIND_TICKET, &ticket_hash(ticket)))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    let Some((account_id, number)) = unpair(&target) else {
        return Ok(None);
    };
    Ok(get(data, account_id, number)
        .await?
        .filter(|p| p.state == State::Pending && !p.is_expired(now)))
}

/// The passkey a credential id belongs to.
pub async fn by_credential(data: &Store, credential_id: &[u8]) -> trc::Result<Option<Passkey>> {
    let Some(Raw(target)) = data
        .get_value::<Raw>(key(KIND_CREDENTIAL, credential_id))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    match unpair(&target) {
        Some((account_id, number)) => get(data, account_id, number).await,
        None => Ok(None),
    }
}

/// Saves a changed passkey (a new name, a sign-in).
pub async fn save(data: &Store, passkey: &Passkey) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(
        class(KIND_PASSKEY, &pair(passkey.account_id, passkey.number)),
        to_json(passkey)?,
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

/// Removes one passkey and what points at it.
pub async fn remove(data: &Store, passkey: &Passkey) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.clear(class(
        KIND_PASSKEY,
        &pair(passkey.account_id, passkey.number),
    ));
    if !passkey.credential_id.is_empty() {
        batch.clear(class(KIND_CREDENTIAL, &passkey.credential_id));
    }
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

/// The account's user handle, if it has one.
pub async fn user_handle(data: &Store, account_id: u32) -> trc::Result<Option<Vec<u8>>> {
    Ok(data
        .get_value::<Raw>(key(KIND_HANDLE, &account_id.to_be_bytes()))
        .await
        .caused_by(trc::location!())?
        .map(|Raw(handle)| handle))
}

/// The account a user handle belongs to.
pub async fn account_of_handle(data: &Store, handle: &[u8]) -> trc::Result<Option<u32>> {
    Ok(data
        .get_value::<u32>(key(KIND_HANDLE_ACCOUNT, handle))
        .await
        .caused_by(trc::location!())?)
}

/// How many times the account's passkeys were removed (PK-15).
pub async fn epoch(data: &Store, account_id: u32) -> trc::Result<u64> {
    Ok(data
        .get_value::<u64>(key(KIND_EPOCH, &account_id.to_be_bytes()))
        .await
        .caused_by(trc::location!())?
        .unwrap_or(0))
}

/// Counts one more removal, which changes the account's credential version.
pub async fn bump_epoch(data: &Store, account_id: u32) -> trc::Result<u64> {
    let next = epoch(data, account_id).await? + 1;
    let mut batch = BatchBuilder::new();
    batch.set(
        class(KIND_EPOCH, &account_id.to_be_bytes()),
        next.to_be_bytes().to_vec(),
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(next)
}

/// The account's credential version with its passkey removals mixed in.
/// Unchanged until the first removal, so existing sessions stay.
pub fn credential_version(password_version: u64, epoch: u64) -> u64 {
    if epoch == 0 {
        password_version
    } else {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&password_version.to_be_bytes());
        bytes[8..].copy_from_slice(&epoch.to_be_bytes());
        xxhash_rust::xxh3::xxh3_64(&bytes).max(1)
    }
}

/// Removes everything about a deleted account's passkeys (PK-16).
pub async fn forget_account(data: &Store, account_id: u32) -> trc::Result<()> {
    for passkey in all(data, account_id).await? {
        remove(data, &passkey).await?;
    }
    let mut batch = BatchBuilder::new();
    if let Some(handle) = user_handle(data, account_id).await? {
        batch.clear(class(KIND_HANDLE_ACCOUNT, &handle));
    }
    batch.clear(class(KIND_HANDLE, &account_id.to_be_bytes()));
    batch.clear(class(KIND_EPOCH, &account_id.to_be_bytes()));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_carry_the_account() {
        let id = passkey_id(7, 3);
        assert_eq!(split_id(id), (7, 3));
        assert_eq!(split_id(passkey_id(u32::MAX, 1)), (u32::MAX, 1));
        assert_ne!(passkey_id(1, 2), passkey_id(2, 1));
    }

    #[test]
    fn names() {
        assert_eq!(clean_name("  Phone  ").unwrap(), "Phone");
        assert!(clean_name("   ").is_err());
        assert!(clean_name(&"x".repeat(65)).is_err());
        assert!(clean_name(&"é".repeat(64)).is_ok());
        assert!(clean_name("a\u{7}b").is_err());
    }

    #[test]
    fn keys_are_ours() {
        let ValueClass::Any(any) = class(KIND_PASSKEY, &pair(7, 3)) else {
            panic!()
        };
        assert_eq!(any.subspace, SUBSPACE_INBUXA);
        assert_eq!(any.key, [b'N', b'p', 0, 0, 0, 7, 0, 0, 0, 3]);
        assert_eq!(unpair(&pair(9, 4)), Some((9, 4)));
        assert_eq!(unpair(&[1, 2, 3]), None);
    }

    #[test]
    fn removals_change_the_credential_version() {
        assert_eq!(credential_version(42, 0), 42);
        let one = credential_version(42, 1);
        let two = credential_version(42, 2);
        assert_ne!(one, 42);
        assert_ne!(one, two);
        assert_ne!(credential_version(0, 1), 0);
        // A password change still changes it
        assert_ne!(credential_version(43, 1), one);
    }

    #[test]
    fn pending_ones_expire() {
        let passkey = Passkey {
            account_id: 1,
            number: 1,
            name: "Phone".into(),
            state: State::Pending,
            ticket_expires: 100,
            rp_id: String::new(),
            credential_id: Vec::new(),
            public_key: Vec::new(),
            sign_count: 0,
            transports: Vec::new(),
            backed_up: false,
            aaguid: Vec::new(),
            created_at: 0,
            last_used_at: None,
        };
        assert!(!passkey.is_expired(99));
        assert!(passkey.is_expired(100));
        let active = Passkey {
            state: State::Active,
            ..passkey.clone()
        };
        assert!(!active.is_expired(1_000));
        let json = serde_json::to_vec(&active).unwrap();
        let Json(back) = Json::<Passkey>::deserialize(&json).unwrap();
        assert_eq!(back, active);
    }

    #[test]
    fn tickets_are_hashed() {
        assert_eq!(ticket_hash("abc"), ticket_hash("abc"));
        assert_ne!(ticket_hash("abc"), ticket_hash("abd"));
    }
}
