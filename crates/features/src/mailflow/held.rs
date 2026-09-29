/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Mail held for review (dlp-and-mail-flow-rules spec, §2.6).
//!
//! A held message is queued as any other, but released [`HOLD_SECONDS`]
//! from now, the queue's own future-release mechanism: nothing about the
//! queue's stored format changes, so a node on an older version reads it
//! and simply never sends it. Beside it, a review record under `R` `h` +
//! queue id (u64) says why it's held, for the review queue.
//!
//! A reviewer releases it (it's rescheduled from the queue's settings and
//! delivered) or rejects it (it's removed, and the sender told). Unreviewed
//! mail is rejected after [`KEEP_DAYS`].

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize, de::DeserializeOwned};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

const FEATURE: u8 = b'R';
const KIND_HELD: u8 = b'h';

/// How far off a held message's release is set: a century, so it never
/// comes due on its own.
pub const HOLD_SECONDS: u64 = 100 * 365 * 24 * 60 * 60;

/// How long unreviewed mail waits before it's rejected (settled answer 5).
pub const KEEP_DAYS: u64 = 7;

/// A rule that held the message, with its notice.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
pub struct HeldRule {
    pub name: String,
    pub notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Held {
    pub queue_id: u64,
    pub sender: String,
    #[serde(default)]
    pub account_id: Option<u32>,
    #[serde(default)]
    pub tenant_id: Option<u32>,
    pub recipients: Vec<String>,
    pub subject: String,
    pub size: u64,
    pub rules: Vec<HeldRule>,
    /// Each detector that counted, and its count.
    #[serde(default)]
    pub counts: Vec<(String, usize)>,
    /// Seconds since the epoch.
    pub held_at: u64,
    pub expires_at: u64,
}

impl Held {
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(&self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Failed to serialize held message")
                .reason(err)
        })
    }
}

impl<T: DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid held message")
                .reason(err)
        })
    }
}

fn class(queue_id: u64) -> ValueClass {
    let mut key = Vec::with_capacity(10);
    key.push(FEATURE);
    key.push(KIND_HELD);
    key.extend_from_slice(&queue_id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

fn key(queue_id: u64) -> ValueKey<ValueClass> {
    ValueKey::from(class(queue_id))
}

pub async fn get(data: &Store, queue_id: u64) -> trc::Result<Option<Held>> {
    Ok(data
        .get_value::<Json<Held>>(key(queue_id))
        .await
        .caused_by(trc::location!())?
        .map(|Json(held)| held))
}

pub async fn is_held(data: &Store, queue_id: u64) -> trc::Result<bool> {
    get(data, queue_id).await.map(|held| held.is_some())
}

/// Every held message, oldest first.
pub async fn all(data: &Store) -> trc::Result<Vec<Held>> {
    let mut held = Vec::new();
    data.iterate(IterateParams::new(key(0), key(u64::MAX)), |_, value| {
        if let Ok(Json(record)) = Json::<Held>::deserialize(value) {
            held.push(record);
        }
        Ok(true)
    })
    .await
    .caused_by(trc::location!())?;
    held.sort_by_key(|h| (h.held_at, h.queue_id));
    Ok(held)
}

pub async fn create(data: &Store, held: &Held) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(class(held.queue_id), Json(held).serialize()?);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

pub async fn delete(data: &Store, queue_id: u64) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.clear(class(queue_id));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_and_expiry() {
        let held = Held {
            queue_id: 42,
            sender: "dana@example.com".into(),
            account_id: Some(7),
            tenant_id: None,
            recipients: vec!["x@elsewhere.org".into()],
            subject: "Numbers".into(),
            size: 900,
            rules: vec![HeldRule {
                name: "Cards".into(),
                notice: "Held for review".into(),
            }],
            counts: vec![("payment-card".into(), 5)],
            held_at: 1_000,
            expires_at: 1_000 + KEEP_DAYS * 86_400,
        };
        let json = serde_json::to_value(&held).unwrap();
        assert_eq!(json["heldAt"], 1_000);
        assert_eq!(serde_json::from_value::<Held>(json).unwrap(), held);
        assert!(!held.is_expired(1_000 + KEEP_DAYS * 86_400 - 1));
        assert!(held.is_expired(1_000 + KEEP_DAYS * 86_400));
        assert!(HOLD_SECONDS > 90 * 365 * 86_400);
    }
}
