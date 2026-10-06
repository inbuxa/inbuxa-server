/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Dated copies of the evaluated inventory (personal-data catalog spec, §6,
//! `inbuxa:InventorySnapshot`), so the Overview can show when and why what
//! the server holds changed. Stored as JSON under `C` `i` and the time taken
//! (seconds, big-endian) in the fork's subspace; kept as long as the audit
//! log keeps its records (settled 2026-09-28).

use super::{Inventory, Summary};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Store, U64_LEN, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;

const PREFIX: &[u8] = b"Ci";

/// Why a snapshot was taken.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Trigger {
    /// A setting the catalog names changed: the object type that changed.
    SettingChanged { setting: String },
    /// The daily snapshot.
    Daily,
}

#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Seconds since the epoch; also the snapshot's id.
    pub taken_at: u64,
    pub trigger: Trigger,
    pub summary: Summary,
    pub inventory: Inventory,
}

fn key(taken_at: u64) -> Vec<u8> {
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(&taken_at.to_be_bytes());
    key
}

fn class(taken_at: u64) -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: key(taken_at),
    })
}

struct Json(Snapshot);

impl Deserialize for Json {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

/// Stores a snapshot. Two in the same second: the later one wins.
pub async fn record(data: &Store, snapshot: &Snapshot) -> trc::Result<()> {
    let bytes = serde_json::to_vec(snapshot).map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .caused_by(trc::location!())
            .reason(err)
    })?;
    let mut batch = BatchBuilder::new();
    batch.set(class(snapshot.taken_at), bytes);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// One snapshot, by the time it was taken.
pub async fn get(data: &Store, taken_at: u64) -> trc::Result<Option<Snapshot>> {
    Ok(data
        .get_value::<Json>(ValueKey::from(class(taken_at)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(snapshot)| snapshot))
}

/// The times snapshots were taken between `after` and `before` (inclusive,
/// seconds), newest first.
pub async fn list(data: &Store, after: u64, before: u64) -> trc::Result<Vec<u64>> {
    let mut times = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey::from(class(after)),
            ValueKey::from(class(before)),
        )
        .no_values(),
        |key, _| {
            times.push(key.deserialize_be_u64(key.len() - U64_LEN)?);
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    times.reverse();
    Ok(times)
}

/// The newest snapshot's time, if any.
pub async fn latest(data: &Store) -> trc::Result<Option<u64>> {
    Ok(list(data, 0, u64::MAX).await?.first().copied())
}

/// Removes snapshots taken before `before` (seconds). Returns how many went.
pub async fn purge(data: &Store, before: u64) -> trc::Result<usize> {
    let old = list(data, 0, before.saturating_sub(1)).await?;
    if old.is_empty() {
        return Ok(0);
    }
    let mut batch = BatchBuilder::new();
    for taken_at in &old {
        batch.clear(class(*taken_at));
    }
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(old.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sort_by_time() {
        assert!(key(1) < key(2));
        assert!(key(255) < key(256));
        assert_eq!(&key(7)[..2], PREFIX);
    }

    #[test]
    fn a_trigger_reads_as_json_names_it() {
        let changed = serde_json::to_value(Trigger::SettingChanged {
            setting: "x:DataRetention".into(),
        })
        .unwrap();
        assert_eq!(changed["kind"], "settingChanged");
        assert_eq!(changed["setting"], "x:DataRetention");
        assert_eq!(serde_json::to_value(Trigger::Daily).unwrap()["kind"], "daily");
    }
}
