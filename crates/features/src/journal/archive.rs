/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Reports on their way to an outside archive (JR-7). Keys, after `J`:
//!
//! - `o` + the report's queue id: what goes into the built-in journal if
//!   the archive never takes the report, as JSON. Cleared once it's
//!   delivered or kept.
//! - `w` + journal id (u32): how often that journal's archive didn't take a
//!   report, and the last time and reason, for the console's warning.

use super::{FEATURE, Json, entries::Entry};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

const KIND_PENDING: u8 = b'o';
const KIND_FAILURES: u8 = b'w';

/// A report queued to an archive.
#[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    pub address: String,
    /// The entry, should the archive not take it: its own, with the
    /// sending journals' retention, whatever else the built-in journal has.
    pub entry: Entry,
}

/// How a journal's archive has been taking its reports.
#[derive(Debug, Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Failures {
    pub count: u64,
    /// Seconds.
    pub last_at: u64,
    pub last_reason: String,
}

fn class(kind: u8, id: &[u8]) -> ValueClass {
    let mut key = Vec::with_capacity(2 + id.len());
    key.push(FEATURE);
    key.push(kind);
    key.extend_from_slice(id);
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

pub async fn set_pending(data: &Store, queue_id: u64, pending: &Pending) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(
        class(KIND_PENDING, &queue_id.to_be_bytes()),
        Json(pending).serialize()?,
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

pub async fn pending(data: &Store, queue_id: u64) -> trc::Result<Option<Pending>> {
    Ok(data
        .get_value::<Json<Pending>>(ValueKey::from(class(KIND_PENDING, &queue_id.to_be_bytes())))
        .await
        .caused_by(trc::location!())?
        .map(|Json(pending)| pending))
}

pub async fn clear_pending(data: &Store, queue_id: u64) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.clear(class(KIND_PENDING, &queue_id.to_be_bytes()));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

pub async fn failures(data: &Store, journal_id: u32) -> trc::Result<Failures> {
    Ok(data
        .get_value::<Json<Failures>>(ValueKey::from(class(
            KIND_FAILURES,
            &journal_id.to_be_bytes(),
        )))
        .await
        .caused_by(trc::location!())?
        .map(|Json(failures)| failures)
        .unwrap_or_default())
}

/// Counts one report an archive didn't take, for each of `journals`.
pub async fn record_failure(
    data: &Store,
    journals: &[u32],
    at: u64,
    reason: &str,
) -> trc::Result<()> {
    for journal_id in journals {
        let mut failures = failures(data, *journal_id).await?;
        failures.count += 1;
        failures.last_at = at;
        failures.last_reason = reason.chars().take(500).collect();
        let mut batch = BatchBuilder::new();
        batch.set(
            class(KIND_FAILURES, &journal_id.to_be_bytes()),
            Json(&failures).serialize()?,
        );
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }
    Ok(())
}
