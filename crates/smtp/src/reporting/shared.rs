/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: internal DMARC and TLS reports are shared by every node. Any node
//! that receives mail appends to them, so several nodes can write one report
//! at once, and the node that sends it may do so while another is appending.
//! Appends already guard the report's versioned primary key and retry when
//! another writer got there first; these helpers give those retries room and
//! let the sender delete exactly the report it read.

use rand::RngExt;
use std::time::Duration;
use store::{Deserialize, xxhash_rust::xxh3::xxh3_64};

/// How many times a report write that lost to another writer is retried.
/// Upstream retried three times, when only outbound MTA nodes wrote.
pub(crate) const MAX_WRITE_RETRIES: u32 = 10;

/// A short random pause, longer on each attempt, before retrying a report
/// write that lost to another node, so the writers spread out instead of
/// colliding again.
pub(crate) async fn write_retry_pause(attempt: u32) {
    let ms = rand::rng().random_range(5..=25u64) * u64::from(attempt.max(1));
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// A stored value with the hash of the bytes it was read from, for
/// `AssertValue::Hash`: a write asserting it fails if anyone changed the
/// value since.
pub(crate) struct Revisioned<T> {
    pub revision: u64,
    pub value: T,
}

impl<T: Deserialize> Deserialize for Revisioned<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Revisioned {
            revision: xxh3_64(bytes),
            value: T::deserialize(bytes)?,
        })
    }
}
