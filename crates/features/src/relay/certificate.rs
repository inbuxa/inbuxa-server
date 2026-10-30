/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The last time this server ordered a relay's certificate (relay spec,
//! RL-27), kept under `c` + relay id as JSON. A node claims an order by
//! writing it first, so only one node of a cluster orders at a time, and a
//! failed order waits before the next one, as ACME rate limits ask.

use super::{FEATURE, Json};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;

const KIND_CERTIFICATE: u8 = b'c';

/// After a failed order, the next one waits this long.
pub const RETRY_AFTER_FAILURE: u64 = 6 * 3_600;
/// An order not done in this long is taken as lost, and may start again.
pub const ORDER_TIMEOUT: u64 = 3_600;

#[derive(Debug, Clone, PartialEq, Eq, Default, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateOrder {
    /// When it started.
    pub at: u64,
    /// Done: whether it failed, and why. Absent while it runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<Result<(), String>>,
}

impl CertificateOrder {
    /// Whether another order may start at `now`.
    pub fn may_order_again(&self, now: u64) -> bool {
        let wait = match self.done {
            Some(Err(_)) => RETRY_AFTER_FAILURE,
            // A certificate that still won't do an hour after it was got:
            // the name changed, or it was taken off
            Some(Ok(())) | None => ORDER_TIMEOUT,
        };
        self.at + wait <= now
    }

    /// Why the last order failed, if it did.
    pub fn error(&self) -> Option<&str> {
        match &self.done {
            Some(Err(error)) => Some(error),
            _ => None,
        }
    }
}

pub(super) fn certificate_class(relay_id: u32) -> ValueClass {
    let mut key = Vec::with_capacity(6);
    key.push(FEATURE);
    key.push(KIND_CERTIFICATE);
    key.extend_from_slice(&relay_id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

struct Versioned(CertificateOrder, u64);

impl Deserialize for Versioned {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let Json(order) = Json::<CertificateOrder>::deserialize(bytes)?;
        Ok(Versioned(order, xxhash_rust::xxh3::xxh3_64(bytes)))
    }
}

/// The last order for a relay's certificate, if there was one.
pub async fn last_order(data: &Store, relay_id: u32) -> trc::Result<Option<CertificateOrder>> {
    Ok(data
        .get_value::<Json<CertificateOrder>>(ValueKey::from(certificate_class(relay_id)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(order)| order))
}

/// Starts an order for a relay's certificate, unless one is running or
/// the last one failed too recently. True if this node is to order it.
pub async fn claim_order(data: &Store, relay_id: u32, now: u64) -> trc::Result<bool> {
    let current = data
        .get_value::<Versioned>(ValueKey::from(certificate_class(relay_id)))
        .await
        .caused_by(trc::location!())?;
    let assert = match &current {
        Some(Versioned(order, _)) if !order.may_order_again(now) => return Ok(false),
        Some(Versioned(_, version)) => AssertValue::Hash(*version),
        None => AssertValue::None,
    };
    let mut batch = BatchBuilder::new();
    batch.assert_value(certificate_class(relay_id), assert);
    batch.set(
        certificate_class(relay_id),
        Json(&CertificateOrder {
            at: now,
            done: None,
        })
        .serialize()?,
    );
    match data.write(batch.build_all()).await {
        Ok(_) => Ok(true),
        // Another node claimed it first
        Err(err)
            if matches!(
                err.as_ref(),
                trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
            ) =>
        {
            Ok(false)
        }
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

/// Records how a claimed order ended.
pub async fn finish_order(
    data: &Store,
    relay_id: u32,
    at: u64,
    result: Result<(), String>,
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(
        certificate_class(relay_id),
        Json(&CertificateOrder {
            at,
            done: Some(result),
        })
        .serialize()?,
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_wait_their_turn() {
        let running = CertificateOrder {
            at: 1_000,
            done: None,
        };
        assert!(!running.may_order_again(1_000 + ORDER_TIMEOUT - 1));
        assert!(running.may_order_again(1_000 + ORDER_TIMEOUT));
        assert_eq!(running.error(), None);

        let failed = CertificateOrder {
            at: 1_000,
            done: Some(Err("rate limited".into())),
        };
        assert!(!failed.may_order_again(1_000 + ORDER_TIMEOUT));
        assert!(failed.may_order_again(1_000 + RETRY_AFTER_FAILURE));
        assert_eq!(failed.error(), Some("rate limited"));

        let done = CertificateOrder {
            at: 1_000,
            done: Some(Ok(())),
        };
        assert!(done.may_order_again(1_000 + ORDER_TIMEOUT));
        assert_eq!(done.error(), None);
    }
}
