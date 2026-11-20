/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Spam-training samples held past their message (UD-14a).
//!
//! The classifier holds a trained message's blob for `holdSamplesFor`
//! (90 days by default) so it can replay it later. While the message is in
//! the account that costs nothing: the hold and the message share one blob,
//! counted once. Once the account's own copy is gone for good, though, the
//! held blob was stored with nobody counting it, so a member could fill the
//! account, train, delete and fill it again, past the account's and the
//! tenant's limit, for the whole hold period.
//!
//! So a hold now ends with the account's own copy: when the message's data
//! is removed and nothing archives it, or when its archived copy goes other
//! than by restore. The classifier already treats a blob that's gone as a
//! sample to drop from its replay pool, so this shrinks the pool to mail
//! that's still kept; what was learned from the sample stays learned.
//!
//! Each hold is noted as `s` + account + blob hash + until (empty value), so
//! it can be found from the message, with the link it set under that
//! account.

use store::{
    IterateParams, SUBSPACE_UNDELETE, Store, ValueKey,
    write::{AnyClass, BatchBuilder, BlobLink, BlobOp, ValueClass, now},
};
use trc::AddContext;
use types::blob_hash::{BLOB_HASH_LEN, BlobHash};

const KIND_SAMPLE: u8 = b's';

fn class(account_id: u32, hash: &[u8], until: u64) -> ValueClass {
    let mut key = Vec::with_capacity(1 + 4 + hash.len() + 8);
    key.push(KIND_SAMPLE);
    key.extend_from_slice(&account_id.to_be_bytes());
    key.extend_from_slice(hash);
    key.extend_from_slice(&until.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_UNDELETE,
        key,
    })
}

/// Notes a held sample: its blob, linked under `account_id` until `until`.
pub fn note(batch: &mut BatchBuilder, account_id: u32, hash: &BlobHash, until: u64) {
    batch.set(class(account_id, hash.as_slice(), until), vec![]);
}

/// The holds noted for a blob in an account, by their `until`.
async fn holds(data: &Store, account_id: u32, hash: &[u8]) -> trc::Result<Vec<u64>> {
    let mut untils = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey::from(class(account_id, hash, 0)),
            ValueKey::from(class(account_id, hash, u64::MAX)),
        )
        .ascending()
        .no_values(),
        |key, _| {
            if key.len() >= 8 {
                untils.push(u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap()));
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(untils)
}

/// The account's own copy of a message is gone for good: its samples'
/// holds on the blob end with it.
pub async fn release(data: &Store, account_id: u32, hash: &BlobHash) -> trc::Result<()> {
    let untils = holds(data, account_id, hash.as_slice()).await?;
    if untils.is_empty() {
        return Ok(());
    }
    let mut batch = BatchBuilder::new();
    batch.with_account_id(account_id);
    for until in untils {
        batch
            .clear(BlobOp::Link {
                hash: hash.clone(),
                to: BlobLink::Temporary { until },
            })
            .clear(class(account_id, hash.as_slice(), until));
    }
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// Clears notes whose hold has ended on its own, for the scheduled clean-up.
/// Returns how many went.
pub async fn purge_ended(data: &Store) -> trc::Result<usize> {
    let now = now();
    let mut ended = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey::from(ValueClass::Any(AnyClass {
                subspace: SUBSPACE_UNDELETE,
                key: vec![KIND_SAMPLE],
            })),
            ValueKey::from(ValueClass::Any(AnyClass {
                subspace: SUBSPACE_UNDELETE,
                key: vec![KIND_SAMPLE, u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX],
            })),
        )
        .ascending()
        .no_values(),
        |key, _| {
            if key.len() == 1 + 4 + BLOB_HASH_LEN + 8
                && u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap()) <= now
            {
                ended.push(key.to_vec());
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    let count = ended.len();
    for chunk in ended.chunks(512) {
        let mut batch = BatchBuilder::new();
        for key in chunk {
            batch.clear(ValueClass::Any(AnyClass {
                subspace: SUBSPACE_UNDELETE,
                key: key.clone(),
            }));
        }
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sort_by_account_then_blob_then_until() {
        let hash = BlobHash::generate(b"x");
        let key = |account, until| match class(account, hash.as_slice(), until) {
            ValueClass::Any(any) => any.key,
            _ => unreachable!(),
        };
        assert_eq!(key(1, 5).len(), 1 + 4 + BLOB_HASH_LEN + 8);
        assert!(key(1, 5) < key(1, 6));
        assert!(key(1, u64::MAX) < key(2, 0));
    }
}
