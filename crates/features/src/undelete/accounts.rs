/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Deleted accounts kept for their period (UD-15 to UD-17a). The account's
//! record is removed as upstream removes it; a copy waits here with its
//! shares, both ways, until it's restored or its `DestroyAccount` task runs.

use crate::undelete::{
    data::{self, Share},
    records,
};
use store::{
    Deserialize, IterateParams, RegistryStore, SerializeInfallible, Store, U32_LEN, ValueKey,
    write::{BatchBuilder, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::collection::Collection;

/// Every share `account_id` is part of, either way.
async fn shares_of(data: &Store, account_id: u32) -> trc::Result<Vec<Share>> {
    let mut shares = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: ValueClass::Acl(0),
            },
            ValueKey {
                account_id: u32::MAX,
                collection: u8::MAX,
                document_id: u32::MAX,
                class: ValueClass::Acl(u32::MAX),
            },
        )
        .ascending(),
        |key, value| {
            // grantee, owner, collection, document
            let grantee = key.deserialize_be_u32(0)?;
            let owner = key.deserialize_be_u32(U32_LEN)?;
            if grantee == account_id || owner == account_id {
                shares.push(Share {
                    grantee,
                    owner,
                    collection: *key.get(U32_LEN * 2).ok_or_else(|| {
                        trc::StoreEvent::DataCorruption.caused_by(trc::location!())
                    })?,
                    document_id: key.deserialize_be_u32(U32_LEN * 2 + 1)?,
                    permissions: u64::deserialize(value)?,
                });
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    Ok(shares)
}

fn write_shares<'x>(
    batch: &mut BatchBuilder,
    shares: impl Iterator<Item = &'x Share>,
    grant: bool,
) {
    for share in shares {
        batch
            .with_account_id(share.owner)
            .with_collection(Collection::from(share.collection))
            .with_document(share.document_id);
        if grant {
            batch.acl_grant(share.grantee, share.permissions.serialize());
        } else {
            batch.acl_revoke(share.grantee);
        }
    }
}

/// Revokes every share an account is part of and returns them (UD-17a).
pub async fn suspend_shares(data: &Store, account_id: u32) -> trc::Result<Vec<Share>> {
    let shares = shares_of(data, account_id).await?;
    for chunk in shares.chunks(1000) {
        let mut batch = BatchBuilder::new();
        write_shares(&mut batch, chunk.iter(), false);
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }
    Ok(shares)
}

/// Grants back the suspended shares whose other account still exists
/// (UD-17a). Returns the other accounts, whose access changes.
pub async fn reinstate_shares(
    data: &Store,
    account_id: u32,
    shares: &[Share],
    exists: impl Fn(u32) -> bool,
) -> trc::Result<Vec<u32>> {
    let shares = shares
        .iter()
        .filter(|share| {
            let other = if share.owner == account_id {
                share.grantee
            } else {
                share.owner
            };
            other == account_id || exists(other)
        })
        .collect::<Vec<_>>();
    for chunk in shares.chunks(1000) {
        let mut batch = BatchBuilder::new();
        write_shares(&mut batch, chunk.iter().copied(), true);
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }
    let mut others = shares
        .iter()
        .flat_map(|share| [share.owner, share.grantee])
        .filter(|id| *id != account_id)
        .collect::<Vec<_>>();
    others.sort_unstable();
    others.dedup();
    Ok(others)
}

/// When the account is finally destroyed: its hold, and everything undelete
/// kept for it, go too.
pub async fn forget(data: &Store, registry: &RegistryStore, account_id: u32) -> trc::Result<()> {
    if let Some(kept) = data::kept_account(data, account_id).await? {
        let mut batch = BatchBuilder::new();
        data::clear_kept_account(&mut batch, account_id, &kept);
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }
    for (id, item) in records::of_account(data, registry, account_id).await? {
        records::remove(data, registry, id, &item).await?;
    }
    data::clear_account(data, account_id).await
}
