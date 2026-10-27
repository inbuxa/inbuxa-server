/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::SieveScript;
use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use store::write::BatchBuilder;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::collection::Collection;

pub trait SieveScriptDelete: Sync + Send {
    fn sieve_script_delete(
        &self,
        account_id: u32,
        document_id: u32,
        access_token: &AccessToken,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

impl SieveScriptDelete for Server {
    async fn sieve_script_delete(
        &self,
        account_id: u32,
        document_id: u32,
        access_token: &AccessToken,
        batch: &mut BatchBuilder,
    ) -> trc::Result<bool> {
        // Fetch record
        if let Some(obj_) = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::SieveScript,
                document_id,
            ))
            .await?
        {
            // inbuxa: UD-1, LH-4: a deleted script is kept, when archiving
            // is on or a hold covers the account (whole: scripts have no date)
            let keeping = self.keeping(account_id).await?;
            let now = store::write::now();
            if let Some(until) = keeping.until(now, keeping.is_held()) {
                let retention = until.saturating_sub(now);
                let script = obj_
                    .deserialize::<SieveScript>()
                    .caused_by(trc::location!())?;
                let content = self
                    .blob_store()
                    .get_blob(script.blob_hash.as_slice(), 0..usize::MAX)
                    .await?
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or_default();
                inbuxa_features::undelete::groupware::archive_sieve(
                    &self.core.storage.data,
                    self.registry(),
                    account_id,
                    &script.name,
                    content,
                    script.blob_hash.clone(),
                    retention,
                )
                .await?;
            }

            // Delete record
            let script = obj_
                .to_unarchived::<SieveScript>()
                .caused_by(trc::location!())?;
            batch
                .with_account_id(account_id)
                .with_collection(Collection::SieveScript);
            if !script.inner.metadata_kinds().is_empty() {
                self.preload_container_cleanup(
                    access_token.changed_by(),
                    account_id,
                    Collection::SieveScript,
                    &RoaringBitmap::from_iter([document_id]),
                )
                .await
                .caused_by(trc::location!())?
                .release_or_assert_absent(batch, account_id, document_id);
            }
            batch
                .with_document(document_id)
                .custom(
                    ObjectIndexBuilder::<_, ()>::new()
                        .with_current(script)
                        .with_changed_by(access_token.changed_by()),
                )
                .caused_by(trc::location!())?
                .commit_point();

            Ok(true)
        } else {
            Ok(false)
        }
    }
}
