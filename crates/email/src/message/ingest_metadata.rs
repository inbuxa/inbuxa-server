/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::metadata::{
    MetadataLog, MetadataWrite, PrivateMetadataCommit, PrivateMetadataWrite,
};
use store::write::{BatchBuilder, PendingId};
use types::{collection::Collection, metadata::EncodedMetadata};

#[derive(Debug, Default)]
pub struct IngestMetadata {
    pub shared: Option<EncodedMetadata>,
    pub private: Option<PrivateMetadataWrite>,
}

impl IngestMetadata {
    pub fn new(
        shared: Option<EncodedMetadata>,
        private: Option<PrivateMetadataWrite>,
    ) -> Option<Box<Self>> {
        (shared.is_some() || private.is_some())
            .then(|| Box::new(IngestMetadata { shared, private }))
    }

    pub(crate) fn build(
        self,
        batch: &mut BatchBuilder,
        account_id: u32,
        document_id: PendingId,
        commit: &mut PrivateMetadataCommit,
    ) -> trc::Result<()> {
        if let Some(container) = self.shared {
            MetadataWrite {
                account_id,
                collection: Collection::Email,
                previous: None,
                next: Some(container),
                log: MetadataLog::None,
            }
            .build(document_id, batch)?;
        }
        if let Some(write) = self.private {
            write.build(document_id, batch, commit)?;
        }
        Ok(())
    }
}

