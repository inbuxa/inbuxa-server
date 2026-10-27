/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{validate::ValidatedPatches, write::MetadataUpdate};
use common::storage::metadata::ContainerChange;
use jmap_proto::{error::set::SetError, object::metadata::MetadataProperty};
use store::write::metadata::MetadataBuf;
use types::metadata::{EncodedMetadata, MetadataBuilder, MetadataKinds};

impl MetadataUpdate {
    pub fn copied(shared: Option<&MetadataBuf>, private: Option<&MetadataBuf>) -> Self {
        MetadataUpdate::new(copied(None, shared), copied(None, private))
    }

    pub fn copied_without_jmap(shared: Option<&MetadataBuf>) -> Self {
        MetadataUpdate::new(
            shared.and_then(without_jmap).map(ContainerChange::copied),
            None,
        )
    }
}

fn without_jmap(source: &MetadataBuf) -> Option<EncodedMetadata> {
    let view = source.view();
    if view.kinds().contains(MetadataKinds::JMAP) {
        let mut builder = MetadataBuilder::from_view(&view);
        builder.clear_jmap();
        builder.encode()
    } else {
        EncodedMetadata::from_view(&view)
    }
}

impl ValidatedPatches {
    pub fn apply_to_copy<P: MetadataProperty>(
        self,
        shared: Option<&MetadataBuf>,
        private: Option<&MetadataBuf>,
    ) -> Result<MetadataUpdate, SetError<P>> {
        let update = self.apply::<P>(shared, private)?;
        Ok(MetadataUpdate::new(
            copied(update.shared(), shared),
            copied(update.private(), private),
        ))
    }
}

fn copied(
    patched: Option<&ContainerChange>,
    source: Option<&MetadataBuf>,
) -> Option<ContainerChange> {
    match patched {
        Some(change) => change.next().cloned(),
        None => source.and_then(|source| EncodedMetadata::from_view(&source.view())),
    }
    .map(ContainerChange::copied)
}

