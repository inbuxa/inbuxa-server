/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Blobs kept under keys the fork renamed (SPEC §2.4). 0.16 moved them in its
//! migration crate, which 1.0 dropped; a store copied from a Stalwart install
//! still carries the old keys, so the move runs at every startup, before the
//! services that read them.

use crate::{
    Server,
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY},
};
use trc::AddContext;

/// The spam filter's trainer and model blobs, under the names they had before
/// the rename, paired with the current ones.
const RENAMED_SPAM_BLOBS: [(&[u8], &[u8]); 2] = [
    (b"STALWART_SPAM_TRAIN_DATA.lz4", SPAM_TRAINER_KEY),
    (b"STALWART_SPAM_CLASSIFIER_MODEL.lz4", SPAM_CLASSIFIER_KEY),
];

/// Moves each spam blob from its pre-rename key to the current one, so a
/// trained model survives the rename. A blob already under the current key
/// wins and the old one is just removed; with neither, nothing happens.
pub async fn rename_spam_blobs(server: &Server) -> trc::Result<()> {
    let blobs = server.blob_store();
    for (old, new) in RENAMED_SPAM_BLOBS {
        let Some(data) = blobs
            .get_blob(old, 0..usize::MAX)
            .await
            .caused_by(trc::location!())?
        else {
            continue;
        };
        if blobs
            .get_blob(new, 0..usize::MAX)
            .await
            .caused_by(trc::location!())?
            .is_none()
        {
            blobs
                .put_blob(new, &data, server.core.email.compression)
                .await
                .caused_by(trc::location!())?;
        }
        blobs.delete_blob(old).await.caused_by(trc::location!())?;
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = "Moved a spam filter blob to its renamed key",
            Key = new,
        );
    }
    Ok(())
}
