/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

#![warn(clippy::large_futures)]

use crate::v016::migrate_v0_16;
use common::{DATABASE_SCHEMA_VERSION, Server};
use store::{
    IterateParams, SUBSPACE_PROPERTY, SUBSPACE_QUEUE_MESSAGE, SUBSPACE_REPORT_IN,
    SUBSPACE_REPORT_OUT, SerializeInfallible,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass},
};
use trc::AddContext;

pub mod destroy;
pub mod v016;

pub async fn try_migrate(server: &Server) -> trc::Result<()> {
    // inbuxa: before the version check, which returns early on a current
    // store, and before migrate_v0_16, which reads the renamed key.
    rename_spam_blobs(server).await?;

    match server
        .store()
        .get_value::<u32>(AnyKey {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        })
        .await
        .caused_by(trc::location!())?
    {
        Some(DATABASE_SCHEMA_VERSION) => {
            if !std::env::var("DANGER_FORCE_MIGRATE").is_ok_and(|v| v == "1") {
                return Ok(());
            }
        }
        Some(0..=4) => {
            abort(concat!(
                "You must first upgrade to version 0.15, please read ",
                "https://docs.inbuxa.org/install/migrating/"
            ));
        }
        Some(5) => {
            if !server.registry().is_recovery_mode() {
                abort(concat!(
                    "Upgrading to version 0.16 is a multi-step process, please read ",
                    "https://docs.inbuxa.org/install/migrating/"
                ));
            }
        }

        Some(version) => {
            panic!(
                "Unknown database schema version, expected {} or below, found {}",
                DATABASE_SCHEMA_VERSION, version
            );
        }
        _ => {
            if is_new_install(server).await.caused_by(trc::location!())? {
                write_schema_version(server).await?;
                return Ok(());
            } else {
                abort(concat!(
                    "You must first upgrade to version 0.15, please read ",
                    "https://docs.inbuxa.org/install/migrating/"
                ));
            }
        }
    }

    migrate_v0_16(server).await?;
    write_schema_version(server).await
}

async fn write_schema_version(server: &Server) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        }),
        DATABASE_SCHEMA_VERSION.serialize(),
    );

    server
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    Ok(())
}

fn abort(message: &str) -> ! {
    eprintln!("Migration aborted: {message}");
    panic!("Migration aborted: {message}");
}

async fn is_new_install(server: &Server) -> trc::Result<bool> {
    for subspace in [
        SUBSPACE_QUEUE_MESSAGE,
        SUBSPACE_REPORT_IN,
        SUBSPACE_REPORT_OUT,
        SUBSPACE_PROPERTY,
    ] {
        let mut has_data = false;

        server
            .store()
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace,
                        key: vec![0u8],
                    },
                    AnyKey {
                        subspace,
                        key: vec![u8::MAX; 16],
                    },
                )
                .no_values(),
                |_, _| {
                    has_data = true;

                    Ok(false)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if has_data {
            return Ok(false);
        }
    }

    Ok(true)
}

/// inbuxa: the spam filter's trainer and model blobs, under the names they
/// had before the fork renamed them (SPEC §2.4), paired with the current ones.
const RENAMED_SPAM_BLOBS: [(&[u8], &[u8]); 2] = [
    (b"STALWART_SPAM_TRAIN_DATA.lz4", common::manager::SPAM_TRAINER_KEY),
    (
        b"STALWART_SPAM_CLASSIFIER_MODEL.lz4",
        common::manager::SPAM_CLASSIFIER_KEY,
    ),
];

/// Moves each spam blob from its pre-rename key to the current one, so a
/// trained model survives the rename. A blob already under the current key
/// wins and the old one is just removed; with neither, nothing happens.
async fn rename_spam_blobs(server: &Server) -> trc::Result<()> {
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
