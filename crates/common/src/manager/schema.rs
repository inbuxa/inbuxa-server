/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DATABASE_SCHEMA_OSS_FLAG, DATABASE_SCHEMA_VERSION, DATABASE_SCHEMA_VERSION_BASE, Server,
};
use store::{
    IterateParams, SerializeInfallible, Subspace,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass, key::SystemKind},
};
use trc::AddContext;

#[cfg(feature = "enterprise")]
const OTHER_EDITION: &str = "AGPL3-only";
#[cfg(not(feature = "enterprise"))]
const OTHER_EDITION: &str = "AGPL3/SEL";

impl Server {
    pub async fn verify_schema_version(&self) -> trc::Result<()> {
        let version = self
            .store()
            .get_value::<u32>(AnyKey {
                subspace: Subspace::System,
                key: vec![SystemKind::SchemaVersion as u8],
            })
            .await
            .caused_by(trc::location!())?;

        match version {
            Some(DATABASE_SCHEMA_VERSION) => Ok(()),
            Some(version) => {
                let base = version & !DATABASE_SCHEMA_OSS_FLAG;
                if base == DATABASE_SCHEMA_VERSION_BASE {
                    Err(schema_error(format!(
                        "The data store was created by the Stalwart {OTHER_EDITION} edition and cannot be opened by this edition."
                    )))
                } else if base < DATABASE_SCHEMA_VERSION_BASE {
                    Err(schema_error(format!(
                        "The data store was created by a Stalwart version prior to 1.0 (schema version {base}) and cannot be opened by this version."
                    )))
                } else {
                    Err(schema_error(format!(
                        "The data store was created by a newer Stalwart version (schema version {base}, expected {DATABASE_SCHEMA_VERSION_BASE})."
                    )))
                }
            }
            None if self.is_new_install().await? => self.write_schema_version().await,
            None => Err(schema_error(
                "The data store was created by a Stalwart version prior to 1.0 and cannot be opened by this version."
                    .to_string(),
            )),
        }
    }

    async fn write_schema_version(&self) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::Any(AnyClass {
                subspace: Subspace::System,
                key: vec![SystemKind::SchemaVersion as u8],
            }),
            DATABASE_SCHEMA_VERSION.serialize(),
        );

        self.store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())
            .map(|_| ())
    }

    async fn is_new_install(&self) -> trc::Result<bool> {
        for subspace in [
            Subspace::QueueMessage,
            Subspace::ReportIn,
            Subspace::ReportOut,
            Subspace::Property,
        ] {
            let mut has_data = false;

            self.store()
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
                    .no_values()
                    .only_first(),
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
}

fn schema_error(message: String) -> trc::Error {
    trc::EventType::Server(trc::ServerEvent::StartupError)
        .into_err()
        .details(message)
}
