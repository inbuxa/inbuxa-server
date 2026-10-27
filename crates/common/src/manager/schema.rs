/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    DATABASE_SCHEMA_OSS_FLAG, DATABASE_SCHEMA_VERSION, DATABASE_SCHEMA_VERSION_BASE,
    INBUXA_STORE_VERSION, Server, is_current_schema,
};
use store::{
    IterateParams, SerializeInfallible, Subspace,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass, key::SystemKind},
};
use trc::AddContext;

impl Server {
    pub async fn verify_schema_version(&self) -> trc::Result<()> {
        let version = self
            .system_value(SystemKind::SchemaVersion)
            .await
            .caused_by(trc::location!())?;

        match version {
            // inbuxa: either edition (see is_current_schema)
            Some(version) if is_current_schema(version) => self.verify_inbuxa_version().await,
            Some(version) => {
                let base = version & !DATABASE_SCHEMA_OSS_FLAG;
                if base < DATABASE_SCHEMA_VERSION_BASE {
                    Err(schema_error(format!(
                        "The data store was created by an older version (schema version {base}) and cannot be opened by this version. Copy it across with the migration tool."
                    )))
                } else {
                    Err(schema_error(format!(
                        "The data store was created by a newer version (schema version {base}, expected {DATABASE_SCHEMA_VERSION_BASE})."
                    )))
                }
            }
            None if self.is_new_install().await? => {
                self.write_system_value(SystemKind::SchemaVersion, DATABASE_SCHEMA_VERSION)
                    .await?;
                self.write_system_value(SystemKind::InbuxaStoreVersion, INBUXA_STORE_VERSION)
                    .await
            }
            None => Err(schema_error(
                "The data store was created by an older version and cannot be opened by this version. Copy it across with the migration tool."
                    .to_string(),
            )),
        }
    }

    // inbuxa: a store without our mark was written by an upstream 1.0 build
    // (or by its copy tool, during our own upgrade), and gets it on first
    // start; a mark newer than ours means a later line wrote to it
    async fn verify_inbuxa_version(&self) -> trc::Result<()> {
        match self
            .system_value(SystemKind::InbuxaStoreVersion)
            .await
            .caused_by(trc::location!())?
        {
            Some(version) if version <= INBUXA_STORE_VERSION => Ok(()),
            Some(version) => Err(schema_error(format!(
                "The data store was written by a newer release (store version {version}, expected {INBUXA_STORE_VERSION})."
            ))),
            None => {
                trc::event!(
                    Server(trc::ServerEvent::Startup),
                    Details = "Data store opened for the first time by this release line",
                );
                self.write_system_value(SystemKind::InbuxaStoreVersion, INBUXA_STORE_VERSION)
                    .await
            }
        }
    }

    async fn system_value(&self, kind: SystemKind) -> trc::Result<Option<u32>> {
        self.store()
            .get_value::<u32>(AnyKey {
                subspace: Subspace::System,
                key: vec![kind as u8],
            })
            .await
    }

    async fn write_system_value(&self, kind: SystemKind, value: u32) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::Any(AnyClass {
                subspace: Subspace::System,
                key: vec![kind as u8],
            }),
            value.serialize(),
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
