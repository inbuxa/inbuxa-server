/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

#![warn(clippy::large_futures)]

use crate::v016::migrate_v0_16;
use common::{DATABASE_SCHEMA_VERSION, INBUXA_STORE_VERSION, Server};
use registry::schema::{prelude::Object, structs::AcmeProvider};
use store::{
    IterateParams, SUBSPACE_PROPERTY, SUBSPACE_QUEUE_MESSAGE, SUBSPACE_REPORT_IN,
    SUBSPACE_REPORT_OUT, SerializeInfallible,
    registry::write::RegistryWrite,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass},
};
use trc::AddContext;

pub mod destroy;
pub mod fork_subspaces;
pub mod layout;
pub mod v016;

pub async fn try_migrate(server: &Server) -> trc::Result<()> {
    migrate(server, layout::Run::Boot).await.map(|_| ())
}

/// inbuxa: K-S3: `--upgrade-store`. What a start would do to the store
/// before serving, and nothing else; another node's upgrade is refused
/// rather than waited for.
pub async fn upgrade_store(server: &Server) -> trc::Result<layout::Outcome> {
    migrate(server, layout::Run::UpgradeOnly).await
}

/// inbuxa: what an upgrade of this store to this build would do, for
/// `--upgrade-plan`. Reads only: the decisions are `migrate`'s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradePlan {
    /// A store nothing has written yet: a first start marks it, no steps
    NewStore,
    /// The store's layout version and the steps from it; none when current
    Steps {
        from: u32,
        steps: Vec<layout::PlannedStep>,
    },
    /// A newer release changed this store; this build refuses it
    Newer(u32),
    /// Not something an upgrade does: a migration by hand comes first
    NeedsMigration(&'static str),
}

pub async fn upgrade_plan(server: &Server) -> trc::Result<UpgradePlan> {
    let store_version = layout::store_version(server.store()).await?;
    if let Some(version) = store_version.filter(|version| *version > INBUXA_STORE_VERSION) {
        return Ok(UpgradePlan::Newer(version));
    }

    let schema = server
        .store()
        .get_value::<u32>(AnyKey {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        })
        .await
        .caused_by(trc::location!())?;
    let from = match schema {
        Some(DATABASE_SCHEMA_VERSION) => store_version.unwrap_or(1),
        None if is_new_install(server).await.caused_by(trc::location!())? => {
            return Ok(UpgradePlan::NewStore);
        }
        _ => {
            return Ok(UpgradePlan::NeedsMigration(
                "the store is from before 0.16 and needs the migration in \
                 https://docs.inbuxa.org/install/migrating/ first",
            ));
        }
    };

    Ok(UpgradePlan::Steps {
        from,
        steps: layout::steps_from(from),
    })
}

async fn migrate(server: &Server, run: layout::Run) -> trc::Result<layout::Outcome> {
    // inbuxa: a store a newer release has changed is refused before anything
    // below writes to it.
    let store_version = layout::store_version(server.store()).await?;
    if let Some(version) = store_version.filter(|version| *version > INBUXA_STORE_VERSION) {
        abort(&format!(
            "The data store was upgraded by a newer release (store version {version}, this release reads up to {INBUXA_STORE_VERSION}). Run that release again, or restore the backup taken before the upgrade, see https://docs.inbuxa.org/install/migrating/"
        ));
    }

    // inbuxa: before the version check, which returns early on a current
    // store, and before migrate_v0_16, which reads the renamed key.
    rename_spam_blobs(server).await?;
    // inbuxa: #608: also before the version check, and on every start; it
    // only writes when a provider still holds a `mailto:` contact. A failure
    // is logged, never fatal: the old form still works for renewals.
    if let Err(err) = plain_acme_contacts(server).await {
        trc::error!(err.details("Failed to store ACME contacts as plain addresses"));
    }

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
                return layout::upgrade_layout(server, store_version, false, run).await;
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
                return layout::upgrade_layout(server, store_version, true, run).await;
            } else {
                abort(concat!(
                    "You must first upgrade to version 0.15, please read ",
                    "https://docs.inbuxa.org/install/migrating/"
                ));
            }
        }
    }

    migrate_v0_16(server).await?;
    write_schema_version(server).await?;
    layout::upgrade_layout(server, store_version, false, run).await
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

pub(crate) fn abort(message: &str) -> ! {
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
    (
        b"STALWART_SPAM_TRAIN_DATA.lz4",
        common::manager::SPAM_TRAINER_KEY,
    ),
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

/// inbuxa: #608: ACME providers created before #608 were saved with their
/// contacts as `mailto:` URIs, which the provider's email validation refuses
/// on the next edit. Each one becomes the plain address. Older builds read
/// either form, so this needs no store layout step and a rollback is safe.
async fn plain_acme_contacts(server: &Server) -> trc::Result<()> {
    for provider in server
        .registry()
        .list::<AcmeProvider>()
        .await
        .caused_by(trc::location!())?
    {
        let Some(contact) = plain_contacts(provider.object.contact.as_slice())
            .filter(|contact| !contact.is_empty())
        else {
            continue;
        };
        let old = Object {
            inner: provider.object.clone().into(),
            revision: provider.revision,
        };
        let mut updated = provider.object;
        updated.contact = registry::types::map::Map::new(contact);
        let new = Object {
            inner: updated.into(),
            revision: provider.revision,
        };
        server
            .registry()
            .write(RegistryWrite::update(provider.id.id(), &new, &old))
            .await
            .caused_by(trc::location!())?;
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = "Stored an ACME provider's contacts as plain addresses",
            Id = provider.id.id().id().to_string(),
        );
    }
    Ok(())
}

/// The contacts with any `mailto:` prefix taken off, or `None` when none
/// had one. A contact that is then a duplicate is dropped.
fn plain_contacts(contacts: &[String]) -> Option<Vec<String>> {
    if !contacts
        .iter()
        .any(|contact| has_mailto_prefix(contact.trim()))
    {
        return None;
    }
    let mut plain: Vec<String> = Vec::with_capacity(contacts.len());
    for contact in contacts {
        let contact = contact.trim();
        let address = if has_mailto_prefix(contact) {
            contact[7..].trim()
        } else {
            contact
        };
        if !address.is_empty() && !plain.iter().any(|known| known == address) {
            plain.push(address.to_string());
        }
    }
    Some(plain)
}

fn has_mailto_prefix(contact: &str) -> bool {
    contact
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mailto:"))
}

#[cfg(test)]
mod tests {
    use super::plain_contacts;

    #[test]
    fn acme_contacts_lose_mailto() {
        let s = |v: &[&str]| v.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        assert_eq!(plain_contacts(&s(&["admin@example.org"])), None);
        assert_eq!(plain_contacts(&[]), None);
        assert_eq!(
            plain_contacts(&s(&["mailto:admin@example.org", "ops@example.org"])),
            Some(s(&["admin@example.org", "ops@example.org"]))
        );
        assert_eq!(
            plain_contacts(&s(&[" MAILTO:admin@example.org", "admin@example.org"])),
            Some(s(&["admin@example.org"]))
        );
        assert_eq!(plain_contacts(&s(&["mailto:"])), Some(vec![]));
    }
}
