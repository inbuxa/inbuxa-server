/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    Core, Server,
    config::{
        server::{Listeners, tls::parse_certificates},
        storage::Storage,
        telemetry::Telemetry,
    },
    ipc::{QueueEvent, RegistryChange},
    network::security::{BlockedIps, IpWithTtl},
};
use ahash::AHashMap;
use directory::Directories;
use registry::{
    schema::{prelude::ObjectType, structs::BlockedIp},
    types::{
        error::{Error, Warning},
        id::ObjectId,
    },
};
use std::sync::Arc;
use store::{LookupStores, registry::bootstrap::Bootstrap, write::now};

pub struct ReloadResult {
    /// Errors that kept the reload from being applied.
    pub errors: Vec<Error>,
    /// inbuxa: errors in objects that already failed when the running
    /// settings were built; logged, but they don't refuse a reload.
    pub known_errors: Vec<Error>,
    pub warnings: Vec<Warning>,
    pub replaced_core: bool,
}

impl Server {
    pub async fn reload_registry(&self, change: RegistryChange) -> trc::Result<ReloadResult> {
        let mut bootstrap = Bootstrap::new(self.registry().clone()).await;
        let object = match change {
            RegistryChange::Insert(id) => {
                if matches!(id.object(), ObjectType::BlockedIp) {
                    if let Some(ip) = bootstrap.get_infallible::<BlockedIp>(id.id()).await {
                        let expires_at = ip
                            .expires_at
                            .as_ref()
                            .map(|dt| dt.timestamp() as u64)
                            .unwrap_or(u64::MAX);

                        if expires_at > now() {
                            let mut ips = self.inner.data.blocked_ips.write();
                            if let Some(ip) = ip.address.try_to_ip() {
                                ips.blocked_ip_addresses
                                    .insert(IpWithTtl::new(ip, expires_at));
                            } else {
                                ips.blocked_ip_networks
                                    .push(IpWithTtl::new(ip.address, expires_at));
                            }
                        }
                    }
                    return Ok(bootstrap.into());
                } else {
                    id.object()
                }
            }
            RegistryChange::Delete(id) => id.object(),
            RegistryChange::Reload(object) => object,
        };

        match object {
            ObjectType::Certificate => {
                let mut certificates = AHashMap::new();
                parse_certificates(&mut bootstrap, &mut certificates, &mut Default::default())
                    .await;
                self.inner
                    .data
                    .tls_certificates
                    .store(Arc::new(certificates));
            }
            ObjectType::MemoryLookupKey
            | ObjectType::MemoryLookupKeyValue
            | ObjectType::HttpLookup
            | ObjectType::StoreLookup => {
                let lookup = LookupStores::build(&mut bootstrap).await;

                if bootstrap.errors.is_empty() {
                    self.inner.data.lookup_stores.store(Arc::new(lookup.stores));
                }
            }

            ObjectType::BlockedIp => {
                let blocked_ips = BlockedIps::parse(&mut bootstrap).await;
                if bootstrap.errors.is_empty() {
                    *self.inner.data.blocked_ips.write() = blocked_ips;
                }
            }
            ObjectType::Application => {
                self.inner.data.applications.reload(&mut bootstrap).await;
                if bootstrap.errors.is_empty() {
                    self.inner.data.applications.unpack_all(self, false).await;
                }
            }
            _ => {
                // Load stores
                let directory = Directories::build(&mut bootstrap).await;
                let storage = &self.core.storage;
                let storage = Storage {
                    registry: storage.registry.clone(),
                    data: storage.data.clone(),
                    blob: storage.blob.clone(),
                    search: storage.search.clone(),
                    metrics: storage.metrics.clone(),
                    tracing: storage.tracing.clone(),
                    memory: storage.memory.clone(),
                    coordinator: storage.coordinator.clone(),
                    directory: directory.default_directory,
                    directories: directory.directories,
                };

                // inbuxa: upstream swapped the core only when the whole build
                // was free of errors, while boot runs with whatever built. So one
                // object that failed (a DNS lookup that timed out, say) refused
                // every later reload, cluster-wide when the reload came from
                // ReloadSettings, and the running settings went stale. Now a
                // reload is refused only for errors in objects that built when
                // the running settings were built: those would be lost by
                // applying it. Objects that already failed then are missing
                // from the running settings anyway, as at boot, so their
                // errors are reported but don't hold the reload back.
                let tracers = Telemetry::parse(&mut bootstrap, &storage).await;
                let core = Box::pin(Core::parse(&mut bootstrap, storage)).await;
                let mut servers = Listeners::parse(&mut bootstrap).await;

                if !self.has_new_build_errors(&bootstrap.errors) {
                    servers
                        .parse_tcp_acceptors(&mut bootstrap, self.inner.clone())
                        .await;

                    if !self.has_new_build_errors(&bootstrap.errors) {
                        // Update core
                        self.inner.shared_core.store(core.into());

                        // Update tracers
                        tracers.update();

                        // Reload queue settings
                        self.inner
                            .ipc
                            .queue_tx
                            .send(QueueEvent::ReloadSettings)
                            .await
                            .ok();

                        self.record_build_errors(&bootstrap.errors);

                        return Ok(ReloadResult {
                            errors: Vec::new(),
                            known_errors: bootstrap.errors,
                            warnings: bootstrap.warnings,
                            replaced_core: true,
                        });
                    }
                }

                let (known_errors, errors) = std::mem::take(&mut bootstrap.errors)
                    .into_iter()
                    .partition(|error| self.is_known_build_error(error));
                return Ok(ReloadResult {
                    errors,
                    known_errors,
                    warnings: bootstrap.warnings,
                    replaced_core: false,
                });
            }
        }

        Ok(bootstrap.into())
    }
}

impl ReloadResult {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn log(&self) {
        for error in self.errors.iter().chain(&self.known_errors) {
            error.log();
        }
        for warning in &self.warnings {
            warning.log();
        }
    }
}

impl From<Bootstrap> for ReloadResult {
    fn from(bootstrap: Bootstrap) -> Self {
        Self {
            errors: bootstrap.errors,
            known_errors: Vec::new(),
            warnings: bootstrap.warnings,
            replaced_core: false,
        }
    }
}

// inbuxa: which objects failed to build for the running settings
impl Server {
    /// Records the objects that failed to build for the settings now running.
    pub fn record_build_errors(&self, errors: &[Error]) {
        *self.inner.data.build_errors.lock() = errors.iter().filter_map(error_object).collect();
    }

    fn is_known_build_error(&self, error: &Error) -> bool {
        error_object(error).is_some_and(|id| self.inner.data.build_errors.lock().contains(&id))
    }

    fn has_new_build_errors(&self, errors: &[Error]) -> bool {
        errors.iter().any(|error| !self.is_known_build_error(error))
    }
}

fn error_object(error: &Error) -> Option<ObjectId> {
    match error {
        Error::Validation { object_id, .. }
        | Error::Build { object_id, .. }
        | Error::NotFound { object_id } => Some(*object_id),
        Error::Internal { object_id, .. } => *object_id,
    }
}
