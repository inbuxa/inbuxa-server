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
    ipc::{BroadcastEvent, QueueEvent, RegistryChange},
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

                        // inbuxa: the task manager reads the node's role on
                        // every scan; scan now, so a role that gained task
                        // types starts claiming them without waiting out the
                        // refresh interval
                        self.inner.ipc.task_tx.notify_one();

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

// inbuxa: upstream applied a registry write to the running settings only on
// an explicit x:Action ReloadSettings (Directory and Authentication aside), so
// a new MtaDeliverySchedule, say, stayed unknown ("Queue strategy not found")
// until someone reloaded. Writes to objects the settings are built from now
// reload them, here and across the cluster, as ReloadSettings does.

/// Coalesces the full reloads that registry writes trigger: a write waits for
/// a reload that started after it was stored, and joins one if it can, so a
/// burst of writes costs a reload or two rather than one each.
#[derive(Default)]
pub struct SettingsReloadGate {
    requested: std::sync::atomic::AtomicU64,
    state: tokio::sync::Mutex<SettingsReloadState>,
}

#[derive(Default)]
struct SettingsReloadState {
    completed: u64,
    refused: Option<String>,
}

/// The reload a write to `object` calls for: the object to reload, or None
/// when the running settings don't hold that object (accounts, domains and
/// other data read as needed, stores, which take a restart, and objects with
/// reload actions of their own, such as applications). Blocked IPs have a
/// reload of their own; allowed IPs take the full one.
pub fn write_reload_target(object: ObjectType) -> Option<ObjectType> {
    match object {
        ObjectType::Certificate => Some(ObjectType::Certificate),
        ObjectType::MemoryLookupKey
        | ObjectType::MemoryLookupKeyValue
        | ObjectType::HttpLookup
        | ObjectType::StoreLookup => Some(ObjectType::StoreLookup),
        ObjectType::BlockedIp => Some(ObjectType::BlockedIp),
        // Allowed IPs are part of the core's security settings
        // (Security::parse), which only a full reload rebuilds; the blocked-IP
        // reload doesn't touch them
        ObjectType::AllowedIp
        | ObjectType::AcmeProvider
        | ObjectType::AddressBook
        | ObjectType::AiModel
        | ObjectType::Asn
        | ObjectType::Authentication
        | ObjectType::Cache
        | ObjectType::Calendar
        | ObjectType::CalendarAlarm
        | ObjectType::CalendarScheduling
        | ObjectType::ClusterRole
        | ObjectType::DataRetention
        | ObjectType::Directory
        | ObjectType::DkimReportSettings
        | ObjectType::DmarcReportSettings
        | ObjectType::DnsResolver
        | ObjectType::DsnReportSettings
        | ObjectType::Email
        | ObjectType::EventTracingLevel
        | ObjectType::FileStorage
        | ObjectType::Http
        | ObjectType::HttpForm
        | ObjectType::Imap
        | ObjectType::Jmap
        | ObjectType::Metrics
        | ObjectType::MtaConnectionStrategy
        | ObjectType::MtaDeliverySchedule
        | ObjectType::MtaExtensions
        | ObjectType::MtaHook
        | ObjectType::MtaInboundSession
        | ObjectType::MtaInboundThrottle
        | ObjectType::MtaMilter
        | ObjectType::MtaOutboundStrategy
        | ObjectType::MtaOutboundThrottle
        | ObjectType::MtaQueueQuota
        | ObjectType::MtaRoute
        | ObjectType::MtaStageAuth
        | ObjectType::MtaStageConnect
        | ObjectType::MtaStageData
        | ObjectType::MtaStageEhlo
        | ObjectType::MtaStageMail
        | ObjectType::MtaStageRcpt
        | ObjectType::MtaSts
        | ObjectType::MtaTlsStrategy
        | ObjectType::MtaVirtualQueue
        | ObjectType::NetworkListener
        | ObjectType::OidcProvider
        | ObjectType::ReportSettings
        | ObjectType::Search
        | ObjectType::Security
        | ObjectType::SenderAuth
        | ObjectType::Sharing
        | ObjectType::SieveSystemInterpreter
        | ObjectType::SieveSystemScript
        | ObjectType::SieveUserInterpreter
        | ObjectType::SieveUserScript
        | ObjectType::SpamClassifier
        | ObjectType::SpamDnsblServer
        | ObjectType::SpamDnsblSettings
        | ObjectType::SpamFileExtension
        | ObjectType::SpamPyzor
        | ObjectType::SpamRule
        | ObjectType::SpamSettings
        | ObjectType::SpamTag
        | ObjectType::SpfReportSettings
        | ObjectType::SystemSettings
        | ObjectType::TaskManager
        | ObjectType::TlsReportSettings
        | ObjectType::Tracer
        | ObjectType::WebDav
        | ObjectType::WebHook => Some(object),
        _ => None,
    }
}

impl Server {
    /// Applies a stored registry write to `object` to the running settings,
    /// and on success tells the other nodes to do the same. Returns None when
    /// the write needs no reload, Some(Ok(())) when it was applied, and
    /// Some(Err(reason)) when the reload was refused (the write stays stored;
    /// ReloadSettings reports the same errors).
    pub async fn reload_after_write(&self, object: ObjectType) -> Option<Result<(), String>> {
        let target = write_reload_target(object)?;
        let change = RegistryChange::Reload(target);

        if matches!(
            target,
            ObjectType::Certificate | ObjectType::StoreLookup | ObjectType::BlockedIp
        ) {
            // Cheap, and limited to their own objects
            let result = self.reload_and_broadcast(change).await;
            return Some(result);
        }

        let gate = &self.inner.data.settings_reload;
        let ticket = gate
            .requested
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let mut state = gate.state.lock().await;
        if state.completed >= ticket {
            // A reload that started after this write was stored has run
            return Some(state.refused.clone().map_or(Ok(()), Err));
        }
        let covers = gate.requested.load(std::sync::atomic::Ordering::SeqCst);
        let result = self.reload_and_broadcast(change).await;
        state.completed = covers;
        state.refused = result.clone().err();
        Some(result)
    }

    async fn reload_and_broadcast(&self, change: RegistryChange) -> Result<(), String> {
        match Box::pin(self.reload_registry(change)).await {
            Ok(reload) if !reload.has_errors() => {
                reload.log();
                self.cluster_broadcast(BroadcastEvent::RegistryChange(change))
                    .await;
                Ok(())
            }
            Ok(reload) => {
                reload.log();
                let reason = describe_reload_errors(&reload.errors);
                trc::event!(
                    Registry(trc::RegistryEvent::BuildWarning),
                    Details = "Settings didn't reload after a registry write",
                    Reason = reason.clone(),
                );
                Err(reason)
            }
            Err(err) => {
                let reason = err.to_string();
                trc::error!(err.details("Failed to reload settings after a registry write"));
                Err(reason)
            }
        }
    }
}

/// inbuxa: a refused reload's errors in a sentence: the first one, naming its
/// object, and how many more there are.
pub fn describe_reload_errors(errors: &[Error]) -> String {
    let mut description = match errors.first() {
        Some(Error::Build { object_id, message }) => format!("{object_id}: {message}"),
        Some(Error::Validation { object_id, errors }) => format!(
            "{object_id}: {}",
            errors
                .iter()
                .map(|err| err.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        ),
        Some(Error::Internal {
            object_id: Some(object_id),
            error,
        }) => format!("{object_id}: {error}"),
        Some(Error::Internal { error, .. }) => error.to_string(),
        Some(Error::NotFound { object_id }) => format!("{object_id} was not found"),
        None => String::new(),
    };
    let more = errors.len().saturating_sub(1);
    if more > 0 {
        description.push_str(&format!(" ({more} more in the server log.)"));
    }
    description
}
