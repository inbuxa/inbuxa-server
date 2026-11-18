/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use super::{backup::BackupParams, console::store_console};
use crate::{
    BuildServer, Caches, Core, Data, IPC_CHANNEL_BUFFER, Inner, Ipc,
    config::{
        network::AsnGeoLookupConfig, server::Listeners, storage::Storage, telemetry::Telemetry,
    },
    ipc::{BroadcastEvent, PushEvent, QueueEvent, ReportingEvent, TrainTaskController},
    manager::defaults::BootstrapDefaults,
};
use arc_swap::ArcSwap;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
};
use store::{RegistryStore, registry::bootstrap::Bootstrap};
use tokio::sync::{Notify, mpsc};
use utils::{UnwrapFailure, failed};

pub struct BootManager {
    pub bootstrap: Bootstrap,
    pub inner: Arc<Inner>,
    pub servers: Listeners,
    pub ipc_rxs: IpcReceivers,
    /// inbuxa: K-S3: started with `--upgrade-store`: no listeners, no
    /// services; main upgrades the store's layout and exits
    pub upgrade_store: bool,
    /// inbuxa: K-S8: started with `--seed <PATH>`: like `--upgrade-store`,
    /// and then main applies the seed and exits
    pub seed: Option<PathBuf>,
    /// inbuxa: K-S8: whether the store was new when this process started,
    /// before the defaults went in
    pub store_was_new: bool,
}

pub struct IpcReceivers {
    pub push_rx: Option<mpsc::Receiver<PushEvent>>,
    pub queue_rx: Option<mpsc::Receiver<QueueEvent>>,
    pub report_rx: Option<mpsc::Receiver<ReportingEvent>>,
    pub broadcast_rx: Option<mpsc::Receiver<BroadcastEvent>>,
}

const HELP: &str = concat!(
    types::brand_server!(),
    " ",
    types::brand_version!(),
    r#"

Usage: inbuxa [OPTIONS]

Options:
  -c, --config <PATH>              Start server with the specified configuration file
  -e, --export <PATH>              Export all store data to a specific path
  -i, --import <PATH>              Import store data from a specific path
  -o, --console                    Open the store console
  -u, --upgrade-store              Upgrade the store's layout, then exit
      --seed <PATH>                Set up a new store from a file, then exit
  -h, --help                       Print help
  -V, --version                    Print version

An export holds everything in the data and blob stores except short-lived
in-memory state (rate limits, locks, greylisting) and the full-text search
index, which belongs to one search backend. An import into an empty store
queues the index to be rebuilt when the server next starts. EXPORT_TYPES
limits an export to some of: data, registry, blob, changelog, queue, report,
telemetry, tasks.

--upgrade-store does what a start does to the store before it serves, and
exits: 0 when the store is at this release's layout (whether it upgraded it
or found it there), 1 when the upgrade failed, 2 when it refused because
another node holds the upgrade lease, or still runs when a step needs every
other node stopped. It opens no ports and starts no services.

--seed sets up a new store from a file: a JMAP request body, its calls run
once as the system administrator, where {"$file": "<PATH>"} stands for that
file's contents. It upgrades the store's layout first, as --upgrade-store
does, and exits: 0 when the seed was applied (or was before, to this store),
1 when it failed, 2 when it refused because the store was set up already.
"#
);

#[derive(PartialEq, Eq)]
enum StoreOp {
    Export(BackupParams),
    Import(PathBuf),
    Console,
    // inbuxa: K-S3
    UpgradeStore,
    // inbuxa: K-S8
    Seed(PathBuf),
    None,
}

impl BootManager {
    pub async fn init() -> Self {
        let mut config_path = std::env::var("CONFIG_PATH").ok();
        let mut import_export = StoreOp::None;

        // inbuxa: K-S3: the arguments are read with CONFIG_PATH set too, so
        // `--upgrade-store` works where the path comes from the environment;
        // and an option that takes no value no longer swallows the next one,
        // so `--upgrade-store --config <PATH>` works in that order
        let mut args = std::env::args().skip(1);
        let has_args = args.len() > 0;
        while let Some(arg) = args.next().and_then(|arg| {
            arg.strip_prefix("--")
                .or_else(|| arg.strip_prefix('-'))
                .map(|arg| arg.to_string())
        }) {
            let (key, inline) = match arg.split_once('=') {
                Some((key, value)) => (key.to_string(), Some(value.trim().to_string())),
                None => (arg, None),
            };
            let takes_value = matches!(
                key.as_str(),
                "config" | "c" | "export" | "e" | "import" | "i" | "seed"
            );
            let value = if takes_value {
                inline.or_else(|| args.next())
            } else {
                inline
            };

            match (key.as_str(), value) {
                ("help" | "h", _) => {
                    eprintln!("{HELP}");
                    std::process::exit(0);
                }
                ("version" | "V", _) => {
                    println!("{}", types::brand_version!());
                    std::process::exit(0);
                }
                ("config" | "c", Some(value)) => {
                    config_path = Some(value);
                }
                ("export" | "e", Some(value)) => {
                    import_export = StoreOp::Export(BackupParams::new(value.into()));
                }
                ("import" | "i", Some(value)) => {
                    import_export = StoreOp::Import(value.into());
                }
                ("console" | "o", None) => {
                    import_export = StoreOp::Console;
                }
                ("upgrade-store" | "u", None) => {
                    import_export = StoreOp::UpgradeStore;
                }
                ("seed", Some(value)) => {
                    import_export = StoreOp::Seed(value.into());
                }
                (_, None) if takes_value => failed(&format!(
                    "Missing value for argument '{key}', try '--help'."
                )),
                (_, None) => {
                    failed(&format!("Unrecognized command '{key}', try '--help'."));
                }
                (_, Some(_)) => failed(&format!("Argument '{key}' takes no value, try '--help'.")),
            }
        }

        if config_path.is_none() {
            if import_export == StoreOp::None {
                eprintln!("{HELP}");
                std::process::exit(if has_args { 1 } else { 0 });
            }
            // A job that asked for a store operation must not pass without one
            failed("Missing '--config' argument (or CONFIG_PATH) for this command.");
        }

        // Initialize registry
        let upgrade_store = import_export == StoreOp::UpgradeStore;
        let seed = match &import_export {
            StoreOp::Seed(path) => Some(path.clone()),
            _ => None,
        };
        // inbuxa: K-S8: a seed run boots as --upgrade-store does
        let one_shot = upgrade_store || seed.is_some();
        let registry = RegistryStore::init(
            PathBuf::from(config_path.unwrap()),
            import_export == StoreOp::None || one_shot,
        )
        .await
        .failed("⚠️ Startup failed");
        if one_shot && (registry.is_bootstrap_mode() || registry.is_recovery_mode()) {
            failed(
                "--upgrade-store and --seed need a configured server: there is no data \
                 store in bootstrap mode, and recovery mode is for a person at the console.",
            );
        }
        let mut bootstrap = Bootstrap::new(registry).await;

        // inbuxa: K-S8: a seed is only for a new store, which the defaults
        // below stop being
        let store_was_new = seed.is_some()
            && super::defaults::is_new_install(&bootstrap)
                .await
                .failed("⚠️ Startup failed");

        // Add safe defaults if missing
        if import_export == StoreOp::None || seed.is_some() {
            bootstrap.insert_safe_defaults().await;
        }

        // Start listeners
        // inbuxa: K-S3: not for --upgrade-store, which serves nothing
        let mut servers = if one_shot {
            Listeners::default()
        } else {
            let servers = Listeners::parse(&mut bootstrap).await;
            servers.bind_and_drop_priv(&mut bootstrap);
            servers
        };

        // Parse storage
        let storage = Storage::parse(&mut bootstrap).await;

        // Parse telemetry
        let telemetry = Telemetry::parse(&mut bootstrap, &storage).await;

        match import_export {
            StoreOp::None | StoreOp::UpgradeStore | StoreOp::Seed(_) => {
                // Parse components
                let core: Box<Core> =
                    Box::new(Box::pin(Core::parse(&mut bootstrap, storage)).await);
                let data = Data::parse(&mut bootstrap).await;
                let cache = Caches::parse(&mut bootstrap).await;

                // Enable telemetry

                telemetry.enable();

                if one_shot {
                    trc::event!(
                        Server(trc::ServerEvent::Startup),
                        Details = if upgrade_store {
                            "Started with --upgrade-store: upgrading the store layout, then exiting"
                        } else {
                            "Started with --seed: setting up a new store from a file, then exiting"
                        },
                        Hostname = bootstrap.registry.local_hostname().to_string(),
                        Version = types::brand_version!(),
                    );
                } else if bootstrap.registry.is_bootstrap_mode() {
                    trc::event!(
                        Server(trc::ServerEvent::BootstrapMode),
                        Hostname = bootstrap.registry.local_hostname().to_string(),
                        Details =
                            "No configuration file was found. Port 8080 is open for initial setup.",
                        Version = types::brand_version!(),
                    );
                } else if bootstrap.registry.is_recovery_mode() {
                    trc::event!(
                        Server(trc::ServerEvent::RecoveryMode),
                        Details = "Port 8080 is open for troubleshooting and recovery.",
                        Hostname = bootstrap.registry.local_hostname().to_string(),
                        Version = types::brand_version!(),
                    );
                } else {
                    trc::event!(
                        Server(trc::ServerEvent::Startup),
                        Hostname = bootstrap.registry.local_hostname().to_string(),
                        Version = types::brand_version!(),
                    );
                }

                if core.storage.coordinator.is_enabled() {
                    trc::event!(
                        Cluster(trc::ClusterEvent::Startup),
                        Id = bootstrap.registry.node_id(),
                        Type = bootstrap
                            .registry
                            .cluster_role()
                            .unwrap_or("[default]")
                            .to_string(),
                        Details = bootstrap.registry.cluster_push_shard()
                    );
                }

                // Build shared inner
                let has_remote_asn = matches!(
                    core.network.asn_geo_lookup,
                    AsnGeoLookupConfig::Resource { .. }
                );
                let (ipc, ipc_rxs) = build_ipc(!core.storage.coordinator.is_none());
                let inner = Arc::new(Inner {
                    shared_core: ArcSwap::new(Arc::from(core)),
                    data,
                    ipc,
                    cache,
                });

                if !bootstrap.registry.is_recovery_mode() && !one_shot {
                    // Load spam model
                    if let Err(err) = inner.build_server().spam_model_reload().await {
                        trc::error!(
                            err.details("Failed to load spam filter model")
                                .caused_by(trc::location!())
                        );
                    }

                    // Fetch ASN database
                    if has_remote_asn {
                        inner
                            .build_server()
                            .lookup_asn_country(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
                            .await;
                    }
                }

                // Parse TCP acceptors
                if !one_shot {
                    servers
                        .parse_tcp_acceptors(&mut bootstrap, inner.clone())
                        .await;
                }

                // inbuxa: a reload isn't refused over objects that failed here
                inner.build_server().record_build_errors(&bootstrap.errors);

                // inbuxa: AU-1.10: the server's own registry writes are
                // recorded from here on, after boot's defaults
                inner.build_server().install_audit_hook();

                BootManager {
                    inner,
                    bootstrap,
                    servers,
                    ipc_rxs,
                    upgrade_store,
                    seed,
                    store_was_new,
                }
            }
            StoreOp::Export(path) => {
                // Enable telemetry
                telemetry.enable();

                // Parse settings and backup
                Box::pin(Core::parse(&mut bootstrap, storage))
                    .await
                    .backup(path)
                    .await;
                std::process::exit(0);
            }
            StoreOp::Import(path) => {
                // Enable telemetry
                telemetry.enable();

                // Parse settings and restore
                let core = Box::pin(Core::parse(&mut bootstrap, storage)).await;
                let imported = core.restore(path).await;
                // inbuxa: the search index isn't exported; rebuild it
                core.queue_reindex(&imported).await;
                std::process::exit(0);
            }
            StoreOp::Console => {
                // Store console
                store_console(
                    Box::pin(Core::parse(&mut bootstrap, storage))
                        .await
                        .storage
                        .data,
                )
                .await;
                std::process::exit(0);
            }
        }
    }
}

pub fn build_ipc(has_pubsub: bool) -> (Ipc, IpcReceivers) {
    // Build ipc receivers
    let (push_tx, push_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (queue_tx, queue_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (report_tx, report_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (broadcast_tx, broadcast_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    (
        Ipc {
            push_tx,
            queue_tx,
            report_tx,
            broadcast_tx: has_pubsub.then_some(broadcast_tx),
            task_tx: Arc::new(Notify::new()),
            task_locks: Arc::new(crate::ipc::TaskLocks::default()),
            train_task_controller: Arc::new(TrainTaskController::default()),
        },
        IpcReceivers {
            push_rx: Some(push_rx),
            queue_rx: Some(queue_rx),
            report_rx: Some(report_rx),
            broadcast_rx: has_pubsub.then_some(broadcast_rx),
        },
    )
}
