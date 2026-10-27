/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

#![warn(clippy::large_futures)]
#![warn(clippy::cast_possible_truncation)]
#![warn(clippy::cast_possible_wrap)]
#![warn(clippy::cast_sign_loss)]

#[cfg(target_os = "linux")]
use common::manager::systemd::ServiceState;
use common::{
    BuildServer, Inner,
    config::server::{Listener, ServerProtocol},
    manager::boot::BootManager,
    network::TcpAcceptor,
};
use http::HttpSessionManager;
use imap::core::ImapSessionManager;
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use services::{StartServices, broadcast::subscriber::spawn_broadcast_subscriber};
use smtp::{StartQueueManager, core::SmtpSessionManager};
use std::{process::ExitCode, sync::Arc, time::Duration};
use tokio::sync::watch;
use trc::Collector;
use utils::{
    runtime::{exit, run_server},
    wait_for_shutdown,
};

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "sse4.2",
    any(target_os = "linux", target_os = "freebsd")
))]
mod cpu;
#[cfg(feature = "dev_mode")]
pub mod test_data;

#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() -> std::io::Result<ExitCode> {
    run_server(async_main())
}

async fn async_main() -> ExitCode {
    // Install AWS-LC-RS as the default Rustls crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install aws-lc-rs as the default rustls crypto provider");

    // Build the shared outbound TLS configurations
    utils::http::init_shared_tls_configs();

    // Prepare the archive compression dictionaries
    store::write::compress::init();

    // Load config and apply macros
    let mut init = BootManager::init().await;

    // Verify database schema version
    if let Err(err) = init.inner.build_server().verify_schema_version().await {
        eprintln!("{err}");
        trc::event!(
            Server(trc::ServerEvent::StartupError),
            Details = "Unsupported database schema version, aborting startup.",
            Reason = err,
        );
        return ExitCode::FAILURE;
    }

    // inbuxa: move blobs still under pre-rename keys (0.16 did this in its
    // migration crate) before the services read them
    if let Err(err) =
        common::manager::renamed_blobs::rename_spam_blobs(&init.inner.build_server()).await
    {
        trc::error!(err.details("Failed to move renamed spam filter blobs"));
    }

    // Init services
    init.start_services().await;
    init.start_queue_manager();

    // Log configuration errors
    init.bootstrap.log_errors();
    init.bootstrap.log_warnings();


    #[cfg(feature = "dev_mode")]
    if std::env::var("INSERT_TEST_DATA").is_ok() {
        let server = init.inner.build_server();
        test_data::insert_test_data(&server).await;
        #[cfg(feature = "enterprise")]
        server.insert_test_metrics().await;
    }

    // Spawn servers
    // Each listener gets its own shutdown channel, registered under its id, so
    // the legacy-protocols switch can close one protocol's ports and leave the
    // rest accepting (legacy-protocols LP-2). The registry lives in `Data` and
    // so outlives the listeners, which it must: it owns the sending ends.
    let listener_control = &init.inner.data.listener_control;
    let spawn_inner = init.inner.clone();
    let (shutdown_tx, shutdown_rx) =
        init.servers
            .spawn_with_control(listener_control, |server, acceptor, shutdown_rx| {
                spawn_listener(&spawn_inner, server, acceptor, shutdown_rx);
            });

    // Leave behind how to spawn a listener, so putting one back opens its port
    // without a restart (LP-5). Only this file knows the session manager for a
    // protocol, so only this file can say.
    let spawn_inner = init.inner.clone();
    init.inner
        .data
        .listener_control
        .set_spawner(Box::new(move |server, acceptor, shutdown_rx| {
            spawn_listener(&spawn_inner, server, acceptor, shutdown_rx);
        }));

    // Start broadcast subscriber
    let inner = init.inner.clone();
    spawn_broadcast_subscriber(init.inner, shutdown_rx);

    #[cfg(target_os = "linux")]
    ServiceState::Ready.notify();

    // Wait for shutdown signal
    wait_for_shutdown().await;

    #[cfg(target_os = "linux")]
    ServiceState::Stopping.notify();

    // inbuxa: hand back the task locks this node holds, so other nodes can
    // run those tasks now rather than when the locks expire
    services::task_manager::lock::release_task_locks(&inner.build_server()).await;

    // Stop services, then the listeners: the shutdown sender no longer reaches
    // them, since each holds its own channel (LP-2).
    let _ = shutdown_tx.send(true);
    inner.data.listener_control.stop_all();

    // Persist the newest cache snapshots before the process exits
    inner.cache.swap.stop().await;

    // Shutdown collector
    Collector::shutdown();

    // Wait for services to finish
    tokio::time::sleep(Duration::from_secs(1)).await;

    exit(0);
}

/// Starts one listener under the session manager its protocol calls for.
///
/// Used twice: once for every listener at startup, and again whenever the
/// legacy-protocols switch puts a listener back (LP-5).
fn spawn_listener(
    inner: &Arc<Inner>,
    server: Listener,
    acceptor: TcpAcceptor,
    shutdown_rx: watch::Receiver<bool>,
) {
    match &server.protocol {
        ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
            SmtpSessionManager::new(inner.clone()),
            inner.clone(),
            acceptor,
            shutdown_rx,
        ),
        ServerProtocol::Http => server.spawn(
            HttpSessionManager::new(inner.clone()),
            inner.clone(),
            acceptor,
            shutdown_rx,
        ),
        ServerProtocol::Imap => server.spawn(
            ImapSessionManager::new(inner.clone()),
            inner.clone(),
            acceptor,
            shutdown_rx,
        ),
        ServerProtocol::Pop3 => server.spawn(
            Pop3SessionManager::new(inner.clone()),
            inner.clone(),
            acceptor,
            shutdown_rx,
        ),
        ServerProtocol::ManageSieve => server.spawn(
            ManageSieveSessionManager::new(inner.clone()),
            inner.clone(),
            acceptor,
            shutdown_rx,
        ),
    }
}
