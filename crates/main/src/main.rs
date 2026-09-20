/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]
#![warn(clippy::cast_possible_truncation)]
#![warn(clippy::cast_possible_wrap)]
#![warn(clippy::cast_sign_loss)]

use common::{BuildServer, config::server::ServerProtocol, manager::boot::BootManager};
use http::HttpSessionManager;
use imap::core::ImapSessionManager;
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use services::{StartServices, broadcast::subscriber::spawn_broadcast_subscriber};
use smtp::{StartQueueManager, core::SmtpSessionManager};
use std::time::Duration;
use trc::Collector;
use utils::wait_for_shutdown;

#[cfg(feature = "dev_mode")]
pub mod test_data;

#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Install AWS-LC-RS as the default Rustls crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install aws-lc-rs as the default rustls crypto provider");

    // Build the shared outbound TLS configurations
    utils::http::init_shared_tls_configs();

    // Load config and apply macros
    let mut init = Box::pin(BootManager::init()).await;

    // Migrate database
    if let Err(err) = migration::try_migrate(&init.inner.build_server()).await {
        trc::event!(
            Server(trc::ServerEvent::StartupError),
            Details = "Failed to migrate database, aborting startup.",
            Reason = err,
        );
        return Ok(());
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
        server.insert_test_metrics().await;
    }

    // Spawn servers
    // Each listener gets its own shutdown channel, registered under its id, so
    // the legacy-protocols switch can close one protocol's ports and leave the
    // rest accepting (legacy-protocols LP-2). The registry lives in `Data` and
    // so outlives the listeners, which it must: it owns the sending ends.
    let listener_control = &init.inner.data.listener_control;
    let (shutdown_tx, shutdown_rx) =
        init.servers
            .spawn_with_control(listener_control, |server, acceptor, shutdown_rx| {
                match &server.protocol {
                    ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
                        SmtpSessionManager::new(init.inner.clone()),
                        init.inner.clone(),
                        acceptor,
                        shutdown_rx,
                    ),
                    ServerProtocol::Http => server.spawn(
                        HttpSessionManager::new(init.inner.clone()),
                        init.inner.clone(),
                        acceptor,
                        shutdown_rx,
                    ),
                    ServerProtocol::Imap => server.spawn(
                        ImapSessionManager::new(init.inner.clone()),
                        init.inner.clone(),
                        acceptor,
                        shutdown_rx,
                    ),
                    ServerProtocol::Pop3 => server.spawn(
                        Pop3SessionManager::new(init.inner.clone()),
                        init.inner.clone(),
                        acceptor,
                        shutdown_rx,
                    ),
                    ServerProtocol::ManageSieve => server.spawn(
                        ManageSieveSessionManager::new(init.inner.clone()),
                        init.inner.clone(),
                        acceptor,
                        shutdown_rx,
                    ),
                };
            });

    // Start broadcast subscriber
    let inner = init.inner.clone();
    spawn_broadcast_subscriber(init.inner, shutdown_rx);

    // Wait for shutdown signal
    wait_for_shutdown().await;

    // Shutdown collector
    Collector::shutdown();

    // Stop services, then the listeners: the shutdown sender no longer reaches
    // them, since each holds its own channel (LP-2).
    let _ = shutdown_tx.send(true);
    inner.data.listener_control.stop_all();

    // Wait for services to finish
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}
