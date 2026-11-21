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
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use trc::Collector;
use utils::wait_for_shutdown;

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

    // inbuxa: K-S3: --upgrade-store upgrades the store's layout and exits
    if init.upgrade_store {
        // Boxed: inline, its future made main's too deep to lay out once
        // every store backend is compiled in (the release image's features)
        let server = init.inner.build_server();
        std::process::exit(Box::pin(upgrade_store_and_exit(&server)).await);
    }

    // inbuxa: K-C9: --upgrade-plan reports what an upgrade would do
    if init.upgrade_plan {
        let server = init.inner.build_server();
        std::process::exit(Box::pin(upgrade_plan_and_exit(&server)).await);
    }

    // inbuxa: K-S8: --seed sets up a new store from a file and exits
    if let Some(path) = init.seed.clone() {
        let server = init.inner.build_server();
        std::process::exit(Box::pin(seed_and_exit(&server, &path, init.store_was_new)).await);
    }

    // inbuxa: K-C11: --store-check runs a check and exits
    if let Some(mode) = init.store_check.clone() {
        let server = init.inner.build_server();
        std::process::exit(Box::pin(store_check_and_exit(&server, &mode)).await);
    }

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

    // inbuxa: store-layout spec SL-5: stop if a newer release changes the store
    migration::layout::spawn_mark_watch(init.inner.clone());

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
    let spawn_inner = init.inner.clone();
    let (shutdown_tx, shutdown_rx) =
        init.servers
            .spawn_with_control(listener_control, |server, acceptor, shutdown_rx| {
                spawn_listener(&spawn_inner, server, acceptor, shutdown_rx);
            });

    // inbuxa: #485: listeners spawned from here on (LP-5) never end the
    // process; and a node starts with no failures left from its last run
    common::network::bind_health::startup_done();
    {
        let server = init.inner.build_server();
        tokio::spawn(async move { server.publish_listener_failures().await });
    }

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
    // inbuxa: #437: and its singleton role leases, so another node (or this
    // one, restarted) takes those roles over at once
    common::manager::singleton_lease::release_singleton_leases(&inner.build_server()).await;

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

/// inbuxa: K-S3: the exit code of `--upgrade-store`: 0 when the store is at
/// this build's layout (upgraded now or already), 1 when the upgrade failed,
/// 2 when it was refused because another node is in the way.
async fn upgrade_store_and_exit(server: &common::Server) -> i32 {
    let (code, message) = upgrade_store_only(server).await;
    eprintln!("{message}");
    flush_and_exit_code(code).await
}

/// inbuxa: K-S8: `--seed`: the layout upgrade, then the seed
async fn seed_and_exit(
    server: &common::Server,
    path: &std::path::Path,
    store_was_new: bool,
) -> i32 {
    use jmap::inbuxa::seed::{SeedOutcome, apply_seed};

    let (code, message) = upgrade_store_only(server).await;
    eprintln!("{message}");
    if code != 0 {
        return flush_and_exit_code(code).await;
    }

    let (code, message) = match apply_seed(server, path, store_was_new).await {
        Ok(SeedOutcome::Applied { calls, created }) => (
            0,
            format!("Applied the seed: {calls} calls, {created} objects created or updated."),
        ),
        Ok(SeedOutcome::AlreadyApplied { changed: false }) => (
            0,
            "This store was seeded before: nothing to do.".to_string(),
        ),
        Ok(SeedOutcome::AlreadyApplied { changed: true }) => (
            0,
            "This store was seeded before, from a different file. The seed is only \
             applied once: change the setup in the console or through the API."
                .to_string(),
        ),
        Ok(SeedOutcome::Refused(reason)) => {
            trc::event!(
                Server(trc::ServerEvent::StartupError),
                Details = "Refused to apply the seed",
                Reason = reason.clone(),
            );
            (2, format!("Refused to apply the seed: {reason}"))
        }
        Err(reason) => {
            trc::event!(
                Server(trc::ServerEvent::StartupError),
                Details = "Failed to apply the seed",
                Reason = reason.clone(),
            );
            (1, reason)
        }
    };
    eprintln!("{message}");
    flush_and_exit_code(code).await
}

/// inbuxa: K-C11: `--store-check`: 0 found nothing wrong, 3 found problems,
/// 2 another check was running, 1 failed
async fn store_check_and_exit(server: &common::Server, mode: &str) -> i32 {
    use services::inbuxa_store_check::{
        CheckMode as Mode, CheckRefusal as Refusal, CheckStatus as Status,
    };

    let mode = Mode::parse(mode).unwrap_or(Mode::Quick);
    let (code, message) = match services::inbuxa_store_check::run_now(server, mode).await {
        Ok(Ok(check)) => {
            let p = &check.progress;
            let summary = format!(
                "Store check {} ({}): {} blobs, {} links, {} messages checked, {} bytes read. \
                 Missing {}, damaged {}, unlinked {}, unreadable {}.",
                check.id,
                mode.as_str(),
                p.blobs_checked,
                p.links_checked,
                p.messages_checked,
                p.bytes_read,
                p.missing,
                p.damaged,
                p.unlinked,
                p.unreadable,
            );
            match check.status {
                Status::Done if p.problems() == 0 => (0, format!("{summary} Nothing wrong.")),
                Status::Done => (
                    3,
                    format!(
                        "{summary} {} problems: the console's Store checks page lists them.",
                        p.problems()
                    ),
                ),
                status => (
                    1,
                    format!(
                        "{summary} It ended {}: {}",
                        status.as_str(),
                        check.error.as_deref().unwrap_or("no reason given")
                    ),
                ),
            }
        }
        Ok(Err(Refusal::Running(id))) => (
            2,
            format!("Store check {id} is running: one check runs at a time."),
        ),
        Err(err) => (1, format!("The store check failed: {err}")),
    };
    println!("{message}");
    flush_and_exit_code(code).await
}

/// inbuxa: K-C9: `--upgrade-plan`: one line of JSON on stdout, for a
/// script to read, and the exit code a shell can branch on
async fn upgrade_plan_and_exit(server: &common::Server) -> i32 {
    use migration::UpgradePlan;

    let target = common::INBUXA_STORE_VERSION;
    let (code, plan) = match migration::upgrade_plan(server).await {
        Ok(UpgradePlan::NewStore) => (
            0,
            serde_json::json!({"store": null, "target": target, "newStore": true, "steps": [], "stopAllNodes": false}),
        ),
        Ok(UpgradePlan::Steps { from, steps }) => {
            let stop = steps.iter().any(|step| !step.rolling_safe);
            let code = match (steps.is_empty(), stop) {
                (true, _) => 0,
                (false, false) => 3,
                (false, true) => 4,
            };
            let steps = steps
                .iter()
                .map(|step| {
                    serde_json::json!({
                        "from": step.from,
                        "to": step.from + 1,
                        "rollingSafe": step.rolling_safe,
                        "what": step.what,
                    })
                })
                .collect::<Vec<_>>();
            (
                code,
                serde_json::json!({"store": from, "target": target, "newStore": false, "steps": steps, "stopAllNodes": stop}),
            )
        }
        Ok(UpgradePlan::Newer(version)) => {
            eprintln!(
                "A newer release changed this store (layout version {version}; this release reads up to {target})."
            );
            (
                2,
                serde_json::json!({"store": version, "target": target, "newer": true}),
            )
        }
        Ok(UpgradePlan::NeedsMigration(reason)) => {
            eprintln!("Can't plan an upgrade: {reason}.");
            return flush_and_exit_code(1).await;
        }
        Err(err) => {
            eprintln!("Can't plan an upgrade: {err}");
            return flush_and_exit_code(1).await;
        }
    };
    println!("{plan}");
    flush_and_exit_code(code).await
}

async fn upgrade_store_only(server: &common::Server) -> (i32, String) {
    use migration::layout::Outcome;

    match migration::upgrade_store(server).await {
        Ok(Outcome::Current) => (
            0,
            format!(
                "The store layout is at version {}: nothing to upgrade.",
                common::INBUXA_STORE_VERSION
            ),
        ),
        Ok(Outcome::Upgraded { from }) => (
            0,
            format!(
                "Upgraded the store layout from version {from} to {}.",
                common::INBUXA_STORE_VERSION
            ),
        ),
        Ok(Outcome::Refused(reason)) => {
            trc::event!(
                Server(trc::ServerEvent::StartupError),
                Details = "Refused to upgrade the store layout",
                Reason = reason.clone(),
            );
            (2, format!("Refused to upgrade the store layout: {reason}."))
        }
        Err(err) => {
            let message = format!("Failed to upgrade the store layout: {err}");
            trc::event!(
                Server(trc::ServerEvent::StartupError),
                Details = "Failed to upgrade the store layout",
                Reason = err,
            );
            (1, message)
        }
    }
}

async fn flush_and_exit_code(code: i32) -> i32 {
    // Let the log reach its collector
    Collector::shutdown();
    tokio::time::sleep(Duration::from_secs(1)).await;
    code
}
