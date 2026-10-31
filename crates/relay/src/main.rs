/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa Relay: takes mail in on port 25 for one downstream inbuxa server
//! or cluster, and sends that downstream's mail on
//! (docs/spec/features/relay.md).
//!
//! It is administered only from the downstream's inbuxa-admin (RL-2). The
//! command line can join, run, show status, and reset; nothing else.

mod app;
mod changelog;
mod deliver;
mod events;
mod link;
mod outbound;
mod recipients;
mod smtp;
mod spool;
mod state;
#[cfg(test)]
mod tests_e2e;
mod upgrade;

use app::App;
use inbuxa_relay_proto::{time, token::JoinToken};
use state::{Identity, JoinStage, Paths, RunLock};
use std::{net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

const USAGE: &str = "\
inbuxa-relay: the inbuxa edge relay

Usage:
  inbuxa-relay join <token>          join the downstream that made the token
  inbuxa-relay run                   run the relay
  inbuxa-relay status                show the link, queue counts and version
  inbuxa-relay reset [--discard-held]
                                     forget the downstream and start over

Options:
  --state <dir>          state directory (default /var/lib/inbuxa-relay)
  --link-listen <addr>   link address and port (default [::]:443)
  --link-allow-any       take the link from anywhere, ignoring the
                         linkAllowFrom it has until the downstream sets
                         another: for a list that locked the downstream out

Everything else is set from the downstream's inbuxa-admin.

The container image reads INBUXA_RELAY_JOIN_TOKEN on its first run, so it
can join and run in one step.
";

struct Args {
    command: String,
    token: Option<String>,
    state: String,
    link_listen: SocketAddr,
    link_allow_any: bool,
    discard_held: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut command = None;
    let mut token = None;
    let mut state = state::DEFAULT_DIR.to_string();
    let mut link_listen: SocketAddr = "[::]:443".parse().expect("address");
    let mut discard_held = false;
    let mut link_allow_any = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--state" => state = args.next().ok_or("--state needs a directory")?,
            "--link-listen" => {
                link_listen = args
                    .next()
                    .ok_or("--link-listen needs an address")?
                    .parse()
                    .map_err(|_| "--link-listen: an address and port, like [::]:443")?;
            }
            "--discard-held" => discard_held = true,
            "--link-allow-any" => link_allow_any = true,
            "-h" | "--help" | "help" => return Err(String::new()),
            "-V" | "--version" => {
                println!("inbuxa-relay {}", app::VERSION);
                std::process::exit(0);
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option {arg}")),
            _ if command.is_none() => command = Some(arg),
            _ if command.as_deref() == Some("join") && token.is_none() => token = Some(arg),
            _ => return Err(format!("unexpected argument {arg}")),
        }
    }
    Ok(Args {
        command: command.ok_or_else(String::new)?,
        token,
        state,
        link_listen,
        link_allow_any,
        discard_held,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("inbuxa-relay: {e}\n");
            }
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let paths = Paths::new(&args.state);
    let result = match args.command.as_str() {
        "join" => match &args.token {
            Some(token) => join(&paths, token),
            None => Err("join needs the token from inbuxa-admin".into()),
        },
        "run" => match run(&paths, args.link_listen, args.link_allow_any) {
            Ok(Stopped::Upgraded) => return ExitCode::from(upgrade::RESTART_EXIT),
            Ok(Stopped::Asked) => Ok(()),
            Err(e) => Err(e),
        },
        "status" => status(&paths),
        "reset" => reset(&paths, args.discard_held),
        other => Err(format!("unknown command {other}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("inbuxa-relay: {e}");
            ExitCode::FAILURE
        }
    }
}

fn join(paths: &Paths, token_text: &str) -> Result<(), String> {
    if Identity::load(paths).map_err(|e| e.to_string())?.is_some() {
        return Err(
            "this relay already belongs to a downstream: run `inbuxa-relay reset` first".into(),
        );
    }
    let token = JoinToken::decode(token_text, time::now()).map_err(|e| e.to_string())?;
    paths.create_dirs().map_err(|e| e.to_string())?;
    let (key, cert) = link::tls::new_link_identity(&token.relay_id).map_err(|e| e.to_string())?;
    let identity = Identity {
        relay_id: token.relay_id.clone(),
        ca_pin: token.ca_spki,
        join_secret: Some(token.secret),
        join_expires_at: token.expires_at,
        stage: JoinStage::Waiting,
        link_key_pem: key,
        link_cert_pem: cert,
    };
    identity.save(paths).map_err(|e| e.to_string())?;
    let hours = token.expires_at.saturating_sub(time::now()).div_ceil(3600);
    println!(
        "Joined, waiting for the downstream. Start the relay with `inbuxa-relay run`; \
         the downstream has {hours} hour{} to finish the join.",
        if hours == 1 { "" } else { "s" }
    );
    Ok(())
}

/// Why `run` ended, when it ended well.
enum Stopped {
    /// A signal asked it to.
    Asked,
    /// A new binary is in place, for the supervisor to start (RL-29).
    Upgraded,
}

fn run(paths: &Paths, link_listen: SocketAddr, link_allow_any: bool) -> Result<Stopped, String> {
    paths.create_dirs().map_err(|e| e.to_string())?;
    let _lock = RunLock::acquire(paths).map_err(|e| e.to_string())?;
    let identity = match Identity::load(paths).map_err(|e| e.to_string())? {
        Some(identity) => identity,
        None => match std::env::var("INBUXA_RELAY_JOIN_TOKEN") {
            Ok(token) if !token.trim().is_empty() => {
                join(paths, &token)?;
                Identity::load(paths)
                    .map_err(|e| e.to_string())?
                    .ok_or("the join didn't save")?
            }
            _ => {
                return Err(
                    "this relay hasn't joined a downstream: run `inbuxa-relay join <token>`".into(),
                );
            }
        },
    };
    let app = Arc::new(App::open(Paths::new(&paths.root), identity).map_err(|e| e.to_string())?);
    if link_allow_any {
        let list = app
            .settings()
            .map(|s| s.link_allow_from.clone())
            .unwrap_or_default();
        if !list.is_empty() {
            eprintln!(
                "inbuxa-relay: --link-allow-any: taking the link from anywhere until the \
                 downstream sets linkAllowFrom again"
            );
        }
        *app.link_allow_any.lock().expect("link_allow_any") = Some(list);
    }
    // A relay is small: a few threads carry it, whatever the host has.
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 4));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        eprintln!("inbuxa-relay {} starting", app::VERSION);
        let listener = tokio::net::TcpListener::bind(link_listen)
            .await
            .map_err(|e| format!("could not listen on {link_listen}: {e}"))?;
        let link = tokio::spawn(link::serve(app.clone(), listener));
        tokio::spawn(smtp::serve(app.clone()));
        tokio::spawn(sweeper(app.clone()));
        let outbound = app.clone();
        tokio::spawn(async move {
            #[cfg(feature = "test-mx")]
            if let Some(port) = std::env::var("INBUXA_RELAY_TEST_MX")
                .ok()
                .and_then(|port| port.parse().ok())
            {
                eprintln!("inbuxa-relay: a test build: all mail goes to 127.0.0.1:{port}");
                let test = Arc::new(deliver::route::TestMx { port });
                return deliver::run(outbound, test).await;
            }
            let dns = Arc::new(deliver::route::Dns::new().await);
            deliver::run(outbound, dns).await
        });
        tokio::select! {
            result = link => match result {
                Ok(Err(e)) => Err(format!("the link stopped: {e}")),
                _ => Err("the link stopped".to_string()),
            },
            _ = shutdown() => {
                app.write_status();
                eprintln!("inbuxa-relay: stopping");
                Ok(Stopped::Asked)
            }
            _ = app.restart.notified() => {
                // Time for the answer to reach the downstream
                tokio::time::sleep(Duration::from_secs(1)).await;
                app.write_status();
                eprintln!("inbuxa-relay: upgraded; exiting for the new binary to start");
                Ok(Stopped::Upgraded)
            }
        }
    })
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

/// Every few seconds: ends run-out leases, expires old held mail, forgets
/// idle addresses and stale uploads, and writes `status.json`.
async fn sweeper(app: Arc<App>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let now = time::now();
        let max_age = app.settings().map(|s| u64::from(s.held_max_age) * 86_400);
        let (leases, expired) = {
            let mut spool = app.spool.lock().expect("spool");
            let leases = spool.sweep_leases(now);
            let expired = max_age
                .map(|age| spool.expire(now, age))
                .unwrap_or_default();
            (leases, expired)
        };
        for meta in &expired {
            app.record(
                "inbound.expired",
                events::data([
                    ("id", serde_json::json!(meta.id)),
                    (
                        "receivedAt",
                        serde_json::json!(time::utc_date(meta.received_at)),
                    ),
                ]),
            );
        }
        if leases || !expired.is_empty() {
            app.inbound_changed();
        }
        app.limiter.lock().expect("limiter").sweep(now);
        if let Ok(dir) = std::fs::read_dir(app.paths.blobs()) {
            for entry in dir.flatten() {
                let old = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > Duration::from_secs(3600));
                if old {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        app.write_status();
    }
}

fn status(paths: &Paths) -> Result<(), String> {
    let Some(identity) = Identity::load(paths).map_err(|e| e.to_string())? else {
        println!("Not joined to a downstream.");
        return Ok(());
    };
    println!("inbuxa-relay {}", app::VERSION);
    println!("Relay:      {}", identity.relay_id);
    println!(
        "Joined:     {}",
        match identity.stage {
            JoinStage::Waiting => "waiting for the downstream",
            JoinStage::Answered => "answered, waiting for the first settings",
            JoinStage::Joined => "yes",
        }
    );
    let running = RunLock::acquire(paths).is_err();
    let status: Option<inbuxa_relay_proto::types::RelayStatus> =
        state::read_json(&paths.status()).map_err(|e| e.to_string())?;
    match (running, status) {
        (true, Some(s)) => {
            println!("Running:    yes, since {}", s.started_at);
            println!("Mode:       {:?}", s.mode);
            println!("Linked:     {} connection(s)", s.link_clients);
            println!("Held mail:  {} message(s)", s.spool.inbound);
            println!("Outbound:   {} message(s)", s.spool.outbound);
            println!("Spool:      {} bytes", s.spool.bytes);
            if let Some(e) = s.last_error {
                println!("Last error: {e}");
            }
        }
        _ => {
            let held = std::fs::read_dir(paths.spool_in())
                .map(|d| {
                    d.flatten()
                        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
                        .count()
                })
                .unwrap_or(0);
            println!("Running:    no");
            println!("Held mail:  {held} message(s)");
        }
    }
    Ok(())
}

fn reset(paths: &Paths, discard_held: bool) -> Result<(), String> {
    if !paths.root.exists() {
        println!("Nothing to reset.");
        return Ok(());
    }
    let _lock =
        RunLock::acquire(paths).map_err(|_| "stop the relay before resetting it".to_string())?;
    let held = std::fs::read_dir(paths.spool_in())
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
                .count()
        })
        .unwrap_or(0);
    if held > 0 && !discard_held {
        return Err(format!(
            "{held} held message(s) are waiting for the downstream. They are sealed to it, \
             so after a reset nobody can read them. Run `inbuxa-relay reset --discard-held` \
             to delete them."
        ));
    }
    for entry in std::fs::read_dir(&paths.root)
        .map_err(|e| e.to_string())?
        .flatten()
    {
        if entry.file_name() == "run.lock" {
            continue;
        }
        let path = entry.path();
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.map_err(|e| format!("{}: {e}", path.display()))?;
    }
    println!(
        "Reset. {}The relay belongs to no downstream; join it again with a new token.",
        if held > 0 {
            format!("{held} held message(s) deleted. ")
        } else {
            String::new()
        }
    );
    Ok(())
}
