/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Running migrations (migrations spec, MG-4 to MG-14): the bundled
//! inbuxa-migrate, as a child of this node, on a migration's answers.
//!
//! A run writes the answers into the migration's work directory, has
//! `inbuxa-migrate plan` turn them into plans, and runs `migrate` on one with
//! `--progress json`, reading its events to keep the migration's record up
//! to date. The child writes into this server through this node's own HTTP
//! listener, on loopback, with a run token that acts as the administrator
//! who started the migration (MG-10).
//!
//! The source's secret is given to the child through its environment and is
//! held in this node's memory between runs, never written anywhere (MG-12).
//! A restart forgets it, and the next run asks for it again.

use common::{BuildServer, Inner, Server, migration_token};
use inbuxa_features::migration::{self as model, Failure, Migration, RunKind, RunResult, Status};
use registry::schema::{
    enums::NetworkListenerProtocol,
    prelude::ObjectType,
    structs::{NetworkListener, SystemSettings},
};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, LazyLock},
    time::Duration,
};
use store::{registry::RegistryQuery, write::now};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Command,
    sync::{Mutex, Notify},
};
use types::id::Id;

/// MG-8: progress is saved at least this often while a run goes on.
const SAVE_EVERY: Duration = Duration::from_secs(30);
/// MG-11: a run whose node hasn't said anything for this long is taken to
/// have stopped with its node.
const STALE_AFTER: u64 = 5 * 60;
/// How much of the engine's stderr is kept to say why a run failed.
const KEEP_STDERR: usize = 4_000;
/// The variables the child is given; everything else named like them is
/// cleared, so it sees only these secrets.
const SOURCE_SECRET_VAR: &str = "MIGRATE_SOURCE_SECRET";
const TARGET_TOKEN_VAR: &str = "MIGRATE_INBUXA_TOKEN";
/// The child's `PATH`: the rest of its environment is cleared.
const SAFE_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The secrets this node holds, by migration (MG-12).
static SECRETS: LazyLock<Mutex<HashMap<u32, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// The runs going on on this node, each with what stops it.
static RUNS: LazyLock<Mutex<HashMap<u32, Arc<Notify>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Why a run couldn't start, or a migration couldn't be stopped or closed,
/// in the console's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NotFound,
    Closed,
    Running,
    NotRunning,
    /// MG-12: no secret was given and this node doesn't hold one.
    SecretNeeded,
    /// MG-11: the migration's work directory is on another node.
    OtherNode(u64),
    /// MG-5: a final pass comes after a move.
    NotMoved,
    NoPasswords,
    Failed(String),
}

impl Refusal {
    pub fn describe(&self) -> String {
        match self {
            Refusal::NotFound => "No such migration.".into(),
            Refusal::Closed => "This migration is closed; start a new one.".into(),
            Refusal::Running => "A run is going on; stop it first, or wait for it.".into(),
            Refusal::NotRunning => "Nothing is running.".into(),
            Refusal::SecretNeeded => {
                "Give the source's password, API key, client secret or key again: \
                 the server doesn't keep it across a restart."
                    .into()
            }
            Refusal::OtherNode(node) => format!(
                "This migration's files are on node {node}. Its runs happen there; \
                 open the console through that node."
            ),
            Refusal::NotMoved => "Move the accounts first; the final pass comes after.".into(),
            Refusal::NoPasswords => "There are no new passwords waiting.".into(),
            Refusal::Failed(why) => why.clone(),
        }
    }
}

fn node_id(server: &Server) -> u64 {
    server.core.network.node_id
}

/// MG-4: where the migrations' work directories are: `$INBUXA_MIGRATIONS_DIR`,
/// or `migrations` in the server's working directory, which the image makes
/// its data volume.
pub fn migrations_dir() -> PathBuf {
    types::branding::env_var("MIGRATIONS_DIR")
        .ok()
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("migrations")
        })
}

fn work_dir(id: u32) -> PathBuf {
    migrations_dir().join(id.to_string())
}

/// MG-4: the inbuxa-migrate the image carries, or `$INBUXA_MIGRATE_BIN`.
fn engine() -> PathBuf {
    types::branding::env_var("MIGRATE_BIN")
        .ok()
        .filter(|bin| !bin.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/inbuxa-migrate"))
}

/// MG-10: an address on this node's loopback that its HTTP listeners
/// answer, plain HTTP first, and whether it's TLS. A listener bound to one
/// address other than loopback is left out: the run token is only taken
/// from loopback. So is one that expects the PROXY protocol from loopback.
async fn local_url(server: &Server) -> Result<(String, bool), String> {
    if let Ok(url) = types::branding::env_var("MIGRATIONS_URL")
        && !url.is_empty()
    {
        return Ok((
            url.trim_end_matches('/').to_string(),
            url.starts_with("https:"),
        ));
    }
    let registry = server.registry();
    let system = registry
        .object::<SystemSettings>(Id::singleton())
        .await
        .map_err(|err| err.to_string())?
        .unwrap_or_default();
    let ids = registry
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::NetworkListener))
        .await
        .map_err(|err| err.to_string())?;
    let mut candidates = Vec::new();
    for id in ids {
        let Ok(Some(listener)) = registry.object::<NetworkListener>(id).await else {
            continue;
        };
        if listener.protocol != NetworkListenerProtocol::Http {
            continue;
        }
        let proxies = if listener.override_proxy_trusted_networks.is_empty() {
            system.proxy_trusted_networks.as_slice()
        } else {
            listener.override_proxy_trusted_networks.as_slice()
        };
        for bind in listener.bind.iter() {
            let bind = bind.0;
            let ip = match bind.ip() {
                IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
                ip if ip.is_loopback() => ip,
                _ => continue,
            };
            if proxies.iter().any(|network| network.matches(&ip)) {
                continue;
            }
            // HTTP is TLS from the first byte or not at all
            candidates.push((listener.tls_implicit, SocketAddr::new(ip, bind.port())));
        }
    }
    // Plain HTTP first; a node whose role leaves a listener off doesn't
    // answer on it
    candidates.sort_by_key(|(tls, addr)| (*tls, addr.is_ipv6()));
    for (tls, addr) in candidates {
        let answers =
            tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
                .await
                .is_ok_and(|connected| connected.is_ok());
        if answers {
            let scheme = if tls { "https" } else { "http" };
            return Ok((format!("{scheme}://{addr}"), tls));
        }
    }
    Err(
        "No HTTP listener answers on this node's loopback. Add one, or set \
         INBUXA_MIGRATIONS_URL."
            .into(),
    )
}

/// Takes the migration for a run on this node, or says why not.
async fn claim(server: &Server, id: u32, kind: RunKind) -> Result<Migration, Refusal> {
    let node = node_id(server);
    let mut refusal = None;
    let claimed = model::update(server.store(), id, |m| {
        refusal = match (m.status, m.node_id) {
            (Status::Closed, _) => Some(Refusal::Closed),
            (Status::Running, _) => Some(Refusal::Running),
            (_, Some(other)) if other != node => Some(Refusal::OtherNode(other)),
            _ if kind == RunKind::FinalPass && !m.moved => Some(Refusal::NotMoved),
            _ => None,
        };
        if refusal.is_some() {
            return false;
        }
        m.status = Status::Running;
        m.run = Some(kind);
        m.result = None;
        m.error = None;
        m.node_id = Some(node);
        m.heartbeat = Some(now());
        m.progress = Default::default();
        m.failures.clear();
        m.started_at = Some(now());
        m.finished_at = None;
        true
    })
    .await
    .map_err(|err| Refusal::Failed(err.to_string()))?;
    match (claimed, refusal) {
        (None, _) => Err(Refusal::NotFound),
        (_, Some(refusal)) => Err(refusal),
        (Some(m), None) => Ok(m),
    }
}

/// MG-5: starts a run of `kind`. `secret`, if given, replaces the one this
/// node holds.
pub async fn start(
    server: &Server,
    id: u32,
    kind: RunKind,
    secret: Option<String>,
) -> Result<(), Refusal> {
    let secret = {
        let mut secrets = SECRETS.lock().await;
        if let Some(secret) = secret.filter(|s| !s.is_empty()) {
            secrets.insert(id, secret);
        }
        secrets.get(&id).cloned()
    };
    let Some(secret) = secret else {
        return match model::get(server.store(), id).await {
            Ok(None) => Err(Refusal::NotFound),
            _ => Err(Refusal::SecretNeeded),
        };
    };
    let migration = claim(server, id, kind).await?;
    let stop = Arc::new(Notify::new());
    RUNS.lock().await.insert(id, stop.clone());
    let server = server.clone();
    tokio::spawn(async move {
        let ended = run(&server, &migration, kind, &secret, &stop).await;
        RUNS.lock().await.remove(&id);
        if let Err(err) = finish(&server, &migration, kind, ended).await {
            trc::error!(err.details("Failed to save a migration's result"));
        }
    });
    Ok(())
}

/// MG-5: stops the run going on.
pub async fn stop(server: &Server, id: u32) -> Result<(), Refusal> {
    if let Some(stop) = RUNS.lock().await.get(&id) {
        stop.notify_one();
        return Ok(());
    }
    let node = node_id(server);
    let mut refusal = None;
    let found = model::update(server.store(), id, |m| {
        refusal = match (m.status, m.node_id) {
            (Status::Running, Some(other)) if other != node => Some(Refusal::OtherNode(other)),
            // Said to be running here, but nothing is: it stopped with an
            // earlier start of this node
            (Status::Running, _) => None,
            _ => Some(Refusal::NotRunning),
        };
        if refusal.is_some() {
            return false;
        }
        m.status = Status::Idle;
        m.result = Some(RunResult::Interrupted);
        m.finished_at = Some(now());
        true
    })
    .await
    .map_err(|err| Refusal::Failed(err.to_string()))?;
    match (found, refusal) {
        (None, _) => Err(Refusal::NotFound),
        (_, Some(refusal)) => Err(refusal),
        _ => Ok(()),
    }
}

/// MG-14: closes a migration: its work directory, archives and all, goes,
/// and so does the secret. It stays listed.
pub async fn close(server: &Server, id: u32) -> Result<(), Refusal> {
    let node = node_id(server);
    let mut refusal = None;
    let mut remove = false;
    let found = model::update(server.store(), id, |m| {
        refusal = match (m.status, m.node_id) {
            (Status::Closed, _) => Some(Refusal::Closed),
            (Status::Running, _) => Some(Refusal::Running),
            (_, Some(other)) if other != node => Some(Refusal::OtherNode(other)),
            _ => None,
        };
        if refusal.is_some() {
            return false;
        }
        remove = m.node_id.is_some();
        m.status = Status::Closed;
        m.passwords_waiting = false;
        m.disk_used = 0;
        true
    })
    .await
    .map_err(|err| Refusal::Failed(err.to_string()))?;
    match (found, refusal) {
        (None, _) => return Err(Refusal::NotFound),
        (_, Some(refusal)) => return Err(refusal),
        _ => {}
    }
    SECRETS.lock().await.remove(&id);
    if remove {
        let dir = work_dir(id);
        if let Err(err) = tokio::fs::remove_dir_all(&dir).await
            && err.kind() != std::io::ErrorKind::NotFound
        {
            trc::error!(
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details(format!(
                        "Failed to remove a closed migration's work directory, {}",
                        dir.display()
                    ))
                    .reason(err)
            );
        }
    }
    Ok(())
}

/// MG-13: the new accounts' passwords, once: the file is deleted as it's
/// read. The CSV goes into a blob of the administrator who takes them.
pub async fn take_passwords(server: &Server, id: u32, account_id: u32) -> Result<String, Refusal> {
    let migration = model::get(server.store(), id)
        .await
        .map_err(|err| Refusal::Failed(err.to_string()))?
        .ok_or(Refusal::NotFound)?;
    match migration.node_id {
        Some(node) if node != node_id(server) => return Err(Refusal::OtherNode(node)),
        _ => {}
    }
    if !migration.passwords_waiting {
        return Err(Refusal::NoPasswords);
    }
    let mut files = passwords_files(&work_dir(id)).await;
    let mut csv = Vec::new();
    for path in &files {
        if let Ok(bytes) = tokio::fs::read(path).await {
            // One header for every file, the first's
            let skip = if csv.is_empty() {
                0
            } else {
                bytes
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(bytes.len(), |n| n + 1)
            };
            csv.extend_from_slice(&bytes[skip..]);
        }
    }
    if csv.is_empty() {
        return Err(Refusal::NoPasswords);
    }
    let blob = server
        .put_jmap_blob(account_id, &csv)
        .await
        .map_err(|err| Refusal::Failed(err.to_string()))?;
    for path in files.drain(..) {
        let _ = tokio::fs::remove_file(path).await;
    }
    model::update(server.store(), id, |m| {
        m.passwords_waiting = false;
        true
    })
    .await
    .map_err(|err| Refusal::Failed(err.to_string()))?;
    Ok(blob.to_string())
}

async fn passwords_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("passwords-") && name.ends_with(".csv") {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    files
}

/// How a run ended, before it's saved.
struct Ended {
    result: RunResult,
    error: Option<String>,
    progress: model::Progress,
    failures: Vec<Failure>,
}

impl Ended {
    fn failed(error: impl Into<String>) -> Self {
        Ended {
            result: RunResult::Failed,
            error: Some(error.into()),
            progress: Default::default(),
            failures: Vec::new(),
        }
    }
}

/// Runs the engine to the end, or until it's stopped.
async fn run(
    server: &Server,
    migration: &Migration,
    kind: RunKind,
    secret: &str,
    stop: &Notify,
) -> Ended {
    let dir = work_dir(migration.id);
    if let Err(err) = private_dir(&dir).await {
        return Ended::failed(format!(
            "The work directory {} can't be made: {err}",
            dir.display()
        ));
    }
    let (url, tls) = match local_url(server).await {
        Ok(found) => found,
        Err(err) => return Ended::failed(err),
    };

    // The plans, from the answers
    let answers = migration.answers(&url, tls);
    if let Err(err) = write_private(
        &dir.join("answers.json"),
        &serde_json::to_vec_pretty(&answers).unwrap_or_default(),
    )
    .await
    {
        return Ended::failed(format!("The answers can't be written: {err}"));
    }
    let planned = Command::new(engine())
        .args(["plan", "--answers", "answers.json", "."])
        .current_dir(&dir)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(Stdio::null())
        .output()
        .await;
    let plans: Value = match planned {
        Ok(out) if out.status.success() => {
            serde_json::from_slice(&out.stdout).unwrap_or(Value::Null)
        }
        Ok(out) => return Ended::failed(tail(&String::from_utf8_lossy(&out.stderr))),
        Err(err) => {
            return Ended::failed(format!(
                "inbuxa-migrate couldn't be started ({}): {err}",
                engine().display()
            ));
        }
    };
    let plan = match kind {
        RunKind::Preview => plans["preview"].as_str(),
        _ => plans["plan"].as_str(),
    }
    .unwrap_or(if kind == RunKind::Preview {
        "preview-plan.json"
    } else {
        "plan.json"
    })
    .to_string();

    // The run, with a token that ends with it
    let token = migration_token::issue(migration.created_by_id, migration.id);
    let mut command = Command::new(engine());
    command
        .args([
            "migrate",
            "--plan",
            &plan,
            "--progress",
            "json",
            "--parallel",
        ])
        .arg(migration.parallel.max(1).to_string())
        .args(match kind {
            RunKind::Preview => &["--dry-run"][..],
            RunKind::FinalPass => &["--again"][..],
            RunKind::Move => &[][..],
        })
        .arg("work")
        .current_dir(&dir)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env(SOURCE_SECRET_VAR, secret)
        .env(TARGET_TOKEN_VAR, &token)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            migration_token::revoke(&token);
            return Ended::failed(format!("inbuxa-migrate couldn't be started: {err}"));
        }
    };

    let mut stderr = child.stderr.take();
    let errors = tokio::spawn(async move {
        let mut text = String::new();
        if let Some(stderr) = stderr.as_mut() {
            let _ = stderr.read_to_string(&mut text).await;
        }
        text
    });
    let mut lines = child.stdout.take().map(|out| BufReader::new(out).lines());

    let mut ended = Ended {
        result: RunResult::Done,
        error: None,
        progress: Default::default(),
        failures: Vec::new(),
    };
    let mut stopped = false;
    let mut saved = tokio::time::Instant::now();
    loop {
        let line = async {
            match lines.as_mut() {
                Some(lines) => lines.next_line().await.ok().flatten(),
                None => None,
            }
        };
        tokio::select! {
            line = line => {
                let Some(line) = line else { break };
                let account_ended = progress(&mut ended, &line);
                if account_ended || saved.elapsed() >= SAVE_EVERY {
                    save_progress(server, migration.id, &ended).await;
                    saved = tokio::time::Instant::now();
                }
            }
            _ = tokio::time::sleep_until(saved + SAVE_EVERY) => {
                save_progress(server, migration.id, &ended).await;
                saved = tokio::time::Instant::now();
            }
            _ = stop.notified() => {
                stopped = true;
                let _ = child.start_kill();
                break;
            }
        }
    }
    let status = child.wait().await;
    migration_token::revoke(&token);
    let errors = errors.await.unwrap_or_default();
    if stopped {
        ended.result = RunResult::Stopped;
        return ended;
    }
    match status.ok().and_then(|s| s.code()) {
        Some(0) => ended.result = RunResult::Done,
        // migrate's own code for "some account didn't finish"
        Some(5) => ended.result = RunResult::Unfinished,
        _ => {
            ended.result = RunResult::Failed;
            ended.error = Some(tail(&errors));
        }
    }
    ended
}

/// Takes one of the engine's events into the run's progress. True when an
/// account ended, which is worth saving at once.
fn progress(ended: &mut Ended, line: &str) -> bool {
    let Ok(event) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    let number = |value: &Value| value.as_u64().unwrap_or(0);
    let p = &mut ended.progress;
    match event["event"].as_str() {
        Some("start") => {
            p.total = number(&event["accounts"]);
            false
        }
        Some("step") if event.get("result").is_some() => {
            let counts = &event["counts"];
            if event["step"] == "export" {
                p.written += number(&counts["created"]) + number(&counts["updated"]);
            } else {
                p.read += number(&counts["created"]) + number(&counts["updated"]);
            }
            p.failed += number(&counts["failed"]);
            let result = event["result"].as_str().unwrap_or_default();
            if result == "failed" || result == "partial" {
                ended.failures.push(Failure {
                    email: event["email"].as_str().unwrap_or_default().to_string(),
                    step: event["step"].as_str().unwrap_or_default().to_string(),
                    detail: event["detail"]
                        .as_str()
                        .unwrap_or_default()
                        .chars()
                        .take(500)
                        .collect(),
                });
                let over = ended.failures.len().saturating_sub(model::MAX_FAILURES);
                ended.failures.drain(..over);
            }
            false
        }
        Some("account") => {
            p.finished = number(&event["n"]).max(p.finished);
            if event["result"] != "done" {
                p.unfinished += 1;
            }
            true
        }
        Some("end") => {
            p.unfinished = number(&event["unfinished"]);
            true
        }
        _ => false,
    }
}

/// MG-8: the run's progress and a heartbeat, written over whatever the
/// record says. A failed write is tried again at the next.
async fn save_progress(server: &Server, id: u32, ended: &Ended) {
    let result = model::update(server.store(), id, |m| {
        if m.status != Status::Running {
            return false;
        }
        m.progress = ended.progress.clone();
        m.failures.clone_from(&ended.failures);
        m.heartbeat = Some(now());
        true
    })
    .await;
    if let Err(err) = result {
        trc::error!(err.details("Failed to save a migration's progress"));
    }
}

/// MG-6: a run's end, with its report for whoever started it.
async fn finish(
    server: &Server,
    migration: &Migration,
    kind: RunKind,
    ended: Ended,
) -> trc::Result<()> {
    let dir = work_dir(migration.id);
    let report = dir.join("work").join(if kind == RunKind::Preview {
        "dry-run-report.csv"
    } else {
        "report.csv"
    });
    let report_blob = match tokio::fs::read(&report).await {
        Ok(bytes) if !bytes.is_empty() => Some(
            server
                .put_jmap_blob(migration.created_by_id, &bytes)
                .await?
                .to_string(),
        ),
        _ => None,
    };
    let passwords = !passwords_files(&dir).await.is_empty();
    let disk_used = disk_used(&dir).await;
    model::update(server.store(), migration.id, |m| {
        m.status = Status::Idle;
        m.result = Some(ended.result);
        m.error.clone_from(&ended.error);
        m.progress = ended.progress.clone();
        m.failures.clone_from(&ended.failures);
        m.heartbeat = None;
        m.finished_at = Some(now());
        m.disk_used = disk_used;
        m.passwords_waiting = passwords;
        if report_blob.is_some() {
            m.report_blob_id.clone_from(&report_blob);
        }
        if kind != RunKind::Preview
            && matches!(ended.result, RunResult::Done | RunResult::Unfinished)
        {
            m.moved = true;
        }
        true
    })
    .await
    .map(|_| ())
}

/// MG-11, MG-12: at start-up, a run this node had is over: it stopped with
/// the node. Then, now and then, a run on a node that went quiet is taken
/// to have stopped with it.
pub fn spawn_migrations(inner: Arc<Inner>) {
    tokio::spawn(async move {
        let server = inner.build_server();
        let node = node_id(&server);
        mark_interrupted(&server, |m| m.node_id == Some(node)).await;
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let server = inner.build_server();
            let cutoff = now().saturating_sub(STALE_AFTER);
            mark_interrupted(&server, |m| {
                m.node_id != Some(node) && m.heartbeat.is_some_and(|at| at < cutoff)
            })
            .await;
        }
    });
}

async fn mark_interrupted(server: &Server, which: impl Fn(&Migration) -> bool) {
    let migrations = match model::all(server.store()).await {
        Ok(migrations) => migrations,
        Err(err) => {
            trc::error!(err.details("Failed to read the migrations"));
            return;
        }
    };
    for migration in migrations
        .into_iter()
        .filter(|m| m.status == Status::Running && which(m))
    {
        let result = model::update(server.store(), migration.id, |m| {
            if m.status != Status::Running || !which(m) {
                return false;
            }
            m.status = Status::Idle;
            m.result = Some(RunResult::Interrupted);
            m.heartbeat = None;
            m.finished_at = Some(now());
            true
        })
        .await;
        if let Err(err) = result {
            trc::error!(err.details("Failed to mark an interrupted migration"));
        }
    }
}

fn tail(text: &str) -> String {
    let text = text.trim();
    let start = text.len().saturating_sub(KEEP_STDERR);
    let start = (start..text.len())
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(text.len());
    if text.is_empty() {
        "inbuxa-migrate stopped without saying why.".into()
    } else {
        text[start..].to_string()
    }
}

async fn disk_used(dir: &Path) -> u64 {
    let mut total = 0;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            match entry.metadata().await {
                Ok(meta) if meta.is_dir() => pending.push(entry.path()),
                Ok(meta) => total += meta.len(),
                Err(_) => {}
            }
        }
    }
    total
}

async fn private_dir(dir: &Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

async fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ended() -> Ended {
        Ended {
            result: RunResult::Done,
            error: None,
            progress: Default::default(),
            failures: Vec::new(),
        }
    }

    #[test]
    fn the_engines_events_make_the_progress() {
        let mut e = ended();
        assert!(!progress(
            &mut e,
            r#"{"event":"start","accounts":2,"parallel":1,"dryRun":false}"#
        ));
        assert!(!progress(
            &mut e,
            r#"{"event":"step","email":"a@x.org","step":"import"}"#
        ));
        assert!(!progress(
            &mut e,
            r#"{"event":"step","email":"a@x.org","step":"import","result":"done",
                "counts":{"fetched":9,"created":7,"updated":1,"deleted":0,"skipped":0,"failed":0},"detail":""}"#
        ));
        assert!(!progress(
            &mut e,
            r#"{"event":"step","email":"a@x.org","step":"export","result":"partial",
                "counts":{"fetched":0,"created":6,"updated":0,"deleted":0,"skipped":0,"failed":2},
                "detail":"2 messages over the size limit"}"#
        ));
        assert!(progress(
            &mut e,
            r#"{"event":"account","email":"a@x.org","n":1,"total":2,"result":"partial"}"#
        ));
        assert!(!progress(&mut e, "not json"));
        assert_eq!(e.progress.total, 2);
        assert_eq!(e.progress.read, 8);
        assert_eq!(e.progress.written, 6);
        assert_eq!(e.progress.failed, 2);
        assert_eq!(e.progress.finished, 1);
        assert_eq!(e.progress.unfinished, 1);
        assert_eq!(e.failures.len(), 1);
        assert_eq!(e.failures[0].step, "export");
        assert!(progress(
            &mut e,
            r#"{"event":"end","done":1,"unfinished":1,"report":"r"}"#
        ));
        assert_eq!(e.progress.unfinished, 1);
    }

    #[test]
    fn a_failure_says_the_end_of_what_the_engine_said() {
        assert_eq!(tail("  \n"), "inbuxa-migrate stopped without saying why.");
        let long = format!("{}é{}", "x".repeat(KEEP_STDERR), "end");
        let kept = tail(&long);
        assert!(kept.ends_with("end"));
        assert!(kept.len() <= KEEP_STDERR + 1);
    }
}
