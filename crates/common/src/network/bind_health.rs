/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa: listeners that can't open (#485).
//!
//! A listener whose port is taken is retried for a while: after a restart
//! the old process often still holds it for a few seconds. Any other bind
//! error is reported at once. A listener that stays shut is:
//!
//! - logged as an error (`network.listen-error`), as before;
//! - kept in [`ListenerFailures`], which `/healthz/ready` reads, so a probe
//!   takes the node out of service without restarting it in a loop;
//! - written to the store under this node's id, so `x:ClusterNode` shows it
//!   in the console whichever node the console talks to.
//!
//! The process stays up: one blocked port shouldn't take every other
//! protocol down with it. `INBUXA_LISTENER_FAILURE=exit` makes a listener
//! that can't open at startup end the process instead (exit code 1), for
//! setups that would rather have their supervisor restart it. Listeners put
//! back later by the legacy-protocols switch (LP-5) only ever report.

use crate::Server;
use parking_lot::Mutex;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use store::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// How long a port in use is retried.
pub const RETRY_FOR: Duration = Duration::from_secs(30);
const FIRST_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Set once the listeners configured at startup have been spawned. Anything
/// spawned after that (LP-5) never ends the process.
pub static STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    Report,
    Exit,
}

impl FailureMode {
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim).unwrap_or_default() {
            "" | "report" => Ok(FailureMode::Report),
            "exit" => Ok(FailureMode::Exit),
            other => Err(format!(
                "INBUXA_LISTENER_FAILURE is '{other}'; it takes 'report' (the default) or 'exit'"
            )),
        }
    }

    pub fn from_env() -> Self {
        Self::parse(types::branding::env_var("LISTENER_FAILURE").ok().as_deref()).unwrap_or_else(
            |err| {
                trc::event!(Server(trc::ServerEvent::StartupError), Details = err,);
                FailureMode::Report
            },
        )
    }
}

/// Listeners of this node that aren't open, keyed "listener-id address".
#[derive(Default)]
pub struct ListenerFailures {
    failed: Mutex<BTreeMap<String, String>>,
}

impl ListenerFailures {
    /// Records why a listener isn't open. True when that changed anything.
    pub fn set(&self, key: &str, reason: &str) -> bool {
        self.failed
            .lock()
            .insert(key.to_string(), reason.to_string())
            .is_none_or(|before| before != reason)
    }

    /// The listener opened, or went away. True when it had been recorded.
    pub fn clear(&self, key: &str) -> bool {
        self.failed.lock().remove(key).is_some()
    }

    /// Forgets every address of a listener, when it's stopped on purpose.
    pub fn clear_listener(&self, id: &str) -> bool {
        let prefix = format!("{id} ");
        let mut failed = self.failed.lock();
        let before = failed.len();
        failed.retain(|key, _| !key.starts_with(&prefix));
        failed.len() != before
    }

    pub fn is_empty(&self) -> bool {
        self.failed.lock().is_empty()
    }

    /// One line per listener: "id address: reason".
    pub fn lines(&self) -> Vec<String> {
        self.failed
            .lock()
            .iter()
            .map(|(key, reason)| format!("{key}: {reason}"))
            .collect()
    }
}

/// Under `O`, listener status (store-layout SL-16), by node id.
fn status_class(node_id: u16) -> ValueClass {
    let mut key = b"Ol".to_vec();
    key.extend_from_slice(&node_id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

struct Lines(Vec<String>);

impl Deserialize for Lines {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(Lines(
            String::from_utf8_lossy(bytes)
                .lines()
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect(),
        ))
    }
}

/// Writes this node's unbound listeners where every node can read them;
/// none clears the record.
pub async fn publish(store: &Store, node_id: u16, lines: &[String]) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    if lines.is_empty() {
        batch.clear(status_class(node_id));
    } else {
        batch.set(status_class(node_id), lines.join("\n").into_bytes());
    }
    store
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

/// A node's unbound listeners, as it last wrote them.
pub async fn read(store: &Store, node_id: u16) -> trc::Result<Vec<String>> {
    Ok(store
        .get_value::<Lines>(ValueKey::from(status_class(node_id)))
        .await
        .caused_by(trc::location!())?
        .map(|Lines(lines)| lines)
        .unwrap_or_default())
}

impl Server {
    /// Writes this node's current failures to the store. A store that's
    /// down is logged and left: readiness reads memory, not the store.
    pub async fn publish_listener_failures(&self) {
        let Ok(node_id) = u16::try_from(self.core.network.node_id) else {
            return;
        };
        let lines = self.inner.data.listener_control.failures().lines();
        if let Err(err) = publish(&self.core.storage.data, node_id, &lines).await {
            trc::error!(err.details("Failed to record this node's listener status"));
        }
    }
}

/// How long to wait before the next try at a port in use, or `None` once
/// `retry_for` has passed since `started`.
pub fn next_backoff(
    started: Instant,
    retry_for: Duration,
    previous: Option<Duration>,
) -> Option<Duration> {
    let next = previous.map_or(FIRST_BACKOFF, |d| (d * 2).min(MAX_BACKOFF));
    let left = retry_for.checked_sub(started.elapsed())?;
    (!left.is_zero()).then(|| next.min(left))
}

/// True for the bind errors worth waiting out.
pub fn is_retryable(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::AddrInUse
}

/// Whether startup is over, for [`STARTED`].
pub fn startup_done() {
    STARTED.store(true, Ordering::Release);
}

pub fn is_startup() -> bool {
    !STARTED.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_mode_from_its_setting() {
        assert_eq!(FailureMode::parse(None), Ok(FailureMode::Report));
        assert_eq!(FailureMode::parse(Some("report")), Ok(FailureMode::Report));
        assert_eq!(FailureMode::parse(Some(" exit ")), Ok(FailureMode::Exit));
        assert!(FailureMode::parse(Some("crash")).is_err());
    }

    #[test]
    fn failures_by_listener() {
        let failures = ListenerFailures::default();
        assert!(failures.is_empty());
        assert!(failures.set("imaps [::]:993", "address in use"));
        assert!(!failures.set("imaps [::]:993", "address in use"));
        assert!(failures.set("imaps [::]:993", "permission denied"));
        assert!(failures.set("imaps-alt [::]:1993", "address in use"));
        assert_eq!(
            failures.lines(),
            vec![
                "imaps [::]:993: permission denied".to_string(),
                "imaps-alt [::]:1993: address in use".to_string()
            ]
        );
        // Stopping "imaps" leaves "imaps-alt" alone
        assert!(failures.clear_listener("imaps"));
        assert_eq!(failures.lines().len(), 1);
        assert!(failures.clear("imaps-alt [::]:1993"));
        assert!(failures.is_empty());
    }

    #[test]
    fn backoff_doubles_and_stops() {
        let now = Instant::now();
        let first = next_backoff(now, RETRY_FOR, None).unwrap();
        assert_eq!(first, FIRST_BACKOFF);
        assert_eq!(
            next_backoff(now, RETRY_FOR, Some(first)),
            Some(FIRST_BACKOFF * 2)
        );
        assert_eq!(
            next_backoff(now, RETRY_FOR, Some(MAX_BACKOFF)),
            Some(MAX_BACKOFF)
        );
        let long_ago = Instant::now() - RETRY_FOR - Duration::from_secs(1);
        assert_eq!(next_backoff(long_ago, RETRY_FOR, Some(first)), None);
    }

    #[test]
    fn only_address_in_use_is_retried() {
        use std::io::{Error, ErrorKind};
        assert!(is_retryable(&Error::from(ErrorKind::AddrInUse)));
        assert!(!is_retryable(&Error::from(ErrorKind::PermissionDenied)));
        assert!(!is_retryable(&Error::from(ErrorKind::AddrNotAvailable)));
    }
}
