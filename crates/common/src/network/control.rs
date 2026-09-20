/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Per-listener shutdown (legacy-protocols spec, LP-2).
//!
//! Upstream gives every listener a clone of one `watch` channel, so the only
//! shutdown signal that exists stops all of them at once — port 25 included.
//! That is enough for "stop the server" and no use at all for "close the IMAP
//! port and leave the rest running", which is what the legacy-protocols switch
//! needs.
//!
//! So each listener gets its own channel, and this registry holds the sending
//! ends, keyed by listener id. Firing one stops exactly one listener: the
//! accept loop in [`super::listen`] breaks and drops its `TcpListener`, which
//! closes the socket. Whole-server shutdown still works, by firing all of them
//! ([`ListenerControl::stop_all`]).
//!
//! What this does **not** do is touch the host's firewall, NAT port-forwards
//! or any proxy in front of the server (LP-20). Closing a listener means this
//! process stops answering; anything that still routes the port is the
//! operator's to reconcile, and is deliberately left alone.

use crate::config::server::ServerProtocol;
use ahash::AHashMap;
use parking_lot::RwLock;
use tokio::sync::watch;

/// A listener that is currently accepting, and the switch that stops it.
struct Running {
    protocol: ServerProtocol,
    ports: Vec<u16>,
    shutdown_tx: watch::Sender<bool>,
}

/// What a caller is told about a running listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerInfo {
    pub id: String,
    pub protocol: ServerProtocol,
    pub ports: Vec<u16>,
}

/// The registry of running listeners and their shutdown switches.
#[derive(Default)]
pub struct ListenerControl {
    running: RwLock<AHashMap<String, Running>>,
}

impl ListenerControl {
    /// Registers a listener about to be spawned, returning the receiver its
    /// accept loop should select on.
    pub fn register(
        &self,
        id: impl Into<String>,
        protocol: ServerProtocol,
        ports: Vec<u16>,
    ) -> watch::Receiver<bool> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.running.write().insert(
            id.into(),
            Running {
                protocol,
                ports,
                shutdown_tx,
            },
        );
        shutdown_rx
    }

    /// Stops one listener by id. Returns what was stopped, or `None` when no
    /// listener of that id is running.
    pub fn stop(&self, id: &str) -> Option<ListenerInfo> {
        let running = self.running.write().remove(id).map(|running| {
            let _ = running.shutdown_tx.send(true);
            ListenerInfo {
                id: id.to_string(),
                protocol: running.protocol,
                ports: running.ports,
            }
        });
        running
    }

    /// Stops every running listener whose protocol `is_legacy` accepts, except
    /// those whose id is in `keep`. Returns what was stopped.
    ///
    /// The caller decides what counts as legacy, because the inbound SMTP
    /// listener shares its protocol with submission and must never be stopped
    /// (LP-3); `keep` is how it is spared.
    pub fn stop_matching(
        &self,
        is_legacy: impl Fn(ServerProtocol, &[u16]) -> bool,
        keep: &[String],
    ) -> Vec<ListenerInfo> {
        let ids: Vec<String> = {
            let running = self.running.read();
            running
                .iter()
                .filter(|(id, listener)| {
                    !keep.contains(id) && is_legacy(listener.protocol, &listener.ports)
                })
                .map(|(id, _)| id.clone())
                .collect()
        };

        ids.iter().filter_map(|id| self.stop(id)).collect()
    }

    /// Stops everything. This is whole-server shutdown, and replaces the single
    /// shared channel upstream fired.
    pub fn stop_all(&self) {
        for (_, running) in self.running.write().drain() {
            let _ = running.shutdown_tx.send(true);
        }
    }

    /// Every listener currently accepting.
    pub fn running(&self) -> Vec<ListenerInfo> {
        let mut out: Vec<ListenerInfo> = self
            .running
            .read()
            .iter()
            .map(|(id, listener)| ListenerInfo {
                id: id.clone(),
                protocol: listener.protocol,
                ports: listener.ports.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Whether a listener of this id is accepting.
    pub fn is_running(&self, id: &str) -> bool {
        self.running.read().contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control() -> ListenerControl {
        let control = ListenerControl::default();
        control.register("smtp", ServerProtocol::Smtp, vec![25]);
        control.register("submission", ServerProtocol::Smtp, vec![465]);
        control.register("imap", ServerProtocol::Imap, vec![993]);
        control.register("pop3", ServerProtocol::Pop3, vec![995]);
        control.register("sieve", ServerProtocol::ManageSieve, vec![4190]);
        control.register("https", ServerProtocol::Http, vec![443]);
        control
    }

    /// One listener stops and the others keep accepting (LP-2).
    #[test]
    fn stop_one_leaves_the_rest() {
        let control = control();

        let stopped = control.stop("imap").expect("imap was running");
        assert_eq!(stopped.protocol, ServerProtocol::Imap);
        assert_eq!(stopped.ports, vec![993]);

        assert!(!control.is_running("imap"));
        for still in ["smtp", "submission", "pop3", "sieve", "https"] {
            assert!(control.is_running(still), "{still} should still accept");
        }
    }

    /// Stopping the same listener twice is not an error, and says so.
    #[test]
    fn stop_is_idempotent() {
        let control = control();
        assert!(control.stop("imap").is_some());
        assert!(control.stop("imap").is_none());
    }

    /// The accept loop's receiver sees the stop.
    #[test]
    fn the_listener_is_told() {
        let control = ListenerControl::default();
        let rx = control.register("imap", ServerProtocol::Imap, vec![993]);

        assert!(!*rx.borrow());
        control.stop("imap");
        assert!(*rx.borrow(), "the accept loop must see true and break");
    }

    /// The legacy protocols stop; inbound SMTP and HTTPS do not (LP-1, LP-3).
    #[test]
    fn stop_matching_spares_inbound_and_http() {
        let control = control();
        let keep = vec!["smtp".to_string()];

        let stopped = control.stop_matching(
            |protocol, _ports| {
                matches!(
                    protocol,
                    ServerProtocol::Imap
                        | ServerProtocol::Pop3
                        | ServerProtocol::ManageSieve
                        | ServerProtocol::Smtp
                )
            },
            &keep,
        );

        let mut stopped_ids: Vec<String> = stopped.into_iter().map(|l| l.id).collect();
        stopped_ids.sort();
        assert_eq!(stopped_ids, vec!["imap", "pop3", "sieve", "submission"]);

        assert!(
            control.is_running("smtp"),
            "port 25 must never close (LP-3)"
        );
        assert!(control.is_running("https"), "JMAP must keep working");
    }

    /// Without `closeSubmission`, submission stays open and only the mail-app
    /// protocols close (LP-1).
    #[test]
    fn stop_matching_can_leave_submission_open() {
        let control = control();
        let keep = vec!["smtp".to_string(), "submission".to_string()];

        let stopped = control.stop_matching(
            |protocol, _ports| {
                matches!(
                    protocol,
                    ServerProtocol::Imap | ServerProtocol::Pop3 | ServerProtocol::ManageSieve
                )
            },
            &keep,
        );

        assert_eq!(stopped.len(), 3);
        assert!(control.is_running("submission"));
        assert!(control.is_running("smtp"));
    }

    /// Whole-server shutdown still stops everything.
    #[test]
    fn stop_all_stops_everything() {
        let control = control();
        let rx = control.register("extra", ServerProtocol::Imap, vec![143]);

        control.stop_all();

        assert!(*rx.borrow());
        assert!(control.running().is_empty());
    }

    /// `running` reports what is accepting, in a stable order.
    #[test]
    fn running_lists_what_accepts() {
        let control = control();
        control.stop("pop3");

        let ids: Vec<String> = control.running().into_iter().map(|l| l.id).collect();
        assert_eq!(ids, vec!["https", "imap", "sieve", "smtp", "submission"]);
    }
}
