/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Turning the legacy-protocols switch, and making it true of the running
//! server (legacy-protocols spec, LP-1, LP-2 and LP-5).
//!
//! Two halves meet here. `inbuxa_features::security` decides what the policy
//! means and owns the listener **objects**; [`ListenerControl`] owns the
//! running **sockets**. Neither can do the job alone, and only `Server` has
//! both, so the join lives here.
//!
//! Order matters in both directions. Closing removes the object first and then
//! stops the socket: a socket stopped before its object is gone would come
//! back on the next restart. Opening puts the object back first and then
//! spawns, for the same reason in reverse.
//!
//! Nothing here touches the host's firewall, NAT port-forwards or any proxy
//! (LP-20). The server stops answering; what still routes the port is the
//! operator's to reconcile.

use crate::{Server, config::server::Listeners, network::TcpAcceptor};
use inbuxa_features::security::{
    listeners,
    protocol_policy::{self, ProtocolPolicy, SavedListener},
};
use store::registry::bootstrap::Bootstrap;

/// What turning the switch actually did.
#[derive(Debug, Default)]
pub struct PolicyChange {
    /// Listeners removed and stopped (LP-1).
    pub closed: Vec<SavedListener>,
    /// Listeners put back and started again (LP-5).
    pub reopened: Vec<SavedListener>,
    /// Listeners that could not be put back, with the reason. Each stays
    /// saved for another try (LP-5).
    pub failed: Vec<(SavedListener, String)>,
    /// Properties the locks overruled (LP-21).
    pub overruled: Vec<&'static str>,
    /// Listeners whose object is right but whose socket needs a restart,
    /// because no spawner was left behind. Empty on a normally booted server.
    pub pending_restart: Vec<String>,
}

impl PolicyChange {
    /// Whether anything at all happened, for the caller deciding to emit
    /// `security.legacy-protocols-changed` (LP-8).
    pub fn is_empty(&self) -> bool {
        self.closed.is_empty()
            && self.reopened.is_empty()
            && self.failed.is_empty()
            && self.overruled.is_empty()
    }
}

impl Server {
    /// The policy in force.
    pub async fn protocol_policy(&self) -> trc::Result<ProtocolPolicy> {
        protocol_policy::get(&self.core.storage.data).await
    }

    /// Turns the switch, and makes it true of the running server.
    ///
    /// `requested` is what the client asked for; the locks are applied to it
    /// first (LP-21), so what gets stored is what the server allows, not what
    /// was asked. Returns what actually happened, for the response and the
    /// event.
    pub async fn set_protocol_policy(
        &self,
        requested: ProtocolPolicy,
        changed_by: Option<String>,
    ) -> trc::Result<PolicyChange> {
        let mut policy = requested;
        let mut change = PolicyChange {
            overruled: policy.apply_locks(),
            ..Default::default()
        };

        // Carry forward what earlier changes saved: the client never sets
        // this, and a /set that omitted it must not lose the listeners still
        // waiting to come back.
        let previous = self.protocol_policy().await?;
        policy.saved_listeners = previous.saved_listeners;
        policy.changed_at = Some(store::write::now() * 1000);
        policy.changed_by = changed_by;

        if policy.legacy_protocols.is_disabled() {
            self.close_legacy_listeners(&mut policy, &mut change).await?;
        } else {
            self.reopen_legacy_listeners(&mut policy, &mut change)
                .await?;
        }

        protocol_policy::set(&self.core.storage.data, &policy).await?;

        Ok(change)
    }

    /// Removes the listener objects the policy closes, then stops their
    /// sockets (LP-1, LP-2).
    async fn close_legacy_listeners(
        &self,
        policy: &mut ProtocolPolicy,
        change: &mut PolicyChange,
    ) -> trc::Result<()> {
        let removed = listeners::close(self.registry(), policy).await?;

        for saved in &removed {
            // The runtime registry is keyed by the listener's name, which is
            // what `close` returns as the saved listener's id.
            self.inner.data.listener_control.stop(&saved.id);
        }

        policy.saved_listeners.extend(removed.iter().cloned());
        change.closed = removed;

        Ok(())
    }

    /// Puts back every saved listener and starts it again (LP-5).
    async fn reopen_legacy_listeners(
        &self,
        policy: &mut ProtocolPolicy,
        change: &mut PolicyChange,
    ) -> trc::Result<()> {
        if policy.saved_listeners.is_empty() {
            return Ok(());
        }

        let saved = std::mem::take(&mut policy.saved_listeners);
        let (restored, failed) = listeners::reopen(self.registry(), &saved).await?;

        // A listener that could not be put back stays saved for another try.
        policy.saved_listeners = failed.iter().map(|(listener, _)| listener.clone()).collect();
        change.failed = failed;

        if !restored.is_empty() {
            change.pending_restart = self.spawn_restored_listeners(&restored).await?;
        }
        change.reopened = restored;

        Ok(())
    }

    /// Binds and spawns the listeners just put back, so a port opens without a
    /// restart. Returns the names that still need one.
    async fn spawn_restored_listeners(&self, restored: &[SavedListener]) -> trc::Result<Vec<String>> {
        let control = &self.inner.data.listener_control;
        if !control.can_spawn() {
            return Ok(restored.iter().map(|listener| listener.id.clone()).collect());
        }

        // Re-parse from the registry rather than from the saved object: the
        // socket has to be created and bound afresh, and the parser is what
        // knows how. The objects are already back, so this sees them.
        let mut bootstrap = Bootstrap::new(self.registry().clone()).await;
        let mut parsed = Listeners::parse(&mut bootstrap).await;
        parsed
            .parse_tcp_acceptors(&mut bootstrap, self.inner.clone())
            .await;

        let wanted: Vec<&str> = restored.iter().map(|l| l.id.as_str()).collect();
        let mut spawned = Vec::new();

        let mut acceptors = std::mem::take(&mut parsed.tcp_acceptors);
        for listener in parsed.servers {
            if !wanted.contains(&listener.id.as_str()) || control.is_running(&listener.id) {
                continue;
            }
            let acceptor = acceptors
                .remove(&listener.id)
                .unwrap_or(TcpAcceptor::Plain);
            let id = listener.id.clone();
            if control.spawn(listener, acceptor) {
                spawned.push(id);
            }
        }

        Ok(restored
            .iter()
            .map(|listener| listener.id.clone())
            .filter(|id| !spawned.contains(id))
            .collect())
    }
}
