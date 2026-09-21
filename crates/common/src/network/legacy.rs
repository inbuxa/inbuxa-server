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
//! Sign-in is the second lock (LP-6): while the switch is off, a sign-in over
//! a legacy protocol is refused before any password is looked at, so a
//! listener that exists by mistake still lets nobody in.
//!
//! Nothing here touches the host's firewall, NAT port-forwards or any proxy
//! (LP-20). The server stops answering; what still routes the port is the
//! operator's to reconcile.

use crate::{Server, config::server::Listeners, network::TcpAcceptor};
use directory::Credentials;
use inbuxa_features::security::{
    listeners,
    protocol_policy::{self, ProtocolPolicy, SavedListener},
};
use registry::types::{error::Error, id::ObjectId};
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

        // Only the wanted listeners, so re-parsing does not bind a port some
        // other listener already holds.
        let wanted: Vec<&str> = restored.iter().map(|l| l.id.as_str()).collect();
        parsed
            .servers
            .retain(|listener| wanted.contains(&listener.id.as_str()));

        // Bind, but do not drop privileges again. A port below 1024 fails
        // here once privileges are gone; that listener is reported as needing
        // a restart rather than quietly left dead.
        let errors_before = bootstrap.errors.len();
        parsed.bind(&mut bootstrap);
        let unbindable: Vec<ObjectId> = bootstrap.errors[errors_before..]
            .iter()
            .filter_map(|error| match error {
                Error::Build { object_id, .. } => Some(*object_id),
                _ => None,
            })
            .collect();
        parsed
            .servers
            .retain(|listener| !unbindable.contains(&listener.registry_id));

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

/// A protocol a mail app signs in over, which the switch refuses (LP-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyProtocol {
    Imap,
    Pop3,
    ManageSieve,
    /// SMTP AUTH, on any SMTP listener: only mail apps authenticate, so
    /// inbound delivery is untouched (LP-3).
    Submission,
}

impl LegacyProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            LegacyProtocol::Imap => "imap",
            LegacyProtocol::Pop3 => "pop3",
            LegacyProtocol::ManageSieve => "manageSieve",
            LegacyProtocol::Submission => "submission",
        }
    }

    /// What the mail app is told, at server scope (LP-12, LP-6). Each
    /// protocol's own framing — IMAP's `[ALERT]`, ManageSieve's quoting —
    /// is added by its session; POP3 carries `[AUTH]` in the text, since its
    /// errors have no separate code, and SMTP is the whole reply line.
    pub fn refusal(&self) -> &'static str {
        match self {
            LegacyProtocol::Imap => {
                "This server allows only INBUXA webmail and JMAP apps. This mail app can't sign in."
            }
            LegacyProtocol::Pop3 => {
                "[AUTH] This server allows only INBUXA webmail and JMAP apps. This mail app can't sign in."
            }
            LegacyProtocol::ManageSieve => "This server allows only INBUXA webmail and JMAP apps.",
            LegacyProtocol::Submission => {
                "535 5.7.0 This server allows only INBUXA webmail and JMAP apps. This mail app can't send.\r\n"
            }
        }
    }

    /// The refusal as an error: `auth.legacy-protocol-refused`, not
    /// `auth.failed`, so it never counts against the account or feeds the
    /// auto-ban (LP-11). It names the protocol and the domain, never the
    /// account; the session it is raised in adds the remote IP.
    pub fn refused(&self, credentials: &Credentials) -> trc::Error {
        trc::AuthEvent::LegacyProtocolRefused
            .into_err()
            .details(self.refusal())
            .ctx(trc::Key::Source, self.as_str())
            .ctx(trc::Key::Policy, "server")
            .ctx_opt(trc::Key::Domain, domain_of(credentials))
    }
}

/// The domain a sign-in is for, from the name it gives, if it gives one.
fn domain_of(credentials: &Credentials) -> Option<String> {
    let username = match credentials {
        Credentials::Basic { username, .. } => Some(username.as_str()),
        Credentials::Bearer { username, .. } => username.as_deref(),
    }?;
    username
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim().to_lowercase())
        .filter(|domain| !domain.is_empty())
}

impl Server {
    /// Refuses a sign-in over a legacy protocol while the server-wide switch
    /// is off (LP-6). Called before the credentials are checked, so the
    /// answer is the same for a right password, a wrong one and an account
    /// that doesn't exist (LP-11).
    ///
    /// Read from the store on each sign-in rather than cached, so every node
    /// of a cluster answers the same the moment the switch turns.
    pub async fn refuse_legacy_sign_in(
        &self,
        protocol: LegacyProtocol,
        credentials: &Credentials,
    ) -> trc::Result<()> {
        if self.protocol_policy().await?.legacy_protocols.is_disabled() {
            Err(protocol.refused(credentials))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(username: &str) -> Credentials {
        Credentials::Basic {
            username: username.to_string(),
            secret: "wrong or right, it is never read".to_string(),
            mfa_token: None,
        }
    }

    #[test]
    fn refusals_read_as_the_spec_writes_them() {
        // LP-12, with "Your organization" read as "This server" (LP-6).
        assert_eq!(
            LegacyProtocol::Imap.refusal(),
            "This server allows only INBUXA webmail and JMAP apps. This mail app can't sign in."
        );
        assert!(
            LegacyProtocol::Pop3
                .refusal()
                .starts_with("[AUTH] This server allows")
        );
        assert_eq!(
            LegacyProtocol::ManageSieve.refusal(),
            "This server allows only INBUXA webmail and JMAP apps."
        );
        assert_eq!(
            LegacyProtocol::Submission.refusal(),
            "535 5.7.0 This server allows only INBUXA webmail and JMAP apps. This mail app can't send.\r\n"
        );
    }

    #[test]
    fn a_refusal_is_not_a_failed_sign_in() {
        let err = LegacyProtocol::Imap.refused(&basic("maria@Example.org"));
        assert!(err.matches(trc::EventType::Auth(trc::AuthEvent::LegacyProtocolRefused)));
        assert!(!err.matches(trc::EventType::Auth(trc::AuthEvent::Failed)));
        // The session stays open: the mail app is told, not thrown off.
        assert!(!err.must_disconnect());
        assert!(err.should_write_err());
        assert_eq!(err.value_as_str(trc::Key::Domain), Some("example.org"));
        assert_eq!(err.value_as_str(trc::Key::Source), Some("imap"));
        assert_eq!(err.value_as_str(trc::Key::AccountName), None);
    }

    #[test]
    fn the_domain_comes_from_the_name_given() {
        assert_eq!(domain_of(&basic("a@b.test")), Some("b.test".to_string()));
        assert_eq!(domain_of(&basic("no-domain")), None);
        assert_eq!(domain_of(&basic("trailing@")), None);
        let bearer = Credentials::Bearer {
            username: None,
            token: "t".to_string(),
        };
        assert_eq!(domain_of(&bearer), None);
    }
}
