/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Taking the legacy listeners away and putting them back (legacy-protocols
//! spec, LP-1 and LP-5).
//!
//! The switch removes the listener **objects**, not just their sockets. A
//! stopped socket comes back on the next restart, which would reopen every
//! port the operator just closed; a removed object does not. It also means a
//! server that boots with the switch on never spawns them in the first place,
//! with no boot-time special case.
//!
//! Each removed object is kept whole in the policy so LP-5 can put it back
//! exactly as it was. Closing the running socket is a separate step, and lives
//! in `common`, which owns the listener registry: this crate sits below it.
//!
//! None of this touches the host's firewall or any port-forward (LP-20).

use crate::security::protocol_policy::{ProtocolPolicy, SavedListener};
use registry::schema::{
    enums::NetworkListenerProtocol,
    prelude::Object,
    structs::NetworkListener,
};
use store::{
    RegistryStore,
    registry::write::{RegistryWrite, RegistryWriteResult},
};
use trc::AddContext;

/// How the registry schema spells a listener's protocol. These are the strings
/// [`ProtocolPolicy::closes`] matches on.
pub fn protocol_name(protocol: NetworkListenerProtocol) -> &'static str {
    match protocol {
        NetworkListenerProtocol::Smtp => "smtp",
        NetworkListenerProtocol::Lmtp => "lmtp",
        NetworkListenerProtocol::Http => "http",
        NetworkListenerProtocol::Imap => "imap",
        NetworkListenerProtocol::Pop3 => "pop3",
        NetworkListenerProtocol::ManageSieve => "manageSieve",
    }
}

/// Every port a listener binds. A listener may bind several, and one of them
/// being 25 makes the whole listener inbound (LP-3).
pub fn ports(listener: &NetworkListener) -> Vec<u16> {
    listener.bind.iter().map(|addr| addr.0.port()).collect()
}

/// Whether the policy closes this listener.
pub fn closes(policy: &ProtocolPolicy, listener: &NetworkListener) -> bool {
    policy.closes(protocol_name(listener.protocol), &ports(listener))
}

/// Saves a listener whole, ready to be put back (LP-5).
fn save(listener: &NetworkListener) -> trc::Result<SavedListener> {
    Ok(SavedListener {
        id: listener.name.clone(),
        protocol: protocol_name(listener.protocol).to_string(),
        ports: ports(listener),
        object: serde_json::to_value(listener).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .reason(err)
        })?,
    })
}

/// Removes every listener the policy closes, saving each one whole first
/// (LP-1). Returns what was removed, in the order the registry listed it.
///
/// The caller then stops the matching running sockets, by the `id` of each
/// returned listener — which is the listener's name, the same key the runtime
/// registry uses.
pub async fn close(
    registry: &RegistryStore,
    policy: &ProtocolPolicy,
) -> trc::Result<Vec<SavedListener>> {
    let mut removed = Vec::new();

    for listener in registry
        .list::<NetworkListener>()
        .await
        .caused_by(trc::location!())?
    {
        if !closes(policy, &listener.object) {
            continue;
        }

        let saved = save(&listener.object)?;
        match registry
            .write(RegistryWrite::delete(listener.id))
            .await
            .caused_by(trc::location!())?
        {
            RegistryWriteResult::Success(_) | RegistryWriteResult::NotFound { .. } => {
                removed.push(saved);
            }
            // Anything else means the registry declined the delete. Leave the
            // listener alone and say nothing was removed, so the policy does
            // not claim a port is closed while it is still accepting.
            _ => {}
        }
    }

    Ok(removed)
}

/// Puts back every saved listener (LP-5).
///
/// Returns the ones restored and the ones that could not be, each with the
/// reason. A listener that cannot come back — its port taken in the meantime,
/// say — does not stop the others, and stays saved for another try.
pub async fn reopen(
    registry: &RegistryStore,
    saved: &[SavedListener],
) -> trc::Result<(Vec<SavedListener>, Vec<(SavedListener, String)>)> {
    let mut restored = Vec::new();
    let mut failed = Vec::new();

    for listener in saved {
        let object: NetworkListener = match serde_json::from_value(listener.object.clone()) {
            Ok(object) => object,
            Err(err) => {
                failed.push((listener.clone(), format!("saved listener unreadable: {err}")));
                continue;
            }
        };

        let object: Object = object.into();
        match registry
            .write(RegistryWrite::insert(&object))
            .await
            .caused_by(trc::location!())?
        {
            RegistryWriteResult::Success(_) => restored.push(listener.clone()),
            other => failed.push((listener.clone(), format!("{other:?}"))),
        }
    }

    Ok((restored, failed))
}

/// The listener objects that exist right now, as `(name, protocol, ports)`.
/// The confirmation (LP-16) lists exactly what will close, before anything
/// happens.
pub async fn would_close(
    registry: &RegistryStore,
    policy: &ProtocolPolicy,
) -> trc::Result<Vec<SavedListener>> {
    let mut out = Vec::new();
    for listener in registry
        .list::<NetworkListener>()
        .await
        .caused_by(trc::location!())?
    {
        if closes(policy, &listener.object) {
            out.push(save(&listener.object)?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::protocol_policy::LegacyProtocols;
    use registry::{schema::prelude::SocketAddr, types::map::Map};
    use std::str::FromStr;

    fn listener(name: &str, protocol: NetworkListenerProtocol, binds: &[&str]) -> NetworkListener {
        NetworkListener {
            name: name.to_string(),
            protocol,
            bind: Map::new(
                binds
                    .iter()
                    .map(|addr| SocketAddr::from_str(addr).unwrap())
                    .collect::<Vec<_>>(),
            ),
            ..Default::default()
        }
    }

    fn disabled() -> ProtocolPolicy {
        ProtocolPolicy {
            legacy_protocols: LegacyProtocols::Disabled,
            ..Default::default()
        }
    }

    /// The protocol names match what the policy matches on.
    #[test]
    fn protocol_names_are_the_schema_spelling() {
        assert_eq!(protocol_name(NetworkListenerProtocol::Imap), "imap");
        assert_eq!(protocol_name(NetworkListenerProtocol::Pop3), "pop3");
        assert_eq!(
            protocol_name(NetworkListenerProtocol::ManageSieve),
            "manageSieve"
        );
        assert_eq!(protocol_name(NetworkListenerProtocol::Smtp), "smtp");
    }

    /// Every bound port is seen, so a listener that also binds 25 is caught.
    #[test]
    fn every_bound_port_is_seen() {
        let l = listener(
            "mixed",
            NetworkListenerProtocol::Smtp,
            &["[::]:465", "0.0.0.0:25"],
        );
        let mut p = ports(&l);
        p.sort();
        assert_eq!(p, vec![25, 465]);
    }

    /// The mail-app listeners close; inbound and JMAP do not (LP-1, LP-3).
    #[test]
    fn the_right_listeners_close() {
        let policy = disabled();

        for (name, protocol, binds) in [
            ("imaps", NetworkListenerProtocol::Imap, &["[::]:993"][..]),
            ("pop3s", NetworkListenerProtocol::Pop3, &["[::]:995"][..]),
            (
                "sieve",
                NetworkListenerProtocol::ManageSieve,
                &["[::]:4190"][..],
            ),
        ] {
            assert!(
                closes(&policy, &listener(name, protocol, binds)),
                "{name} should close"
            );
        }

        for (name, protocol, binds) in [
            ("smtp", NetworkListenerProtocol::Smtp, &["[::]:25"][..]),
            // Locked whole, so submission stays too (LP-21).
            (
                "submissions",
                NetworkListenerProtocol::Smtp,
                &["[::]:465"][..],
            ),
            ("https", NetworkListenerProtocol::Http, &["[::]:443"][..]),
            ("lmtp", NetworkListenerProtocol::Lmtp, &["[::]:11200"][..]),
        ] {
            assert!(
                !closes(&policy, &listener(name, protocol, binds)),
                "{name} must stay"
            );
        }
    }

    /// A submission listener that also binds 25 is inbound, and stays (LP-3).
    /// Kept so LP-3 stays covered if the LP-21 lock is ever lifted.
    #[test]
    fn a_listener_that_also_binds_25_stays() {
        let policy = disabled();
        let l = listener(
            "mixed",
            NetworkListenerProtocol::Smtp,
            &["[::]:465", "[::]:25"],
        );
        assert!(!closes(&policy, &l));
    }

    /// A saved listener keeps every field, including ones this code never
    /// reads, and comes back as the same object (LP-5).
    #[test]
    fn a_saved_listener_round_trips() {
        let mut original = listener("imaps", NetworkListenerProtocol::Imap, &["[::]:993"]);
        original.socket_no_delay = true;
        original.socket_backlog = Some(2048);

        let saved = save(&original).unwrap();
        assert_eq!(saved.id, "imaps");
        assert_eq!(saved.protocol, "imap");
        assert_eq!(saved.ports, vec![993]);

        let back: NetworkListener = serde_json::from_value(saved.object).unwrap();
        assert_eq!(back, original);
    }

    /// While the switch is off, nothing closes.
    #[test]
    fn enabled_closes_nothing() {
        let policy = ProtocolPolicy::default();
        assert!(!closes(
            &policy,
            &listener("imaps", NetworkListenerProtocol::Imap, &["[::]:993"])
        ));
    }
}
