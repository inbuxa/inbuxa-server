/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `inbuxa:ProtocolPolicy`, the server-wide legacy mail protocols switch
//! (legacy-protocols spec, data model and LP-1 to LP-8). Stored as JSON under
//! `P` + `p` in the fork's subspace; unset fields read as the defaults.
//!
//! This module is the fact, not the act. It holds what the operator chose and
//! which listeners were taken away to honour it. Closing sockets belongs to
//! `common`, which owns the listener registry, and removing the listener
//! objects belongs to the caller that has the registry to hand: this crate
//! sits below both.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use store::{
    Deserialize, SUBSPACE_INBUXA, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// Whether the legacy mail protocols may be used at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum LegacyProtocols {
    /// IMAP, POP3, ManageSieve and SMTP submission work as configured.
    #[default]
    Enabled,
    /// They are off: the ports are closed and sign-in over them is refused.
    Disabled,
}

impl LegacyProtocols {
    pub fn is_disabled(&self) -> bool {
        matches!(self, LegacyProtocols::Disabled)
    }
}

/// A listener taken away to honour the switch, kept whole so it can be put
/// back exactly as it was (LP-1, LP-5).
///
/// `object` is the listener's registry object verbatim. Keeping the whole
/// object rather than a few fields is what lets LP-5 promise "exactly the
/// saved listeners": a listener has proxy networks, TLS timeouts and socket
/// options that nobody should have to re-derive, and a field this code has
/// never heard of must survive the round trip too.
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedListener {
    /// The listener's name, as the operator knows it.
    pub id: String,
    /// `imap`, `pop3`, `manageSieve` or `smtp`, as the registry spells it.
    pub protocol: String,
    /// The ports it was accepting on, for the confirmation's list (LP-16).
    pub ports: Vec<u16>,
    /// The registry object, whole.
    pub object: serde_json::Value,
}

/// The server-wide switch.
#[derive(Debug, Clone, PartialEq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProtocolPolicy {
    /// The switch itself.
    pub legacy_protocols: LegacyProtocols,
    /// With `disabled`, also close SMTP submission (LP-3). The inbound
    /// listener on port 25 is never closed, whatever this says.
    pub close_submission: bool,
    /// The listeners removed when the switch went off (LP-1), for LP-5.
    pub saved_listeners: Vec<SavedListener>,
    /// When the switch last changed, in milliseconds since the epoch.
    pub changed_at: Option<u64>,
    /// The account that last changed it.
    pub changed_by: Option<String>,
}

impl Default for ProtocolPolicy {
    fn default() -> Self {
        ProtocolPolicy {
            legacy_protocols: LegacyProtocols::Enabled,
            close_submission: true,
            saved_listeners: Vec::new(),
            changed_at: None,
            changed_by: None,
        }
    }
}

/// The properties `inbuxa:ProtocolPolicy` has, as they appear over JMAP.
pub const PROPERTIES: &[&str] = &[
    "legacyProtocols",
    "closeSubmission",
    "savedListeners",
    "changedAt",
    "changedBy",
];

/// The registry protocols the switch closes, as the schema spells them.
///
/// `smtp` is deliberately absent: an SMTP listener is submission or inbound
/// depending on its port, which only the caller can tell (LP-3).
pub const LEGACY_PROTOCOLS: &[&str] = &["imap", "pop3", "manageSieve"];

/// The port that always means inbound mail, and is never closed (LP-3).
pub const INBOUND_SMTP_PORT: u16 = 25;

/// Protocols the switch may never close, whatever is asked of it (LP-21).
///
/// `http` carries JMAP, so closing it would lock every account out of its mail
/// and the operator out of INBUXA Admin. `smtp` is locked whole — inbound and
/// submission alike — by John's decision of 2026-09-20; LP-3 already spared
/// inbound, and this extends it to 465 and 587. `lmtp` is internal and was
/// never a candidate.
///
/// Locking submission costs the feature nothing: the ports stay open and
/// sign-in over them is still refused (LP-6), which is the case acceptance
/// test 2 already describes.
///
/// The front ends read this list rather than carry their own copy, so
/// unlocking later is a server change and no admin release.
pub const LOCKED_PROTOCOLS: &[&str] = &["smtp", "lmtp", "http"];

/// Whether this protocol is locked open (LP-21).
pub fn is_locked(protocol: &str) -> bool {
    LOCKED_PROTOCOLS
        .iter()
        .any(|locked| locked.eq_ignore_ascii_case(protocol))
}

impl ProtocolPolicy {
    /// Whether a listener of this protocol and these ports is one the switch
    /// closes. A listener bound to port 25 is inbound whatever its name, and
    /// any other SMTP listener counts as submission (LP-3).
    pub fn closes(&self, protocol: &str, ports: &[u16]) -> bool {
        if !self.legacy_protocols.is_disabled() {
            return false;
        }
        // The lock is checked first and answers for every caller, so no
        // request phrasing can reach past it (LP-21).
        if is_locked(protocol) {
            return false;
        }
        if LEGACY_PROTOCOLS.contains(&protocol) {
            return true;
        }
        protocol.eq_ignore_ascii_case("smtp")
            && self.close_submission
            && !ports.contains(&INBOUND_SMTP_PORT)
    }

    /// Applies the locks to what a client asked for, returning what was
    /// overruled so the response can say so (LP-21).
    ///
    /// `closeSubmission` is recorded and ignored rather than refused: the
    /// field is specified, and the lock is meant to be temporary.
    pub fn apply_locks(&mut self) -> Vec<&'static str> {
        let mut overruled = Vec::new();
        if self.close_submission && is_locked("smtp") {
            self.close_submission = false;
            overruled.push("closeSubmission");
        }
        overruled
    }

    /// Whether creating a listener of this protocol is refused right now
    /// (LP-4), so a closed port cannot be quietly reopened.
    pub fn refuses_new_listener(&self, protocol: &str, ports: &[u16]) -> bool {
        self.closes(protocol, ports)
    }

    /// What's wrong with these values, naming the property.
    pub fn check(&self) -> Result<(), (&'static str, String)> {
        if self.saved_listeners.len() > 1024 {
            return Err((
                "savedListeners",
                "must hold at most 1024 listeners".to_string(),
            ));
        }
        for saved in &self.saved_listeners {
            if saved.id.is_empty() {
                return Err(("savedListeners", "a saved listener has no id".to_string()));
            }
        }
        Ok(())
    }
}

fn key() -> ValueClass {
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key: b"Pp".to_vec(),
    })
}

struct Json(ProtocolPolicy);

impl Deserialize for Json {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

/// The policy in force.
pub async fn get(data: &Store) -> trc::Result<ProtocolPolicy> {
    Ok(data
        .get_value::<Json>(ValueKey::from(key()))
        .await
        .caused_by(trc::location!())?
        .map(|Json(policy)| policy)
        .unwrap_or_default())
}

/// Stores a new policy.
pub async fn set(data: &Store, policy: &ProtocolPolicy) -> trc::Result<()> {
    let bytes = serde_json::to_vec(policy).map_err(|err| {
        trc::StoreEvent::UnexpectedError
            .caused_by(trc::location!())
            .reason(err)
    })?;
    let mut batch = BatchBuilder::new();
    batch.set(key(), bytes);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disabled() -> ProtocolPolicy {
        ProtocolPolicy {
            legacy_protocols: LegacyProtocols::Disabled,
            ..Default::default()
        }
    }

    /// The default is on, and every property survives the round trip.
    #[test]
    fn defaults_and_partial_json() {
        let policy = ProtocolPolicy::default();
        assert_eq!(policy.legacy_protocols, LegacyProtocols::Enabled);
        assert!(policy.close_submission);
        assert!(policy.check().is_ok());

        let partial: ProtocolPolicy =
            serde_json::from_str(r#"{"legacyProtocols": "disabled"}"#).unwrap();
        assert!(partial.legacy_protocols.is_disabled());
        assert!(
            partial.close_submission,
            "an unset closeSubmission reads as the default, true"
        );

        let json = serde_json::to_value(&policy).unwrap();
        for property in PROPERTIES {
            assert!(json.get(property).is_some(), "{property}");
        }
        assert_eq!(json["legacyProtocols"], "enabled");
    }

    /// While the switch is on, nothing closes (LP-1).
    #[test]
    fn enabled_closes_nothing() {
        let policy = ProtocolPolicy::default();
        for (protocol, ports) in [
            ("imap", vec![993]),
            ("pop3", vec![995]),
            ("manageSieve", vec![4190]),
            ("smtp", vec![465]),
            ("smtp", vec![25]),
        ] {
            assert!(!policy.closes(protocol, &ports), "{protocol} {ports:?}");
        }
    }

    /// The mail-app protocols close. Submission does not, while SMTP is
    /// locked (LP-1, LP-21).
    #[test]
    fn disabled_closes_the_legacy_protocols() {
        let policy = disabled();
        assert!(policy.closes("imap", &[993]));
        assert!(policy.closes("pop3", &[995]));
        assert!(policy.closes("manageSieve", &[4190]));
        assert!(!policy.closes("smtp", &[465]), "SMTP is locked (LP-21)");
        assert!(!policy.closes("smtp", &[587]), "SMTP is locked (LP-21)");
    }

    /// SMTP and JMAP cannot be closed, however the question is put (LP-21).
    #[test]
    fn smtp_and_jmap_are_locked() {
        assert!(is_locked("smtp"));
        assert!(is_locked("SMTP"), "the lock ignores case");
        assert!(is_locked("http"));
        assert!(is_locked("lmtp"));
        assert!(!is_locked("imap"));
        assert!(!is_locked("pop3"));
        assert!(!is_locked("manageSieve"));

        // Even asked for directly, with closeSubmission set by hand.
        let forced = ProtocolPolicy {
            legacy_protocols: LegacyProtocols::Disabled,
            close_submission: true,
            ..Default::default()
        };
        for ports in [vec![465], vec![587], vec![25], vec![2525]] {
            assert!(!forced.closes("smtp", &ports), "smtp {ports:?}");
        }
        assert!(!forced.closes("http", &[443]));
    }

    /// A client asking to close submission is overruled, not refused, and the
    /// overrule is reported (LP-21, acceptance test 18).
    #[test]
    fn close_submission_is_overruled_and_reported() {
        let mut policy = ProtocolPolicy {
            legacy_protocols: LegacyProtocols::Disabled,
            close_submission: true,
            ..Default::default()
        };

        let overruled = policy.apply_locks();
        assert_eq!(overruled, vec!["closeSubmission"]);
        assert!(!policy.close_submission);

        // Applying twice says nothing the second time.
        assert!(policy.apply_locks().is_empty());
    }

    /// Port 25 is inbound whatever the listener is called, and never closes
    /// (LP-3). It is doubly safe now that SMTP is locked (LP-21), and this
    /// test stands so LP-3 stays covered if the lock is ever lifted.
    #[test]
    fn port_25_is_never_closed() {
        let policy = disabled();
        assert!(!policy.closes("smtp", &[25]));
        assert!(
            !policy.closes("smtp", &[25, 465]),
            "a listener that also binds 25 is inbound and stays"
        );
    }

    /// JMAP, DAV and internal delivery are never touched.
    #[test]
    fn http_and_lmtp_are_never_closed() {
        let policy = disabled();
        assert!(!policy.closes("http", &[443]));
        assert!(!policy.closes("lmtp", &[11200]));
    }

    /// Without `closeSubmission`, 465 and 587 stay open (acceptance test 2).
    /// The lock makes this the only behaviour for now (LP-21).
    #[test]
    fn submission_stays_open_when_asked() {
        let policy = ProtocolPolicy {
            legacy_protocols: LegacyProtocols::Disabled,
            close_submission: false,
            ..Default::default()
        };
        assert!(!policy.closes("smtp", &[465]));
        assert!(!policy.closes("smtp", &[587]));
        assert!(
            policy.closes("imap", &[993]),
            "the mail-app protocols close regardless"
        );
    }

    /// A new legacy listener is refused while the switch is on (LP-4), and an
    /// inbound one is still allowed.
    #[test]
    fn new_legacy_listeners_are_refused() {
        let policy = disabled();
        assert!(policy.refuses_new_listener("imap", &[143]));
        assert!(!policy.refuses_new_listener("smtp", &[25]));
        assert!(!ProtocolPolicy::default().refuses_new_listener("imap", &[143]));
    }

    /// A saved listener keeps its whole registry object, so LP-5 can put back
    /// fields this code never reads.
    #[test]
    fn saved_listeners_survive_the_round_trip() {
        let policy = ProtocolPolicy {
            legacy_protocols: LegacyProtocols::Disabled,
            saved_listeners: vec![SavedListener {
                id: "imaps".to_string(),
                protocol: "imap".to_string(),
                ports: vec![993],
                object: serde_json::json!({
                    "bind": ["[::]:993"],
                    "tls": {"implicit": true},
                    "somethingThisCodeHasNeverHeardOf": 7,
                }),
            }],
            ..Default::default()
        };
        assert!(policy.check().is_ok());

        let round_tripped: ProtocolPolicy =
            serde_json::from_slice(&serde_json::to_vec(&policy).unwrap()).unwrap();
        assert_eq!(round_tripped, policy);
        assert_eq!(
            round_tripped.saved_listeners[0].object["somethingThisCodeHasNeverHeardOf"],
            7
        );
    }

    /// A saved listener with no id is refused, naming the property.
    #[test]
    fn a_nameless_saved_listener_is_refused() {
        let policy = ProtocolPolicy {
            saved_listeners: vec![SavedListener {
                id: String::new(),
                protocol: "imap".to_string(),
                ports: vec![993],
                object: serde_json::Value::Null,
            }],
            ..Default::default()
        };
        assert_eq!(policy.check().unwrap_err().0, "savedListeners");
    }
}
