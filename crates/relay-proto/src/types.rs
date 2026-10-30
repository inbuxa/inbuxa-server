/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The relay's data types (spec "The relay's JMAP API"). `Envelope` follows
//! RFC 8621 §7 field for field.

use crate::b64;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

/// Type names, as they appear in method names and `StateChange`.
pub mod type_name {
    pub const RELAY: &str = "Relay";
    pub const RECIPIENT_DOMAIN: &str = "RecipientDomain";
    pub const RECIPIENT: &str = "Recipient";
    pub const INBOUND: &str = "Inbound";
    pub const OUTBOUND: &str = "Outbound";
    pub const RELAY_EVENT: &str = "RelayEvent";
}

/// The `urn:inbuxa:jmap:relay` capability object in the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub protocol_version: u32,
    pub relay_version: String,
    pub max_blob_size: u64,
    #[serde(default)]
    pub features: Vec<String>,
}

/// The `Relay` object's id: there is only one.
pub const RELAY_SINGLETON: &str = "singleton";

/// Bounds the relay enforces on settings.
pub mod limits {
    pub const LIVE_VERDICT_TIMEOUT_MAX: u32 = 120;
    pub const HELD_MAX_AGE_DAYS_MAX: u32 = 90;
}

/// What the downstream sets on `Relay` (spec table "`Relay`").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RelaySettings {
    /// Public name: EHLO, banner, and the SMTP certificate's name.
    pub hostname: String,
    /// Port 25 listen addresses.
    pub smtp_listen: Vec<String>,
    /// The domains served (RL-1, RL-4).
    pub domains: Vec<String>,
    pub max_message_size: u64,
    pub max_recipients: u32,
    pub rate_limits: RateLimits,
    /// DNSBL zones, checked at connect in held mode. Empty by default (RL-14).
    pub dnsbl: Vec<String>,
    /// Seconds to wait for a live verdict (RL-13).
    pub live_verdict_timeout: u32,
    /// Days held inbound mail waits for the downstream.
    pub held_max_age: u32,
    pub spool_max_bytes: u64,
    /// Seconds between outbound attempts, in order; the last repeats.
    pub outbound_retry: Vec<u32>,
    /// Seconds before outbound mail is given up.
    pub outbound_expiry: u32,
    /// The STARTTLS certificate for port 25.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_certificate: Option<SmtpCertificate>,
    /// The downstream's public sealing key (RL-21).
    #[serde(with = "b64::option", skip_serializing_if = "Option::is_none")]
    pub sealing_key: Option<[u8; 32]>,
    /// The key recipient hashes are made with (RL-11).
    #[serde(with = "b64::option", skip_serializing_if = "Option::is_none")]
    pub recipient_key: Option<[u8; 32]>,
}

impl Default for RelaySettings {
    fn default() -> Self {
        RelaySettings {
            hostname: String::new(),
            smtp_listen: vec!["[::]:25".into()],
            domains: Vec::new(),
            max_message_size: 50 * 1024 * 1024,
            max_recipients: 100,
            rate_limits: RateLimits::default(),
            dnsbl: Vec::new(),
            live_verdict_timeout: 30,
            held_max_age: 30,
            spool_max_bytes: 2 * 1024 * 1024 * 1024,
            outbound_retry: vec![120, 300, 600, 1800, 3600, 7200, 14_400],
            outbound_expiry: 3 * 86_400,
            smtp_certificate: None,
            sealing_key: None,
            recipient_key: None,
        }
    }
}

impl RelaySettings {
    /// What is wrong with these settings, or nothing.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.hostname.is_empty() {
            out.push("hostname is required".into());
        }
        if self.smtp_listen.is_empty() {
            out.push("smtpListen needs at least one address".into());
        }
        for addr in &self.smtp_listen {
            if addr.parse::<std::net::SocketAddr>().is_err() {
                out.push(format!("smtpListen: {addr} is not an address and port"));
            }
        }
        if self.domains.is_empty() {
            out.push("domains needs at least one domain".into());
        }
        if self.max_message_size == 0 || self.max_recipients == 0 {
            out.push("maxMessageSize and maxRecipients must be above zero".into());
        }
        if !(1..=limits::LIVE_VERDICT_TIMEOUT_MAX).contains(&self.live_verdict_timeout) {
            out.push(format!(
                "liveVerdictTimeout must be 1 to {} seconds",
                limits::LIVE_VERDICT_TIMEOUT_MAX
            ));
        }
        if !(1..=limits::HELD_MAX_AGE_DAYS_MAX).contains(&self.held_max_age) {
            out.push(format!(
                "heldMaxAge must be 1 to {} days",
                limits::HELD_MAX_AGE_DAYS_MAX
            ));
        }
        if self.outbound_retry.is_empty() || self.outbound_retry.contains(&0) {
            out.push("outboundRetry needs intervals above zero".into());
        }
        if self.sealing_key.is_none() {
            out.push("sealingKey is required".into());
        }
        if self.recipient_key.is_none() {
            out.push("recipientKey is required".into());
        }
        out
    }

    /// Whether `domain` (lowercased) is served.
    pub fn serves(&self, domain: &str) -> bool {
        self.domains.iter().any(|d| d.eq_ignore_ascii_case(domain))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RateLimits {
    /// New connections a minute from one IP.
    pub connections_per_minute: u32,
    /// Messages a minute from one IP.
    pub messages_per_minute: u32,
    /// Sessions open at once from one IP.
    pub concurrent_sessions: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        RateLimits {
            connections_per_minute: 60,
            messages_per_minute: 60,
            concurrent_sessions: 10,
        }
    }
}

/// A PEM chain and its private key. `/get` never returns the key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmtpCertificate {
    pub chain_pem: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_pem: String,
}

impl std::fmt::Debug for SmtpCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpCertificate")
            .field("chain_pem", &format_args!("{} bytes", self.chain_pem.len()))
            .finish_non_exhaustive()
    }
}

/// What the relay sets on `Relay` (`status`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RelayStatus {
    pub started_at: String,
    pub relay_version: String,
    pub link_clients: u32,
    pub mode: Mode,
    pub spool: SpoolStatus,
    /// The `Recipient` state string the relay holds.
    pub recipient_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// False in a container image: update the image instead (RL-29).
    pub self_upgrade: bool,
}

/// Live while a link client has push on for `Inbound` (spec "Live mode").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    /// Port 25 stays closed until the first settings and recipient set.
    #[default]
    Unconfigured,
    Live,
    Held,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SpoolStatus {
    pub inbound: u64,
    pub outbound: u64,
    pub bytes: u64,
}

/// RFC 8621 `Envelope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub mail_from: Address,
    pub rcpt_to: Vec<Address>,
}

/// RFC 8621 `Address`: an address and its SMTP parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<BTreeMap<String, Option<String>>>,
}

impl Address {
    pub fn new(email: impl Into<String>) -> Self {
        Address {
            email: email.into(),
            parameters: None,
        }
    }
}

/// The SMTP session a message arrived in: what the downstream judges it by
/// (RL-23).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub local_ip: IpAddr,
    pub helo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    /// The reverse DNS name, if the relay looked one up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInfo {
    pub version: String,
    pub cipher: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InboundState {
    /// Live: waiting for the downstream's verdict.
    Pending,
    /// Waiting for the downstream to take it.
    Held,
    /// Leased to one link connection (RL-15).
    Claimed,
}

/// A message the relay accepted on port 25.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Inbound {
    pub id: String,
    pub received_at: String,
    pub state: InboundState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_until: Option<String>,
    pub envelope: Envelope,
    pub session: Session,
    pub size: u64,
    /// The sealed message (RL-21).
    pub blob_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub door_checks: Vec<DoorCheck>,
}

/// One check the relay ran at the door, and what it found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoorCheck {
    /// e.g. `dnsbl:zen.example.org`.
    pub check: String,
    pub result: String,
}

/// The downstream's answer for a pending message (RL-12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum Verdict {
    Accept,
    Reject(Reply),
    Tempfail(Reply),
}

/// An SMTP reply for the relay to give.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reply {
    pub code: u16,
    /// e.g. `5.7.1`.
    pub enhanced: String,
    pub text: String,
}

impl Verdict {
    /// The reply, if it is a valid one for its kind.
    pub fn is_valid(&self) -> bool {
        let ok = |r: &Reply, class: u16, first: char| {
            r.code / 100 == class
                && r.enhanced.starts_with(first)
                && r.enhanced.split('.').count() == 3
                && r.enhanced.split('.').all(|p| p.parse::<u16>().is_ok())
                && !r.text.contains(['\r', '\n'])
        };
        match self {
            Verdict::Accept => true,
            Verdict::Reject(r) => ok(r, 5, '5'),
            Verdict::Tempfail(r) => ok(r, 4, '4'),
        }
    }
}

/// A relay event, for the downstream's history and tracer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayEvent {
    pub id: String,
    pub at: String,
    /// e.g. `inbound.accepted`, `inbound.expired`, `smtp.rejected`.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub data: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn verdict_wire_form() {
        assert_eq!(
            serde_json::to_value(Verdict::Accept).unwrap(),
            json!({"type": "accept"})
        );
        let v: Verdict = serde_json::from_value(
            json!({"type": "reject", "code": 550, "enhanced": "5.7.1", "text": "spam"}),
        )
        .unwrap();
        assert!(v.is_valid());
        let bad = Verdict::Reject(Reply {
            code: 450,
            enhanced: "5.7.1".into(),
            text: "x".into(),
        });
        assert!(!bad.is_valid());
        let injected = Verdict::Tempfail(Reply {
            code: 451,
            enhanced: "4.3.0".into(),
            text: "a\r\n250 ok".into(),
        });
        assert!(!injected.is_valid());
    }

    #[test]
    fn settings_defaults_need_the_downstream_parts() {
        let mut s = RelaySettings::default();
        assert_eq!(s.problems().len(), 4);
        s.hostname = "relay.example.com".into();
        s.domains = vec!["example.com".into()];
        s.sealing_key = Some([1; 32]);
        s.recipient_key = Some([2; 32]);
        assert!(s.problems().is_empty());
        s.live_verdict_timeout = 121;
        s.held_max_age = 91;
        assert_eq!(s.problems().len(), 2);
        assert!(s.serves("EXAMPLE.com"));
    }

    #[test]
    fn certificate_key_stays_out_of_debug() {
        let cert = SmtpCertificate {
            chain_pem: "chain".into(),
            key_pem: "SECRET".into(),
        };
        assert!(!format!("{cert:?}").contains("SECRET"));
    }

    #[test]
    fn settings_round_trip() {
        let s = RelaySettings {
            sealing_key: Some([3; 32]),
            ..Default::default()
        };
        let value = serde_json::to_value(&s).unwrap();
        assert!(value.get("recipientKey").is_none());
        assert_eq!(serde_json::from_value::<RelaySettings>(value).unwrap(), s);
    }
}
