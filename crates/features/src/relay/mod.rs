/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! inbuxa Relay, the downstream's side (docs/spec/features/relay.md, "The
//! downstream"): the `inbuxa:Relay` objects, and the keys every node of
//! this server or cluster shares to link to them.
//!
//! Kept in the fork's subspace (`store::SUBSPACE_INBUXA`), never in the
//! registry, so an upstream schema import never touches them. Every key
//! starts with `E` (edge), then one byte for the kind:
//!
//! - `k`: the downstream's keys ([`DownstreamKeys`]), as JSON. One per
//!   server or cluster, made with the first relay.
//! - `r` + relay id (u32): a relay ([`Relay`]), as JSON.
//!
//! Numbers are big-endian. There are few relays, so they're read whole.

use inbuxa_relay_proto::{
    b64,
    pin::{Pin, spki_pin},
    seal,
    token::JoinToken,
    types::RelaySettings,
};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize, de::DeserializeOwned};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, assert::AssertValue},
};
use trc::AddContext;
use types::id::Id;

const FEATURE: u8 = b'E';
const KIND_KEYS: u8 = b'k';
const KIND_RELAY: u8 = b'r';
const CREATE_ATTEMPTS: usize = 5;

const MAX_NAME: usize = 100;
const MAX_DESCRIPTION: usize = 2_000;
const MAX_PEM: usize = 64 * 1024;
const MAX_DOMAINS: usize = 5_000;

/// The keys every node shares: the link CA that issues each node's link
/// client certificate (RL-6), and the key held mail is sealed to (RL-21).
/// Made once, with the first relay, and never shown.
#[derive(Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownstreamKeys {
    pub link_ca_key_pem: String,
    pub link_ca_cert_pem: String,
    /// The pin of the link CA's key, which every relay keeps.
    #[serde(with = "b64")]
    pub link_ca_pin: Pin,
    #[serde(with = "b64")]
    pub sealing_secret: [u8; 32],
    #[serde(with = "b64")]
    pub sealing_public: [u8; 32],
    pub created_at: u64,
}

impl std::fmt::Debug for DownstreamKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownstreamKeys")
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// Where a relay is in joining this downstream (relay spec, "Joining and
/// reset").
#[derive(Clone, Default, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Join {
    /// The token's secret, until the join is done.
    #[serde(with = "b64::option", skip_serializing_if = "Option::is_none")]
    pub secret: Option<[u8; 32]>,
    pub expires_at: u64,
    /// The relay's link key, pinned once its proof checked out (RL-7).
    #[serde(with = "b64::option", skip_serializing_if = "Option::is_none")]
    pub relay_pin: Option<Pin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joined_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub enum JoinState {
    /// The token is out and the relay hasn't finished joining.
    Waiting,
    /// The token ran out before the relay joined: it needs a new one.
    Expired,
    Joined,
}

impl Join {
    pub fn state(&self, now: u64) -> JoinState {
        if self.relay_pin.is_some() {
            JoinState::Joined
        } else if self.expires_at > now {
            JoinState::Waiting
        } else {
            JoinState::Expired
        }
    }
}

/// One `inbuxa:Relay`.
#[derive(Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct Relay {
    #[serde(default)]
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The host the downstream dials.
    pub address: String,
    #[serde(default = "default_link_port")]
    pub link_port: u16,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Route outbound mail through relays (RL-24).
    #[serde(default)]
    pub send_through: bool,
    /// Takes mail in but sends none (RL-20).
    #[serde(default)]
    pub inbound_only: bool,
    /// What the downstream pushes to the relay, but for the certificate and
    /// the keys, which it adds itself. Empty `domains` means every domain
    /// this server has.
    #[serde(default)]
    pub settings: RelaySettings,
    /// The STARTTLS certificate chain for the relay's port 25, PEM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smtp_certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smtp_private_key: Option<String>,
    /// The key this relay's recipient hashes are made with (RL-11).
    #[serde(with = "b64", default)]
    pub recipient_key: [u8; 32],
    #[serde(default)]
    pub join: Join,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("address", &self.address)
            .field("link_port", &self.link_port)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

fn default_link_port() -> u16 {
    443
}

fn yes() -> bool {
    true
}

/// Why a relay can't be saved: the property at fault, and what's wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    pub property: &'static str,
    pub reason: String,
}

fn invalid(property: &'static str, reason: impl Into<String>) -> Result<(), Invalid> {
    Err(Invalid {
        property,
        reason: reason.into(),
    })
}

/// A host name, loosely: labels of letters, digits and hyphens.
fn is_host_name(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn is_pem(text: &str, label: &str) -> bool {
    text.contains(&format!("-----BEGIN {label}")) && text.contains("-----END ")
}

impl Relay {
    /// Checks what an administrator sets. The keys are the server's and
    /// aren't checked here.
    pub fn validate(&self) -> Result<(), Invalid> {
        let name = self.name.trim();
        if name.is_empty() || name.len() > MAX_NAME {
            return invalid("name", format!("A name of 1 to {MAX_NAME} characters."));
        }
        if self.description.len() > MAX_DESCRIPTION {
            return invalid("description", "The description is too long.");
        }
        let address = self.address.trim();
        if !(is_host_name(address) || address.parse::<std::net::IpAddr>().is_ok()) {
            return invalid(
                "address",
                "The relay's host name or IP address, without a port or scheme.",
            );
        }
        if self.link_port == 0 {
            return invalid("linkPort", "A port from 1 to 65535.");
        }
        if self.send_through && self.inbound_only {
            return invalid(
                "inboundOnly",
                "A relay that sends no mail can't have mail sent through it.",
            );
        }
        let settings = &self.settings;
        if settings.smtp_certificate.is_some()
            || settings.sealing_key.is_some()
            || settings.recipient_key.is_some()
        {
            return invalid(
                "settings",
                "The certificate is set with smtpCertificate, and the keys are the server's.",
            );
        }
        if !is_host_name(&settings.hostname) {
            return invalid(
                "settings",
                "hostname: the relay's public name, which its MX record points at.",
            );
        }
        if settings.domains.len() > MAX_DOMAINS
            || settings.domains.iter().any(|domain| !is_host_name(domain))
        {
            return invalid(
                "settings",
                "domains: domain names, or none for every domain on this server.",
            );
        }
        // What the relay itself would refuse, with the parts the server
        // fills in (the keys, and the domains if none are named) in place
        let mut check = settings.clone();
        check.sealing_key = Some([0; 32]);
        check.recipient_key = Some([0; 32]);
        if check.domains.is_empty() {
            check.domains.push("example.com".into());
        }
        if let Some(problem) = check.problems().into_iter().next() {
            return invalid("settings", problem);
        }
        match (&self.smtp_certificate, &self.smtp_private_key) {
            (None, None) => {}
            (Some(chain), Some(key)) => {
                if chain.len() > MAX_PEM || !is_pem(chain, "CERTIFICATE") {
                    return invalid("smtpCertificate", "A PEM certificate chain.");
                }
                if key.len() > MAX_PEM || !is_pem(key, "") || !key.contains("PRIVATE KEY") {
                    return invalid("smtpPrivateKey", "A PEM private key.");
                }
            }
            (Some(_), None) => {
                return invalid("smtpPrivateKey", "The certificate needs its private key.");
            }
            (None, Some(_)) => {
                return invalid("smtpCertificate", "The private key needs its certificate.");
            }
        }
        Ok(())
    }

    /// What the audit log may show of a relay: what an administrator sets,
    /// with the private key only as whether there is one.
    pub fn audit_view(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "description": self.description,
            "address": self.address,
            "linkPort": self.link_port,
            "enabled": self.enabled,
            "sendThrough": self.send_through,
            "inboundOnly": self.inbound_only,
            "settings": self.settings,
            "smtpCertificate": self.smtp_certificate,
        })
    }

    /// The id a relay knows itself by: the object's JMAP id.
    pub fn relay_id(&self) -> String {
        Id::from(self.id).to_string()
    }

    /// Starts a join (relay spec, "Joining and reset", step 1): a new token,
    /// a new recipient key, and any pinned key forgotten. Returns the token
    /// to show the administrator once.
    pub fn start_join(&mut self, keys: &DownstreamKeys, now: u64) -> String {
        let token = JoinToken::issue(self.relay_id(), keys.link_ca_pin, now);
        self.recipient_key = random_key();
        self.join = Join {
            secret: Some(token.secret),
            expires_at: token.expires_at,
            relay_pin: None,
            joined_at: None,
        };
        token.encode()
    }
}

/// 32 bytes from the system's random source.
pub fn random_key() -> [u8; 32] {
    use aws_lc_rs::rand::SecureRandom;
    let mut key = [0u8; 32];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut key)
        .expect("system random source");
    key
}

/// New downstream keys: a P-256 link CA, and an X25519 sealing key pair.
pub fn new_downstream_keys(now: u64) -> trc::Result<DownstreamKeys> {
    let failed = |err: rcgen::Error| {
        trc::EventType::Server(trc::ServerEvent::ThreadError)
            .into_err()
            .details("Could not make the relay link CA")
            .reason(err)
    };
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(failed)?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(failed)?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "inbuxa relay link CA");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    // The relay pins the key, not the certificate; the dates only have to
    // cover the downstream's life
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2126, 1, 1);
    let cert = params.self_signed(&key).map_err(failed)?;
    let (sealing_secret, sealing_public) = seal::generate_keypair();
    Ok(DownstreamKeys {
        link_ca_pin: spki_pin(&rcgen::PublicKeyData::subject_public_key_info(&key)),
        link_ca_key_pem: key.serialize_pem(),
        link_ca_cert_pem: cert.pem(),
        sealing_secret: *sealing_secret,
        sealing_public,
        created_at: now,
    })
}

struct Json<T>(T);

impl<T: SerdeSerialize> Serialize for Json<&T> {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        serde_json::to_vec(self.0).map_err(|err| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Could not serialize a relay")
                .reason(err)
        })
    }
}

impl<T: DeserializeOwned + Sync + Send> Deserialize for Json<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        serde_json::from_slice(bytes).map(Json).map_err(|err| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid relay")
                .reason(err)
        })
    }
}

fn class(kind: u8, id: Option<u32>) -> ValueClass {
    let mut key = Vec::with_capacity(6);
    key.push(FEATURE);
    key.push(kind);
    if let Some(id) = id {
        key.extend_from_slice(&id.to_be_bytes());
    }
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

fn relay_key(id: u32) -> ValueKey<ValueClass> {
    ValueKey::from(class(KIND_RELAY, Some(id)))
}

/// The downstream's keys, if a relay was ever added.
pub async fn keys(data: &Store) -> trc::Result<Option<DownstreamKeys>> {
    Ok(data
        .get_value::<Json<DownstreamKeys>>(ValueKey::from(class(KIND_KEYS, None)))
        .await
        .caused_by(trc::location!())?
        .map(|Json(keys)| keys))
}

/// The downstream's keys, made now if this is the first relay. Two nodes
/// making them at once keep the same ones: the key must be absent.
pub async fn keys_or_new(data: &Store, now: u64) -> trc::Result<DownstreamKeys> {
    if let Some(keys) = keys(data).await? {
        return Ok(keys);
    }
    let fresh = new_downstream_keys(now)?;
    let mut batch = BatchBuilder::new();
    batch.assert_value(class(KIND_KEYS, None), AssertValue::None);
    batch.set(class(KIND_KEYS, None), Json(&fresh).serialize()?);
    match data.write(batch.build_all()).await {
        Ok(_) => Ok(fresh),
        Err(err)
            if matches!(
                err.as_ref(),
                trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
            ) =>
        {
            keys(data).await?.ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("The relay keys vanished")
            })
        }
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

pub async fn get(data: &Store, id: u32) -> trc::Result<Option<Relay>> {
    Ok(data
        .get_value::<Json<Relay>>(relay_key(id))
        .await
        .caused_by(trc::location!())?
        .map(|Json(relay)| relay))
}

/// Every relay, oldest first.
pub async fn all(data: &Store) -> trc::Result<Vec<Relay>> {
    let mut relays = Vec::new();
    data.iterate(
        IterateParams::new(relay_key(0), relay_key(u32::MAX)),
        |_, value| {
            if let Ok(Json(relay)) = Json::<Relay>::deserialize(value) {
                relays.push(relay);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    relays.sort_by_key(|relay| relay.id);
    Ok(relays)
}

/// Writes a new relay under the next free id and starts its join. Returns
/// the stored relay and its join token. Two nodes creating relays at once
/// can't take the same id: the key must be absent.
pub async fn create(data: &Store, relay: &Relay, now: u64) -> trc::Result<(Relay, String)> {
    let keys = keys_or_new(data, now).await?;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let id = all(data).await?.iter().map(|r| r.id).max().unwrap_or(0) + 1;
        let mut stored = Relay {
            id,
            ..relay.clone()
        };
        let token = stored.start_join(&keys, now);
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(KIND_RELAY, Some(id)), AssertValue::None);
        batch.set(class(KIND_RELAY, Some(id)), Json(&stored).serialize()?);
        match data.write(batch.build_all()).await {
            Ok(_) => return Ok((stored, token)),
            Err(err)
                if attempt < CREATE_ATTEMPTS
                    && matches!(
                        err.as_ref(),
                        trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                    ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

/// A relay as stored, with the version [`replace`] checks: a hash of the
/// stored bytes.
struct Versioned(Relay, u64);

impl Deserialize for Versioned {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let Json(relay) = Json::<Relay>::deserialize(bytes)?;
        Ok(Versioned(relay, xxhash_rust::xxh3::xxh3_64(bytes)))
    }
}

/// A relay and its version, for a change made with [`replace`].
pub async fn get_versioned(data: &Store, id: u32) -> trc::Result<Option<(Relay, u64)>> {
    Ok(data
        .get_value::<Versioned>(relay_key(id))
        .await
        .caused_by(trc::location!())?
        .map(|Versioned(relay, version)| (relay, version)))
}

/// Replaces a stored relay (same id) if it is still at `version`. False if
/// something else changed it first, such as a node recording the join
/// while an administrator edits the relay: read it again and retry.
pub async fn replace(data: &Store, relay: &Relay, version: u64) -> trc::Result<bool> {
    let mut batch = BatchBuilder::new();
    batch.assert_value(
        class(KIND_RELAY, Some(relay.id)),
        AssertValue::Hash(version),
    );
    batch.set(class(KIND_RELAY, Some(relay.id)), Json(relay).serialize()?);
    match data.write(batch.build_all()).await {
        Ok(_) => Ok(true),
        Err(err)
            if matches!(
                err.as_ref(),
                trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
            ) =>
        {
            Ok(false)
        }
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

pub async fn delete(data: &Store, id: u32) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.clear(class(KIND_RELAY, Some(id)));
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use inbuxa_relay_proto::{time, token::JoinToken};

    fn relay() -> Relay {
        Relay {
            id: 3,
            name: "Edge one".into(),
            description: String::new(),
            address: "relay1.example.com".into(),
            link_port: 443,
            enabled: true,
            send_through: false,
            inbound_only: false,
            settings: RelaySettings {
                hostname: "mx1.example.com".into(),
                ..Default::default()
            },
            smtp_certificate: None,
            smtp_private_key: None,
            recipient_key: [0; 32],
            join: Join::default(),
            created_by: String::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn validates() {
        assert_eq!(relay().validate(), Ok(()));
        let bad = |change: fn(&mut Relay)| {
            let mut r = relay();
            change(&mut r);
            r.validate().unwrap_err().property
        };
        assert_eq!(bad(|r| r.name = " ".into()), "name");
        assert_eq!(
            bad(|r| r.address = "https://relay1.example.com".into()),
            "address"
        );
        assert_eq!(
            bad(|r| r.address = "relay1.example.com:443".into()),
            "address"
        );
        assert_eq!(bad(|r| r.link_port = 0), "linkPort");
        assert_eq!(
            bad(|r| {
                r.send_through = true;
                r.inbound_only = true;
            }),
            "inboundOnly"
        );
        assert_eq!(bad(|r| r.settings.hostname = "mx1".into()), "settings");
        assert_eq!(
            bad(|r| r.settings.domains = vec!["not a domain".into()]),
            "settings"
        );
        assert_eq!(bad(|r| r.settings.held_max_age = 91), "settings");
        assert_eq!(bad(|r| r.settings.sealing_key = Some([1; 32])), "settings");
        assert_eq!(
            bad(|r| r.smtp_certificate = Some("x".into())),
            "smtpPrivateKey"
        );

        let mut ip = relay();
        ip.address = "2001:db8::25".into();
        assert_eq!(ip.validate(), Ok(()));
    }

    #[test]
    fn joins() {
        let now = time::now();
        let keys = new_downstream_keys(now).unwrap();
        let mut r = relay();
        let token = r.start_join(&keys, now);
        let decoded = JoinToken::decode(&token, now).unwrap();
        assert_eq!(decoded.relay_id, Id::from(3u32).to_string());
        assert_eq!(decoded.ca_spki, keys.link_ca_pin);
        assert_eq!(Some(decoded.secret), r.join.secret);
        assert_eq!(r.join.state(now), JoinState::Waiting);
        assert_eq!(r.join.state(decoded.expires_at), JoinState::Expired);
        assert_ne!(r.recipient_key, [0; 32]);

        // A new join forgets the pinned key and the old recipient key
        r.join.relay_pin = Some([7; 32]);
        assert_eq!(r.join.state(decoded.expires_at), JoinState::Joined);
        let old_key = r.recipient_key;
        let second = r.start_join(&keys, now);
        assert_ne!(second, token);
        assert_eq!(r.join.relay_pin, None);
        assert_ne!(r.recipient_key, old_key);

        // The pin is of the key inside the CA certificate the relay sees
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD
            .decode(
                keys.link_ca_cert_pem
                    .lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
        let ca_key = rcgen::KeyPair::from_pem(&keys.link_ca_key_pem).unwrap();
        let spki = rcgen::PublicKeyData::subject_public_key_info(&ca_key);
        assert!(der.windows(spki.len()).any(|w| w == spki));
        assert_eq!(spki_pin(&spki), keys.link_ca_pin);

        // The sealing key opens what's sealed to its public half
        let sealed = seal::seal(&keys.sealing_public, b"aad", b"hello").unwrap();
        assert_eq!(
            seal::open(&keys.sealing_secret, b"aad", &sealed).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn stored_form_round_trips() {
        let now = time::now();
        let keys = new_downstream_keys(now).unwrap();
        let mut r = relay();
        r.start_join(&keys, now);
        let bytes = Json(&r).serialize().unwrap();
        let Json(back) = Json::<Relay>::deserialize(&bytes).unwrap();
        assert!(back == r);
        let bytes = Json(&keys).serialize().unwrap();
        let Json(back) = Json::<DownstreamKeys>::deserialize(&bytes).unwrap();
        assert!(back == keys);
        // Neither shows its secrets when printed
        assert!(!format!("{keys:?}").contains("PRIVATE"));
        assert!(!format!("{r:?}").contains("recipient"));
    }
}
