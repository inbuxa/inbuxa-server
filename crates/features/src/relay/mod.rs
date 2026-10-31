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
//! - `s` + relay id (u32) + node id (u64): that node's link to the relay
//!   ([`link::NodeLink`]), as JSON.
//! - `i` + relay id (u32) + `Inbound` id: a message taken from the relay.
//! - `o` + relay id (u32) + `Outbound` id: a message handed to the relay
//!   ([`outbound::Handed`]), as JSON.
//! - `c` + relay id (u32): the last order for the relay's certificate
//!   ([`certificate::CertificateOrder`]), as JSON.
//! - `d`: what the relays last put in the domains' DNS records, hashed
//!   ([`dns::dns_change`]).
//!
//! Numbers are big-endian. There are few relays, so they're read whole.
//! The secrets in `k` and `r` are wrapped under the key file
//! `INBUXA_RELAY_KEY_FILE` names, when it names one ([`wrap`], RL-35).

pub mod certificate;
pub mod dns;
pub mod link;
pub mod messages;
pub mod outbound;
pub mod wrap;

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
use wrap::Secret;

/// Wakes the link service on this node when a relay is added, changed or
/// removed here. Other nodes see it at their next scan.
pub static CHANGED: std::sync::LazyLock<tokio::sync::Notify> =
    std::sync::LazyLock::new(tokio::sync::Notify::new);

/// Tells this node's link service that the relays changed.
pub fn changed() {
    CHANGED.notify_one();
}

const FEATURE: u8 = b'E';
const KIND_KEYS: u8 = b'k';
const KIND_RELAY: u8 = b'r';
const KIND_STATUS: u8 = b's';
const KIND_INGESTED: u8 = b'i';
const KIND_HANDED: u8 = b'o';
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
    pub link_ca_key_pem: Secret<String>,
    pub link_ca_cert_pem: String,
    /// The pin of the link CA's key, which every relay keeps.
    #[serde(with = "b64")]
    pub link_ca_pin: Pin,
    pub sealing_secret: Secret<[u8; 32]>,
    #[serde(with = "b64")]
    pub sealing_public: [u8; 32],
    pub created_at: u64,
    /// The CA replacing the link CA, while a replacement is under way
    /// (RL-34).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_link_ca: Option<NextLinkCa>,
}

/// A link CA on its way in: pushed to the relays as `nextLinkCaPin` until
/// every joined relay trusts it, then the link CA.
#[derive(Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct NextLinkCa {
    pub key_pem: Secret<String>,
    pub cert_pem: String,
    #[serde(with = "b64")]
    pub pin: Pin,
    pub started_at: u64,
}

/// What an administrator asks of a link CA replacement (RL-34).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkCaChange {
    Start,
    Finish,
    Cancel,
}

impl LinkCaChange {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "start" => Some(LinkCaChange::Start),
            "finish" => Some(LinkCaChange::Finish),
            "cancel" => Some(LinkCaChange::Cancel),
            _ => None,
        }
    }
}

impl DownstreamKeys {
    /// Some secret is in the clear while a key file is named (RL-35).
    pub fn needs_wrapping(&self) -> bool {
        self.link_ca_key_pem.needs_wrapping()
            || self.sealing_secret.needs_wrapping()
            || self
                .next_link_ca
                .as_ref()
                .is_some_and(|next| next.key_pem.needs_wrapping())
    }

    /// The keys with the next link CA as the link CA, if there is one.
    pub fn finished(&self) -> Option<DownstreamKeys> {
        let next = self.next_link_ca.as_ref()?;
        Some(DownstreamKeys {
            link_ca_key_pem: next.key_pem.clone(),
            link_ca_cert_pem: next.cert_pem.clone(),
            link_ca_pin: next.pin,
            next_link_ca: None,
            ..self.clone()
        })
    }
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
    /// The link CA the token named. A join started before a replacement
    /// finished can't complete after it (RL-34).
    #[serde(with = "b64::option", skip_serializing_if = "Option::is_none")]
    pub ca_pin: Option<Pin>,
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
    /// Its MX preference, where DNS is published for a domain (RL-25).
    #[serde(default = "default_mx_preference")]
    pub mx_preference: u16,
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
    #[serde(default)]
    pub recipient_key: Secret<[u8; 32]>,
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

fn default_mx_preference() -> u16 {
    10
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
            || settings.next_link_ca_pin.is_some()
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
        self.recipient_key = Secret::new(random_key());
        self.join = Join {
            secret: Some(token.secret),
            expires_at: token.expires_at,
            relay_pin: None,
            joined_at: None,
            ca_pin: Some(keys.link_ca_pin),
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
    let (key_pem, cert_pem, pin) = new_link_ca()?;
    let (sealing_secret, sealing_public) = seal::generate_keypair();
    Ok(DownstreamKeys {
        link_ca_pin: pin,
        link_ca_key_pem: Secret::new(key_pem),
        link_ca_cert_pem: cert_pem,
        sealing_secret: Secret::new(*sealing_secret),
        sealing_public,
        created_at: now,
        next_link_ca: None,
    })
}

/// A new P-256 link CA: its key, its certificate, and its key's pin.
fn new_link_ca() -> trc::Result<(String, String, Pin)> {
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
    Ok((
        key.serialize_pem(),
        cert.pem(),
        spki_pin(&rcgen::PublicKeyData::subject_public_key_info(&key)),
    ))
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

struct VersionedKeys(DownstreamKeys, u64);

impl Deserialize for VersionedKeys {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let Json(keys) = Json::<DownstreamKeys>::deserialize(bytes)?;
        Ok(VersionedKeys(keys, xxhash_rust::xxh3::xxh3_64(bytes)))
    }
}

/// Starts, finishes or cancels a replacement of the link CA (RL-34), and
/// says whether anything changed: starting one already under way, or
/// finishing or cancelling none, changes nothing. Finishing makes the next
/// CA the link CA; each node then takes a certificate from it, and the
/// relays that trust it make it their only one.
pub async fn change_link_ca(data: &Store, change: LinkCaChange, now: u64) -> trc::Result<bool> {
    keys_or_new(data, now).await?;
    loop {
        let Some(VersionedKeys(keys, version)) = data
            .get_value::<VersionedKeys>(ValueKey::from(class(KIND_KEYS, None)))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(false);
        };
        let next = match change {
            LinkCaChange::Start if keys.next_link_ca.is_none() => {
                let (key_pem, cert_pem, pin) = new_link_ca()?;
                DownstreamKeys {
                    next_link_ca: Some(NextLinkCa {
                        key_pem: Secret::new(key_pem),
                        cert_pem,
                        pin,
                        started_at: now,
                    }),
                    ..keys
                }
            }
            LinkCaChange::Finish => match keys.finished() {
                Some(next) => next,
                None => return Ok(false),
            },
            LinkCaChange::Cancel if keys.next_link_ca.is_some() => DownstreamKeys {
                next_link_ca: None,
                ..keys
            },
            _ => return Ok(false),
        };
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(KIND_KEYS, None), AssertValue::Hash(version));
        batch.set(class(KIND_KEYS, None), Json(&next).serialize()?);
        match data.write(batch.build_all()).await {
            Ok(_) => {
                changed();
                return Ok(true);
            }
            Err(err)
                if matches!(
                    err.as_ref(),
                    trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
}

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

/// Wraps every relay secret stored in the clear, once a key file is named
/// (RL-35), and says whether there were any. Each is written again, which
/// wraps it, unless something changed it first.
pub async fn wrap_stored(data: &Store) -> trc::Result<bool> {
    if !wrap::turned_on() {
        return Ok(false);
    }
    let mut wrapped = false;
    while let Some(VersionedKeys(keys, version)) = data
        .get_value::<VersionedKeys>(ValueKey::from(class(KIND_KEYS, None)))
        .await
        .caused_by(trc::location!())?
        .filter(|VersionedKeys(keys, _)| keys.needs_wrapping())
    {
        let mut batch = BatchBuilder::new();
        batch.assert_value(class(KIND_KEYS, None), AssertValue::Hash(version));
        batch.set(class(KIND_KEYS, None), Json(&keys).serialize()?);
        match data.write(batch.build_all()).await {
            Ok(_) => {
                wrapped = true;
                break;
            }
            Err(err)
                if matches!(
                    err.as_ref(),
                    trc::EventType::Store(trc::StoreEvent::AssertValueFailed)
                ) => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
    for relay in all(data).await? {
        while let Some((relay, version)) = get_versioned(data, relay.id)
            .await?
            .filter(|(relay, _)| relay.recipient_key.needs_wrapping())
        {
            if replace(data, &relay, version).await? {
                wrapped = true;
                break;
            }
        }
    }
    Ok(wrapped)
}

/// The downstream keys and every relay as the store holds them: what a copy
/// of the store gives away (RL-T27).
pub async fn stored_bytes(data: &Store) -> trc::Result<Vec<Vec<u8>>> {
    struct Raw(Vec<u8>);
    impl Deserialize for Raw {
        fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
            Ok(Raw(bytes.to_vec()))
        }
    }
    let mut out = Vec::new();
    if let Some(Raw(bytes)) = data
        .get_value::<Raw>(ValueKey::from(class(KIND_KEYS, None)))
        .await
        .caused_by(trc::location!())?
    {
        out.push(bytes);
    }
    for relay in all(data).await? {
        if let Some(Raw(bytes)) = data
            .get_value::<Raw>(relay_key(relay.id))
            .await
            .caused_by(trc::location!())?
        {
            out.push(bytes);
        }
    }
    Ok(out)
}

/// Removes a relay, and every node's record of its link.
pub async fn delete(data: &Store, id: u32) -> trc::Result<()> {
    let nodes = link::statuses(data, id).await?;
    let mut batch = BatchBuilder::new();
    batch.clear(class(KIND_RELAY, Some(id)));
    batch.clear(certificate::certificate_class(id));
    link::clear_statuses(&mut batch, id, &nodes);
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    link::forget_ingested(data, id, u64::MAX).await?;
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
            mx_preference: 10,
            settings: RelaySettings {
                hostname: "mx1.example.com".into(),
                ..Default::default()
            },
            smtp_certificate: None,
            smtp_private_key: None,
            recipient_key: Secret::new([0; 32]),
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
        assert!(r.recipient_key != Secret::new([0; 32]));

        // A new join forgets the pinned key and the old recipient key
        r.join.relay_pin = Some([7; 32]);
        assert_eq!(r.join.state(decoded.expires_at), JoinState::Joined);
        let old_key = r.recipient_key.clone();
        let second = r.start_join(&keys, now);
        assert_ne!(second, token);
        assert_eq!(r.join.relay_pin, None);
        assert!(r.recipient_key != old_key);

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
        let ca_key = rcgen::KeyPair::from_pem(&keys.link_ca_key_pem.open().unwrap()).unwrap();
        let spki = rcgen::PublicKeyData::subject_public_key_info(&ca_key);
        assert!(der.windows(spki.len()).any(|w| w == spki));
        assert_eq!(spki_pin(&spki), keys.link_ca_pin);

        // The sealing key opens what's sealed to its public half
        let sealed = seal::seal(&keys.sealing_public, b"aad", b"hello").unwrap();
        assert_eq!(
            seal::open(&keys.sealing_secret.open().unwrap(), b"aad", &sealed).unwrap(),
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
