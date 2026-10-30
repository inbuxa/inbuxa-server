/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! What the link service needs that isn't the link itself (relay spec,
//! "The link service"): each node's link certificate, recording a join,
//! the settings and recipient set a relay is sent, and each node's view of
//! each relay's link, under `E` `s` + relay id + node id.

use super::{
    DownstreamKeys, FEATURE, Json, KIND_INGESTED, KIND_STATUS, Relay, get_versioned, replace,
};
use inbuxa_relay_proto::{
    pin::{Pin, pins_match},
    recipient::{self, RecipientDomain, RecipientHash},
    types::{RelaySettings, RelayStatus, SmtpCertificate},
};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::collections::{BTreeMap, BTreeSet};
use store::{
    Deserialize, IterateParams, SUBSPACE_INBUXA, Serialize, Store, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass},
};
use trc::AddContext;

/// A node's link certificate lasts this long (relay spec, "Identities")...
pub const NODE_CERT_LIFETIME: u64 = 30 * 86_400;
/// ...and is made again after this long.
pub const NODE_CERT_RENEW_AFTER: u64 = 20 * 86_400;

const JOIN_ATTEMPTS: usize = 5;

/// A node's link client certificate and key, as DER, issued by the link CA.
pub struct NodeCertificate {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub ca_der: Vec<u8>,
    pub issued_at: u64,
}

fn cert_error(err: rcgen::Error) -> trc::Error {
    trc::EventType::Server(trc::ServerEvent::ThreadError)
        .into_err()
        .details("Could not issue a relay link certificate")
        .reason(err)
}

/// A link client certificate for `node_id`, valid from an hour ago for
/// [`NODE_CERT_LIFETIME`]. Each node makes its own when it starts and
/// when the last one is old; it is never stored.
pub fn issue_node_certificate(
    keys: &DownstreamKeys,
    node_id: u64,
    now: u64,
) -> trc::Result<NodeCertificate> {
    let ca_key = rcgen::KeyPair::from_pem(&keys.link_ca_key_pem).map_err(cert_error)?;
    let issuer =
        rcgen::Issuer::from_ca_cert_pem(&keys.link_ca_cert_pem, ca_key).map_err(cert_error)?;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
    let mut params = rcgen::CertificateParams::new(vec![format!("node-{node_id}.link.invalid")])
        .map_err(cert_error)?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("inbuxa node {node_id}"));
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let at = |seconds: u64| {
        time::OffsetDateTime::from_unix_timestamp(seconds as i64)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
    };
    params.not_before = at(now.saturating_sub(3600));
    params.not_after = at(now + NODE_CERT_LIFETIME);
    let cert = params.signed_by(&key, &issuer).map_err(cert_error)?;
    let ca_der = rustls_pem_der(&keys.link_ca_cert_pem).ok_or_else(|| {
        trc::StoreEvent::DataCorruption
            .into_err()
            .details("The relay link CA certificate is unreadable")
    })?;
    Ok(NodeCertificate {
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
        ca_der,
        issued_at: now,
    })
}

/// The DER inside one PEM block.
fn rustls_pem_der(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(
            pem.lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>(),
        )
        .ok()
}

/// How a join came out, for the node that tried it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinRecorded {
    /// This node recorded the relay's pin.
    Joined,
    /// Another node already recorded this same pin.
    AlreadyJoined,
    /// The relay was given a new token, or joined with another key, meanwhile.
    Superseded,
}

/// Records that the relay holding `secret`'s token proved it, with its link
/// key's pin: from now on only that key is trusted (RL-7, RL-8). The token's
/// secret is deleted.
pub async fn record_join(
    data: &Store,
    relay_id: u32,
    secret: &[u8; 32],
    pin: Pin,
    now: u64,
) -> trc::Result<JoinRecorded> {
    for _ in 0..JOIN_ATTEMPTS {
        let Some((mut relay, version)) = get_versioned(data, relay_id).await? else {
            return Ok(JoinRecorded::Superseded);
        };
        if let Some(pinned) = relay.join.relay_pin {
            return Ok(if pins_match(&pinned, &pin) {
                JoinRecorded::AlreadyJoined
            } else {
                JoinRecorded::Superseded
            });
        }
        if relay
            .join
            .secret
            .is_none_or(|stored| !pins_match(&stored, secret))
        {
            return Ok(JoinRecorded::Superseded);
        }
        relay.join.secret = None;
        relay.join.relay_pin = Some(pin);
        relay.join.joined_at = Some(now);
        if replace(data, &relay, version).await? {
            return Ok(JoinRecorded::Joined);
        }
    }
    Ok(JoinRecorded::Superseded)
}

/// A domain this server has, as the recipient set needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDomain {
    /// The domain's name and its aliases, lowercased.
    pub names: Vec<String>,
    /// Every address is accepted: a catch-all address, or relaying allowed.
    pub catch_all: bool,
    pub subaddress_separator: Option<String>,
}

/// Every domain the relay serves and every address it accepts, before
/// hashing. The same on every node, so every node sends the same set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecipientPlan {
    pub domains: BTreeMap<String, RecipientDomain>,
    pub addresses: BTreeSet<String>,
}

impl RecipientPlan {
    /// The plan for `relay`: its own domain list if it names one, else every
    /// local domain. `addresses` are this server's, lowercased; those at a
    /// domain the relay doesn't serve are left out.
    pub fn new(relay: &Relay, local: &[LocalDomain], addresses: &[String]) -> Self {
        let named: BTreeSet<String> = relay
            .settings
            .domains
            .iter()
            .map(|domain| domain.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        let mut domains = BTreeMap::new();
        for domain in local {
            for name in &domain.names {
                if named.is_empty() || named.contains(name) {
                    domains.insert(
                        name.clone(),
                        RecipientDomain {
                            domain: name.clone(),
                            catch_all: domain.catch_all,
                            subaddress_separator: domain.subaddress_separator.clone(),
                        },
                    );
                }
            }
        }
        let addresses = addresses
            .iter()
            .filter_map(|address| recipient::normalize(address, None))
            .filter(|address| {
                address
                    .rsplit_once('@')
                    .is_some_and(|(_, domain)| domains.contains_key(domain))
            })
            .collect();
        RecipientPlan { domains, addresses }
    }

    /// The hashes the relay holds, sorted, as `Recipient/replace` takes them.
    pub fn hashes(&self, key: &[u8; 32]) -> Vec<RecipientHash> {
        let mut hashes: Vec<RecipientHash> = self
            .addresses
            .iter()
            .map(|address| recipient::hash(key, address))
            .collect();
        hashes.sort_unstable();
        hashes.dedup();
        hashes
    }
}

/// What the relay is sent with `Relay/set`: its settings as an
/// administrator made them, with the served domains, the keys and the
/// STARTTLS certificate added.
pub fn pushed_settings(
    relay: &Relay,
    keys: &DownstreamKeys,
    plan: &RecipientPlan,
) -> RelaySettings {
    let mut settings = relay.settings.clone();
    settings.domains = plan.domains.keys().cloned().collect();
    settings.sealing_key = Some(keys.sealing_public);
    settings.recipient_key = Some(relay.recipient_key);
    settings.smtp_certificate = match (&relay.smtp_certificate, &relay.smtp_private_key) {
        (Some(chain_pem), Some(key_pem)) => Some(SmtpCertificate {
            chain_pem: chain_pem.clone(),
            key_pem: key_pem.clone(),
        }),
        _ => None,
    };
    settings
}

/// A node's link to a relay, as that node sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub enum LinkState {
    #[default]
    Connecting,
    /// Joining with the token.
    Joining,
    Linked,
    Down,
    /// The join can't go on: a wrong proof, or the token ran out.
    JoinFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NodeLink {
    pub node_id: u64,
    pub state: LinkState,
    /// When `state` began.
    pub since: u64,
    /// The last time the relay answered.
    pub last_seen: Option<u64>,
    pub last_error: Option<String>,
    /// What the relay last said of itself.
    pub relay: Option<RelayStatus>,
    /// How many recipients this node last sent.
    pub recipients: Option<u64>,
    pub updated_at: u64,
}

fn status_class(relay_id: u32, node_id: u64) -> ValueClass {
    let mut key = Vec::with_capacity(14);
    key.push(FEATURE);
    key.push(KIND_STATUS);
    key.extend_from_slice(&relay_id.to_be_bytes());
    key.extend_from_slice(&node_id.to_be_bytes());
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

pub async fn set_status(data: &Store, relay_id: u32, link: &NodeLink) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(
        status_class(relay_id, link.node_id),
        Json(link).serialize()?,
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

/// Every node's link to `relay_id`, by node.
pub async fn statuses(data: &Store, relay_id: u32) -> trc::Result<Vec<NodeLink>> {
    let mut links = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey::from(status_class(relay_id, 0)),
            ValueKey::from(status_class(relay_id, u64::MAX)),
        ),
        |_, value| {
            if let Ok(Json(link)) = Json::<NodeLink>::deserialize(value) {
                links.push(link);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    links.sort_by_key(|link| link.node_id);
    Ok(links)
}

/// Forgets every node's link to a relay that is gone.
pub(super) fn clear_statuses(batch: &mut BatchBuilder, relay_id: u32, nodes: &[NodeLink]) {
    for link in nodes {
        batch.clear(status_class(relay_id, link.node_id));
    }
}

// ---- Messages taken ---------------------------------------------------------

/// The longest `Inbound` id kept: the relay's are 25 characters.
pub const INBOUND_ID_MAX: usize = 64;

/// Whether `id` can be an `Inbound` id: never anything but letters and
/// digits.
pub fn is_inbound_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= INBOUND_ID_MAX && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// A relay's message, taken at `at`.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
struct Taken {
    id: String,
    at: u64,
}

fn ingested_class(relay_id: u32, inbound_id: &[u8]) -> ValueClass {
    let mut key = Vec::with_capacity(6 + inbound_id.len());
    key.push(FEATURE);
    key.push(KIND_INGESTED);
    key.extend_from_slice(&relay_id.to_be_bytes());
    key.extend_from_slice(inbound_id);
    ValueClass::Any(AnyClass {
        subspace: SUBSPACE_INBUXA,
        key,
    })
}

/// RL-16: whether a relay's message was taken already.
pub async fn was_ingested(data: &Store, relay_id: u32, inbound_id: &str) -> trc::Result<bool> {
    data.get_value::<Json<Taken>>(ValueKey::from(ingested_class(
        relay_id,
        inbound_id.as_bytes(),
    )))
    .await
    .caused_by(trc::location!())
    .map(|value| value.is_some())
}

/// RL-16: records a relay's message as taken, before the relay is told so.
pub async fn record_ingested(
    data: &Store,
    relay_id: u32,
    inbound_id: &str,
    now: u64,
) -> trc::Result<()> {
    let taken = Taken {
        id: inbound_id.to_string(),
        at: now,
    };
    let mut batch = BatchBuilder::new();
    batch.set(
        ingested_class(relay_id, inbound_id.as_bytes()),
        Json(&taken).serialize()?,
    );
    data.write(batch.build_all())
        .await
        .caused_by(trc::location!())?;
    Ok(())
}

/// Forgets the messages from a relay taken before `before`: RL-16 keeps
/// them for `heldMaxAge` and a day. How many went.
pub async fn forget_ingested(data: &Store, relay_id: u32, before: u64) -> trc::Result<usize> {
    let mut old = Vec::new();
    data.iterate(
        IterateParams::new(
            ValueKey::from(ingested_class(relay_id, &[])),
            ValueKey::from(ingested_class(relay_id, &[u8::MAX; INBOUND_ID_MAX + 1])),
        ),
        |_, value| {
            if let Ok(Json(taken)) = Json::<Taken>::deserialize(value)
                && taken.at < before
            {
                old.push(taken.id);
            }
            Ok(true)
        },
    )
    .await
    .caused_by(trc::location!())?;
    for chunk in old.chunks(500) {
        let mut batch = BatchBuilder::new();
        for id in chunk {
            batch.clear(ingested_class(relay_id, id.as_bytes()));
        }
        data.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }
    Ok(old.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{Join, new_downstream_keys};
    use inbuxa_relay_proto::time;

    fn relay(domains: &[&str]) -> Relay {
        Relay {
            id: 1,
            name: "Edge".into(),
            description: String::new(),
            address: "relay.example.net".into(),
            link_port: 443,
            enabled: true,
            send_through: false,
            inbound_only: false,
            settings: RelaySettings {
                hostname: "mx1.example.com".into(),
                domains: domains.iter().map(|d| d.to_string()).collect(),
                ..Default::default()
            },
            smtp_certificate: None,
            smtp_private_key: None,
            recipient_key: [9; 32],
            join: Join::default(),
            created_by: String::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    fn local() -> Vec<LocalDomain> {
        vec![
            LocalDomain {
                names: vec!["example.com".into(), "example.net".into()],
                catch_all: false,
                subaddress_separator: Some("+".into()),
            },
            LocalDomain {
                names: vec!["other.org".into()],
                catch_all: true,
                subaddress_separator: None,
            },
        ]
    }

    #[test]
    fn plans_recipients() {
        let addresses = vec![
            "Jane@Example.com".to_string(),
            "jane@example.net".into(),
            "list@other.org".into(),
            "stray@elsewhere.com".into(),
        ];
        let all = RecipientPlan::new(&relay(&[]), &local(), &addresses);
        assert_eq!(
            all.domains.keys().collect::<Vec<_>>(),
            ["example.com", "example.net", "other.org"]
        );
        assert!(all.domains["other.org"].catch_all);
        assert_eq!(all.addresses.len(), 3);
        assert!(all.addresses.contains("jane@example.com"));

        // A relay naming its domains serves only those
        let one = RecipientPlan::new(&relay(&["Example.COM."]), &local(), &addresses);
        assert_eq!(one.domains.keys().collect::<Vec<_>>(), ["example.com"]);
        assert_eq!(
            one.addresses.iter().collect::<Vec<_>>(),
            ["jane@example.com"]
        );

        // The hashes are what the relay looks up
        let hashes = one.hashes(&[9; 32]);
        assert_eq!(hashes, vec![recipient::hash(&[9; 32], "jane@example.com")]);
        let keys = new_downstream_keys(time::now()).unwrap();
        let settings = pushed_settings(&relay(&["example.com"]), &keys, &one);
        assert_eq!(settings.domains, ["example.com"]);
        assert_eq!(settings.sealing_key, Some(keys.sealing_public));
        assert_eq!(settings.recipient_key, Some([9; 32]));
        assert!(settings.problems().is_empty(), "{:?}", settings.problems());
    }

    #[test]
    fn issues_node_certificates() {
        let now = time::now();
        let keys = new_downstream_keys(now).unwrap();
        let cert = issue_node_certificate(&keys, 7, now).unwrap();
        // Chained to the CA the relay pins
        let (_, parsed) = x509_parser::parse_x509_certificate(&cert.cert_der).unwrap();
        let (_, ca) = x509_parser::parse_x509_certificate(&cert.ca_der).unwrap();
        assert_eq!(parsed.issuer(), ca.subject());
        assert!(parsed.verify_signature(Some(ca.public_key())).is_ok());
        assert_eq!(
            inbuxa_relay_proto::pin::spki_pin(ca.tbs_certificate.subject_pki.raw),
            keys.link_ca_pin
        );
        let validity = parsed.validity();
        assert_eq!(
            validity.not_after.timestamp() as u64,
            now + NODE_CERT_LIFETIME
        );
    }
}
