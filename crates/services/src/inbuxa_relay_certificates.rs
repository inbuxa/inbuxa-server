/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Each relay's SMTP certificate (relay spec, RL-27). A joined relay whose
//! certificate is missing, for another name, or runs out within 30 days
//! gets one ordered by DNS-01 for its public name, when a domain whose DNS
//! and certificates this server manages covers that name. One node orders
//! it; the relay gets it with its settings over every link. Without such a
//! domain, nothing is ordered, and an administrator uploads one.
//!
//! A relay set to use one of this server's own certificates (RL-36) is
//! never ordered one: it gets a copy of that certificate, and of each
//! renewal, the newest certificate for the same names.

use common::{
    BuildServer, Inner, Server,
    network::acme::relay::{RelayCertificateNeed, RelayServerCertificate, relay_certificate_need},
};
use inbuxa_features::relay::{self as relays, Relay, certificate};
use std::sync::Arc;
use store::write::now;

/// Orders the certificates the relays need, each in its own task.
pub(crate) async fn order_relay_certificates(inner: &Arc<Inner>, all: &[Relay]) {
    let server = inner.build_server();
    let data = server.store();
    let now = now();
    for relay in all
        .iter()
        .filter(|r| r.enabled && r.join.relay_pin.is_some())
    {
        let hostname = relay.settings.hostname.trim().to_string();
        if hostname.is_empty() {
            continue;
        }
        if let Some(id) = &relay.certificate_id {
            follow_server_certificate(&server, relay, id, &hostname, now).await;
            continue;
        }
        let Some(need) = relay_certificate_need(relay.smtp_certificate.as_deref(), &hostname, now)
        else {
            continue;
        };
        let domain = match server.relay_acme_domain(&hostname).await {
            Ok(Some(domain)) => domain,
            // Nothing manages the name: an administrator uploads one
            Ok(None) => continue,
            Err(err) => {
                trc::event!(
                    Acme(trc::AcmeEvent::Error),
                    Hostname = hostname,
                    Reason = err.to_string(),
                    Details = "Failed to look up the domain for a relay's certificate",
                );
                continue;
            }
        };
        match certificate::claim_order(data, relay.id, now).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                trc::error!(err.details("Failed to claim a relay certificate order"));
                continue;
            }
        }
        // Renewing keeps the relay's key; a new name gets a new one
        let reuse_key = (need == RelayCertificateNeed::Expiring)
            .then(|| relay.smtp_private_key.clone())
            .flatten();
        let inner = inner.clone();
        let (relay_id, relay_name) = (relay.id, relay.name.clone());
        tokio::spawn(async move {
            let server = inner.build_server();
            let data = server.store();
            trc::event!(
                Acme(trc::AcmeEvent::OrderStart),
                Hostname = hostname.clone(),
                Domain = domain.name.clone(),
                Details = format!("{} (relay {relay_name})", need.as_str()),
            );
            let result = match server
                .acme_relay_certificate(&domain, &hostname, reuse_key)
                .await
            {
                Ok(pem) => install(data, relay_id, &hostname, pem.certificate, pem.private_key)
                    .await
                    .map_err(|err| err.to_string()),
                Err(err) => Err(err.to_string()),
            };
            match &result {
                Ok(()) => {
                    trc::event!(
                        Acme(trc::AcmeEvent::OrderCompleted),
                        Hostname = hostname.clone(),
                        Domain = domain.name.clone(),
                        Details = format!("Installed on relay {relay_name}"),
                    );
                    relays::changed();
                }
                Err(error) => trc::event!(
                    Acme(trc::AcmeEvent::OrderInvalid),
                    Hostname = hostname.clone(),
                    Domain = domain.name.clone(),
                    Reason = error.clone(),
                    Details = format!("No certificate for relay {relay_name}"),
                ),
            }
            if let Err(err) = certificate::finish_order(data, relay_id, now, result).await {
                trc::error!(err.details("Failed to record a relay certificate order"));
            }
        });
    }
}

/// Puts the certificate on the relay, unless its public name changed
/// while it was ordered.
async fn install(
    data: &store::Store,
    relay_id: u32,
    hostname: &str,
    chain_pem: String,
    key_pem: String,
) -> trc::Result<()> {
    for _ in 0..5 {
        let Some((mut relay, version)) = relays::get_versioned(data, relay_id).await? else {
            return Err(trc::StoreEvent::NotFound
                .into_err()
                .details("The relay was removed"));
        };
        if !relay
            .settings
            .hostname
            .trim()
            .eq_ignore_ascii_case(hostname)
        {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("The relay's public name changed while its certificate was ordered"));
        }
        relay.smtp_certificate = Some(chain_pem.clone());
        relay.smtp_private_key = Some(key_pem.clone());
        relay.updated_at = now();
        if relays::replace(data, &relay, version).await? {
            return Ok(());
        }
    }
    Err(trc::StoreEvent::UnexpectedError
        .into_err()
        .details("The relay kept changing"))
}

/// Keeps a relay set to use one of this server's certificates (RL-36) on
/// the newest one for its names, and records why when there is none, as
/// its `certificateError`. A relay already on it writes nothing.
async fn follow_server_certificate(
    server: &Server,
    relay: &Relay,
    id: &str,
    hostname: &str,
    now: u64,
) {
    let data = server.store();
    let found = match server
        .relay_server_certificate(id, relay.smtp_certificate.as_deref(), hostname)
        .await
    {
        Ok(found) => found,
        Err(err) => {
            trc::error!(err.details("Failed to read a relay's server certificate"));
            return;
        }
    };
    let result = match found {
        Ok(cert)
            if relay.smtp_certificate.as_deref() == Some(cert.chain.as_str())
                && relay.smtp_private_key.as_deref() == Some(cert.key.as_str())
                && relay.certificate_id.as_deref() == Some(cert.id.to_string().as_str()) =>
        {
            Ok(())
        }
        Ok(cert) => match install_server_certificate(data, relay.id, id, hostname, cert).await {
            Ok(true) => {
                relays::changed();
                Ok(())
            }
            // The choice changed meanwhile: the next scan follows the new one
            Ok(false) => return,
            Err(err) => {
                trc::error!(err.details("Failed to copy a server certificate to a relay"));
                return;
            }
        },
        Err(reason) => Err(reason),
    };
    let last = match certificate::last_order(data, relay.id).await {
        Ok(last) => last,
        Err(err) => {
            trc::error!(err.details("Failed to read a relay's certificate record"));
            return;
        }
    };
    if last.as_ref().and_then(|order| order.error()) != result.as_ref().err().map(String::as_str)
        && let Err(err) = certificate::finish_order(data, relay.id, now, result).await
    {
        trc::error!(err.details("Failed to record a relay's server certificate"));
    }
}

/// Puts a copy of `cert` on the relay, while it still uses certificate
/// `chosen` under the same public name. False if that changed.
async fn install_server_certificate(
    data: &store::Store,
    relay_id: u32,
    chosen: &str,
    hostname: &str,
    cert: RelayServerCertificate,
) -> trc::Result<bool> {
    for _ in 0..5 {
        let Some((mut relay, version)) = relays::get_versioned(data, relay_id).await? else {
            return Ok(false);
        };
        if relay.certificate_id.as_deref() != Some(chosen)
            || !relay
                .settings
                .hostname
                .trim()
                .eq_ignore_ascii_case(hostname)
        {
            return Ok(false);
        }
        relay.certificate_id = Some(cert.id.to_string());
        relay.smtp_certificate = Some(cert.chain.clone());
        relay.smtp_private_key = Some(cert.key.clone());
        relay.updated_at = now();
        if relays::replace(data, &relay, version).await? {
            return Ok(true);
        }
    }
    Err(trc::StoreEvent::UnexpectedError
        .into_err()
        .details("The relay kept changing"))
}
