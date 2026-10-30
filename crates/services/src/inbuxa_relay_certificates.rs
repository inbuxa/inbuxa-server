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

use common::{
    BuildServer, Inner,
    network::acme::relay::{RelayCertificateNeed, relay_certificate_need},
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
