/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! A relay's SMTP certificate (relay spec, RL-27). This server orders it
//! for the relay's public name by DNS-01, through the DNS server of the
//! domain that covers the name, with that domain's ACME provider: the relay
//! never runs ACME and opens no port 80. Without such a domain, an
//! administrator uploads one.

use crate::{
    Server,
    network::acme::{
        AcmeDnsParameters, AcmeError, AcmeResult, ChallengeType, ParsedCert, PemCert,
        directory::AcmeRequestBuilder,
    },
};
use registry::schema::{
    prelude::ObjectType,
    structs::{AcmeProvider, CertificateManagement, DnsManagement, Domain},
};
use store::registry::RegistryQuery;
use types::id::Id;

/// A relay's certificate is renewed this long before it runs out.
pub const RELAY_RENEW_BEFORE: u64 = 30 * 86_400;

/// Why a relay needs a certificate ordered, if it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCertificateNeed {
    Missing,
    /// It doesn't name the relay's public name, which changed, say.
    OtherName,
    /// It runs out within [`RELAY_RENEW_BEFORE`], or has.
    Expiring,
}

impl RelayCertificateNeed {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelayCertificateNeed::Missing => "The relay has no certificate",
            RelayCertificateNeed::OtherName => "The relay's certificate is for another name",
            RelayCertificateNeed::Expiring => "The relay's certificate runs out within 30 days",
        }
    }
}

fn names(san: &str, hostname: &str) -> bool {
    let san = san.trim_end_matches('.');
    san.eq_ignore_ascii_case(hostname)
        || san.strip_prefix("*.").is_some_and(|parent| {
            hostname
                .split_once('.')
                .is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(parent))
        })
}

/// Whether the certificate in `chain_pem` will do for `hostname` at `now`.
/// One that can't be read is as good as none.
pub fn relay_certificate_need(
    chain_pem: Option<&str>,
    hostname: &str,
    now: u64,
) -> Option<RelayCertificateNeed> {
    let hostname = hostname.trim().trim_end_matches('.');
    let Some(parsed) = chain_pem.and_then(|pem| ParsedCert::parse(pem).ok()) else {
        return Some(RelayCertificateNeed::Missing);
    };
    if !parsed.sans.iter().any(|san| names(san, hostname)) {
        return Some(RelayCertificateNeed::OtherName);
    }
    let not_after = parsed.valid_not_after.timestamp().max(0) as u64;
    (not_after < now + RELAY_RENEW_BEFORE).then_some(RelayCertificateNeed::Expiring)
}

/// When the certificate in `chain_pem` runs out, if it can be read.
pub fn relay_certificate_not_after(chain_pem: &str) -> Option<i64> {
    ParsedCert::parse(chain_pem)
        .ok()
        .map(|parsed| parsed.valid_not_after.timestamp())
}

impl Server {
    /// The domain whose DNS and certificates this server manages that
    /// covers `hostname`, the closest one if several do.
    pub async fn relay_acme_domain(&self, hostname: &str) -> AcmeResult<Option<Domain>> {
        let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut found: Option<Domain> = None;
        for id in self
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Domain))
            .await?
        {
            let Some(domain) = self.registry().object::<Domain>(id).await? else {
                continue;
            };
            let name = domain.name.to_ascii_lowercase();
            let covers = hostname == name || hostname.ends_with(&format!(".{name}"));
            if covers
                && matches!(domain.dns_management, DnsManagement::Automatic(_))
                && matches!(
                    domain.certificate_management,
                    CertificateManagement::Automatic(_)
                )
                && found
                    .as_ref()
                    .is_none_or(|f| f.name.len() < domain.name.len())
            {
                found = Some(domain);
            }
        }
        Ok(found)
    }

    /// Orders a certificate for a relay's public name, by DNS-01 through
    /// `domain`'s DNS server, whatever challenge its ACME provider uses for
    /// the domain itself. `reuse_key_pem` keeps the relay's key.
    pub async fn acme_relay_certificate(
        &self,
        domain: &Domain,
        hostname: &str,
        reuse_key_pem: Option<String>,
    ) -> AcmeResult<PemCert> {
        let (DnsManagement::Automatic(dns), CertificateManagement::Automatic(cert)) =
            (&domain.dns_management, &domain.certificate_management)
        else {
            return Err(AcmeError::Invalid(format!(
                "{} doesn't have both its DNS and its certificates managed here",
                domain.name
            )));
        };
        let Some(provider) = self
            .registry()
            .object::<AcmeProvider>(cert.acme_provider_id)
            .await?
        else {
            return Err(AcmeError::Invalid(format!(
                "ACME provider with ID {} not found",
                cert.acme_provider_id
            )));
        };
        let updater = self
            .build_dns_updater(dns.dns_server_id)
            .await?
            .map_err(|err| AcmeError::Invalid(format!("Failed to build DNS updater: {err}")))?;
        let mut request = AcmeRequestBuilder::new(provider).await?;
        request.challenge = ChallengeType::Dns01;
        let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        request
            .renew(
                self,
                vec![hostname],
                reuse_key_pem,
                Some(AcmeDnsParameters {
                    updater,
                    origin: dns.origin.clone(),
                }),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn certificate(names: &[&str], days: i64) -> String {
        let mut params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(days);
        params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
    }

    #[test]
    fn when_a_relay_needs_a_certificate() {
        let now = store::write::now();
        let host = "mx1.example.com";
        assert_eq!(
            relay_certificate_need(None, host, now),
            Some(RelayCertificateNeed::Missing)
        );
        assert_eq!(
            relay_certificate_need(Some("not a certificate"), host, now),
            Some(RelayCertificateNeed::Missing)
        );
        let good = certificate(&[host], 90);
        assert_eq!(relay_certificate_need(Some(&good), host, now), None);
        assert_eq!(
            relay_certificate_need(Some(&good), "MX1.example.com.", now),
            None
        );
        assert_eq!(
            relay_certificate_need(Some(&good), "mx2.example.com", now),
            Some(RelayCertificateNeed::OtherName)
        );
        let soon = certificate(&[host], 20);
        assert_eq!(
            relay_certificate_need(Some(&soon), host, now),
            Some(RelayCertificateNeed::Expiring)
        );
        // A wildcard names one level down, no more
        let wild = certificate(&["*.example.com"], 90);
        assert_eq!(relay_certificate_need(Some(&wild), host, now), None);
        assert_eq!(
            relay_certificate_need(Some(&wild), "a.mx1.example.com", now),
            Some(RelayCertificateNeed::OtherName)
        );
        assert!(relay_certificate_not_after(&good).is_some_and(|at| at > now as i64));
    }
}
