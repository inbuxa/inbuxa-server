/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Where a domain's mail goes, and what TLS it asks for: MX, addresses,
//! TLSA and MTA-STS, through the server's own lookups (RL-30).

use inbuxa_outbound_tls::{
    Policy,
    dnssec::{self, DnssecStatus, Resolvers, TlsaResult},
    mail_auth::{
        self,
        common::parse::TxtRecordParser,
        hickory_resolver::{
            TokioResolver,
            config::{CLOUDFLARE, ResolverConfig, ResolverOpts},
            net::runtime::TokioRuntimeProvider,
            proto::op::ResponseCode,
        },
        mta_sts::MtaSts,
    },
};
use std::{
    collections::HashMap,
    future::Future,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

/// A domain's MX hosts, best first, and whether the answer was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mx {
    Hosts {
        hosts: Vec<String>,
        secure: bool,
    },
    /// RFC 7505: the domain takes no mail.
    Null,
}

/// A lookup failure: for good (the domain doesn't exist) or for now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    Permanent(String),
    Temporary(String),
}

pub trait Resolve: Send + Sync + 'static {
    fn mx(&self, domain: &str) -> impl Future<Output = Result<Mx, LookupError>> + Send;

    /// The host's addresses, and whether they were signed. `secure` asks
    /// for the DNSSEC status; without it, it may be reported as false.
    fn addresses(
        &self,
        host: &str,
        secure: bool,
    ) -> impl Future<Output = Result<(Vec<IpAddr>, bool), LookupError>> + Send;

    fn tlsa(&self, host: &str) -> impl Future<Output = Result<TlsaResult, LookupError>> + Send;

    /// The domain's MTA-STS policy, if it publishes one.
    fn mta_sts(&self, domain: &str) -> impl Future<Output = Option<Arc<Policy>>> + Send;

    /// Port 25, except in tests.
    fn port(&self) -> u16 {
        25
    }
}

const MTA_STS_TIMEOUT: Duration = Duration::from_secs(30);
const MTA_STS_MAX: usize = 64 * 1024;

/// The real thing: the system's resolvers, one validating.
pub struct Dns {
    dnssec: TokioResolver,
    plain: TokioResolver,
    /// The validating resolver works; without it there is no DANE.
    validates: bool,
    sts: Mutex<HashMap<String, (Arc<Policy>, u64)>>,
}

impl Dns {
    pub async fn new() -> Dns {
        let (config, opts) = mail_auth::hickory_resolver::system_conf::read_system_conf()
            .unwrap_or_else(|e| {
                eprintln!(
                    "inbuxa-relay: no usable resolv.conf ({e}); using Cloudflare's resolvers"
                );
                (
                    ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                    ResolverOpts::default(),
                )
            });
        let mut validating = opts.clone();
        validating.validate = true;
        let build = |config: ResolverConfig, opts: ResolverOpts| {
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                .with_options(opts)
                .build()
                .expect("DNS resolver")
        };
        let dnssec = build(config.clone(), validating);
        let plain = build(config, opts);
        let validates = dnssec::validates(&dnssec).await;
        if !validates {
            eprintln!(
                "inbuxa-relay: the resolver doesn't validate DNSSEC, so DANE can't be checked"
            );
        }
        Dns {
            dnssec,
            plain,
            validates,
            sts: Mutex::new(HashMap::new()),
        }
    }

    fn resolvers(&self) -> Resolvers<'_> {
        Resolvers {
            dnssec: &self.dnssec,
            plain: &self.plain,
        }
    }

    async fn fetch_policy(&self, domain: &str, id: &str) -> Result<Policy, String> {
        let url_host = format!("mta-sts.{domain}");
        let body = super::https::get(&url_host, "/.well-known/mta-sts.txt", MTA_STS_MAX)
            .await
            .map_err(|e| format!("fetching the MTA-STS policy failed: {e}"))?;
        let text = std::str::from_utf8(&body).map_err(|e| e.to_string())?;
        Policy::parse(text, id.to_string())
    }
}

fn fqdn(name: &str) -> String {
    let name = name.trim_end_matches('.');
    format!("{name}.")
}

fn lookup_error(err: mail_auth::Error) -> LookupError {
    match err {
        mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(ResponseCode::NXDomain)) => {
            LookupError::Permanent("the domain doesn't exist".into())
        }
        err => LookupError::Temporary(err.to_string()),
    }
}

impl Resolve for Dns {
    async fn mx(&self, domain: &str) -> Result<Mx, LookupError> {
        let name = fqdn(domain);
        let records = if self.validates {
            dnssec::mx(&self.resolvers(), &name).await.map(|(r, _)| r)
        } else {
            // Without validation every answer is insecure anyway.
            dnssec::mx(
                &Resolvers {
                    dnssec: &self.plain,
                    plain: &self.plain,
                },
                &name,
            )
            .await
            .map(|(r, _)| r)
        }
        .map_err(lookup_error)?;
        let secure = self.validates && records.dnssec_status == DnssecStatus::Secure;
        if records.rrset.is_empty() {
            // RFC 5321 §5.1: no MX means the domain itself.
            return Ok(Mx::Hosts {
                hosts: vec![domain.trim_end_matches('.').to_lowercase()],
                secure,
            });
        }
        let mut hosts = Vec::new();
        for mx in records.rrset.iter() {
            for host in mx.exchanges.iter() {
                if mx.preference == 0 && host.as_ref() == "." {
                    return Ok(Mx::Null);
                }
                let host = host.trim_end_matches('.').to_string();
                if !host.is_empty() && !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        Ok(Mx::Hosts { hosts, secure })
    }

    async fn addresses(
        &self,
        host: &str,
        secure: bool,
    ) -> Result<(Vec<IpAddr>, bool), LookupError> {
        let name = fqdn(host);
        let resolvers = if secure && self.validates {
            self.resolvers()
        } else {
            Resolvers {
                dnssec: &self.plain,
                plain: &self.plain,
            }
        };
        let v4 = dnssec::ipv4(&resolvers, &name).await;
        let v6 = dnssec::ipv6(&resolvers, &name).await;
        let mut ips = Vec::new();
        let mut all_secure = true;
        let mut last_err = None;
        match v4 {
            Ok((set, _)) => {
                all_secure &= set.rrset.is_empty() || set.dnssec_status == DnssecStatus::Secure;
                ips.extend(set.rrset.iter().copied().map(IpAddr::V4));
            }
            Err(e) => last_err = Some(e),
        }
        match v6 {
            Ok((set, _)) => {
                all_secure &= set.rrset.is_empty() || set.dnssec_status == DnssecStatus::Secure;
                ips.extend(set.rrset.iter().copied().map(IpAddr::V6));
            }
            Err(e) => last_err = Some(e),
        }
        if ips.is_empty() {
            return Err(match last_err {
                Some(e) => lookup_error(e),
                None => LookupError::Temporary(format!("{host} has no addresses")),
            });
        }
        Ok((ips, secure && self.validates && all_secure))
    }

    async fn tlsa(&self, host: &str) -> Result<TlsaResult, LookupError> {
        if !self.validates {
            return Ok(TlsaResult::Missing);
        }
        match dnssec::tlsa(&self.resolvers(), &format!("_25._tcp.{}", fqdn(host))).await {
            Ok((result, _)) => Ok(result),
            Err(mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(_))) => {
                Ok(TlsaResult::Missing)
            }
            Err(e) => Err(LookupError::Temporary(e.to_string())),
        }
    }

    async fn mta_sts(&self, domain: &str) -> Option<Arc<Policy>> {
        let now = inbuxa_relay_proto::time::now();
        let cached = self
            .sts
            .lock()
            .expect("sts")
            .get(domain)
            .filter(|(_, until)| *until > now)
            .map(|(p, _)| p.clone());
        let record = match self
            .plain
            .txt_lookup(fqdn(&format!("_mta-sts.{domain}")))
            .await
        {
            Ok(lookup) => lookup.answers().iter().find_map(|r| match &r.data {
                mail_auth::hickory_resolver::proto::rr::RData::TXT(txt) => {
                    let bytes: Vec<u8> = txt
                        .txt_data
                        .iter()
                        .flat_map(|p| p.iter().copied())
                        .collect();
                    MtaSts::parse(&bytes).ok()
                }
                _ => None,
            }),
            // A failed lookup keeps a cached policy in force.
            Err(_) => return cached,
        };
        let Some(record) = record else {
            return cached;
        };
        if let Some(policy) = &cached
            && policy.id == record.id
        {
            return cached;
        }
        // A new id whose policy can't be fetched keeps the cached one in
        // force until it expires (RFC 8461 §5.1).
        match tokio::time::timeout(MTA_STS_TIMEOUT, self.fetch_policy(domain, &record.id)).await {
            Ok(Ok(policy)) => {
                let max_age = if (3600..31_557_600).contains(&policy.max_age) {
                    policy.max_age
                } else {
                    86_400
                };
                let policy = Arc::new(policy);
                self.sts
                    .lock()
                    .expect("sts")
                    .insert(domain.to_string(), (policy.clone(), now + max_age));
                Some(policy)
            }
            _ => cached,
        }
    }
}
