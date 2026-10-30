/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

//! The DNSSEC lookups DANE needs (RFC 7672 §2.1): MX, A and AAAA with how
//! secure each answer is, and TLSA records only from a signed zone. Each
//! answer comes with until when it may be cached; the caller caches.

use crate::{Tlsa, TlsaEntry, TlsaMatching};
pub use mail_auth::DnssecStatus;
use mail_auth::{
    MX, RecordSet,
    hickory_resolver::{
        TokioResolver,
        lookup::Lookup,
        net::{DnsError, NetError},
        proto::{
            dnssec::Proof,
            op::ResponseCode,
            rr::{
                Name, RData, Record, RecordType,
                rdata::tlsa::{CertUsage, Matching, Selector},
            },
        },
    },
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

/// A validating resolver, and a plain one for names proved unsigned.
pub struct Resolvers<'a> {
    pub dnssec: &'a TokioResolver,
    pub plain: &'a TokioResolver,
}

pub enum TlsaResult {
    Secure(Arc<Tlsa>),
    Bogus,
    Missing,
}

/// An answer, and until when it may be cached: `None` when it mustn't be.
pub type Cacheable<T> = (T, Option<Instant>);

/// Whether `resolver` validates DNSSEC: the root's DNSKEY comes back
/// proved secure. Through a resolver that strips signatures, DANE can't
/// work, and every lookup would look insecure.
pub async fn validates(resolver: &TokioResolver) -> bool {
    resolver
        .lookup(Name::root(), RecordType::DNSKEY)
        .await
        .is_ok_and(|lookup| lookup.answers().iter().any(|r| r.proof.is_secure()))
}

/// MX records for `name`, a fully qualified name.
pub async fn mx(
    resolvers: &Resolvers<'_>,
    name: &str,
) -> mail_auth::Result<Cacheable<RecordSet<MX>>> {
    let (mx_lookup, forced_insecure) = match validated_lookup(
        resolvers.dnssec,
        resolvers.plain,
        Name::from_str_relaxed::<&str>(name)?,
        RecordType::MX,
    )
    .await
    {
        Ok(validated) => (validated.lookup, validated.insecure),
        Err(err) => {
            if let Some(denial) = NegativeAnswer::from_error(&err)
                && denial.response_code == ResponseCode::NoError
            {
                let records = RecordSet {
                    rrset: Arc::new([]),
                    dnssec_status: denial.dnssec_status,
                };
                return Ok((records, denial.valid_until));
            }
            return Err(err.into());
        }
    };
    let mx_records = mx_lookup.answers();
    let mut dnssec_status: Option<DnssecStatus> = None;
    let mut records: Vec<(u16, Vec<Box<str>>)> = Vec::with_capacity(mx_records.len());
    for mx_record in mx_records {
        if let RData::MX(mx) = &mx_record.data {
            dnssec_status = Some(match dnssec_status {
                Some(status) => least_secure(status, proof_to_dnssec_status(mx_record.proof)),
                None => proof_to_dnssec_status(mx_record.proof),
            });

            let preference = mx.preference;
            let exchange = mx.exchange.to_lowercase().to_ascii().into_boxed_str();

            if let Some(record) = records.iter_mut().find(|r| r.0 == preference) {
                record.1.push(exchange);
            } else {
                records.push((preference, vec![exchange]));
            }
        }
    }

    records.sort_unstable_by_key(|a| a.0);
    let rrset: Arc<[MX]> = records
        .into_iter()
        .map(|(preference, exchanges)| MX {
            preference,
            exchanges: exchanges.into_boxed_slice(),
        })
        .collect::<Arc<[MX]>>();
    let records = RecordSet {
        rrset,
        dnssec_status: if forced_insecure {
            DnssecStatus::Insecure
        } else {
            dnssec_status.unwrap_or(DnssecStatus::Indeterminate)
        },
    };

    Ok((records, Some(mx_lookup.valid_until())))
}

/// TLSA records for `name` (`_25._tcp.<host>.`). Only a secure answer may
/// be cached.
pub async fn tlsa(
    resolvers: &Resolvers<'_>,
    name: &str,
) -> mail_auth::Result<Cacheable<TlsaResult>> {
    // Through `validated_lookup`, like the MX and address lookups: a TLSA
    // name that is a signed CNAME to a name with no TLSA record (seen at
    // `_25._tcp.mail.usefulinsight.com`, behind Hetzner's resolvers) is
    // otherwise called bogus, and the message waits on it until it
    // expires.
    let tlsa_lookup = match validated_lookup(
        resolvers.dnssec,
        resolvers.plain,
        Name::from_str_relaxed(name)?,
        RecordType::TLSA,
    )
    .await
    {
        // A TLSA record proved to sit in an unsigned zone is no DANE
        // policy at all.
        Ok(validated) if validated.insecure => return Ok((TlsaResult::Missing, None)),
        Ok(validated) => validated.lookup,
        Err(err) => {
            if let Some(denial) = NegativeAnswer::from_error(&err) {
                return Ok((
                    if denial.dnssec_status == DnssecStatus::Bogus {
                        TlsaResult::Bogus
                    } else {
                        TlsaResult::Missing
                    },
                    None,
                ));
            }
            return Err(err.into());
        }
    };

    let mut entries = Vec::new();
    let mut has_end_entities = false;
    let mut has_intermediates = false;
    let mut dnssec_status: Option<DnssecStatus> = None;

    for record in tlsa_lookup.answers() {
        if let RData::TLSA(tlsa) = &record.data {
            dnssec_status = Some(match dnssec_status {
                Some(status) => least_secure(status, proof_to_dnssec_status(record.proof)),
                None => proof_to_dnssec_status(record.proof),
            });

            if !record.proof.is_secure() {
                continue;
            }

            let is_end_entity = match tlsa.cert_usage {
                CertUsage::DaneEe => true,
                CertUsage::DaneTa => false,
                _ => continue,
            };
            let matching = match tlsa.matching {
                Matching::Raw => TlsaMatching::Full,
                Matching::Sha256 => TlsaMatching::Sha256,
                Matching::Sha512 => TlsaMatching::Sha512,
                _ => continue,
            };
            let is_spki = match tlsa.selector {
                Selector::Spki => true,
                Selector::Full => false,
                _ => continue,
            };
            if is_end_entity {
                has_end_entities = true;
            } else {
                has_intermediates = true;
            }
            entries.push(TlsaEntry {
                is_end_entity,
                is_spki,
                matching,
                data: tlsa.cert_data.clone(),
            });
        }
    }

    Ok(match dnssec_status {
        Some(DnssecStatus::Bogus) => (TlsaResult::Bogus, None),
        Some(DnssecStatus::Secure) => (
            TlsaResult::Secure(Arc::new(Tlsa {
                entries,
                has_end_entities,
                has_intermediates,
            })),
            Some(tlsa_lookup.valid_until()),
        ),
        _ => (TlsaResult::Missing, None),
    })
}

/// A records for `name`, a fully qualified name.
pub async fn ipv4(
    resolvers: &Resolvers<'_>,
    name: &str,
) -> mail_auth::Result<Cacheable<RecordSet<Ipv4Addr>>> {
    addresses(resolvers, name, RecordType::A, |data| match data {
        RData::A(addr) => Some(addr.0),
        _ => None,
    })
    .await
}

/// AAAA records for `name`, a fully qualified name.
pub async fn ipv6(
    resolvers: &Resolvers<'_>,
    name: &str,
) -> mail_auth::Result<Cacheable<RecordSet<Ipv6Addr>>> {
    addresses(resolvers, name, RecordType::AAAA, |data| match data {
        RData::AAAA(addr) => Some(addr.0),
        _ => None,
    })
    .await
}

async fn addresses<T>(
    resolvers: &Resolvers<'_>,
    key: &str,
    record_type: RecordType,
    address: impl Fn(&RData) -> Option<T>,
) -> mail_auth::Result<Cacheable<RecordSet<T>>> {
    let name = Name::from_str_relaxed::<&str>(key)?;
    let (lookup, forced_insecure) = match validated_lookup(
        resolvers.dnssec,
        resolvers.plain,
        name.clone(),
        record_type,
    )
    .await
    {
        Ok(validated) => (validated.lookup, validated.insecure),
        Err(err) => {
            if let Some(denial) = NegativeAnswer::from_error(&err)
                && denial.response_code == ResponseCode::NoError
            {
                let records = RecordSet {
                    rrset: Arc::new([]),
                    dnssec_status: denial.dnssec_status,
                };
                return Ok((records, denial.valid_until));
            }
            return Err(err.into());
        }
    };

    let answers = lookup.answers();
    let records = RecordSet {
        rrset: answers
            .iter()
            .filter_map(|record| address(&record.data))
            .collect::<Arc<[T]>>(),
        dnssec_status: if forced_insecure {
            DnssecStatus::Insecure
        } else {
            tlsa_base_status(&name, answers, record_type)
        },
    };

    Ok((records, Some(lookup.valid_until())))
}

// inbuxa: hickory 0.26.3 calls some valid answers bogus, and the queue then
// retries those hosts until the message expires. Two cases seen in production
// (the hickory vendored since upstream v0.16.26 gets both right in the
// `--ignored` tests below; this stays as the fallback):
//
// - A zone delegated beneath an unsigned zone, such as `l.google.com` under
//   `google.com`. To prove the delegation insecure, hickory wants an SOA
//   record in the DS reply, and public resolvers often send none.
// - A signed CNAME to a signed name without the record type queried. Hickory
//   checks the denial of existence against the name first asked for, not the
//   target's, and rejects it. TLSA lookups hit this too: a TLSA name that is
//   a CNAME to the zone apex, with no TLSA there, held mail to it for a week.
//
// When hickory says bogus, check the answer again with lookups it gets right.
// A signed CNAME is followed and the lookup repeated at its target. Otherwise
// the name's zone and its parents are looked up, nearest first. If one
// validates as unsigned, nothing below it can be signed, so the plain resolver
// answers and the result is insecure. If one validates as signed first, the
// verdict stands.

const MAX_BOGUS_ALIASES: usize = 8;

struct ValidatedLookup {
    lookup: Lookup,
    insecure: bool,
}

enum BogusRecheck {
    Alias(Name),
    Insecure,
    Bogus,
}

async fn validated_lookup(
    dnssec: &TokioResolver,
    plain: &TokioResolver,
    name: Name,
    record_type: RecordType,
) -> Result<ValidatedLookup, NetError> {
    let mut query = name;
    let mut aliases = 0;

    loop {
        let err = match dnssec.lookup(query.clone(), record_type).await {
            Ok(lookup) => {
                return Ok(ValidatedLookup {
                    lookup,
                    insecure: false,
                });
            }
            Err(err @ NetError::Dns(DnsError::DnssecBogus)) => err,
            Err(err) => return Err(err),
        };

        match recheck_bogus(dnssec, &query).await {
            BogusRecheck::Alias(target) if aliases < MAX_BOGUS_ALIASES => {
                aliases += 1;
                query = target;
            }
            BogusRecheck::Insecure => {
                return plain
                    .lookup(query, record_type)
                    .await
                    .map(|lookup| ValidatedLookup {
                        lookup,
                        insecure: true,
                    });
            }
            BogusRecheck::Alias(_) | BogusRecheck::Bogus => return Err(err),
        }
    }
}

async fn recheck_bogus(dnssec: &TokioResolver, name: &Name) -> BogusRecheck {
    if let Ok(lookup) = dnssec.lookup(name.clone(), RecordType::CNAME).await
        && let Some(target) = secure_alias(name, lookup.answers())
    {
        return BogusRecheck::Alias(target);
    }

    let mut zone = name.clone();
    while !zone.is_root() {
        if let Ok(lookup) = dnssec.lookup(zone.clone(), RecordType::SOA).await {
            match apex_status(&zone, lookup.answers()) {
                Some(DnssecStatus::Insecure) => return BogusRecheck::Insecure,
                Some(DnssecStatus::Secure) => return BogusRecheck::Bogus,
                _ => {}
            }
        }
        zone = zone.base_name();
    }

    BogusRecheck::Bogus
}

fn secure_alias(query: &Name, answers: &[Record]) -> Option<Name> {
    answers.iter().find_map(|record| match &record.data {
        RData::CNAME(target) if &record.name == query && record.proof.is_secure() => {
            Some(target.0.clone())
        }
        _ => None,
    })
}

fn apex_status(zone: &Name, answers: &[Record]) -> Option<DnssecStatus> {
    answers
        .iter()
        .filter(|record| record.record_type() == RecordType::SOA && &record.name == zone)
        .map(|record| proof_to_dnssec_status(record.proof))
        .reduce(least_secure)
}

struct NegativeAnswer {
    response_code: ResponseCode,
    dnssec_status: DnssecStatus,
    valid_until: Option<Instant>,
}

impl NegativeAnswer {
    fn from_error(err: &NetError) -> Option<Self> {
        let NetError::Dns(dns_error) = err else {
            return None;
        };

        match dns_error {
            DnsError::NoRecordsFound(no_records) => Some(NegativeAnswer {
                response_code: no_records.response_code,
                dnssec_status: no_records
                    .authorities
                    .as_deref()
                    .map(denial_dnssec_status)
                    .unwrap_or(DnssecStatus::Indeterminate),
                valid_until: no_records
                    .negative_ttl
                    .map(|ttl| Instant::now() + Duration::from_secs(ttl as u64)),
            }),
            DnsError::Nsec {
                response, proof, ..
            } => Some(NegativeAnswer {
                response_code: response.response_code,
                dnssec_status: proof_to_dnssec_status(*proof),
                valid_until: None,
            }),
            _ => None,
        }
    }
}

fn denial_dnssec_status(authorities: &[Record]) -> DnssecStatus {
    authorities
        .iter()
        .filter(|record| matches!(record.record_type(), RecordType::NSEC | RecordType::NSEC3))
        .map(|record| proof_to_dnssec_status(record.proof))
        .reduce(least_secure)
        .unwrap_or(DnssecStatus::Indeterminate)
}

fn proof_to_dnssec_status(proof: Proof) -> DnssecStatus {
    match proof {
        Proof::Secure => DnssecStatus::Secure,
        Proof::Insecure => DnssecStatus::Insecure,
        Proof::Bogus => DnssecStatus::Bogus,
        Proof::Indeterminate => DnssecStatus::Indeterminate,
    }
}

fn tlsa_base_status(query: &Name, answers: &[Record], address_type: RecordType) -> DnssecStatus {
    let mut addresses: Option<DnssecStatus> = None;
    let mut alias: Option<DnssecStatus> = None;

    for record in answers {
        let status = proof_to_dnssec_status(record.proof);
        if record.record_type() == address_type {
            addresses = Some(match addresses {
                Some(current) => least_secure(current, status),
                None => status,
            });
        } else if record.record_type() == RecordType::CNAME && &record.name == query {
            alias = Some(match alias {
                Some(current) => least_secure(current, status),
                None => status,
            });
        }
    }

    match (addresses, alias) {
        (Some(DnssecStatus::Insecure), Some(DnssecStatus::Secure)) => DnssecStatus::Secure,
        (Some(status), _) => status,
        (None, _) => DnssecStatus::Indeterminate,
    }
}

pub fn least_secure(a: DnssecStatus, b: DnssecStatus) -> DnssecStatus {
    fn rank(status: DnssecStatus) -> u8 {
        match status {
            DnssecStatus::Bogus => 0,
            DnssecStatus::Indeterminate => 1,
            DnssecStatus::Insecure => 2,
            DnssecStatus::Secure => 3,
        }
    }

    if rank(a) <= rank(b) { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_auth::hickory_resolver::proto::rr::rdata::{A, CNAME, SOA};
    use std::net::Ipv4Addr;

    fn name(value: &str) -> Name {
        Name::from_ascii(value).unwrap()
    }

    fn address(owner: &str, proof: Proof) -> Record {
        let mut record =
            Record::from_rdata(name(owner), 3600, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))));
        record.proof = proof;
        record
    }

    fn alias(owner: &str, target: &str, proof: Proof) -> Record {
        let mut record = Record::from_rdata(name(owner), 3600, RData::CNAME(CNAME(name(target))));
        record.proof = proof;
        record
    }

    #[test]
    fn tlsa_base_status_follows_address_records() {
        let query = name("mx.example.org.");

        for (proof, expected) in [
            (Proof::Secure, DnssecStatus::Secure),
            (Proof::Insecure, DnssecStatus::Insecure),
            (Proof::Bogus, DnssecStatus::Bogus),
            (Proof::Indeterminate, DnssecStatus::Indeterminate),
        ] {
            assert_eq!(
                tlsa_base_status(&query, &[address("mx.example.org.", proof)], RecordType::A),
                expected,
                "proof {proof}"
            );
        }
    }

    #[test]
    fn tlsa_base_status_is_indeterminate_without_addresses() {
        assert_eq!(
            tlsa_base_status(&name("mx.example.org."), &[], RecordType::A),
            DnssecStatus::Indeterminate
        );
    }

    #[test]
    fn tlsa_base_status_takes_least_secure_address() {
        let query = name("mx.example.org.");

        assert_eq!(
            tlsa_base_status(
                &query,
                &[
                    address("mx.example.org.", Proof::Secure),
                    address("mx.example.org.", Proof::Insecure),
                ],
                RecordType::A
            ),
            DnssecStatus::Insecure
        );
    }

    #[test]
    fn tlsa_base_status_keeps_secure_alias_to_insecure_zone() {
        let query = name("mx.example.org.");

        assert_eq!(
            tlsa_base_status(
                &query,
                &[
                    alias("mx.example.org.", "mx.provider.net.", Proof::Secure),
                    address("mx.provider.net.", Proof::Insecure),
                ],
                RecordType::A
            ),
            DnssecStatus::Secure
        );
    }

    #[test]
    fn tlsa_base_status_skips_insecure_alias() {
        let query = name("mx.example.org.");

        assert_eq!(
            tlsa_base_status(
                &query,
                &[
                    alias("mx.example.org.", "mx.provider.net.", Proof::Insecure),
                    address("mx.provider.net.", Proof::Insecure),
                ],
                RecordType::A
            ),
            DnssecStatus::Insecure
        );
    }

    #[test]
    fn tlsa_base_status_ignores_alias_below_query_name() {
        let query = name("mx.example.org.");

        assert_eq!(
            tlsa_base_status(
                &query,
                &[
                    alias("mx.provider.net.", "mx.other.net.", Proof::Secure),
                    address("mx.other.net.", Proof::Insecure),
                ],
                RecordType::A
            ),
            DnssecStatus::Insecure
        );
    }

    fn soa(owner: &str, proof: Proof) -> Record {
        let mut record = Record::from_rdata(
            name(owner),
            3600,
            RData::SOA(SOA::new(
                name("ns1.example.org."),
                name("hostmaster.example.org."),
                1,
                900,
                900,
                1800,
                60,
            )),
        );
        record.proof = proof;
        record
    }

    #[test]
    fn secure_alias_follows_signed_cname() {
        assert_eq!(
            secure_alias(
                &name("mail.example.org."),
                &[alias("mail.example.org.", "mx.example.net.", Proof::Secure)]
            ),
            Some(name("mx.example.net."))
        );
    }

    #[test]
    fn secure_alias_ignores_unsigned_or_other_cname() {
        let query = name("mail.example.org.");

        assert_eq!(
            secure_alias(
                &query,
                &[alias(
                    "mail.example.org.",
                    "mx.example.net.",
                    Proof::Insecure
                )]
            ),
            None
        );
        assert_eq!(
            secure_alias(
                &query,
                &[alias(
                    "other.example.org.",
                    "mx.example.net.",
                    Proof::Secure
                )]
            ),
            None
        );
    }

    #[test]
    fn apex_status_reads_the_zone_soa() {
        let zone = name("example.com.");

        for (proof, expected) in [
            (Proof::Secure, Some(DnssecStatus::Secure)),
            (Proof::Insecure, Some(DnssecStatus::Insecure)),
            (Proof::Bogus, Some(DnssecStatus::Bogus)),
        ] {
            assert_eq!(
                apex_status(&zone, &[soa("example.com.", proof)]),
                expected,
                "proof {proof}"
            );
        }
    }

    #[test]
    fn apex_status_ignores_other_records() {
        assert_eq!(
            apex_status(
                &name("example.com."),
                &[
                    soa("sub.example.com.", Proof::Insecure),
                    address("example.com.", Proof::Insecure),
                ]
            ),
            None
        );
    }

    // Needs the network: a signed MX pointing into a zone delegated beneath an
    // unsigned one. Run with `--ignored` to check a hickory upgrade. hickory
    // 0.26.3 called it bogus and the recheck proved it insecure; the vendored
    // hickory proves it itself. Either way the answer has to come out insecure.
    // The TLSA test below prints whether hickory alone gets its case right.
    #[tokio::test]
    #[ignore]
    async fn validated_lookup_proves_delegation_below_unsigned_zone() {
        use mail_auth::hickory_resolver::{
            config::{CLOUDFLARE, ResolverConfig, ResolverOpts},
            net::runtime::TokioRuntimeProvider,
        };

        let build = |validate: bool| {
            // Same options as the server's DNSSEC resolver; hickory fails
            // validation with concurrent requests.
            let mut opts = ResolverOpts::default();
            opts.validate = validate;
            opts.num_concurrent_reqs = 1;
            opts.cache_size = 0;
            TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                TokioRuntimeProvider::default(),
            )
            .with_options(opts)
            .build()
            .unwrap()
        };
        let (dnssec, plain) = (build(true), build(false));

        let query = name("aspmx.l.google.com.");
        let validated = validated_lookup(&dnssec, &plain, query.clone(), RecordType::A)
            .await
            .unwrap();
        assert!(!validated.lookup.answers().is_empty());
        let status = if validated.insecure {
            DnssecStatus::Insecure
        } else {
            tlsa_base_status(&query, validated.lookup.answers(), RecordType::A)
        };
        assert_eq!(status, DnssecStatus::Insecure);
    }

    // Needs the network: a TLSA name that is a signed CNAME to the zone apex,
    // which has no TLSA record. Cloudflare's resolver answers with a compact
    // denial at the name itself; Hetzner's (and others) follow the CNAME, and
    // hickory then calls the answer bogus. Point the lookup at a resolver that
    // follows it with INBUXA_TEST_DNS_TCP=<ip:port> (TCP), for instance over
    // an SSH tunnel to 185.12.64.2:53 from a Hetzner host.
    #[tokio::test]
    #[ignore]
    async fn validated_lookup_follows_signed_cname_for_tlsa() {
        use mail_auth::hickory_resolver::{
            config::{
                CLOUDFLARE, ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts,
            },
            net::runtime::TokioRuntimeProvider,
        };

        let config = match std::env::var("INBUXA_TEST_DNS_TCP") {
            Ok(addr) => {
                let addr: std::net::SocketAddr = addr.parse().unwrap();
                let mut ns = NameServerConfig::new(addr.ip(), true, vec![ConnectionConfig::tcp()]);
                if let Some(c) = ns.connections.first_mut() {
                    c.port = addr.port();
                }
                ResolverConfig::from_parts(None, vec![], vec![ns])
            }
            Err(_) => ResolverConfig::udp_and_tcp(&CLOUDFLARE),
        };
        let build = |validate: bool| {
            let mut opts = ResolverOpts::default();
            opts.validate = validate;
            opts.num_concurrent_reqs = 1;
            opts.cache_size = 0;
            TokioResolver::builder_with_config(config.clone(), TokioRuntimeProvider::default())
                .with_options(opts)
                .build()
                .unwrap()
        };
        let (dnssec, plain) = (build(true), build(false));
        let query = name("_25._tcp.mail.usefulinsight.com.");

        let direct = dnssec.lookup(query.clone(), RecordType::TLSA).await;
        eprintln!(
            "hickory alone: {:?}",
            direct.as_ref().err().map(|e| e.to_string())
        );

        let err = match validated_lookup(&dnssec, &plain, query, RecordType::TLSA).await {
            Ok(validated) => panic!(
                "expected no TLSA record, got {:?}",
                validated.lookup.answers()
            ),
            Err(err) => err,
        };
        let denial = NegativeAnswer::from_error(&err).expect("a denial of existence");
        assert_eq!(denial.response_code, ResponseCode::NoError);
        assert_ne!(denial.dnssec_status, DnssecStatus::Bogus);
    }
}
