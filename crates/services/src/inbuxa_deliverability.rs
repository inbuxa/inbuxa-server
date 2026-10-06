/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! The deliverability check (deliverability spec, DL-1 to DL-16): every node
//! that sends mail asks what the rest of the internet sees of it, once a day
//! and when an administrator asks (**Check now**), and keeps one report.
//!
//! Each node checks itself, because only it knows which address it sends
//! from: a cluster's nodes can each leave from their own (DL-1, DL-2). The
//! report holds facts; the console grades them.

use common::{
    BuildServer, Inner, Server, config::smtp::auth::Dkim1Signer, expr::functions::EmptyResolver,
};
use futures::future::join_all;
use inbuxa_features::deliverability::{
    self as model, Address, AddressSource, Certificate, DkimKey, DkimState, Dmarc, DomainReport,
    Listing, ListingState, MtaSts, Report, Settings, SpfResult,
    lists::{self, Answer, BlockList, Subject},
};
use mail_auth::{
    AuthenticatedMessage, DkimResult, DnsError, Error, SpfResult as Spf,
    common::headers::HeaderWriter,
    dmarc::{self, Alignment},
    mta_sts::{MtaSts as MtaStsRecord, TlsRpt},
    spf::verify::SpfParameters,
};
use registry::schema::{prelude::ObjectType, structs::Domain};
use smtp::outbound::mta_sts::{lookup::MtaStsLookup, verify::VerifyPolicy};
use std::{
    collections::BTreeSet,
    future::Future,
    net::IpAddr,
    sync::{Arc, LazyLock},
    time::Duration,
};
use store::{registry::RegistryQuery, write::now};
use tokio::sync::Notify;
use types::id::Id;

/// DL-16: no single lookup holds a run up for longer than this.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// DL-16: lookups in flight at once.
const PARALLEL: usize = 8;
const MTA_STS_TIMEOUT: Duration = Duration::from_secs(10);
const DAY: u64 = 86_400;
/// After a start, wait this long before a run that's overdue.
const SETTLE: Duration = Duration::from_secs(120);

/// DL-15: wakes this node's check, from **Check now** here or on another node.
pub static CHECK_NOW: LazyLock<Notify> = LazyLock::new(Notify::new);

pub fn spawn_deliverability(inner: Arc<Inner>) {
    tokio::spawn(async move {
        let mut first = true;
        loop {
            let server = inner.build_server();
            let wait = match due_in(&server).await {
                Ok(wait) => wait,
                Err(err) => {
                    trc::error!(err.details("Failed to read the deliverability report"));
                    Duration::from_secs(3600)
                }
            };
            let wait = if first { wait.max(SETTLE) } else { wait };
            first = false;
            let asked = tokio::select! {
                _ = tokio::time::sleep(wait) => false,
                _ = CHECK_NOW.notified() => true,
            };
            let server = inner.build_server();
            if !server.core.network.roles.outbound_mta {
                continue;
            }
            // DL-15: asked again within ten minutes, the last report stands
            if asked
                && let Ok(Some(last)) =
                    model::report(server.store(), server.core.network.node_id).await
                && now().saturating_sub(last.checked_at) < model::MIN_INTERVAL_SECS
            {
                continue;
            }
            if let Err(err) = run(&server).await {
                trc::error!(err.details("Failed to run the deliverability check"));
            }
        }
    });
}

/// DL-14: once a day, at a minute in the first hour of the day (UTC) that's
/// the node's own, so nodes and servers don't all ask the lists at once.
async fn due_in(server: &Server) -> trc::Result<Duration> {
    let node_id = server.core.network.node_id;
    let last = model::report(server.store(), node_id)
        .await?
        .map(|r| r.checked_at)
        .unwrap_or(0);
    let slot = slot_for(&server.core.network.server_name, node_id);
    let next = next_slot(last, slot);
    Ok(Duration::from_secs(next.saturating_sub(now())))
}

fn slot_for(hostname: &str, node_id: u64) -> u64 {
    let hash = hostname
        .bytes()
        .fold(node_id.wrapping_mul(0x9e37_79b9_7f4a_7c15), |h, b| {
            h.rotate_left(5) ^ b as u64
        });
    hash % 3600
}

/// The first daily slot after `last`; 0 (never ran) is due now.
fn next_slot(last: u64, slot: u64) -> u64 {
    if last == 0 {
        return 0;
    }
    let mut next = last - last % DAY + slot;
    if next <= last {
        next += DAY;
    }
    next
}

/// Runs the check on this node and keeps the report.
pub async fn run(server: &Server) -> trc::Result<Report> {
    let settings = model::settings(server.store()).await?;
    let addresses = addresses(server, &settings).await;
    let mut domains = Vec::new();
    let ids = server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Domain))
        .await?;
    for id in ids {
        if let Some(domain) = server.registry().object::<Domain>(id).await? {
            domains.push(check_domain(server, &settings, &domain, &addresses).await?);
        }
    }
    let certificates = certificates(server, &addresses).await;
    let report = Report {
        node_id: server.core.network.node_id,
        hostname: server.core.network.server_name.clone(),
        checked_at: now(),
        addresses,
        domains,
        certificates,
    };
    model::put_report(server.store(), &report).await?;
    Ok(report)
}

// --- DL-1, DL-2: the addresses ---------------------------------------------

async fn addresses(server: &Server, settings: &Settings) -> Vec<Address> {
    let queue = &server.core.smtp.queue;
    // The strategy the scheduler picks for a message it knows nothing about:
    // what an expression on the node's own name, as a cluster uses, gives.
    let strategy = server
        .eval_if::<String, _>(&queue.connection, &EmptyResolver, 0)
        .await
        .unwrap_or_else(|| "default".to_string());
    let connection = server.get_connection_or_default(&strategy, 0);
    let ehlo = connection
        .ehlo_hostname
        .clone()
        .unwrap_or_else(|| server.core.network.server_name.clone());

    let mut found: Vec<(IpAddr, AddressSource, String)> = connection
        .source_ipv4
        .iter()
        .chain(connection.source_ipv6.iter())
        .map(|source| {
            (
                source.ip,
                AddressSource::Configured,
                source.host.clone().unwrap_or_else(|| ehlo.clone()),
            )
        })
        .collect();
    if found.is_empty() {
        for ip in resolve_name(server, &ehlo).await {
            found.push((ip, AddressSource::Ehlo, ehlo.clone()));
        }
    }

    let mut out = Vec::with_capacity(found.len());
    for (ip, source, ehlo) in found {
        let mut address = Address {
            ip: ip.to_string(),
            source,
            strategy: strategy.clone(),
            ehlo: ehlo.clone(),
            ..Default::default()
        };
        reverse_dns(server, ip, &ehlo, &mut address).await;
        address.listings = listings(server, settings, Subject::Ip(ip)).await;
        out.push(address);
    }
    out
}

/// The IPv4 and IPv6 addresses `name` resolves to; none when it doesn't.
async fn resolve_name(server: &Server, name: &str) -> Vec<IpAddr> {
    let dns = &server.core.smtp.resolvers.dns;
    let cache = &server.inner.cache;
    let fqdn = fqdn(name);
    let mut ips = Vec::new();
    if let Some(Ok(v4)) = timed(dns.ipv4_lookup(fqdn.as_str(), Some(&cache.dns_ipv4))).await {
        ips.extend(v4.rrset.iter().copied().map(IpAddr::V4));
    }
    if let Some(Ok(v6)) = timed(dns.ipv6_lookup(fqdn.as_str(), Some(&cache.dns_ipv6))).await {
        ips.extend(v6.rrset.iter().copied().map(IpAddr::V6));
    }
    ips
}

/// DL-5: the PTR names, whether one resolves back, and whether that one is
/// the EHLO name.
async fn reverse_dns(server: &Server, ip: IpAddr, ehlo: &str, address: &mut Address) {
    let dns = &server.core.smtp.resolvers.dns;
    match timed(dns.ptr_lookup(ip, Some(&server.inner.cache.dns_ptr))).await {
        Some(Ok(names)) => {
            address.ptr = names.rrset.iter().map(|n| bare(n)).collect();
        }
        Some(Err(Error::Dns(DnsError::RecordNotFound(_)))) => {}
        Some(Err(err)) => address.ptr_error = Some(err.to_string()),
        None => address.ptr_error = Some("No answer in 5 seconds".into()),
    }
    for name in address.ptr.clone() {
        if resolve_name(server, &name).await.contains(&ip) {
            address.forward_confirmed = true;
            if name.eq_ignore_ascii_case(&bare(ehlo)) {
                address.ehlo_matches = true;
            }
        }
    }
}

// --- DL-4, DL-6, DL-12: blocklists ----------------------------------------

async fn listings(server: &Server, settings: &Settings, subject: Subject<'_>) -> Vec<Listing> {
    let mut out = Vec::new();
    let mut asked = Vec::new();
    for list in lists::LISTS {
        let Some(name) = list.query(&subject) else {
            continue;
        };
        if settings.is_off(list.name) {
            out.push(Listing {
                list: list.name.into(),
                state: ListingState::Off,
                ..Default::default()
            });
        } else {
            asked.push((list, name));
        }
    }
    for chunk in asked.chunks(PARALLEL) {
        out.extend(join_all(chunk.iter().map(|(list, name)| ask(server, list, name))).await);
    }
    // In the lists' own order, whether asked or off
    out.sort_by_key(|l| lists::LISTS.iter().position(|list| list.name == l.list));
    out
}

async fn ask(server: &Server, list: &BlockList, name: &str) -> Listing {
    let dns = &server.core.smtp.resolvers.dns;
    let mut listing = Listing {
        list: list.name.into(),
        ..Default::default()
    };
    match timed(dns.ipv4_lookup(name, Some(&server.inner.cache.dns_ipv4))).await {
        Some(Ok(answer)) => {
            let Some(code) = answer.rrset.first().copied() else {
                return listing;
            };
            listing.code = Some(code.to_string());
            match list.read(code) {
                Answer::Listed(meaning) => {
                    listing.state = ListingState::Listed;
                    listing.meaning = Some(meaning.into());
                }
                Answer::Refused(meaning) => {
                    listing.state = ListingState::Refused;
                    listing.meaning = Some(meaning.into());
                }
                Answer::Unknown => {
                    listing.state = ListingState::Refused;
                    listing.meaning = Some("An answer this list doesn't define".into());
                }
            }
        }
        // Not on the list
        Some(Err(Error::Dns(DnsError::RecordNotFound(_)))) => {}
        // A list that refuses the resolver often answers REFUSED or SERVFAIL
        Some(Err(err)) => {
            listing.state = ListingState::Error;
            listing.meaning = Some(err.to_string());
        }
        None => {
            listing.state = ListingState::Error;
            listing.meaning = Some("No answer in 5 seconds".into());
        }
    }
    listing
}

// --- DL-7 to DL-12: per domain --------------------------------------------

async fn check_domain(
    server: &Server,
    settings: &Settings,
    domain: &Domain,
    addresses: &[Address],
) -> trc::Result<DomainReport> {
    let name = domain.name.to_lowercase();
    let mut report = DomainReport {
        domain: name.clone(),
        tenant_id: domain.member_tenant_id.map(|id| id.document_id()),
        ..Default::default()
    };
    let dns = &server.core.smtp.resolvers.dns;
    let cache = &server.inner.cache;

    // DL-7: SPF for every address the node sends from
    for address in addresses {
        let Ok(ip) = address.ip.parse::<IpAddr>() else {
            continue;
        };
        let sender = format!("postmaster@{name}");
        let output = dns
            .check_host(cache.build_auth_parameters(SpfParameters::new(
                ip,
                &name,
                &address.ehlo,
                &server.core.network.server_name,
                &sender,
            )))
            .await;
        report.spf.push(SpfResult {
            ip: address.ip.clone(),
            result: spf_name(output.result()).into(),
        });
    }

    // DL-8: each key the domain signs with is the one published
    report.dkim = dkim_keys(server, &name).await?;

    // DL-9: what DMARC asks of alignment; the console works it out
    if let Some(Ok(record)) =
        timed(dns.txt_lookup::<dmarc::Dmarc>(format!("_dmarc.{name}."), Some(&cache.dns_txt))).await
    {
        report.dmarc = Some(Dmarc {
            policy: match record.p {
                dmarc::Policy::None | dmarc::Policy::Unspecified => "none",
                dmarc::Policy::Quarantine => "quarantine",
                dmarc::Policy::Reject => "reject",
            }
            .into(),
            adkim: alignment(&record.adkim).into(),
            aspf: alignment(&record.aspf).into(),
        });
    }

    // DL-10
    report.mta_sts = mta_sts(server, &name).await;

    // DL-11
    report.tls_rpt = matches!(
        timed(dns.txt_lookup::<TlsRpt>(format!("_smtp._tls.{name}."), Some(&cache.dns_txt))).await,
        Some(Ok(_))
    );

    // DL-12
    report.listings = listings(server, settings, Subject::Domain(&name)).await;

    Ok(report)
}

/// Signs a message that's never sent with each of the domain's DKIM keys,
/// and verifies it as a receiver would: a key that's missing from DNS, or
/// published but different, fails here before it fails anyone's mail.
async fn dkim_keys(server: &Server, domain: &str) -> trc::Result<Vec<DkimKey>> {
    let Some(signers) = server.dkim_signers(domain).await? else {
        return Ok(Vec::new());
    };
    let message = format!(
        "From: deliverability-check@{domain}\r\n\
         To: deliverability-check@{domain}\r\n\
         Subject: Deliverability check\r\n\
         Date: Mon, 5 Oct 2026 00:00:00 +0000\r\n\
         Message-ID: <deliverability-check@{domain}>\r\n\
         \r\n\
         This message is signed to check the DKIM keys in DNS. It is never sent.\r\n"
    );
    let mut keys = Vec::new();
    for signer in &signers.dkim1 {
        let signature = match signer {
            Dkim1Signer::RsaSha256(signer) => signer.sign(message.as_bytes()),
            Dkim1Signer::Ed25519Sha256(signer) => signer.sign(message.as_bytes()),
        };
        let Ok(signature) = signature else {
            continue;
        };
        let selector = signature.s.clone();
        let mut signed = Vec::with_capacity(message.len() + 512);
        signature.write_header(&mut signed);
        signed.extend_from_slice(message.as_bytes());
        let state = match AuthenticatedMessage::parse(&signed) {
            Some(parsed) => {
                let outputs = server
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_dkim(server.inner.cache.build_auth_parameters(&parsed))
                    .await;
                outputs
                    .first()
                    .map(|output| dkim_state(output.result()))
                    .unwrap_or(DkimState::Error)
            }
            None => DkimState::Error,
        };
        keys.push(DkimKey { selector, state });
    }
    Ok(keys)
}

fn dkim_state(result: &DkimResult) -> DkimState {
    match result {
        DkimResult::Pass => DkimState::Matches,
        DkimResult::PermError(Error::Dns(DnsError::RecordNotFound(_)))
        | DkimResult::TempError(Error::Dns(DnsError::RecordNotFound(_))) => DkimState::Missing,
        DkimResult::TempError(_) => DkimState::Error,
        _ => DkimState::Different,
    }
}

async fn mta_sts(server: &Server, domain: &str) -> MtaSts {
    let dns = &server.core.smtp.resolvers.dns;
    let cache = &server.inner.cache;
    let mut out = MtaSts::default();
    let Some(Ok(record)) =
        timed(dns.txt_lookup::<MtaStsRecord>(format!("_mta-sts.{domain}."), Some(&cache.dns_txt)))
            .await
    else {
        return out;
    };
    out.record_id = Some(record.id.clone());
    match server.lookup_mta_sts_policy(domain, MTA_STS_TIMEOUT).await {
        Ok(policy) => {
            out.fetched = true;
            out.mode = Some(
                match policy.mode {
                    common::config::smtp::resolver::Mode::Enforce => "enforce",
                    common::config::smtp::resolver::Mode::Testing => "testing",
                    common::config::smtp::resolver::Mode::None => "none",
                }
                .into(),
            );
            out.max_age = Some(policy.max_age);
            if let Some(Ok(mxs)) = timed(dns.mx_lookup(domain, Some(&cache.dns_mx))).await {
                for mx in mxs.rrset.iter() {
                    for exchange in mx.exchanges.iter() {
                        let host = bare(exchange);
                        if !policy.verify(&host) && !out.mx_not_covered.contains(&host) {
                            out.mx_not_covered.push(host);
                        }
                    }
                }
            }
        }
        Err(err) => out.error = Some(err.to_string()),
    }
    out
}

// --- DL-13: certificates ---------------------------------------------------

/// The EHLO names, and the server's MX names that point at this node, each
/// with whether the node holds a certificate for it.
async fn certificates(server: &Server, addresses: &[Address]) -> Vec<Certificate> {
    let mine: Vec<IpAddr> = addresses.iter().filter_map(|a| a.ip.parse().ok()).collect();
    let mut names: BTreeSet<String> = addresses.iter().map(|a| bare(&a.ehlo)).collect();
    let default_host = server.core.network.server_name.as_str();
    for mx in &server.core.network.info.mxs {
        let name = bare(mx.hostname.as_deref().unwrap_or(default_host));
        if !names.contains(&name)
            && resolve_name(server, &name)
                .await
                .iter()
                .any(|ip| mine.contains(ip))
        {
            names.insert(name);
        }
    }
    names
        .into_iter()
        .map(|name| Certificate {
            covered: server.resolve_certificate(&name).is_some(),
            name,
        })
        .collect()
}

// --- Helpers ---------------------------------------------------------------

async fn timed<T>(lookup: impl Future<Output = T>) -> Option<T> {
    tokio::time::timeout(LOOKUP_TIMEOUT, lookup).await.ok()
}

fn fqdn(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.'))
}

fn bare(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

fn spf_name(result: Spf) -> &'static str {
    match result {
        Spf::Pass => "pass",
        Spf::Fail => "fail",
        Spf::SoftFail => "softFail",
        Spf::Neutral => "neutral",
        Spf::TempError => "tempError",
        Spf::PermError => "permError",
        Spf::None => "none",
    }
}

fn alignment(alignment: &Alignment) -> &'static str {
    match alignment {
        Alignment::Relaxed => "relaxed",
        Alignment::Strict => "strict",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_daily_slot_follows_the_last_run() {
        let day = 20_000 * DAY;
        // Never ran: due now
        assert_eq!(next_slot(0, 600), 0);
        // Ran at 14:00: next is tomorrow's slot
        assert_eq!(next_slot(day + 14 * 3600, 600), day + DAY + 600);
        // Ran just before today's slot: today's slot
        assert_eq!(next_slot(day + 300, 600), day + 600);
        // Ran at the slot: tomorrow's
        assert_eq!(next_slot(day + 600, 600), day + DAY + 600);
    }

    #[test]
    fn slots_fall_in_the_first_hour_and_differ_by_node() {
        let a = slot_for("mx2.example.org", 2);
        let b = slot_for("mx3.example.org", 3);
        assert!(a < 3600 && b < 3600);
        assert_ne!(a, b);
    }
}
