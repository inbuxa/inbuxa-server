/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::expression::SpamFilterResolver;
use crate::SpamFilterContext;
use common::{
    Server,
    config::mailstore::spamfilter::{DnsBlServer, Element, IpResolver, Location, SpamLookup},
    expr::{Bump, Variable, functions::ResolveVariable},
};
use compact_str::{CompactString, ToCompactString};
use mail_auth::dns::ToFqdn;
#[cfg(not(stalwart_tests))]
use mail_auth::hickory_resolver::{
    net::{DnsError, NetError},
    proto::rr::{Name, RData},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::xxhash_rust::xxh3::xxh3_64;
use trc::SpamEvent;

#[cfg(stalwart_tests)]
use test_support::resolve_zone;

const MAX_NEGATIVE_TTL: u32 = 3600;
const EXPIRY_SPREAD_STEPS: u32 = 1024;
const EXPIRY_SPREAD_DIVISOR: u32 = 10;
const MIN_CACHE_LIFETIME: Duration = Duration::from_secs(1);
const FAILURE_CACHE_LIFETIME: Duration = Duration::from_secs(60);

enum Zone {
    Cached(SpamLookup),
    Lookup(Box<str>),
}

enum DnsblAnswer {
    Listed {
        codes: Arc<[IpResolver]>,
        expires: Instant,
    },
    NotListed {
        expires: Instant,
    },
}

pub(crate) async fn check_dnsbl(
    server: &Server,
    ctx: &mut SpamFilterContext<'_>,
    resolver: &impl ResolveVariable,
    scope: Element,
    location: Location,
) {
    let (mut checks, max_checks) = match scope {
        Element::Email => (
            ctx.result.rbl_email_checks,
            server.core.spam.dnsbl.max_email_checks,
        ),
        Element::Ip => (
            ctx.result.rbl_ip_checks,
            server.core.spam.dnsbl.max_ip_checks,
        ),
        Element::Url => (
            ctx.result.rbl_url_checks,
            server.core.spam.dnsbl.max_url_checks,
        ),
        Element::Domain => (
            ctx.result.rbl_domain_checks,
            server.core.spam.dnsbl.max_domain_checks,
        ),
        Element::Header | Element::Body | Element::Any => unreachable!(),
    };

    let mut arena = std::mem::take(ctx.arena.get_mut());
    for dnsbl in &server.core.spam.dnsbl.servers {
        if dnsbl.scope == scope
            && checks < max_checks
            && let Some(codes) = dnsbl_codes(
                server,
                dnsbl,
                SpamFilterResolver::new(
                    &ctx.input,
                    &ctx.output,
                    &ctx.result.tags,
                    resolver,
                    location,
                ),
                scope,
                &mut checks,
                &mut arena,
            )
            .await
        {
            for code in codes.iter() {
                if let Some(tag) = dnsbl_tag(
                    server,
                    dnsbl,
                    &SpamFilterResolver::new(
                        &ctx.input,
                        &ctx.output,
                        &ctx.result.tags,
                        code,
                        location,
                    ),
                    &mut arena,
                )
                .await
                {
                    ctx.result.add_tag(tag);
                }
            }
        }
    }
    *ctx.arena.get_mut() = arena;

    match scope {
        Element::Email => ctx.result.rbl_email_checks = checks,
        Element::Ip => ctx.result.rbl_ip_checks = checks,
        Element::Url => ctx.result.rbl_url_checks = checks,
        Element::Domain => ctx.result.rbl_domain_checks = checks,
        Element::Header | Element::Body | Element::Any => unreachable!(),
    }
}

async fn dnsbl_codes(
    server: &Server,
    config: &DnsBlServer,
    resolver: SpamFilterResolver<'_, impl ResolveVariable>,
    element: Element,
    checks: &mut usize,
    arena: &mut Bump,
) -> Option<Arc<[IpResolver]>> {
    let time = Instant::now();
    let span_id = resolver.input.span_id;
    let spam_lookup = &server.inner.cache.spam_lookup;
    let zone = server
        .eval_if_with(&config.zone, &resolver, arena, span_id, |zone| match zone {
            Variable::String(zone) => Some(match spam_lookup.get(zone) {
                Some(entry) => Zone::Cached(entry),
                None => Zone::Lookup(zone.into()),
            }),
            _ => None,
        })
        .await
        .flatten()?;

    let zone = match zone {
        Zone::Cached(SpamLookup::Dnsbl(codes)) => return Some(codes),
        Zone::Cached(_) => return None,
        Zone::Lookup(zone) => zone,
    };

    #[cfg(stalwart_tests)]
    {
        if zone.contains(".11.20.") {
            let parts = zone.split('.').collect::<Vec<_>>();

            return if config.tags.if_then.iter().any(|i| i.expr.items.len() == 3) && parts[0] != "2"
            {
                None
            } else {
                Some(Arc::from([IpResolver::new(
                    format!("127.0.{}.{}", parts[1], parts[0]).parse().unwrap(),
                )]))
            };
        }
    }

    let guard = match spam_lookup.get_value_or_guard_async(&zone).await {
        Ok(SpamLookup::Dnsbl(codes)) => return Some(codes),
        Ok(_) => return None,
        Err(guard) => guard,
    };

    *checks += 1;

    match resolve_zone(server, zone.to_fqdn().as_ref()).await {
        Ok(DnsblAnswer::Listed { codes, expires }) => {
            let expires = cache_expiry(&zone, time, expires, Instant::now());
            trc::event!(
                Spam(SpamEvent::Dnsbl),
                Hostname = zone,
                Result = codes
                    .iter()
                    .map(|code| trc::Value::from(CompactString::from(code.text())))
                    .collect::<Vec<_>>(),
                Details = element.as_str(),
                Elapsed = time.elapsed()
            );

            guard.insert_with_expiry(SpamLookup::Dnsbl(codes.clone()), expires);

            Some(codes)
        }
        Ok(DnsblAnswer::NotListed { expires }) => {
            let expires = cache_expiry(&zone, time, expires, Instant::now());
            trc::event!(
                Spam(SpamEvent::Dnsbl),
                Hostname = zone,
                Result = trc::Value::None,
                Details = element.as_str(),
                Elapsed = time.elapsed()
            );

            guard.insert_with_expiry(SpamLookup::None, expires);

            None
        }
        Err(err) => {
            trc::event!(
                Spam(SpamEvent::DnsblError),
                Hostname = zone,
                Elapsed = time.elapsed(),
                Details = element.as_str(),
                CausedBy = err
            );

            guard.insert(SpamLookup::None, FAILURE_CACHE_LIFETIME);

            None
        }
    }
}

fn cache_expiry(zone: &str, start: Instant, expires: Instant, now: Instant) -> Instant {
    spread_expiry(zone, start, expires).max(now + MIN_CACHE_LIFETIME)
}

fn negative_expiry(ttl: Option<u32>) -> Instant {
    Instant::now() + Duration::from_secs(ttl.unwrap_or_default().min(MAX_NEGATIVE_TTL).into())
}

fn spread_expiry(zone: &str, start: Instant, expires: Instant) -> Instant {
    let step = (xxh3_64(zone.as_bytes()) % u64::from(EXPIRY_SPREAD_STEPS)) as u32;
    expires
        - expires.saturating_duration_since(start) / EXPIRY_SPREAD_DIVISOR * step
            / EXPIRY_SPREAD_STEPS
}

#[cfg(not(stalwart_tests))]
async fn resolve_zone(server: &Server, zone: &str) -> Result<DnsblAnswer, CompactString> {
    let name = Name::from_str_relaxed(zone).map_err(|err| err.to_compact_string())?;

    match server
        .core
        .smtp
        .resolvers
        .dns
        .resolver()
        .ipv4_lookup(name)
        .await
    {
        Ok(lookup) => {
            let expires = lookup.valid_until();
            let codes = lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::A(a) => Some(IpResolver::new(a.0.into())),
                    _ => None,
                })
                .collect::<Arc<[_]>>();

            Ok(if !codes.is_empty() {
                DnsblAnswer::Listed { codes, expires }
            } else {
                DnsblAnswer::NotListed { expires }
            })
        }
        Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => Ok(DnsblAnswer::NotListed {
            expires: negative_expiry(no_records.negative_ttl),
        }),
        Err(err) => Err(err.to_compact_string()),
    }
}

async fn dnsbl_tag(
    server: &Server,
    config: &DnsBlServer,
    resolver: &SpamFilterResolver<'_, impl ResolveVariable>,
    arena: &mut Bump,
) -> Option<CompactString> {
    let tags = resolver.tags;
    server
        .eval_if_with(
            &config.tags,
            resolver,
            arena,
            resolver.input.span_id,
            |tag| match tag {
                Variable::String(tag) if !tags.contains(tag) => Some(CompactString::from(tag)),
                _ => None,
            },
        )
        .await
        .flatten()
}


