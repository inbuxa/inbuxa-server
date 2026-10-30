/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Outbound delivery (spec "Outbound"): each message handed over is sent
//! by MX, one domain at a time, with DANE where the destination's TLSA
//! records are signed, MTA-STS where it enforces a policy, and otherwise
//! TLS per `outboundTls`. After each attempt the message's
//! `deliveryStatus` is updated and pushed; the downstream writes any DSN.
//! TLS results go up as `outbound.tls` events, for TLS-RPT.

pub mod client;
pub mod https;
pub mod route;
#[cfg(test)]
mod tests;
pub mod tls;

use crate::{app::App, outbound::Meta};
use client::{RcptOutcome, Session};
use inbuxa_outbound_tls::{Mode, Policy, Tlsa, TlsaMatching, dnssec::TlsaResult};
use inbuxa_relay_proto::{
    time,
    types::{Address, Delivered, DeliveryStatus, Displayed, OutboundTls, RelaySettings},
};
use route::{LookupError, Mx, Resolve};
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tls::{TlsFailure, TlsMode};
use tokio::sync::Semaphore;

/// Messages delivered at once.
const CONCURRENCY: usize = 8;
/// MX hosts tried per domain, and addresses per host.
const MX_MAX: usize = 5;
const ADDRESSES_PER_HOST: usize = 2;
/// A finished message the downstream never cleared goes after a week.
const FINISHED_KEEP: u64 = 7 * 86_400;
const TICK: Duration = Duration::from_secs(5);

pub async fn run<R: Resolve>(app: Arc<App>, resolve: Arc<R>) {
    let running = Arc::new(Semaphore::new(CONCURRENCY));
    let mut tick = tokio::time::interval(TICK);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = app.outbound_wake.notified() => {}
        }
        let now = time::now();
        housekeeping(&app, now);
        let Some(settings) = app.settings().filter(|s| s.problems().is_empty()) else {
            continue;
        };
        let free = running.available_permits();
        if free == 0 {
            continue;
        }
        let due = app.outbox.lock().expect("outbox").take_due(now, free);
        for meta in due {
            let Ok(permit) = running.clone().try_acquire_owned() else {
                app.outbox.lock().expect("outbox").release(&meta.id);
                continue;
            };
            let (app, resolve, settings) = (app.clone(), resolve.clone(), settings.clone());
            tokio::spawn(async move {
                attempt(&app, &*resolve, &settings, meta).await;
                drop(permit);
            });
        }
    }
}

/// Gives up on what has expired, and forgets what was never cleared.
fn housekeeping(app: &App, now: u64) {
    let (expired, swept) = {
        let mut outbox = app.outbox.lock().expect("outbox");
        let expired = outbox.expire(now);
        (expired, outbox.sweep_finished(now, FINISHED_KEEP))
    };
    let expired = match expired {
        Ok(expired) => expired,
        Err(e) => {
            app.set_error(format!("could not write to the outbound spool: {e}"));
            return;
        }
    };
    for (id, recipients) in &expired {
        app.record(
            "outbound.expired",
            crate::events::data([("id", json!(id)), ("recipients", json!(recipients))]),
        );
    }
    if !expired.is_empty() || swept > 0 {
        app.outbound_changed();
        app.relay_changed();
    }
}

async fn attempt<R: Resolve>(app: &App, resolve: &R, settings: &RelaySettings, meta: Meta) {
    let path = app.outbox.lock().expect("outbox").eml_path(&meta.id);
    let mut by_domain: BTreeMap<String, Vec<&Address>> = BTreeMap::new();
    for rcpt in meta.queued() {
        let domain = rcpt
            .email
            .rsplit_once('@')
            .map(|(_, d)| d.trim_end_matches('.').to_lowercase())
            .unwrap_or_default();
        by_domain.entry(domain).or_default().push(rcpt);
    }
    let mut statuses = Vec::new();
    for (domain, rcpts) in &by_domain {
        let target = Target {
            app,
            resolve,
            settings,
            meta: &meta,
            path: &path,
            domain,
            rcpts,
        };
        statuses.extend(target.deliver().await);
    }
    let recorded = app.outbox.lock().expect("outbox").record(
        &meta.id,
        statuses,
        &settings.outbound_retry,
        time::now(),
    );
    match recorded {
        Ok(true) => app.outbound_changed(),
        Ok(false) => {}
        Err(e) => app.set_error(format!("could not write to the outbound spool: {e}")),
    }
}

/// One message's recipients at one domain.
struct Target<'a, R> {
    app: &'a App,
    resolve: &'a R,
    settings: &'a RelaySettings,
    meta: &'a Meta,
    path: &'a Path,
    domain: &'a str,
    rcpts: &'a [&'a Address],
}

fn status(delivered: Delivered, smtp_reply: String, mx: Option<&str>) -> DeliveryStatus {
    DeliveryStatus {
        smtp_reply,
        delivered,
        displayed: Displayed::Unknown,
        mx: mx.map(str::to_string),
    }
}

impl<R: Resolve> Target<'_, R> {
    fn every(&self, delivered: Delivered, reply: String) -> Vec<(String, DeliveryStatus)> {
        self.rcpts
            .iter()
            .map(|r| (r.email.clone(), status(delivered, reply.clone(), None)))
            .collect()
    }

    async fn deliver(&self) -> Vec<(String, DeliveryStatus)> {
        let domain = self.domain;
        let (hosts, mx_secure) = match self.resolve.mx(domain).await {
            Ok(Mx::Hosts { hosts, secure }) => (hosts, secure),
            Ok(Mx::Null) => {
                return self.every(
                    Delivered::No,
                    format!("556 5.1.10 {domain} accepts no mail (null MX)"),
                );
            }
            Err(LookupError::Permanent(e)) => {
                return self.every(Delivered::No, format!("550 5.1.2 {domain}: {e}"));
            }
            Err(LookupError::Temporary(e)) => {
                return self.every(
                    Delivered::Queued,
                    format!("451 4.4.3 Looking up {domain} failed: {e}"),
                );
            }
        };
        let sts = self
            .resolve
            .mta_sts(domain)
            .await
            .filter(|p| p.mode != Mode::None);
        let enforce = sts.as_ref().is_some_and(|p| p.enforce());
        let mut last = format!("451 4.4.0 No MX host of {domain} could be reached");

        for host in hosts.iter().take(MX_MAX) {
            if let Some(policy) = &sts
                && !policy.verify(host)
            {
                self.tls_event(
                    host,
                    None,
                    &TlsMode::Verified,
                    Some(policy),
                    Some(&TlsFailure {
                        reason: "the MX host isn't in the MTA-STS policy".into(),
                        result_type: "validation-failure",
                        handshake: false,
                    }),
                );
                if enforce {
                    last = format!("451 4.7.5 {host} isn't in {domain}'s MTA-STS policy");
                    continue;
                }
            }
            let (ips, ips_secure) = match self.resolve.addresses(host, mx_secure).await {
                Ok(found) => found,
                Err(LookupError::Permanent(e) | LookupError::Temporary(e)) => {
                    last = format!("451 4.4.3 Looking up {host} failed: {e}");
                    continue;
                }
            };
            let fallback = if enforce {
                TlsMode::Verified
            } else if self.settings.outbound_tls == OutboundTls::Required {
                TlsMode::Required
            } else {
                TlsMode::Opportunistic
            };
            // DANE needs the MX answer and the host's addresses signed
            // (RFC 7672 §2.2), and then takes precedence over MTA-STS.
            let mode = if mx_secure && ips_secure {
                match self.resolve.tlsa(host).await {
                    Ok(TlsaResult::Secure(tlsa))
                        if tlsa.has_end_entities || tlsa.has_intermediates =>
                    {
                        TlsMode::Dane(tlsa)
                    }
                    Ok(TlsaResult::Secure(_)) => TlsMode::DaneEncrypt,
                    Ok(TlsaResult::Bogus) => {
                        self.tls_event(
                            host,
                            None,
                            &TlsMode::DaneEncrypt,
                            None,
                            Some(&TlsFailure {
                                reason: "the TLSA records failed DNSSEC validation".into(),
                                result_type: "dnssec-invalid",
                                handshake: false,
                            }),
                        );
                        last = format!("451 4.7.5 {host}'s TLSA records failed DNSSEC validation");
                        continue;
                    }
                    Ok(TlsaResult::Missing) => fallback,
                    Err(LookupError::Permanent(e) | LookupError::Temporary(e)) => {
                        last = format!("451 4.4.3 Looking up TLSA for {host} failed: {e}");
                        continue;
                    }
                }
            } else {
                fallback
            };

            for ip in ips.iter().take(ADDRESSES_PER_HOST) {
                let session = Session {
                    addr: SocketAddr::new(*ip, self.resolve.port()),
                    mx: host,
                    domain,
                    helo: &self.settings.hostname,
                    mode: mode.clone(),
                    mail_from: &self.meta.envelope.mail_from,
                    rcpt_to: self.rcpts,
                    message: self.path,
                    size: self.meta.size,
                };
                match session.run().await {
                    Ok(delivered) => {
                        if delivered.tls.is_some() || mode.is_required() {
                            self.tls_event(host, Some(*ip), &mode, sts.as_deref(), None);
                        }
                        let mut counts = [0usize; 3];
                        let statuses = self
                            .rcpts
                            .iter()
                            .zip(delivered.outcomes)
                            .map(|(rcpt, outcome)| {
                                let (delivered, reply, n) = match outcome {
                                    RcptOutcome::Delivered(r) => (Delivered::Yes, r, 0),
                                    RcptOutcome::Refused(r) => (Delivered::No, r, 1),
                                    RcptOutcome::Deferred(r) => (Delivered::Queued, r, 2),
                                };
                                counts[n] += 1;
                                (rcpt.email.clone(), status(delivered, reply, Some(host)))
                            })
                            .collect();
                        self.app.record(
                            "outbound.attempt",
                            crate::events::data([
                                ("id", json!(self.meta.id)),
                                ("domain", json!(domain)),
                                ("mx", json!(host)),
                                ("ip", json!(ip.to_string())),
                                (
                                    "tls",
                                    delivered.tls.as_ref().map_or(
                                        Value::Null,
                                        |t| json!({ "version": t.version, "cipher": t.cipher }),
                                    ),
                                ),
                                ("delivered", json!(counts[0])),
                                ("refused", json!(counts[1])),
                                ("deferred", json!(counts[2])),
                            ]),
                        );
                        return statuses;
                    }
                    Err(failure) => {
                        if let Some(tls) = &failure.tls {
                            self.tls_event(host, Some(*ip), &mode, sts.as_deref(), Some(tls));
                        }
                        last = format!("451 4.4.1 {}", failure.reason);
                    }
                }
            }
        }
        self.every(Delivered::Queued, last)
    }

    /// One session's TLS result, for the downstream's TLS-RPT reports
    /// (RFC 8460): the policy that applied and what came of it.
    fn tls_event(
        &self,
        mx: &str,
        ip: Option<std::net::IpAddr>,
        mode: &TlsMode,
        sts: Option<&Policy>,
        failure: Option<&TlsFailure>,
    ) {
        let policy_strings: Vec<String> = match mode {
            TlsMode::Dane(tlsa) => tlsa_strings(tlsa),
            TlsMode::Verified => sts
                .map(|p| p.to_string().lines().map(str::to_string).collect())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let mut data = crate::events::data([
            ("domain", json!(self.domain)),
            ("mx", json!(mx)),
            ("policyType", json!(mode.policy_type())),
            ("policyStrings", json!(policy_strings)),
            (
                "result",
                json!(failure.map_or("success", |f| f.result_type)),
            ),
        ]);
        if let Some(ip) = ip {
            data.insert("ip".into(), json!(ip.to_string()));
        }
        if let Some(failure) = failure {
            data.insert("reason".into(), json!(failure.reason));
        }
        self.app.record("outbound.tls", data);
    }
}

/// TLSA records in presentation form (RFC 6698 §2.2), as TLS-RPT reports
/// them.
fn tlsa_strings(tlsa: &Tlsa) -> Vec<String> {
    tlsa.entries
        .iter()
        .map(|e| {
            let hex: String = e.data.iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "{} {} {} {hex}",
                if e.is_end_entity { 3 } else { 2 },
                u8::from(e.is_spki),
                match e.matching {
                    TlsaMatching::Full => 0,
                    TlsaMatching::Sha256 => 1,
                    TlsaMatching::Sha512 => 2,
                }
            )
        })
        .collect()
}
