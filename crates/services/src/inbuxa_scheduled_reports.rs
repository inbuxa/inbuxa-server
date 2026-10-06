/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Scheduled reports and the weekly digest (scheduled-reports spec).
//!
//! Every node looks once a minute for reports that are due. A run is
//! claimed with the task lock, keyed by report and due time, and the due
//! time is recorded on the report, so it goes once however many nodes there
//! are (RP-16). The report is built from what the server already keeps
//! (RP-1 to RP-8) and mailed signed (RP-14) to accounts on this server
//! (RP-23).

use common::{BuildServer, Inner, KV_LOCK_TASK, Server};
use inbuxa_features::{
    deliverability::{self as dlv, DkimState, ListingState},
    scheduled_reports::{self as model, Report, Run, RunStatus, Section},
};
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, address::Address},
};
use registry::{
    schema::{
        enums::{DkimAuthResult, DmarcActionDisposition, DmarcResult, StorageQuota, TlsResultType},
        prelude::{Object, ObjectInner, ObjectType, Property},
        structs::{Account, Certificate, Domain, UserRoles},
    },
    types::EnumImpl,
};
use smtp::reporting::inbuxa_send::send_signed;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};
use store::{
    ValueKey,
    registry::RegistryQuery,
    write::{RegistryClass, ValueClass, now},
};
use trc::MetricType;
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

const TICK: Duration = Duration::from_secs(60);
const SETTLE: Duration = Duration::from_secs(90);
/// RP-7.
const QUOTA_WARN: f64 = 0.9;
/// RP-8.
const CERT_DAYS: u64 = 21;
/// RP-17: failed runs in a row before the dashboard hears of it.
pub const FAILURES_FOR_ATTENTION: u32 = 2;

pub fn spawn_scheduled_reports(inner: Arc<Inner>) {
    tokio::spawn(async move {
        tokio::time::sleep(SETTLE).await;
        loop {
            let server = inner.build_server();
            if let Err(err) = tick(&server).await {
                trc::error!(err.details("Failed to run scheduled reports"));
            }
            tokio::time::sleep(TICK).await;
        }
    });
}

async fn tick(server: &Server) -> trc::Result<()> {
    let now = now();
    model::ensure_digest(server.store(), now).await?;
    for report in model::reports(server.store()).await? {
        if !report.enabled {
            continue;
        }
        let Some(due) = report.schedule.next_due(report.last_due) else {
            continue;
        };
        if due > now {
            continue;
        }
        let key = [
            b"sched-report:".as_slice(),
            &report.id.to_be_bytes(),
            &due.to_be_bytes(),
        ]
        .concat();
        match server
            .in_memory_store()
            .try_lock(KV_LOCK_TASK, &key, 3600)
            .await
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                trc::error!(err.details("Failed to claim a scheduled report run"));
                continue;
            }
        }
        // A server that was down sends one catch-up run, not one per miss
        let (from, to) = report.schedule.period(due.max(now - 60));
        let outcome = run(server, &report, from, to, false).await;
        record(server, report.id, outcome, Some(now.max(due))).await?;
    }
    Ok(())
}

/// RP-18: builds the current period and mails it now.
pub fn send_now(server: Server, id: u64) {
    tokio::spawn(async move {
        let result = async {
            let Some(report) = model::report(server.store(), id).await? else {
                return Ok(());
            };
            let (from, to) = report.schedule.period(now());
            let outcome = run(&server, &report, from, to, true).await;
            record(&server, id, outcome, None).await
        }
        .await;
        if let Err(err) = result {
            trc::error!(err.details("Failed to send a report by hand"));
        }
    });
}

struct Outcome {
    run: Run,
    failing: Option<Vec<String>>,
}

/// Writes the run onto the report as it is now, so an edit made meanwhile
/// isn't lost.
async fn record(server: &Server, id: u64, outcome: Outcome, due: Option<u64>) -> trc::Result<()> {
    let Some(mut report) = model::report(server.store(), id).await? else {
        return Ok(());
    };
    if let Some(due) = due {
        report.last_due = due;
        if outcome.run.status == RunStatus::Failed {
            report.failed_in_a_row += 1;
        } else {
            report.failed_in_a_row = 0;
        }
    }
    if let Some(failing) = outcome.failing {
        report.failing = failing;
    }
    report.push_run(outcome.run);
    model::put_report(server.store(), &report).await
}

async fn run(server: &Server, report: &Report, from: u64, to: u64, by_hand: bool) -> Outcome {
    let started = now();
    let failed = |reason: String| Outcome {
        run: Run {
            at: started,
            by_hand,
            status: RunStatus::Failed,
            reason: Some(reason),
            ..Run::default()
        },
        failing: None,
    };

    let recipients = match recipients(server, report).await {
        Ok(r) if r.is_empty() => {
            return failed("No recipient is an account on this server.".into());
        }
        Ok(r) => r,
        Err(err) => {
            trc::error!(err.details("Failed to resolve report recipients"));
            return failed("The recipients couldn't be looked up.".into());
        }
    };
    let built = match build(server, report, from, to).await {
        Ok(built) => built,
        Err(err) => {
            trc::error!(err.details("Failed to build a scheduled report"));
            return failed("The report couldn't be built.".into());
        }
    };
    let settings = model::settings(server.store()).await.unwrap_or_default();
    let from_address = settings
        .from_address
        .clone()
        .filter(|a| a.contains('@'))
        .unwrap_or_else(|| format!("postmaster@{}", server.core.email.default_domain_name));
    let sign_domain = from_address
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .to_string();
    let message = compose(
        report,
        &built,
        from,
        to,
        settings.from_name(),
        &from_address,
        &recipients,
    );
    let size = message.len() as u64;
    match send_signed(server, &from_address, &recipients, &message, &sign_domain).await {
        Ok(()) => Outcome {
            run: Run {
                at: started,
                by_hand,
                status: RunStatus::Sent,
                reason: None,
                recipients: recipients.len() as u32,
                size,
            },
            failing: built.failing,
        },
        Err(reason) => failed(reason),
    }
}

/// RP-21: the system administrators; RP-23: otherwise the report's own
/// recipients that are accounts on this server.
async fn recipients(server: &Server, report: &Report) -> trc::Result<Vec<String>> {
    if report.built_in {
        let mut out = Vec::new();
        let mut domains = DomainNames::default();
        for id in server
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Account))
            .await?
        {
            if let Some(Account::User(user)) = server.registry().object::<Account>(id).await?
                && matches!(user.roles, UserRoles::Admin)
                && user.member_tenant_id.is_none()
                && let Some(domain) = domains.get(server, user.domain_id).await?
            {
                out.push(format!("{}@{}", user.name, domain));
            }
        }
        return Ok(out);
    }
    let mut out = Vec::new();
    for address in &report.recipients {
        if server.rcpt_id_from_email(address).await?.is_some() {
            out.push(address.to_lowercase());
        }
    }
    out.dedup();
    Ok(out)
}

#[derive(Default)]
struct DomainNames(HashMap<Id, Option<String>>);

impl DomainNames {
    async fn get(&mut self, server: &Server, id: Id) -> trc::Result<Option<String>> {
        if let Some(name) = self.0.get(&id) {
            return Ok(name.clone());
        }
        let name = server
            .registry()
            .object::<Domain>(id)
            .await?
            .map(|d| d.name.to_lowercase());
        self.0.insert(id, name.clone());
        Ok(name)
    }
}

// --- Building -------------------------------------------------------------

struct Part {
    title: &'static str,
    lines: Vec<String>,
    csv: Option<(String, String)>,
    link: &'static str,
}

struct Built {
    attention: Vec<String>,
    parts: Vec<Part>,
    /// RP-5: what's failing now, to keep for next time.
    failing: Option<Vec<String>>,
}

async fn build(server: &Server, report: &Report, from: u64, to: u64) -> trc::Result<Built> {
    let mut built = Built {
        attention: Vec::new(),
        parts: Vec::new(),
        failing: None,
    };
    let tenant = report.tenant_id;
    for section in report.effective_sections() {
        let part = match section {
            Section::MailFlow => mail_flow(server, from, to).await?,
            Section::Queue => queue(server, from, to).await?,
            Section::Spoofing => spoofing(server, tenant, from, to, &mut built.attention).await?,
            Section::TlsFailures => {
                tls_failures(server, tenant, from, to, &mut built.attention).await?
            }
            Section::Deliverability => {
                let (part, failing) =
                    deliverability(server, tenant, &report.failing, &mut built.attention).await?;
                built.failing = Some(failing);
                part
            }
            Section::Security => security(server, from, to).await?,
            Section::Storage => storage(server, tenant, from, to, &mut built.attention).await?,
            Section::Certificates => certificates(server, to, &mut built.attention).await?,
        };
        if let Some(part) = part {
            built.parts.push(part);
        }
    }
    built.attention.truncate(5);
    Ok(built)
}

fn number(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn change(now: u64, before: u64) -> String {
    if before == 0 {
        String::new()
    } else {
        let pct = (now as f64 - before as f64) / before as f64 * 100.0;
        if pct.abs() < 1.0 {
            " (about the same as before)".into()
        } else if pct > 0.0 {
            format!(" (up {:.0}%)", pct)
        } else {
            format!(" (down {:.0}%)", -pct)
        }
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", number(n), if n == 1 { one } else { many })
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = header.join(",");
    out.push_str("\r\n");
    for row in rows {
        out.push_str(
            &row.iter()
                .map(|v| csv_field(v))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

/// Counter totals for each metric over [from, to), all nodes.
async fn counters(server: &Server, from: u64, to: u64, names: &[&str]) -> trc::Result<Vec<u64>> {
    let wanted: Vec<Option<MetricType>> = names.iter().map(|n| MetricType::parse(n)).collect();
    let mut totals = vec![0u64; names.len()];
    let (Some(from_id), Some(to_id)) = (
        SnowflakeIdGenerator::from_timestamp(from),
        SnowflakeIdGenerator::from_timestamp(to),
    ) else {
        return Ok(totals);
    };
    for sample in server.read_metrics(from_id, to_id, true, |_| true).await? {
        if let registry::schema::structs::Metric::Counter(c) = &sample.metric
            && let Some(i) = wanted.iter().position(|w| *w == Some(c.metric))
        {
            totals[i] += c.count;
        }
    }
    Ok(totals)
}

/// Each node's histogram totals only grow (until a restart), so the period's
/// count and sum are the positive steps between its samples.
async fn histogram(server: &Server, from: u64, to: u64, name: &str) -> trc::Result<(u64, u64)> {
    let Some(wanted) = MetricType::parse(name) else {
        return Ok((0, 0));
    };
    let (Some(from_id), Some(to_id)) = (
        SnowflakeIdGenerator::from_timestamp(from),
        SnowflakeIdGenerator::from_timestamp(to),
    ) else {
        return Ok((0, 0));
    };
    let mut last: HashMap<u64, (u64, u64)> = HashMap::new();
    let (mut count, mut sum) = (0, 0);
    for sample in server.read_metrics(from_id, to_id, true, |_| true).await? {
        if let registry::schema::structs::Metric::Histogram(h) = &sample.metric
            && h.metric == wanted
        {
            let node = SnowflakeIdGenerator::to_node_id(sample.id);
            if let Some((c, s)) = last.get(&node)
                && h.count >= *c
                && h.sum >= *s
            {
                count += h.count - c;
                sum += h.sum - s;
            }
            last.insert(node, (h.count, h.sum));
        }
    }
    Ok((count, sum))
}

/// A gauge's first and last readings in [from, to).
async fn gauge(server: &Server, from: u64, to: u64, name: &str) -> trc::Result<Option<(u64, u64)>> {
    let Some(wanted) = MetricType::parse(name) else {
        return Ok(None);
    };
    let (Some(from_id), Some(to_id)) = (
        SnowflakeIdGenerator::from_timestamp(from),
        SnowflakeIdGenerator::from_timestamp(to),
    ) else {
        return Ok(None);
    };
    let mut first = None;
    let mut last = None;
    for sample in server.read_metrics(from_id, to_id, true, |_| true).await? {
        if let registry::schema::structs::Metric::Gauge(g) = &sample.metric
            && g.metric == wanted
        {
            first.get_or_insert(g.count);
            last = Some(g.count);
        }
    }
    Ok(first.zip(last))
}

/// RP-1.
async fn mail_flow(server: &Server, from: u64, to: u64) -> trc::Result<Option<Part>> {
    const NAMES: [&str; 5] = [
        "queue.message-queued",
        "queue.authenticated-message-queued",
        "message-ingest.spam",
        "queue.dsn-queued",
        "message-ingest.ham",
    ];
    let len = to - from;
    let now = counters(server, from, to, &NAMES).await?;
    let before = counters(server, from.saturating_sub(len), from, &NAMES).await?;
    if now.iter().all(|n| *n == 0) && before.iter().all(|n| *n == 0) {
        return Ok(None);
    }
    let received = now[0].saturating_sub(now[1]);
    let received_before = before[0].saturating_sub(before[1]);
    let mut lines = vec![
        format!(
            "Received: {}{}",
            plural(received, "message", "messages"),
            change(received, received_before)
        ),
        format!(
            "Sent by your people: {}{}",
            plural(now[1], "message", "messages"),
            change(now[1], before[1])
        ),
        format!(
            "Delivered as spam: {}{}",
            plural(now[2], "message", "messages"),
            change(now[2], before[2])
        ),
        format!(
            "Bounced: {}{}",
            plural(now[3], "message", "messages"),
            change(now[3], before[3])
        ),
    ];
    let (count, sum) = histogram(server, from, to, "delivery.total-time").await?;
    if count > 0 {
        let avg_ms = sum / count;
        lines.push(if avg_ms < 1000 {
            format!("Average delivery time: {} ms", avg_ms)
        } else {
            format!("Average delivery time: {:.1} s", avg_ms as f64 / 1000.0)
        });
    }
    Ok(Some(Part {
        title: "Mail flow",
        lines,
        csv: None,
        link: "Management/CustomComponent/Dashboard",
    }))
}

/// RP-2.
async fn queue(server: &Server, from: u64, to: u64) -> trc::Result<Option<Part>> {
    let Some((_, waiting)) = gauge(server, from, to, "queue.count").await? else {
        return Ok(None);
    };
    if waiting == 0 {
        return Ok(None);
    }
    Ok(Some(Part {
        title: "Queue",
        lines: vec![format!(
            "{} waiting to be delivered at the end of the period.",
            plural(waiting, "message", "messages")
        )],
        csv: None,
        link: "Management/x:QueuedMessage",
    }))
}

/// Received reports of one kind whose arrival falls in [from, to).
async fn received(
    server: &Server,
    object_type: ObjectType,
    tenant: Option<u32>,
    from: u64,
    to: u64,
) -> trc::Result<Vec<ObjectInner>> {
    let ids = server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(object_type).greater_than(Property::ExpiresAt, 0u64))
        .await?;
    let object_id = object_type.to_id();
    let mut out = Vec::new();
    for id in ids {
        let Some(object) = server
            .store()
            .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id: id.id(),
            })))
            .await?
        else {
            continue;
        };
        if let Some(tenant) = tenant
            && object.inner.member_tenant_id() != Some(Id::from(tenant))
        {
            continue;
        }
        let received_at = match &object.inner {
            ObjectInner::DmarcExternalReport(r) => r.received_at.timestamp(),
            ObjectInner::TlsExternalReport(r) => r.received_at.timestamp(),
            _ => continue,
        } as u64;
        if received_at >= from && received_at < to {
            out.push(object.inner);
        }
    }
    Ok(out)
}

#[derive(Default)]
struct Spoofed {
    failed: u64,
    delivered: u64,
    quarantined: u64,
    rejected: u64,
    sources: BTreeMap<String, u64>,
}

/// RP-3: the console's grouping (#88), here: a failure is a record whose
/// DKIM and SPF both failed DMARC.
async fn spoofing(
    server: &Server,
    tenant: Option<u32>,
    from: u64,
    to: u64,
    attention: &mut Vec<String>,
) -> trc::Result<Option<Part>> {
    let mut domains: BTreeMap<String, Spoofed> = BTreeMap::new();
    for inner in received(server, ObjectType::DmarcExternalReport, tenant, from, to).await? {
        let ObjectInner::DmarcExternalReport(r) = inner else {
            continue;
        };
        for record in r.report.records.iter() {
            let passed = record.evaluated_dkim == DmarcResult::Pass
                || record.evaluated_spf == DmarcResult::Pass
                || record.dkim_results.iter().any(|d| {
                    d.result == DkimAuthResult::Pass
                        && d.domain.eq_ignore_ascii_case(&r.report.policy_domain)
                });
            if passed {
                continue;
            }
            let d = domains
                .entry(r.report.policy_domain.to_lowercase())
                .or_default();
            d.failed += record.count;
            match record.evaluated_disposition {
                DmarcActionDisposition::Reject => d.rejected += record.count,
                DmarcActionDisposition::Quarantine => d.quarantined += record.count,
                _ => d.delivered += record.count,
            }
            let source = record
                .source_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "unknown".into());
            *d.sources.entry(source).or_default() += record.count;
        }
    }
    domains.retain(|_, d| d.failed > 0);
    if domains.is_empty() {
        return Ok(None);
    }
    let mut lines = Vec::new();
    let mut rows = Vec::new();
    for (domain, d) in &domains {
        attention.push(format!(
            "{} said {} from {} and couldn't prove it",
            plural(d.failed, "message", "messages"),
            if d.failed == 1 { "it was" } else { "they were" },
            domain
        ));
        let mut top: Vec<_> = d.sources.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        lines.push(format!(
            "{domain}: {} failed from {}; receivers delivered {}, sent {} to spam and rejected {}.",
            plural(d.failed, "message", "messages"),
            plural(d.sources.len() as u64, "server", "servers"),
            number(d.delivered),
            number(d.quarantined),
            number(d.rejected)
        ));
        lines.push(format!(
            "  Most from: {}",
            top.iter()
                .take(3)
                .map(|(ip, n)| format!("{ip} ({})", number(**n)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        for (ip, n) in &d.sources {
            rows.push(vec![domain.clone(), ip.clone(), n.to_string()]);
        }
    }
    Ok(Some(Part {
        title: "Mail pretending to be you",
        lines,
        csv: Some((
            "spoofing.csv".into(),
            csv(&["domain", "source_ip", "failed_messages"], &rows),
        )),
        link: "Management/x:DmarcExternalReport",
    }))
}

fn tls_kind(kind: TlsResultType) -> &'static str {
    match kind {
        TlsResultType::StartTlsNotSupported => "the server didn't offer encryption",
        TlsResultType::CertificateHostMismatch => "the certificate doesn't cover the MX name",
        TlsResultType::CertificateExpired => "the certificate had expired",
        TlsResultType::CertificateNotTrusted => "the certificate wasn't trusted",
        TlsResultType::ValidationFailure => "the certificate couldn't be validated",
        TlsResultType::TlsaInvalid => "DANE (TLSA) records don't match",
        TlsResultType::DnssecInvalid => "DNSSEC didn't validate",
        TlsResultType::DaneRequired => "DANE was required but unavailable",
        TlsResultType::StsPolicyFetchError => "the MTA-STS policy couldn't be fetched",
        TlsResultType::StsPolicyInvalid => "the MTA-STS policy is invalid",
        TlsResultType::StsWebpkiInvalid => "the MTA-STS site's certificate wasn't valid",
        _ => "another TLS problem",
    }
}

/// RP-4.
async fn tls_failures(
    server: &Server,
    tenant: Option<u32>,
    from: u64,
    to: u64,
    attention: &mut Vec<String>,
) -> trc::Result<Option<Part>> {
    let mut domains: BTreeMap<String, BTreeMap<&'static str, u64>> = BTreeMap::new();
    let mut rows = Vec::new();
    for inner in received(server, ObjectType::TlsExternalReport, tenant, from, to).await? {
        let ObjectInner::TlsExternalReport(r) = inner else {
            continue;
        };
        for policy in r.report.policies.iter() {
            for failure in policy.failure_details.iter() {
                if failure.failed_session_count == 0 {
                    continue;
                }
                let kind = tls_kind(failure.result_type);
                *domains
                    .entry(policy.policy_domain.to_lowercase())
                    .or_default()
                    .entry(kind)
                    .or_default() += failure.failed_session_count;
                rows.push(vec![
                    policy.policy_domain.to_lowercase(),
                    failure.result_type.as_str().to_string(),
                    failure.failed_session_count.to_string(),
                    failure.receiving_mx_hostname.clone().unwrap_or_default(),
                ]);
            }
        }
    }
    if domains.is_empty() {
        return Ok(None);
    }
    let mut lines = Vec::new();
    for (domain, kinds) in &domains {
        let total: u64 = kinds.values().sum();
        attention.push(format!(
            "{} to {} failed TLS",
            plural(total, "delivery", "deliveries"),
            domain
        ));
        for (kind, n) in kinds {
            lines.push(format!(
                "{domain}: {kind} ({})",
                plural(*n, "connection", "connections")
            ));
        }
    }
    Ok(Some(Part {
        title: "Secure delivery to you",
        lines,
        csv: Some((
            "tls-failures.csv".into(),
            csv(&["domain", "result", "failed_sessions", "mx"], &rows),
        )),
        link: "Management/x:TlsExternalReport",
    }))
}

/// RP-5: the server-side list of what counts as a Fail, keyed so the next
/// run can say what changed.
fn failing_facts(reports: &[dlv::Report]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for report in reports {
        for a in &report.addresses {
            for l in a
                .listings
                .iter()
                .filter(|l| l.state == ListingState::Listed)
            {
                out.insert(
                    format!("ip:{}:list:{}", a.ip, l.list),
                    format!("{} ({}) is listed on {}", a.ip, report.hostname, l.list),
                );
            }
            if a.ptr.is_empty() {
                out.insert(
                    format!("ip:{}:ptr", a.ip),
                    format!("{} ({}) has no reverse DNS", a.ip, report.hostname),
                );
            } else if !a.forward_confirmed {
                out.insert(
                    format!("ip:{}:fcrdns", a.ip),
                    format!("{}'s reverse DNS doesn't point back to it", a.ip),
                );
            }
        }
        for d in &report.domains {
            for l in d
                .listings
                .iter()
                .filter(|l| l.state == ListingState::Listed)
            {
                out.insert(
                    format!("domain:{}:list:{}", d.domain, l.list),
                    format!("{} is listed on {}", d.domain, l.list),
                );
            }
            for s in d.spf.iter().filter(|s| s.result != "pass") {
                out.insert(
                    format!("domain:{}:spf:{}", d.domain, s.ip),
                    format!("SPF for {} doesn't let {} send", d.domain, s.ip),
                );
            }
            for k in &d.dkim {
                match k.state {
                    DkimState::Missing => {
                        out.insert(
                            format!("domain:{}:dkim:{}", d.domain, k.selector),
                            format!("{}'s DKIM key {} isn't in DNS", d.domain, k.selector),
                        );
                    }
                    DkimState::Different => {
                        out.insert(
                            format!("domain:{}:dkim:{}", d.domain, k.selector),
                            format!(
                                "{}'s DKIM key {} in DNS isn't the one signing",
                                d.domain, k.selector
                            ),
                        );
                    }
                    _ => {}
                }
            }
            if d.mta_sts.record_id.is_some() && !d.mta_sts.fetched {
                out.insert(
                    format!("domain:{}:mta-sts", d.domain),
                    format!("{}'s MTA-STS policy can't be fetched", d.domain),
                );
            }
        }
        for c in report.certificates.iter().filter(|c| !c.covered) {
            out.insert(
                format!("cert:{}", c.name),
                format!("No certificate covers {}", c.name),
            );
        }
    }
    out
}

async fn deliverability(
    server: &Server,
    tenant: Option<u32>,
    before: &[String],
    attention: &mut Vec<String>,
) -> trc::Result<(Option<Part>, Vec<String>)> {
    let mut reports = dlv::reports(server.store()).await?;
    if let Some(tenant) = tenant {
        reports = reports.iter().map(|r| r.for_tenant(tenant)).collect();
    }
    let now = failing_facts(&reports);
    let before: BTreeSet<&str> = before.iter().map(|s| s.as_str()).collect();
    let mut lines = Vec::new();
    let mut rows = Vec::new();
    for (key, text) in &now {
        let new = !before.contains(key.as_str());
        if new {
            attention.push(format!("Deliverability: {text}"));
        }
        lines.push(format!("{}{text}", if new { "New: " } else { "Still: " }));
        rows.push(vec![
            key.clone(),
            text.clone(),
            if new { "new" } else { "still" }.into(),
        ]);
    }
    for key in before.iter().filter(|k| !now.contains_key(**k)) {
        lines.push(format!("Fixed: {key}"));
        rows.push(vec![key.to_string(), String::new(), "fixed".into()]);
    }
    let failing = now.keys().cloned().collect();
    if lines.is_empty() {
        return Ok((None, failing));
    }
    Ok((
        Some(Part {
            title: "Deliverability",
            lines,
            csv: Some((
                "deliverability.csv".into(),
                csv(&["finding", "detail", "change"], &rows),
            )),
            link: "Management/CustomComponent/Deliverability",
        }),
        failing,
    ))
}

/// RP-6.
async fn security(server: &Server, from: u64, to: u64) -> trc::Result<Option<Part>> {
    const NAMES: [&str; 6] = [
        "auth.failed",
        "security.authentication-ban",
        "security.abuse-ban",
        "security.scan-ban",
        "security.loiter-ban",
        "security.ip-blocked",
    ];
    let len = to - from;
    let now = counters(server, from, to, &NAMES).await?;
    let before = counters(server, from.saturating_sub(len), from, &NAMES).await?;
    if now.iter().all(|n| *n == 0) {
        return Ok(None);
    }
    let bans: u64 = now[1..5].iter().sum();
    let bans_before: u64 = before[1..5].iter().sum();
    let mut lines = Vec::new();
    if now[0] > 0 {
        lines.push(format!(
            "Failed sign-ins: {}{}",
            number(now[0]),
            change(now[0], before[0])
        ));
    }
    if bans > 0 {
        lines.push(format!(
            "Addresses banned: {}{} (sign-in {}, abuse {}, scanning {}, loitering {})",
            number(bans),
            change(bans, bans_before),
            number(now[1]),
            number(now[2]),
            number(now[3]),
            number(now[4])
        ));
    }
    if now[5] > 0 {
        lines.push(format!(
            "Connections from blocked addresses: {}{}",
            number(now[5]),
            change(now[5], before[5])
        ));
    }
    Ok(Some(Part {
        title: "Security",
        lines,
        csv: None,
        link: "Management/CustomComponent/Dashboard",
    }))
}

/// RP-7.
async fn storage(
    server: &Server,
    tenant: Option<u32>,
    from: u64,
    to: u64,
    attention: &mut Vec<String>,
) -> trc::Result<Option<Part>> {
    let mut full = Vec::new();
    let mut domains = DomainNames::default();
    for id in server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Account))
        .await?
    {
        let Some(Account::User(user)) = server.registry().object::<Account>(id).await? else {
            continue;
        };
        if let Some(tenant) = tenant
            && user.member_tenant_id != Some(Id::from(tenant))
        {
            continue;
        }
        let Some(limit) = user
            .quotas
            .get(&StorageQuota::MaxDiskQuota)
            .copied()
            .filter(|q| *q > 0)
        else {
            continue;
        };
        let used = server.get_used_quota_account(id.id() as u32).await?.max(0) as u64;
        if (used as f64) / (limit as f64) >= QUOTA_WARN {
            let domain = domains
                .get(server, user.domain_id)
                .await?
                .unwrap_or_default();
            full.push((format!("{}@{}", user.name, domain), used, limit));
        }
    }
    full.sort_by(|a, b| {
        (b.1 as f64 / b.2 as f64)
            .partial_cmp(&(a.1 as f64 / a.2 as f64))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut lines = Vec::new();
    if !full.is_empty() {
        attention.push(format!(
            "{} at 90% or more of their storage",
            plural(full.len() as u64, "person is", "people are")
        ));
        for (address, used, limit) in full.iter().take(10) {
            lines.push(format!(
                "{address}: {:.0}% full ({} of {})",
                *used as f64 / *limit as f64 * 100.0,
                size(*used),
                size(*limit)
            ));
        }
        if full.len() > 10 {
            lines.push(format!(
                "…and {} more (in the attachment).",
                full.len() - 10
            ));
        }
    }
    if tenant.is_none() {
        for (name, what) in [("user.count", "people"), ("domain.count", "domains")] {
            if let Some((first, last)) = gauge(server, from, to, name).await?
                && first != last
            {
                lines.push(format!(
                    "{}: {} (was {})",
                    if what == "people" {
                        "People"
                    } else {
                        "Domains"
                    },
                    number(last),
                    number(first)
                ));
            }
        }
    }
    if lines.is_empty() {
        return Ok(None);
    }
    let rows: Vec<_> = full
        .iter()
        .map(|(a, u, l)| vec![a.clone(), u.to_string(), l.to_string()])
        .collect();
    Ok(Some(Part {
        title: "Storage",
        lines,
        csv: (!rows.is_empty()).then(|| {
            (
                "storage.csv".into(),
                csv(&["address", "used_bytes", "limit_bytes"], &rows),
            )
        }),
        link: "Management/x:Account/User",
    }))
}

fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// RP-8.
async fn certificates(
    server: &Server,
    to: u64,
    attention: &mut Vec<String>,
) -> trc::Result<Option<Part>> {
    let mut soon = Vec::new();
    for id in server
        .registry()
        .query::<Vec<Id>>(RegistryQuery::new(ObjectType::Certificate))
        .await?
    {
        let Some(cert) = server.registry().object::<Certificate>(id).await? else {
            continue;
        };
        let expires = cert.not_valid_after.timestamp().max(0) as u64;
        if expires < to + CERT_DAYS * 86_400 {
            let name = cert
                .subject_alternative_names
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| "a certificate".into());
            soon.push((name, expires));
        }
    }
    if soon.is_empty() {
        return Ok(None);
    }
    soon.sort_by_key(|(_, at)| *at);
    let mut lines = Vec::new();
    for (name, at) in &soon {
        let days = at.saturating_sub(to) / 86_400;
        let line = if *at <= to {
            format!("{name}: expired")
        } else {
            format!("{name}: expires in {}", plural(days, "day", "days"))
        };
        attention.push(format!("Certificate {line}"));
        lines.push(line);
    }
    Ok(Some(Part {
        title: "Certificates",
        lines,
        csv: None,
        link: "Settings/x:Certificate",
    }))
}

/// RP-19: the report for a period as files, without mailing anyone: the
/// summary as text, and a CSV for each section that has rows. A download
/// doesn't move the deliverability baseline the next mail compares with.
pub async fn export_files(
    server: &Server,
    report: &Report,
    from: u64,
    to: u64,
) -> trc::Result<Vec<(String, Vec<u8>)>> {
    let built = build(server, report, from, to).await?;
    let mut summary = format!("{}\n{}\n\n", report.name, model::period_label(from, to));
    if built.parts.is_empty() {
        summary.push_str("Nothing to report for this period.\n");
    }
    for part in &built.parts {
        summary.push_str(&format!("{}\n", part.title));
        for line in &part.lines {
            summary.push_str(&format!("  {line}\n"));
        }
        summary.push('\n');
    }
    let mut files = vec![("summary.txt".to_string(), summary.into_bytes())];
    for part in built.parts {
        if let Some((name, body)) = part.csv {
            files.push((name, body.into_bytes()));
        }
    }
    Ok(files)
}

// --- The mail -------------------------------------------------------------

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn compose(
    report: &Report,
    built: &Built,
    from: u64,
    to: u64,
    from_name: &str,
    from_address: &str,
    recipients: &[String],
) -> Vec<u8> {
    let period = model::period_label(from, to);
    let admin = std::env::var("INBUXA_ADMIN_URL")
        .ok()
        .map(|u| u.trim_end_matches('/').to_string())
        .filter(|u| u.starts_with("https://") || u.starts_with("http://"));
    let mut text = String::new();
    let mut html = String::from(
        "<div style=\"font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:640px;color:#16262f;line-height:1.5\">",
    );
    html.push_str(&format!(
        "<h1 style=\"font-size:20px;margin:0 0 4px\">{}</h1><p style=\"margin:0 0 16px;color:#5f6b73\">{}</p>",
        escape(&report.name),
        escape(&period)
    ));
    text.push_str(&format!("{}\n{}\n\n", report.name, period));

    if built.parts.is_empty() {
        // RP-9, Decision 6
        let line = "Nothing to report for this period.";
        text.push_str(line);
        text.push('\n');
        html.push_str(&format!("<p>{line}</p>"));
    } else {
        if !built.attention.is_empty() {
            text.push_str("Needs your attention\n");
            html.push_str("<div style=\"border:1px solid #d9383a;border-radius:8px;padding:12px 16px;margin-bottom:16px\"><strong>Needs your attention</strong><ul style=\"margin:6px 0 0;padding-left:20px\">");
            for line in &built.attention {
                text.push_str(&format!("- {line}\n"));
                html.push_str(&format!("<li>{}</li>", escape(line)));
            }
            text.push('\n');
            html.push_str("</ul></div>");
        }
        for part in &built.parts {
            text.push_str(&format!("{}\n", part.title));
            html.push_str(&format!(
                "<h2 style=\"font-size:16px;margin:20px 0 6px\">{}</h2><ul style=\"margin:0;padding-left:20px\">",
                escape(part.title)
            ));
            for line in &part.lines {
                text.push_str(&format!("  {line}\n"));
                html.push_str(&format!("<li>{}</li>", escape(line)));
            }
            html.push_str("</ul>");
            if let Some(admin) = &admin {
                let url = format!("{admin}/{}", part.link);
                text.push_str(&format!("  {url}\n"));
                html.push_str(&format!(
                    "<p style=\"margin:4px 0 0\"><a href=\"{}\">Open in the console</a></p>",
                    escape(&url)
                ));
            }
            text.push('\n');
        }
    }
    let footer = "Sent by your inbuxa server. Change or turn off this report in the console under Reports › Scheduled reports.";
    text.push_str(&format!("--\n{footer}\n"));
    html.push_str(&format!(
        "<p style=\"margin-top:24px;font-size:12px;color:#5f6b73\">{footer}</p></div>"
    ));

    let mut builder = MessageBuilder::new()
        .from(Address::new_address(
            Some(from_name.to_string()),
            from_address.to_string(),
        ))
        .to(recipients
            .iter()
            .map(|r| Address::new_address(None::<String>, r.clone()))
            .collect::<Vec<_>>())
        .subject(format!("{}: {}", report.name, period))
        .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
        .text_body(text)
        .html_body(html);
    if report.attach_csv {
        for part in &built.parts {
            if let Some((name, body)) = &part.csv {
                builder = builder.attachment("text/csv", name.clone(), body.clone().into_bytes());
            }
        }
    }
    builder.write_to_vec().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use inbuxa_features::deliverability::{
        Address as DlvAddress, DomainReport, Listing, SpfResult,
    };

    #[test]
    fn numbers_and_changes() {
        assert_eq!(number(1234567), "1,234,567");
        assert_eq!(number(12), "12");
        assert_eq!(change(110, 100), " (up 10%)");
        assert_eq!(change(50, 100), " (down 50%)");
        assert_eq!(change(5, 0), "");
        assert_eq!(plural(1, "message", "messages"), "1 message");
        assert_eq!(size(1536), "1.5 KB");
    }

    #[test]
    fn csv_quotes_what_needs_it() {
        assert_eq!(
            csv(&["a", "b"], &[vec!["x,y".into(), "say \"hi\"".into()]]),
            "a,b\r\n\"x,y\",\"say \"\"hi\"\"\"\r\n"
        );
    }

    #[test]
    fn failing_facts_are_keyed_for_changes() {
        let report = dlv::Report {
            node_id: 1,
            hostname: "mx.example.org".into(),
            addresses: vec![DlvAddress {
                ip: "192.0.2.1".into(),
                ptr: vec![],
                listings: vec![Listing {
                    list: "Spamhaus ZEN".into(),
                    state: ListingState::Listed,
                    ..Listing::default()
                }],
                ..DlvAddress::default()
            }],
            domains: vec![DomainReport {
                domain: "example.org".into(),
                spf: vec![SpfResult {
                    ip: "192.0.2.1".into(),
                    result: "fail".into(),
                }],
                ..DomainReport::default()
            }],
            ..dlv::Report::default()
        };
        let facts = failing_facts(&[report]);
        assert_eq!(
            facts.keys().cloned().collect::<Vec<_>>(),
            vec![
                "domain:example.org:spf:192.0.2.1",
                "ip:192.0.2.1:list:Spamhaus ZEN",
                "ip:192.0.2.1:ptr"
            ]
        );
    }

    #[test]
    fn quiet_period_mail_says_so() {
        let report = model::Report::digest(0);
        let built = Built {
            attention: vec![],
            parts: vec![],
            failing: None,
        };
        let raw = compose(
            &report,
            &built,
            1_790_000_000,
            1_790_604_800,
            "inbuxa reports",
            "postmaster@example.org",
            &["admin@example.org".into()],
        );
        let message = mail_parser::MessageParser::default().parse(&raw).unwrap();
        assert!(message.subject().unwrap().starts_with("Weekly digest: "));
        assert!(
            message
                .body_text(0)
                .unwrap()
                .contains("Nothing to report for this period.")
        );
        assert!(String::from_utf8_lossy(&raw).contains("Auto-Submitted: auto-generated"));
    }
}
