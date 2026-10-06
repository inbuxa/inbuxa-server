/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Live tracing and live metrics (monitoring spec MON-20 to MON-24), in the
//! shapes INBUXA Admin reads: `event: trace` frames of `x:TraceEvent`s, and
//! `event: metrics` frames of `{@type, metric, count[, sum]}` totals.

use common::telemetry::tracers::TraceEvents;
use http_body_util::{StreamBody, combinators::BoxBody};
use http_proto::HttpResponse;
use hyper::{StatusCode, body::Bytes};
use hyper::body::Frame;
use registry::{jmap::IntoValue, schema::structs::Trace};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use trc::{
    Collector, EventType, Key, MetricType,
    ipc::subscriber::{Interests, SubscriberBuilder},
};
use utils::url_params::UrlParams;

/// Live streams at once per node (MON-24).
const MAX_STREAMS: usize = 8;
/// How long one stream lasts (MON-24).
const STREAM_LIFETIME: Duration = Duration::from_secs(30 * 60);
/// The idle keep-alive (observed upstream: 30 s).
const PING_INTERVAL: Duration = Duration::from_secs(30);

static STREAMS: AtomicUsize = AtomicUsize::new(0);

/// A stream slot, freed when the stream ends.
struct Slot;

impl Slot {
    fn take() -> Option<Slot> {
        STREAMS
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_STREAMS).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        STREAMS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Removes the live subscriber when the stream ends.
struct Subscription(String);

impl Drop for Subscription {
    fn drop(&mut self) {
        Collector::remove_subscriber(std::mem::take(&mut self.0));
    }
}

/// Live telemetry is server-level: nobody inside a tenant sees it (MON-31).
pub fn assert_server_level(access_token: &common::auth::AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::SecurityEvent::Unauthorized
            .into_err()
            .details("Live telemetry is server-level"))
    } else {
        Ok(())
    }
}

fn too_many() -> trc::Error {
    trc::LimitEvent::ConcurrentRequest
        .into_err()
        .details("Too many live telemetry streams")
}

fn frame(event: &str, data: String) -> Frame<Bytes> {
    Frame::data(Bytes::from(format!("event: {event}\ndata: {data}\n\n")))
}

fn event_stream(body: BoxBody<Bytes, hyper::Error>) -> HttpResponse {
    HttpResponse::new(StatusCode::OK)
        .with_content_type("text/event-stream")
        .with_cache_control("no-store")
        .with_stream_body(body)
}

/// A `Key` from its camel-case name, or the hyphenated one upstream's docs
/// use (`remote-ip`), MON-20.
fn parse_key(name: &str) -> Option<Key> {
    Key::parse(name).or_else(|| {
        let mut camel = String::with_capacity(name.len());
        let mut upper = false;
        for c in name.chars() {
            if c == '-' || c == '_' {
                upper = true;
            } else if upper {
                camel.extend(c.to_uppercase());
                upper = false;
            } else {
                camel.push(c);
            }
        }
        Key::parse(&camel)
    })
}

fn value_text(value: &trc::Value) -> String {
    match value {
        trc::Value::String(v) => v.to_string(),
        trc::Value::UInt(v) => v.to_string(),
        trc::Value::Int(v) => v.to_string(),
        trc::Value::Ipv4(v) => v.to_string(),
        trc::Value::Ipv6(v) => v.to_string(),
        trc::Value::Bool(v) => v.to_string(),
        trc::Value::Bytes(v) => String::from_utf8_lossy(v).into_owned(),
        trc::Value::Array(values) => values.iter().map(value_text).collect::<Vec<_>>().join(","),
        _ => String::new(),
    }
}

/// `GET /api/live/tracing` (MON-20, MON-21).
pub fn live_tracing(query: Option<&str>) -> trc::Result<HttpResponse> {
    let slot = Slot::take().ok_or_else(too_many)?;

    // Filters: `filter` anywhere, a key name for that key only; all must hold
    let mut anywhere = None;
    let mut by_key = Vec::new();
    for (name, value) in http_proto::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        let value = value.to_lowercase();
        let name = name.as_ref();
        if name == "filter" {
            anywhere = Some(value);
        } else if name != "token"
            && let Some(key) = parse_key(name)
        {
            by_key.push((key, value));
        }
    }

    // Every event but raw I/O (MON-21)
    let mut interests = Interests::default();
    for event in EventType::variants() {
        if !event.is_raw_io() {
            interests.set(event.to_id() as usize);
        }
    }
    let id = format!("live-tracing-{}", store::rand::random::<u64>());
    let (_, mut rx) = SubscriberBuilder::new(id.clone())
        .with_interests(interests.clone())
        .with_lossy(true)
        .register();
    Collector::union_interests(interests);
    Collector::reload();
    let subscription = Subscription(id);

    Ok(event_stream(BoxBody::new(StreamBody::new(async_stream::stream! {
        let _slot = slot;
        let _subscription = subscription;
        let ends = Instant::now() + STREAM_LIFETIME;
        loop {
            let wait = PING_INTERVAL.min(ends.saturating_duration_since(Instant::now()));
            if wait.is_zero() {
                break;
            }
            match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(events)) => {
                    let matching = events
                        .iter()
                        .filter(|event| {
                            let texts = event
                                .keys
                                .iter()
                                .map(|(key, value)| (*key, value_text(value).to_lowercase()))
                                .collect::<Vec<_>>();
                            anywhere.as_ref().is_none_or(|needle| {
                                texts.iter().any(|(_, text)| text.contains(needle.as_str()))
                            }) && by_key.iter().all(|(key, needle)| {
                                texts.iter().any(|(k, text)| k == key && text == needle)
                            })
                        })
                        .map(|event| event.as_ref())
                        .collect::<Vec<_>>();
                    if !matching.is_empty() {
                        let events = Trace::build_trace_events(matching.iter().copied(), matching.len())
                            .into_iter()
                            .map(|event| event.into_value())
                            .collect::<Vec<_>>();
                        yield Ok(frame("trace", serde_json::to_string(&events).unwrap_or_default()));
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    if Instant::now() >= ends {
                        break;
                    }
                    yield Ok(frame("ping", format!("{{\"interval\": {}}}", PING_INTERVAL.as_millis())));
                }
            }
        }
    }))))
}

/// The current totals of the named metrics, all when `names` is empty, in
/// the `{@type, metric, count[, sum]}` shape (MON-22).
fn metric_frame(names: &[MetricType]) -> String {
    let wants = |metric: MetricType| names.is_empty() || names.contains(&metric);
    let mut out = Vec::new();
    for counter in Collector::collect_counters() {
        if let Some(metric) = MetricType::parse(counter.id().as_str())
            && wants(metric)
        {
            out.push(serde_json::json!({
                "@type": "Counter", "metric": metric.as_str(), "count": counter.value()
            }));
        }
    }
    for gauge in Collector::collect_gauges() {
        if wants(gauge.id()) {
            out.push(serde_json::json!({
                "@type": "Gauge", "metric": gauge.id().as_str(), "count": gauge.get()
            }));
        }
    }
    for histogram in Collector::collect_histograms() {
        if wants(histogram.id()) {
            out.push(serde_json::json!({
                "@type": "Histogram", "metric": histogram.id().as_str(),
                "count": histogram.count(), "sum": histogram.sum()
            }));
        }
    }
    serde_json::to_string(&out).unwrap_or_default()
}

/// `GET /api/live/metrics` (MON-22).
pub fn live_metrics(params: &UrlParams<'_>) -> trc::Result<HttpResponse> {
    let slot = Slot::take().ok_or_else(too_many)?;
    let names = params
        .get("metrics")
        .map(|list| {
            list.split(',')
                .filter_map(|name| MetricType::parse(name.trim()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let interval = Duration::from_secs(
        params
            .parse::<u64>("interval")
            .filter(|interval| *interval >= 1)
            .unwrap_or(30),
    );
    Ok(event_stream(BoxBody::new(StreamBody::new(async_stream::stream! {
        let _slot = slot;
        let ends = Instant::now() + STREAM_LIFETIME;
        while Instant::now() < ends {
            yield Ok(frame("metrics", metric_frame(&names)));
            tokio::time::sleep(interval).await;
        }
    }))))
}
