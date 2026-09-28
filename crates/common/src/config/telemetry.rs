/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::config::storage::Storage;
use ahash::{AHashMap, AHashSet};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::HeaderMap;
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_otlp::{
    LogExporter, MetricExporter, SpanExporter, WithExportConfig, WithHttpConfig,
};
use opentelemetry_sdk::{Resource, metrics::Temporality};
use opentelemetry_semantic_conventions::resource::SERVICE_VERSION;
use registry::schema::{
    enums::{EventPolicy, LogRotateFrequency},
    prelude::ObjectType,
    structs::{self, EventTracingLevel, MetricsPrometheus, Tracer, WebHook},
};
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};
use store::registry::bootstrap::Bootstrap;
use trc::{EventType, Level, MetricType, TelemetryEvent, ipc::subscriber::Interests};

#[derive(Debug)]
pub struct TelemetrySubscriber {
    pub id: String,
    pub interests: Interests,
    pub typ: TelemetrySubscriberType,
    pub lossy: bool,
    /// inbuxa: a hash of the settings the running tracer is built from
    /// (everything but its events, level and lossiness, which change in
    /// place), so a reload can tell which tracers to start over.
    pub settings: u64,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum TelemetrySubscriberType {
    ConsoleTracer(ConsoleTracer),
    LogTracer(LogTracer),
    OtelTracer(OtelTracer),
    Webhook(WebhookTracer),
    #[cfg(unix)]
    JournalTracer(crate::telemetry::tracers::journald::Subscriber),
    // inbuxa: MON-10: trace history
    StoreTracer(StoreTracer),
}

/// Where trace history goes: traces to `tracing`, index tasks to `data`.
#[derive(Debug)]
pub struct StoreTracer {
    pub tracing: store::Store,
    pub data: store::Store,
}

#[derive(Debug)]
pub struct OtelTracer {
    pub span_exporter: SpanExporter,
    pub span_exporter_enable: bool,
    pub log_exporter: LogExporter,
    pub log_exporter_enable: bool,
    pub throttle: Duration,
}

pub struct OtelMetrics {
    pub resource: Resource,
    pub instrumentation: InstrumentationScope,
    pub exporter: MetricExporter,
    pub interval: Duration,
}

#[derive(Debug)]
pub struct ConsoleTracer {
    pub ansi: bool,
    pub multiline: bool,
    pub buffered: bool,
}

#[derive(Debug)]
pub struct LogTracer {
    pub path: String,
    pub prefix: String,
    pub rotate: RotationStrategy,
    pub ansi: bool,
    pub multiline: bool,
}

#[derive(Debug)]
pub struct WebhookTracer {
    pub url: String,
    pub key: String,
    pub timeout: Duration,
    pub throttle: Duration,
    pub discard_after: Duration,
    pub tls_allow_invalid_certs: bool,
    pub headers: HeaderMap,
    pub client: reqwest::Client,
}


#[derive(Debug)]
pub enum RotationStrategy {
    Daily,
    Hourly,
    Minutely,
    Never,
}

#[derive(Debug)]
pub struct Telemetry {
    pub tracers: Tracers,
    pub metrics: Interests,
}

#[derive(Debug)]
pub struct Tracers {
    pub interests: Interests,
    pub levels: AHashMap<EventType, Level>,
    pub subscribers: Vec<TelemetrySubscriber>,
}

#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub prometheus: Option<PrometheusMetrics>,
    pub otel: Option<Arc<OtelMetrics>>,
    pub log_path: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PrometheusMetrics {
    pub auth: Option<String>,
}

impl Telemetry {
    pub async fn parse(bp: &mut Bootstrap, storage: &Storage) -> Self {
        let mut telemetry = Telemetry {
            tracers: Tracers::parse(bp, storage).await,
            metrics: Interests::default(),
        };

        // Parse metrics
        let metrics = bp.setting_infallible::<structs::Metrics>().await;
        apply_metrics(metrics.metrics, metrics.metrics_policy, |metric_type| {
            let event_id = metric_type.event_id();
            if event_id != usize::MAX {
                telemetry.metrics.set(event_id);
            }
        });

        telemetry
    }
}

impl Tracers {
    pub async fn parse(bp: &mut Bootstrap, storage: &Storage) -> Self {
        let mut custom_levels = AHashMap::new();
        let mut tracers: Vec<TelemetrySubscriber> = Vec::new();
        let mut global_interests = Interests::default();

        if !bp.registry.is_recovery_mode() {
            // Parse custom logging levels
            for level in bp.list_infallible::<EventTracingLevel>().await {
                custom_levels.insert(level.object.event, level.object.level.into());
            }

            // Parse tracers
            for tracer in bp.list_infallible::<Tracer>().await {
                let id = tracer.id;
                let tracer = tracer.object;
                let settings = tracer_settings(&tracer);
                let level;
                let lossy;
                let events;
                let events_policy;
                let enable;

                let typ = match tracer {
                    Tracer::Log(tracer) if tracer.enable => {
                        level = Level::from(tracer.level);
                        lossy = tracer.lossy;
                        events = tracer.events;
                        events_policy = tracer.events_policy;
                        enable = tracer.enable;

                        TelemetrySubscriberType::LogTracer(LogTracer {
                            path: tracer.path,
                            prefix: tracer.prefix,
                            rotate: match tracer.rotate {
                                LogRotateFrequency::Daily => RotationStrategy::Daily,
                                LogRotateFrequency::Hourly => RotationStrategy::Hourly,
                                LogRotateFrequency::Minutely => RotationStrategy::Minutely,
                                LogRotateFrequency::Never => RotationStrategy::Never,
                            },
                            ansi: tracer.ansi,
                            multiline: tracer.multiline,
                        })
                    }
                    Tracer::Stdout(tracer) if tracer.enable => {
                        level = Level::from(tracer.level);
                        lossy = tracer.lossy;
                        events = tracer.events;
                        events_policy = tracer.events_policy;
                        enable = tracer.enable;

                        if !tracers
                            .iter()
                            .any(|t| matches!(t.typ, TelemetrySubscriberType::ConsoleTracer(_)))
                        {
                            TelemetrySubscriberType::ConsoleTracer(ConsoleTracer {
                                ansi: tracer.ansi,
                                multiline: tracer.multiline,
                                buffered: tracer.buffered,
                            })
                        } else {
                            bp.build_error(id, "Only one console tracer is allowed");
                            continue;
                        }
                    }
                    Tracer::Journal(tracer) if tracer.enable => {
                        #[cfg(unix)]
                        {
                            level = Level::from(tracer.level);
                            lossy = tracer.lossy;
                            events = tracer.events;
                            events_policy = tracer.events_policy;
                            enable = tracer.enable;

                            if !tracers
                                .iter()
                                .any(|t| matches!(t.typ, TelemetrySubscriberType::JournalTracer(_)))
                            {
                                match crate::telemetry::tracers::journald::Subscriber::new() {
                                    Ok(subscriber) => {
                                        TelemetrySubscriberType::JournalTracer(subscriber)
                                    }
                                    Err(e) => {
                                        bp.build_error(
                                            id,
                                            format!("Failed to create journald subscriber: {e}"),
                                        );
                                        continue;
                                    }
                                }
                            } else {
                                bp.build_error(id, "Only one journal tracer is allowed");
                                continue;
                            }
                        }

                        #[cfg(not(unix))]
                        {
                            bp.build_error(id, "Journald is only available on Unix systems.");
                            continue;
                        }
                    }
                    Tracer::OtelHttp(tracer) if tracer.enable => {
                        level = Level::from(tracer.level);
                        lossy = tracer.lossy;
                        events = tracer.events;
                        events_policy = tracer.events_policy;
                        enable = tracer.enable;

                        let headers = match tracer
                            .http_auth
                            .build_headers(tracer.http_headers, None)
                            .await
                        {
                            Ok(headers) => headers
                                .into_iter()
                                .filter_map(|(k, v)| {
                                    k.and_then(|k| {
                                        Some((k.to_string(), v.to_str().ok()?.to_string()))
                                    })
                                })
                                .collect::<HashMap<String, String>>(),
                            Err(err) => {
                                bp.build_error(
                                    id,
                                    format!("Failed to build OpenTelemetry HTTP headers: {err}"),
                                );
                                continue;
                            }
                        };

                        let mut span_exporter = SpanExporter::builder()
                            .with_http()
                            .with_endpoint(tracer.endpoint.clone())
                            .with_timeout(tracer.timeout.into_inner());
                        let mut log_exporter = LogExporter::builder()
                            .with_http()
                            .with_endpoint(tracer.endpoint)
                            .with_timeout(tracer.timeout.into_inner());
                        if !headers.is_empty() {
                            span_exporter = span_exporter.with_headers(headers.clone());
                            log_exporter = log_exporter.with_headers(headers);
                        }

                        match (span_exporter.build(), log_exporter.build()) {
                            (Ok(span_exporter), Ok(log_exporter)) => {
                                TelemetrySubscriberType::OtelTracer(OtelTracer {
                                    span_exporter,
                                    log_exporter,
                                    throttle: tracer.throttle.into_inner(),
                                    span_exporter_enable: tracer.enable_span_exporter,
                                    log_exporter_enable: tracer.enable_log_exporter,
                                })
                            }
                            (Err(err), _) => {
                                bp.build_error(
                                    id,
                                    format!("Failed to build OpenTelemetry span exporter: {err}"),
                                );
                                continue;
                            }
                            (_, Err(err)) => {
                                bp.build_error(
                                    id,
                                    format!("Failed to build OpenTelemetry log exporter: {err}"),
                                );
                                continue;
                            }
                        }
                    }
                    Tracer::OtelGrpc(tracer) if tracer.enable => {
                        level = Level::from(tracer.level);
                        lossy = tracer.lossy;
                        events = tracer.events;
                        events_policy = tracer.events_policy;
                        enable = tracer.enable;

                        let mut span_exporter = SpanExporter::builder()
                            .with_tonic()
                            .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                            .with_timeout(tracer.timeout.into_inner());
                        let mut log_exporter = LogExporter::builder()
                            .with_tonic()
                            .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                            .with_timeout(tracer.timeout.into_inner());
                        if let Some(endpoint) = tracer.endpoint {
                            span_exporter = span_exporter.with_endpoint(endpoint.clone());
                            log_exporter = log_exporter.with_endpoint(endpoint);
                        }

                        match (span_exporter.build(), log_exporter.build()) {
                            (Ok(span_exporter), Ok(log_exporter)) => {
                                TelemetrySubscriberType::OtelTracer(OtelTracer {
                                    span_exporter,
                                    log_exporter,
                                    throttle: tracer.throttle.into_inner(),
                                    span_exporter_enable: tracer.enable_span_exporter,
                                    log_exporter_enable: tracer.enable_log_exporter,
                                })
                            }
                            (Err(err), _) => {
                                bp.build_error(
                                    id,
                                    format!("Failed to build OpenTelemetry span exporter: {err}"),
                                );
                                continue;
                            }
                            (_, Err(err)) => {
                                bp.build_error(
                                    id,
                                    format!("Failed to build OpenTelemetry log exporter: {err}"),
                                );
                                continue;
                            }
                        }
                    }
                    _ => continue,
                };

                if !enable {
                    continue;
                }

                // Create tracer
                let mut tracer = TelemetrySubscriber {
                    id: format!("t_{}", id.id()),
                    interests: Default::default(),
                    lossy,
                    typ,
                    settings,
                };

                // Parse disabled events
                let exclude_event = match &tracer.typ {
                    TelemetrySubscriberType::ConsoleTracer(_) => None,
                    TelemetrySubscriberType::LogTracer(_) => {
                        EventType::Telemetry(TelemetryEvent::LogError).into()
                    }
                    TelemetrySubscriberType::OtelTracer(_) => {
                        EventType::Telemetry(TelemetryEvent::OtelExporterError).into()
                    }
                    TelemetrySubscriberType::Webhook(_) => {
                        EventType::Telemetry(TelemetryEvent::WebhookError).into()
                    }
                    #[cfg(unix)]
                    TelemetrySubscriberType::JournalTracer(_) => {
                        EventType::Telemetry(TelemetryEvent::JournalError).into()
                    }
                    TelemetrySubscriberType::StoreTracer(_) => None,
                };

                // Parse disabled events
                apply_events(events, events_policy, |event_type| {
                    if exclude_event != Some(event_type) {
                        let event_level = custom_levels
                            .get(&event_type)
                            .copied()
                            .unwrap_or(event_type.level());
                        if level.is_contained(event_level) {
                            tracer.interests.set(event_type);
                            global_interests.set(event_type);
                        }
                    }
                });

                if !tracer.interests.is_empty() {
                    tracers.push(tracer);
                } else {
                    bp.build_warning(id, "No events enabled for tracer");
                }
            }


            // Parse webhooks
            for hook in bp.list_infallible::<WebHook>().await {
                let id = hook.id;
                let hook = hook.object;
                let settings = webhook_settings(&hook);

                if !hook.enable {
                    continue;
                }

                let headers = match hook
                    .http_auth
                    .build_headers(hook.http_headers, "application/json".into())
                    .await
                {
                    Ok(headers) => headers,
                    Err(err) => {
                        bp.build_error(id, format!("Unable to build HTTP headers: {}", err));
                        continue;
                    }
                };

                // Build tracer
                let mut tracer = TelemetrySubscriber {
                    id: format!("w_{}", id.id()),
                    interests: Default::default(),
                    lossy: hook.lossy,
                    settings,
                    typ: TelemetrySubscriberType::Webhook(WebhookTracer {
                        url: hook.url,
                        timeout: hook.timeout.into_inner(),
                        tls_allow_invalid_certs: hook.allow_invalid_certs,
                        client: utils::http::http_client_builder(hook.allow_invalid_certs)
                            .build()
                            .unwrap_or_default(),
                        headers,
                        key: hook
                            .signature_key
                            .secret()
                            .await
                            .map_err(|err| {
                                bp.build_error(
                                    id,
                                    format!("Unable to retrieve signature key: {}", err),
                                );
                            })
                            .unwrap_or_default()
                            .unwrap_or_default()
                            .into_owned(),
                        throttle: hook.throttle.into_inner(),
                        discard_after: hook.discard_after.into_inner(),
                    }),
                };

                // Parse webhook events
                // inbuxa: personal-data catalog, finding 1: an include list is
                // sent as named; otherwise a webhook honors its level as a
                // tracer does, and never sends a protocol's raw input or
                // output (whole messages)
                let level = Level::from(hook.level);
                let named = (hook.events_policy == EventPolicy::Include)
                    .then(|| hook.events.iter().copied().collect::<AHashSet<_>>())
                    .unwrap_or_default();
                apply_events(hook.events, hook.events_policy, |event_type| {
                    if webhook_wants(event_type, level, &custom_levels, &named) {
                        tracer.interests.set(event_type);
                        global_interests.set(event_type);
                    }
                });

                if !tracer.interests.is_empty() {
                    tracers.push(tracer);
                } else {
                    bp.build_error(id, "No events enabled for webhook");
                }
            }

            // inbuxa: MON-10 to MON-12: trace history, when a tracing store is set:
            // info and above, the span edges and MAIL FROM, never raw I/O
            if !storage.tracing.is_none() {
                let mut interests = Interests::default();
                for event_type in EventType::variants() {
                    let event_level = custom_levels
                        .get(event_type)
                        .copied()
                        .unwrap_or(event_type.level());
                    if !event_type.is_raw_io()
                        && (Level::Info.is_contained(event_level)
                            || event_type.is_span_start()
                            || event_type.is_span_end()
                            || event_type.as_str().starts_with("smtp.mail-from"))
                    {
                        interests.set(event_type.to_id() as usize);
                        global_interests.set(event_type.to_id() as usize);
                    }
                }
                tracers.push(TelemetrySubscriber {
                    id: "trace-history".to_string(),
                    interests,
                    typ: TelemetrySubscriberType::StoreTracer(StoreTracer {
                        tracing: storage.tracing.clone(),
                        data: storage.data.clone(),
                    }),
                    lossy: true,
                    // Stores take a restart
                    settings: 0,
                });
            }

            #[cfg(feature = "dev_mode")]
            if let Ok(level) = std::env::var("LOG") {
                let level = Level::from_str(&level).expect("Invalid LOG level");
                for event_type in EventType::variants() {
                    let event_level = custom_levels
                        .get(event_type)
                        .copied()
                        .unwrap_or(event_type.level());
                    if level.is_contained(event_level) {
                        global_interests.set(event_type.to_id() as usize);
                    }
                }

                tracers.push(TelemetrySubscriber {
                    id: "default".to_string(),
                    interests: global_interests.clone(),
                    typ: TelemetrySubscriberType::ConsoleTracer(ConsoleTracer {
                        ansi: true,
                        multiline: false,
                        buffered: true,
                    }),
                    lossy: false,
                    settings: 0,
                });
            }
        } else {
            // Add default tracer if none were found
            let level = types::branding::env_var("RECOVERY_MODE_LOG_LEVEL")
                .ok()
                .and_then(|level| Level::from_str(&level).ok())
                .unwrap_or(Level::Info);
            for event_type in EventType::variants() {
                let event_level = custom_levels
                    .get(event_type)
                    .copied()
                    .unwrap_or(event_type.level());
                if level.is_contained(event_level) {
                    global_interests.set(event_type.to_id() as usize);
                }
            }

            tracers.push(TelemetrySubscriber {
                id: "recover-log".to_string(),
                interests: global_interests.clone(),
                typ: TelemetrySubscriberType::ConsoleTracer(ConsoleTracer {
                    ansi: true,
                    multiline: false,
                    buffered: true,
                }),
                lossy: false,
                settings: 0,
            });
        }

        Tracers {
            subscribers: tracers,
            interests: global_interests,
            levels: custom_levels,
        }
    }
}

impl Metrics {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let metrics = bp.setting_infallible::<structs::Metrics>().await;
        let resource = Resource::builder()
            .with_service_name("inbuxa")
            .with_attribute(KeyValue::new(SERVICE_VERSION, types::brand_version_full!()))
            .build();
        let instrumentation = InstrumentationScope::builder("inbuxa")
            .with_version(types::brand_version_full!())
            .build();

        Metrics {
            prometheus: match metrics.prometheus {
                MetricsPrometheus::Enabled(prom) => {
                    let secret = prom
                        .auth_secret
                        .secret()
                        .await
                        .map_err(|err| {
                            bp.build_error(
                                ObjectType::Metrics.singleton(),
                                format!("Unable to retrieve Prometheus auth secret: {err}"),
                            );
                        })
                        .unwrap_or_default();
                    Some(PrometheusMetrics {
                        auth: prom.auth_username.and_then(|user| {
                            secret.map(|secret| STANDARD.encode(format!("{user}:{secret}")))
                        }),
                    })
                }
                MetricsPrometheus::Disabled => None,
            },
            otel: match metrics.open_telemetry {
                structs::MetricsOtel::Http(otel) => {
                    let headers = match otel.http_auth.build_headers(otel.http_headers, None).await
                    {
                        Ok(headers) => headers
                            .into_iter()
                            .filter_map(|(k, v)| {
                                k.and_then(|k| Some((k.to_string(), v.to_str().ok()?.to_string())))
                            })
                            .collect::<HashMap<String, String>>(),
                        Err(err) => {
                            bp.build_error(
                                ObjectType::Metrics.singleton(),
                                format!("Failed to build OpenTelemetry HTTP headers: {err}"),
                            );
                            Default::default()
                        }
                    };

                    let mut exporter = MetricExporter::builder()
                        .with_temporality(Temporality::Delta)
                        .with_http()
                        .with_endpoint(otel.endpoint)
                        .with_timeout(otel.timeout.into_inner());
                    if !headers.is_empty() {
                        exporter = exporter.with_headers(headers);
                    }

                    match exporter.build() {
                        Ok(exporter) => Some(Arc::new(OtelMetrics {
                            exporter,
                            interval: otel.interval.into_inner(),
                            resource,
                            instrumentation,
                        })),
                        Err(err) => {
                            bp.build_error(
                                ObjectType::Metrics.singleton(),
                                format!("Failed to build OpenTelemetry metrics exporter: {err}"),
                            );
                            None
                        }
                    }
                }
                structs::MetricsOtel::Grpc(otel) => {
                    let mut exporter = MetricExporter::builder()
                        .with_temporality(Temporality::Delta)
                        .with_tonic()
                        .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                        .with_timeout(otel.timeout.into_inner());
                    if let Some(endpoint) = otel.endpoint {
                        exporter = exporter.with_endpoint(endpoint);
                    }

                    match exporter.build() {
                        Ok(exporter) => Some(Arc::new(OtelMetrics {
                            exporter,
                            interval: otel.interval.into_inner(),
                            resource,
                            instrumentation,
                        })),
                        Err(err) => {
                            bp.build_error(
                                ObjectType::Metrics.singleton(),
                                format!("Failed to build OpenTelemetry metrics exporter: {err}"),
                            );
                            None
                        }
                    }
                }
                structs::MetricsOtel::Disabled => None,
            },
            log_path: bp
                .list_infallible::<Tracer>()
                .await
                .into_iter()
                .find_map(|tracer| {
                    if let Tracer::Log(log_tracer) = tracer.object
                        && log_tracer.enable
                    {
                        Some(log_tracer.path)
                    } else {
                        None
                    }
                }),
        }
    }
}

// inbuxa: what a tracer is built from, less what changes in place
macro_rules! in_place_reset {
    ($tracer:expr) => {{
        $tracer.enable = true;
        $tracer.level = Default::default();
        $tracer.lossy = false;
        $tracer.events = Default::default();
        $tracer.events_policy = Default::default();
    }};
}

fn settings_hash(settings: &impl std::fmt::Debug) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    format!("{settings:?}").hash(&mut hasher);
    hasher.finish()
}

fn tracer_settings(tracer: &Tracer) -> u64 {
    let mut tracer = tracer.clone();
    match &mut tracer {
        Tracer::Log(tracer) => in_place_reset!(tracer),
        Tracer::Stdout(tracer) => in_place_reset!(tracer),
        Tracer::Journal(tracer) => in_place_reset!(tracer),
        Tracer::OtelHttp(tracer) => in_place_reset!(tracer),
        Tracer::OtelGrpc(tracer) => in_place_reset!(tracer),
    }
    settings_hash(&tracer)
}

/// inbuxa: whether a webhook at `level` receives this event type. Its own
/// error event never, or a failing webhook would report itself to itself.
/// An event `named` in an include list always: naming it is the choice.
/// Otherwise (the exclude policy, the default) only events at or above its
/// level, as for a tracer, and never a protocol's raw input or output, which
/// carries whole messages and credentials.
fn webhook_wants(
    event_type: EventType,
    level: Level,
    custom_levels: &AHashMap<EventType, Level>,
    named: &AHashSet<EventType>,
) -> bool {
    if event_type == EventType::Telemetry(TelemetryEvent::WebhookError) {
        return false;
    }
    if named.contains(&event_type) {
        return true;
    }
    let event_level = custom_levels
        .get(&event_type)
        .copied()
        .unwrap_or(event_type.level());
    level.is_contained(event_level) && !event_type.is_raw_io()
}

fn webhook_settings(hook: &WebHook) -> u64 {
    let mut hook = hook.clone();
    in_place_reset!(hook);
    settings_hash(&hook)
}

fn apply_events(
    event_types: impl IntoIterator<Item = EventType>,
    policy: EventPolicy,
    mut apply_fn: impl FnMut(EventType),
) {
    let mut exclude_events = AHashSet::new();

    for event_type in event_types {
        if policy == EventPolicy::Include {
            apply_fn(event_type);
        } else {
            exclude_events.insert(event_type);
        }
    }

    if policy != EventPolicy::Include {
        for event_type in EventType::variants() {
            if !exclude_events.contains(event_type) {
                apply_fn(*event_type);
            }
        }
    }
}

fn apply_metrics(
    event_types: impl IntoIterator<Item = MetricType>,
    policy: EventPolicy,
    mut apply_fn: impl FnMut(MetricType),
) {
    let mut exclude_events = AHashSet::new();

    for event_type in event_types {
        if policy == EventPolicy::Include {
            apply_fn(event_type);
        } else {
            exclude_events.insert(event_type);
        }
    }

    if policy != EventPolicy::Include {
        for event_type in MetricType::variants() {
            if !exclude_events.contains(event_type) {
                apply_fn(*event_type);
            }
        }
    }
}

impl std::fmt::Debug for OtelMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtelMetrics")
            .field("interval", &self.interval)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trc::{AuthEvent, SmtpEvent};

    fn wants(event: EventType, level: Level, named: &[EventType]) -> bool {
        webhook_wants(
            event,
            level,
            &AHashMap::new(),
            &named.iter().copied().collect(),
        )
    }

    #[test]
    fn a_webhook_honors_its_level() {
        let success = EventType::Auth(AuthEvent::Success);
        assert!(wants(success, Level::Info, &[]));
        assert!(!wants(success, Level::Error, &[]), "info is below error");
    }

    #[test]
    fn raw_io_goes_out_only_when_named() {
        let raw = EventType::Smtp(SmtpEvent::RawInput);
        assert!(raw.is_raw_io());
        // Not with the exclude policy, even at trace
        assert!(!wants(raw, Level::Info, &[]));
        assert!(!wants(raw, Level::Trace, &[]));
        // Named in an include list, whatever the level
        assert!(wants(raw, Level::Info, &[raw]));
    }

    #[test]
    fn a_named_event_is_sent_whatever_its_level() {
        let start = EventType::Smtp(SmtpEvent::ConnectionStart);
        assert!(!Level::Info.is_contained(start.level()), "below info");
        assert!(!wants(start, Level::Info, &[]));
        assert!(wants(start, Level::Info, &[start]));
    }

    #[test]
    fn a_custom_level_counts() {
        let start = EventType::Smtp(SmtpEvent::ConnectionStart);
        let custom = [(start, Level::Info)].into_iter().collect::<AHashMap<_, _>>();
        assert!(webhook_wants(start, Level::Info, &custom, &AHashSet::new()));
        // Raw I/O raised to info still needs naming
        let raw = EventType::Smtp(SmtpEvent::RawInput);
        let custom = [(raw, Level::Info)].into_iter().collect::<AHashMap<_, _>>();
        assert!(!webhook_wants(raw, Level::Info, &custom, &AHashSet::new()));
    }

    #[test]
    fn a_webhook_never_hears_its_own_errors() {
        let own = EventType::Telemetry(TelemetryEvent::WebhookError);
        assert!(!wants(own, Level::Trace, &[own]));
    }
}
