/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Monitoring acceptance tests, from `docs/spec/features/monitoring.md`, for
//! what the shared suites in `tests/src/telemetry` don't cover. Each check
//! names the test number or requirement.

use crate::utils::{
    server::{TestServer, TestServerBuilder},
    smtp::SmtpConnection,
};
use common::telemetry::{metrics::store::MetricsStore, tracers::store::TracingStore};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::{
        Alert, AlertEmail, AlertEvent, AlertEventProperties, CertificateManagement,
        DkimManagement, DnsManagement, Domain, Expression, MetricsStore as MetricsStoreSetting,
        MtaStageAuth, Search, Tenant, TracingStore as TracingStoreSetting, UserRoles,
    },
};
use serde_json::{Value, json};
use std::time::Duration;
use trc::{ClusterEvent, Collector, EventType, MetricType};

const SECRET: &str = "monitoring test user passphrase";

pub async fn test(test: &mut TestServer) {
    println!("Running monitoring tests...");
    let admin = test.account("admin@example.org");
    let base = admin.base_url();

    // Acceptance test 1: history on by default, 30 and 90 days, hourly
    let retention = admin
        .jmap_method_call("x:DataRetention/get", json!({"ids": ["singleton"]}))
        .await;
    let retention = &retention.list()[0];
    assert_eq!(retention["holdTracesFor"], 30 * 86_400_000u64, "test 1: {retention}");
    assert_eq!(retention["holdMetricsFor"], 90 * 86_400_000u64, "test 1");
    assert_eq!(retention["metricsCollectionInterval"]["@type"], "Hourly", "test 1");
    for object in ["x:TracingStore/get", "x:MetricsStore/get"] {
        let store = admin
            .jmap_method_call(object, json!({"ids": ["singleton"]}))
            .await;
        assert_eq!(store.list()[0]["@type"], "Default", "test 1: {object}");
    }

    // Acceptance test 3: two ticks: counters hold the increase, gauges the
    // reading, idle counters write nothing
    test.server
        .metrics_store()
        .purge_metrics(Duration::ZERO)
        .await
        .unwrap();
    test.server.store_metrics().await;
    Collector::update_event_counter(EventType::Cluster(ClusterEvent::PublisherError), 7);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    test.server.store_metrics().await;
    let samples = admin
        .jmap_method_call("x:Metric/get", json!({"ids": null}))
        .await;
    let samples = samples.list();
    let errors = samples
        .iter()
        .filter(|s| s["metric"] == "cluster.publisher-error")
        .collect::<Vec<_>>();
    assert_eq!(errors.last().map(|s| &s["count"]), Some(&json!(7)), "test 3: {errors:?}");
    let memory = samples
        .iter()
        .filter(|s| s["metric"] == "server.memory" && s["@type"] == "Gauge")
        .count();
    assert_eq!(memory, 2, "test 3 / MON-5: a gauge every tick");
    assert!(
        samples.iter().all(|s| s["timestamp"].is_string()),
        "test 3: timestamps"
    );

    // Acceptance test 5: every gauge and histogram in Prometheus output
    // (MON-6: one edition). Histograms appear once they've seen a value
    Collector::update_gauge(MetricType::QueueCount, 3);
    let exported = test.server.export_prometheus_metrics().await.unwrap();
    for name in ["queue_count", "server_memory", "domain_count"] {
        assert!(exported.contains(name), "test 5: {name} in {exported}");
    }
    let histograms = Collector::collect_histograms()
        .map(|h| h.id())
        .collect::<Vec<_>>();
    let gauges = Collector::collect_gauges().map(|g| g.id()).collect::<Vec<_>>();
    assert!(gauges.contains(&MetricType::QueueCount), "test 5: queue.count gauge");
    let _ = histograms;

    // Acceptance tests 7 to 9: what a trace holds
    test.server
        .tracing_store()
        .purge_spans(Duration::ZERO, Some(test.server.search_store()))
        .await
        .unwrap();
    let mut probe = SmtpConnection::connect().await;
    probe.send("QUIT").await;
    let user = admin
        .create_user_account("mon@example.org", SECRET, "Monitoring", &[], vec![])
        .await;
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "sender@example.org",
        &["mon@example.org"],
        "From: sender@example.org\r\nTo: mon@example.org\r\nSubject: Traced\r\n\r\nHello.\r\n",
    )
    .await;
    lmtp.quit().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    test.server.notify_task_queue();
    test.wait_for_tasks().await;
    let traces = admin
        .jmap_method_call("x:Trace/get", json!({"ids": null}))
        .await;
    let traces = traces.list().to_vec();
    assert_eq!(traces.len(), 2, "test 7: the probe left no trace: {traces:?}");
    for trace in &traces {
        let events = trace["events"].as_array().cloned().unwrap_or_else(|| {
            trace["events"]
                .as_object()
                .map(|o| o.values().cloned().collect())
                .unwrap_or_default()
        });
        assert!(
            events.iter().all(|e| {
                let name = e["event"].as_str().unwrap_or_default();
                !name.ends_with("raw-input") && !name.ends_with("raw-output")
            }),
            "test 8: no raw I/O"
        );
        assert!(trace["timestamp"].is_string(), "test 9: timestamp");
        assert!(trace["size"].is_number(), "test 9: size");
    }
    assert!(
        traces.iter().any(|t| t["from"] == "sender@example.org"),
        "test 9: from, {traces:?}"
    );
    assert!(
        traces
            .iter()
            .any(|t| t["to"].as_str().is_some_and(|to| to.contains("mon@example.org"))),
        "test 9: to"
    );

    // Acceptance test 24: destroy removes a trace; create is refused
    let trace_id = traces[0]["id"].as_str().unwrap().to_string();
    let response = admin
        .jmap_method_call("x:Trace/set", json!({"destroy": [trace_id]}))
        .await;
    assert_eq!(
        response.0.pointer("/methodResponses/0/1/destroyed/0"),
        Some(&json!(trace_id)),
        "test 24: {response:?}"
    );
    let response = admin
        .jmap_method_call("x:Trace/set", json!({"create": {"i0": {"events": []}}}))
        .await;
    assert!(
        response.0.pointer("/methodResponses/0/1/notCreated/i0").is_some(),
        "test 24: create refused"
    );

    // Acceptance test 11: trace search off
    admin
        .registry_update_setting(
            Search {
                index_telemetry: false,
                ..Default::default()
            },
            &[Property::IndexTelemetry],
        )
        .await;
    let response = admin
        .jmap_method_call("x:Trace/query", json!({"filter": {"text": "example.org"}}))
        .await;
    assert!(response.to_string().contains("unsupportedFilter"), "test 11: {response:?}");
    let response = admin
        .jmap_method_call(
            "x:Trace/query",
            json!({"filter": {"timestampIsGreaterThan": "2020-01-01T00:00:00Z"}}),
        )
        .await;
    assert!(
        response.0.pointer("/methodResponses/0/1/ids").is_some(),
        "test 11: timestamp still works"
    );
    admin
        .registry_update_setting(
            Search {
                index_telemetry: true,
                ..Default::default()
            },
            &[Property::IndexTelemetry],
        )
        .await;

    // Acceptance tests 14 to 17: live telemetry
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let token = |kind: &'static str| {
        let http = http.clone();
        let auth = admin.basic_auth();
        let url = format!("{base}/api/token/{kind}");
        async move {
            let response = http.get(url).header("authorization", auth).send().await.unwrap();
            assert_eq!(response.status(), 200, "test 16: token for {kind}");
            response.text().await.unwrap()
        }
    };
    let metrics_token = token("metrics").await;
    let frame = first_frame(
        &http,
        &format!("{base}/api/live/metrics?token={metrics_token}&metrics=server.memory&interval=1"),
        "metrics",
    )
    .await;
    let parsed: Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(parsed[0]["metric"], "server.memory", "test 15: {frame}");
    assert_eq!(parsed[0]["@type"], "Gauge", "test 15");
    // The same token again, within its minute (MON-23 Decision)
    let _ = first_frame(
        &http,
        &format!("{base}/api/live/metrics?token={metrics_token}&metrics=server.memory&interval=1"),
        "metrics",
    )
    .await;
    // Without a token or credentials: refused
    let refused = http
        .get(format!("{base}/api/live/metrics?token=not-a-token"))
        .send()
        .await
        .unwrap();
    assert_ne!(refused.status(), 200, "test 16: a bad token");

    // Test 14: live tracing sees a matching event, and never raw I/O
    let tracing_token = token("tracing").await;
    let url = format!("{base}/api/live/tracing?token={tracing_token}&filter=mon%40example.org");
    let reader = tokio::spawn({
        let http = http.clone();
        async move { first_frame(&http, &url, "trace").await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "sender@example.org",
        &["mon@example.org"],
        "From: sender@example.org\r\nTo: mon@example.org\r\nSubject: Live\r\n\r\nHello.\r\n",
    )
    .await;
    lmtp.quit().await;
    let frame = reader.await.unwrap();
    let events: Value = serde_json::from_str(&frame).unwrap();
    assert!(events.as_array().is_some_and(|e| !e.is_empty()), "test 14: {frame}");
    assert!(!frame.contains("raw-input"), "test 14: no raw I/O");
    assert!(frame.contains("keyValues"), "test 14: x:TraceEvent shape");

    // Test 17: at most eight streams at once
    let mut open = Vec::new();
    for _ in 0..8 {
        let response = http
            .get(format!("{base}/api/live/metrics?token={metrics_token}&interval=60"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "test 17");
        open.push(response);
    }
    let ninth = http
        .get(format!("{base}/api/live/metrics?token={metrics_token}&interval=60"))
        .send()
        .await
        .unwrap();
    assert_ne!(ninth.status(), 200, "test 17: the ninth stream");
    drop(open);
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Acceptance tests 19 to 21: alerts
    let refused = admin
        .registry_create_object_expect_err(Alert {
            enable: true,
            condition: Expression {
                else_: "metric('no.such-metric') > 1".into(),
                ..Default::default()
            },
            email_alert: AlertEmail::Disabled,
            event_alert: AlertEvent::Disabled,
        })
        .await;
    let _ = refused; // test 21: refused on save
    let alert = admin
        .registry_create_object(Alert {
            enable: true,
            condition: Expression {
                else_: "domain_count > 50".into(),
                ..Default::default()
            },
            email_alert: AlertEmail::Disabled,
            event_alert: AlertEvent::Enabled(AlertEventProperties {
                event_message: "%{domain.count}% domains".to_string().into(),
            }),
        })
        .await;
    let fired = || Collector::read_metric(MetricType::TelemetryAlertEvent);
    let before = fired();
    Collector::update_gauge(MetricType::DomainCount, 100);
    test.server.process_alerts().await.unwrap();
    assert_eq!(fired(), before + 1.0, "test 19: an underscore condition fires");
    test.server.process_alerts().await.unwrap();
    assert_eq!(fired(), before + 1.0, "test 20: once while it holds");
    Collector::update_gauge(MetricType::DomainCount, 1);
    test.server.process_alerts().await.unwrap();
    Collector::update_gauge(MetricType::DomainCount, 100);
    test.server.process_alerts().await.unwrap();
    assert_eq!(fired(), before + 2.0, "test 20: again after it was false");
    Collector::update_gauge(MetricType::DomainCount, 1);
    admin
        .registry_destroy(ObjectType::Alert, [alert])
        .await
        .assert_destroyed(&[alert]);

    // Acceptance test 23: a tenant administrator can't reach telemetry
    let tenant = admin
        .registry_create_object(Tenant {
            name: "mon-t".into(),
            ..Default::default()
        })
        .await;
    let domain = admin
        .registry_create_object(Domain {
            name: "mon-t.example.org".into(),
            is_enabled: true,
            member_tenant_id: Some(tenant),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    let t_admin = admin
        .create_user_account("tadmin@mon-t.example.org", SECRET, "T admin", &[], vec![])
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            t_admin.id(),
            json!({ Property::Roles: UserRoles::Admin }),
        )
        .await;
    for method in ["x:Trace/query", "x:Metric/query"] {
        let response = t_admin.jmap_method_call(method, json!({})).await;
        assert!(
            response.to_string().contains("forbidden"),
            "test 23: {method} {response:?}"
        );
    }
    let response = http
        .get(format!("{base}/api/token/tracing"))
        .header("authorization", t_admin.basic_auth())
        .send()
        .await
        .unwrap();
    assert_ne!(response.status(), 200, "test 23: no live token");

    // Clean up
    admin.destroy_account(t_admin).await;
    admin
        .registry_destroy(ObjectType::Domain, [domain])
        .await
        .assert_destroyed(&[domain]);
    admin
        .registry_destroy(ObjectType::Tenant, [tenant])
        .await
        .assert_destroyed(&[tenant]);
    admin.destroy_account(user).await;
    test.wait_for_tasks().await;
}

/// The first `event:` frame of that name on an event stream, its data.
async fn first_frame(http: &reqwest::Client, url: &str, event: &str) -> String {
    let mut response = http.get(url).send().await.unwrap();
    assert_eq!(response.status(), 200, "{url}");
    let mut buffer = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let chunk = tokio::time::timeout_at(deadline, response.chunk())
            .await
            .unwrap_or_else(|_| panic!("no {event} frame from {url}: {buffer}"))
            .unwrap()
            .expect("stream ended");
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(end) = buffer.find("\n\n") {
            let frame = buffer[..end].to_string();
            buffer.drain(..end + 2);
            if frame.starts_with(&format!("event: {event}\n"))
                && let Some(data) = frame.split_once("\ndata: ").map(|(_, d)| d.to_string())
            {
                return data;
            }
        }
    }
}

/// Runs the monitoring tests alone:
/// `cargo test -p tests monitoring_tests -- --ignored`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn monitoring_tests() {
    let mut test = TestServerBuilder::new("monitoring_tests")
        .await
        .with_default_listeners()
        .await
        .with_object(MetricsStoreSetting::Default)
        .await
        .with_object(TracingStoreSetting::Default)
        .await
        .with_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;
    let admin = test.create_admin_account("admin@example.org").await;
    test.insert_account(admin);
    self::test(&mut test).await;
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

