/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::utils::server::TestServer;
use common::BuildServer;
use registry::{
    schema::{
        prelude::ObjectType,
        structs::{
            Alert, AlertEmail, AlertEmailProperties, AlertEvent, AlertEventProperties, Expression,
        },
    },
    types::map::Map,
};
use std::time::Duration;
use tokio::sync::mpsc;
use trc::{
    ClusterEvent, Collector, EventType, Key, MetricType, TelemetryEvent,
    ipc::subscriber::{EventBatch, Interests, SubscriberBuilder},
};

pub async fn test(test: &TestServer) {
    println!("Running Alerts tests...");

    // Create alerts
    let admin = test.account("admin@example.org");
    admin
        .registry_create_object(Alert {
            enable: true,
            condition: Expression {
                else_: "metric('domain.count') > 1 && metric('cluster.publisher-error') > 3".into(),
                ..Default::default()
            },
            email_alert: AlertEmail::Enabled(AlertEmailProperties {
                body: concat!(
                    "Sorry for the bad news, but we found %{domain.count}% ",
                    "domains and %{cluster.publisher-error}% cluster errors."
                )
                .to_string(),
                from_address: "alert@example.com".to_string(),
                from_name: "Alert Subsystem".to_string().into(),
                subject: "Found %{cluster.publisher-error}% cluster errors".to_string(),
                to: Map::new(vec!["jdoe@example.com".to_string()]),
            }),
            event_alert: AlertEvent::Enabled(AlertEventProperties {
                event_message: "Yikes! Found %{cluster.publisher-error}% cluster errors!"
                    .to_string()
                    .into(),
            }),
        })
        .await;
    admin
        .registry_create_object(Alert {
            enable: true,
            condition: Expression {
                else_: "metric('domain.count') < 1 || metric('cluster.publisher-error') < 3".into(),
                ..Default::default()
            },
            email_alert: AlertEmail::Disabled,
            event_alert: AlertEvent::Enabled(AlertEventProperties {
                event_message: "this should not have happened".to_string().into(),
            }),
        })
        .await;
    admin.reload_settings().await;
    let mut alert_events = AlertEvents::listen();

    // Make sure the required metrics are set to 0
    assert_eq!(
        Collector::read_metric(MetricType::ClusterPublisherError),
        0.0
    );
    assert_eq!(Collector::read_metric(MetricType::DomainCount), 1.0);
    assert_eq!(alert_events.received().await, Vec::<String>::new());

    // Increment metrics to trigger alerts
    Collector::update_event_counter(EventType::Cluster(ClusterEvent::PublisherError), 5);
    Collector::update_gauge(MetricType::DomainCount, 3);

    // Make sure the values were set
    assert_eq!(
        Collector::read_metric(MetricType::ClusterPublisherError),
        5.0
    );
    assert_eq!(Collector::read_metric(MetricType::DomainCount), 3.0);

    // Process alerts
    let message = test
        .server
        .inner
        .build_server()
        .process_alerts()
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(message.from, "alert@example.com");
    assert_eq!(message.to, vec!["jdoe@example.com".to_string()]);
    let body = String::from_utf8(message.body).unwrap();
    assert!(
        body.contains("Sorry for the bad news, but we found 3 domains and 5 cluster errors."),
        "{body:?}"
    );
    assert!(body.contains("Subject: Found 5 cluster errors"), "{body:?}");
    assert!(
        body.contains("From: \"Alert Subsystem\" <alert@example.com>"),
        "{body:?}"
    );
    assert!(body.contains("To: <jdoe@example.com>"), "{body:?}");

    // Make sure the event was triggered, and only by the first alert
    assert_eq!(
        alert_events.received().await,
        vec!["Yikes! Found 5 cluster errors!".to_string()]
    );
    alert_events.stop();

    // Cleanup
    admin.registry_destroy_all(ObjectType::Alert).await;
    admin.reload_settings().await;
    test.cleanup().await;
}

// inbuxa: 1.0 dropped the TelemetryAlertEvent metric, and an event's own
// counter only runs while a metric asks for it, so nothing counts the alert
// event any more. The test listens for the event itself instead.
struct AlertEvents {
    id: String,
    rx: mpsc::Receiver<EventBatch>,
}

impl AlertEvents {
    fn listen() -> Self {
        let mut interests = Interests::default();
        interests.set(EventType::Telemetry(TelemetryEvent::AlertEvent));
        let id = "alert-events-test".to_string();
        let (_, rx, _) = SubscriberBuilder::new(id.clone())
            .with_interests(interests.clone())
            .with_lossy(false)
            .register();
        Collector::union_interests(interests);
        Collector::reload();
        AlertEvents { id, rx }
    }

    /// The details of the alert events received until none came for a second.
    async fn received(&mut self) -> Vec<String> {
        let mut details = Vec::new();
        while let Ok(Some(batch)) =
            tokio::time::timeout(Duration::from_secs(1), self.rx.recv()).await
        {
            for event in batch {
                if event.inner.typ == EventType::Telemetry(TelemetryEvent::AlertEvent) {
                    details.push(
                        event
                            .value_as_str(Key::Details)
                            .unwrap_or_default()
                            .to_string(),
                    );
                }
            }
        }
        details
    }

    fn stop(self) {
        Collector::remove_subscriber(self.id);
    }
}
