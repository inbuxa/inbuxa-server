/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

pub mod alerts; // inbuxa: monitoring (MON-25 to MON-30)
pub mod metrics;
pub mod tracers;
pub mod webhooks;

use tracers::log::spawn_log_tracer;
use tracers::otel::spawn_otel_tracer;
use tracers::stdout::spawn_console_tracer;
use ahash::AHashMap;
use parking_lot::Mutex;
use trc::{Collector, ipc::subscriber::SubscriberBuilder};
use webhooks::spawn_webhook_tracer;

use crate::config::telemetry::{Telemetry, TelemetrySubscriberType};

/// inbuxa: the tracers this server started, by subscriber id, with the
/// settings each was built from. Live-tracing streams and other subscribers
/// registered elsewhere aren't listed, so a reload leaves them running.
static RUNNING_TRACERS: Mutex<Option<AHashMap<String, u64>>> = Mutex::new(None);

impl Telemetry {
    pub fn enable(self) {
        let mut running = RUNNING_TRACERS.lock();
        let running = running.get_or_insert_with(AHashMap::new);

        // Spawn tracers
        for tracer in self.tracers.subscribers {
            running.insert(tracer.id.clone(), tracer.settings);
            tracer.typ.spawn(
                SubscriberBuilder::new(tracer.id)
                    .with_interests(tracer.interests)
                    .with_lossy(tracer.lossy),
            );
        }

        // Update global collector
        Collector::set_interests(self.tracers.interests);
        Collector::update_custom_levels(self.tracers.levels);
        Collector::set_metrics(self.metrics);
        Collector::reload();
    }

    // inbuxa: upstream only refreshed the events, level and lossiness of a
    // tracer that was already running, so a Log tracer moved to another
    // path (or any tracer whose own settings changed) kept going as it was
    // built until a restart, while the reload reported the change applied.
    // A tracer whose settings changed is now started over: the new one is
    // registered under the same id and the collector swaps it in at an
    // event boundary, so no event is lost or written twice (see
    // Update::RegisterSubscriber); the old one writes what it has queued
    // and stops.
    pub fn update(self) {
        let mut running = RUNNING_TRACERS.lock();
        let running = running.get_or_insert_with(AHashMap::new);

        // Remove tracers that are no longer active
        running.retain(|id, _| {
            let keep = self
                .tracers
                .subscribers
                .iter()
                .any(|tracer| tracer.id == *id);
            if !keep {
                Collector::remove_subscriber(id.clone());
            }
            keep
        });

        // Start new tracers, start over those whose settings changed and
        // update the rest in place
        for tracer in self.tracers.subscribers {
            if running.get(&tracer.id) == Some(&tracer.settings) {
                Collector::update_subscriber(tracer.id, tracer.interests, tracer.lossy);
            } else {
                running.insert(tracer.id.clone(), tracer.settings);
                tracer.typ.spawn(
                    SubscriberBuilder::new(tracer.id)
                        .with_interests(tracer.interests)
                        .with_lossy(tracer.lossy),
                );
            }
        }

        // Update global collector
        Collector::set_interests(self.tracers.interests);
        Collector::update_custom_levels(self.tracers.levels);
        Collector::set_metrics(self.metrics);
        Collector::reload();
    }

    #[cfg(feature = "test_mode")]
    pub fn test_tracer(level: trc::Level) {
        let mut interests = trc::ipc::subscriber::Interests::default();
        for event in trc::EventType::variants() {
            if level.is_contained(event.level()) {
                interests.set(*event);
            }
        }

        spawn_console_tracer(
            SubscriberBuilder::new("stderr".to_string())
                .with_interests(interests.clone())
                .with_lossy(false),
            crate::config::telemetry::ConsoleTracer {
                ansi: true,
                multiline: false,
                buffered: false,
            },
        );

        Collector::union_interests(interests);
        Collector::reload();
    }
}

impl TelemetrySubscriberType {
    pub fn spawn(self, builder: SubscriberBuilder) {
        match self {
            TelemetrySubscriberType::ConsoleTracer(settings) => {
                spawn_console_tracer(builder, settings)
            }
            TelemetrySubscriberType::LogTracer(settings) => spawn_log_tracer(builder, settings),
            TelemetrySubscriberType::Webhook(settings) => spawn_webhook_tracer(builder, settings),
            TelemetrySubscriberType::OtelTracer(settings) => spawn_otel_tracer(builder, settings),
            // inbuxa: MON-10: trace history
            TelemetrySubscriberType::StoreTracer(settings) => {
                tracers::store::spawn_store_tracer(builder, settings.tracing, settings.data)
            }
            #[cfg(unix)]
            TelemetrySubscriberType::JournalTracer(subscriber) => {
                tracers::journald::spawn_journald_tracer(builder, subscriber)
            }
        }
    }
}
