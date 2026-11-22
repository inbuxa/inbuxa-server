/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use std::time::Duration;
use std::{
    collections::BinaryHeap,
    sync::Arc,
    time::{Instant, SystemTime},
};

use common::{
    BuildServer, Inner, LONG_1D_SLUMBER, Server,
    config::{mailstore::spamfilter, telemetry::OtelMetrics},
    manager::singleton_lease::SingletonRole,
};
use registry::{
    schema::{
        enums::{TaskSpamFilterMaintenanceType, TaskStoreMaintenanceType, TaskType},
        structs::{Task, TaskSpamFilterMaintenance, TaskStatus, TaskStoreMaintenance},
    },
    types::EnumImpl,
};
use store::write::{BatchBuilder, now};
use trc::{ClusterEvent, Collector, MetricType, TaskManagerEvent, TelemetryEvent};

#[derive(PartialEq, Eq)]
struct Action {
    due: Instant,
    event: Event,
}

#[derive(PartialEq, Eq, Debug)]
enum Event {
    PurgeAccount,
    PurgeDataStore,
    PurgeBlobStore,
    OtelMetrics,
    CalculateMetrics,
    TrainSpamClassifier,
    RenewNodeIdLease,
    // inbuxa: MON-4: metric history
    StoreMetrics,
    // inbuxa: MON-25: alert evaluation
    EvaluateAlerts,
    // inbuxa: settings-reorg: probe the other nodes' ports
    ProbePeerPorts,
    // inbuxa: re-queue DKIM rotation and ACME renewal tasks a domain is missing.
    // Test builds never schedule it (`cfg(not(feature = "test_mode"))`).
    #[cfg_attr(feature = "test_mode", allow(dead_code))]
    CheckDomainTasks,
}

// inbuxa: first check a few minutes after start, then daily
#[cfg_attr(feature = "test_mode", allow(dead_code))]
const DOMAIN_TASK_CHECK_DELAY: Duration = Duration::from_secs(5 * 60);
const DOMAIN_TASK_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// When the next metric-history tick is due (MON-4), read from the registry
/// so a change needs no reload (MON-3).
async fn metrics_collection_delay(server: &common::Server) -> Duration {
    utils::cron::SimpleCron::from(
        common::telemetry::metrics::store::retention(server)
            .await
            .metrics_collection_interval,
    )
    .time_to_next()
}

/// The cluster-wide gauges, on the node that does the metrics work: the
/// queue every time, accounts and domains when `others` (once a day).
async fn calculate_cluster_metrics(server: &Server, others: bool) {
    // inbuxa: MON-7: the queue gauge from the queue itself, so it's right
    // after a restart
    match server.total_queued_messages().await {
        // #437: unless the role passed to another node while counting
        Ok((total, oldest)) if server.runs_singleton(SingletonRole::Metrics) => {
            Collector::update_gauge(MetricType::QueueCount, total);
            Collector::update_gauge(MetricType::QueueOldestMessage, oldest.unwrap_or_default());
            Collector::update_gauge(MetricType::ClusterSingletonMetrics, 1);
        }
        Ok(_) => {}
        Err(err) => {
            trc::error!(err.details("Failed to count queued messages"));
        }
    }

    if others {
        match server.total_accounts().await {
            Ok(total) => Collector::update_gauge(MetricType::UserCount, total as u64),
            Err(err) => {
                trc::error!(err.details("Failed to obtain account count"));
            }
        }
        match server.total_domains().await {
            Ok(total) => Collector::update_gauge(MetricType::DomainCount, total as u64),
            Err(err) => {
                trc::error!(err.details("Failed to obtain domain count"));
            }
        }
    }
}

#[derive(Default)]
struct Queue {
    heap: BinaryHeap<Action>,
}

pub fn spawn_task_scheduler(inner: Arc<Inner>) {
    tokio::spawn(async move {
        trc::event!(TaskManager(TaskManagerEvent::SchedulerStarted));
        let start_time = SystemTime::now();

        // Add all events to queue
        let mut queue = Queue::default();
        {
            let server = inner.build_server();

            // Account purge
            queue.schedule(
                Instant::now() + server.core.email.account_purge_frequency.time_to_next(),
                Event::PurgeAccount,
            );
            queue.schedule(
                Instant::now() + server.core.email.data_purge_frequency.time_to_next(),
                Event::PurgeDataStore,
            );
            queue.schedule(
                Instant::now() + server.core.email.blob_purge_frequency.time_to_next(),
                Event::PurgeBlobStore,
            );

            // Node ID lease renewal
            if server.core.storage.coordinator.is_enabled() {
                queue.schedule(
                    Instant::now() + server.registry().refresh_node_id_interval(),
                    Event::RenewNodeIdLease,
                );
                // inbuxa: first round a minute after start, once the others have a lease
                queue.schedule(
                    Instant::now() + Duration::from_secs(60),
                    Event::ProbePeerPorts,
                );
            }

            // Spam classifier training
            if let Some(train_frequency) = server
                .core
                .spam
                .classifier
                .as_ref()
                .and_then(|c| c.train_frequency)
            {
                let next_train = match server.inner.data.spam_classifier.load().as_ref() {
                    spamfilter::SpamClassifier::FhClassifier {
                        last_trained_at, ..
                    }
                    | spamfilter::SpamClassifier::CcfhClassifier {
                        last_trained_at, ..
                    } => now().saturating_sub(*last_trained_at).min(train_frequency),
                    spamfilter::SpamClassifier::Disabled => train_frequency,
                };

                queue.schedule(
                    Instant::now() + Duration::from_secs(next_train),
                    Event::TrainSpamClassifier,
                );
            }

            // inbuxa: K-C10: nodes sharing a queue count it from the store
            if server.core.storage.has_coordinator() {
                Collector::count_queue_from_store_only();
            }

            // OTEL Push Metrics
            if let Some(otel) = &server.core.metrics.otel {
                OtelMetrics::enable_errors();
                queue.schedule(Instant::now() + otel.interval, Event::OtelMetrics);
            }

            // Calculate expensive metrics
            queue.schedule(Instant::now(), Event::CalculateMetrics);

            // inbuxa: MON-25: alerts every minute
            queue.schedule(
                Instant::now() + Duration::from_secs(60),
                Event::EvaluateAlerts,
            );

            // inbuxa: MON-4: metric history on its own schedule
            queue.schedule(
                Instant::now() + metrics_collection_delay(&server).await,
                Event::StoreMetrics,
            );

            // inbuxa: automatic domains keep their DKIM and ACME tasks. Not
            // in test builds: a suite running past the first check would get
            // DKIM keys for its test domains, and the tests call the check
            // themselves.
            #[cfg(not(feature = "test_mode"))]
            queue.schedule(
                Instant::now() + DOMAIN_TASK_CHECK_DELAY,
                Event::CheckDomainTasks,
            );
        }

        let mut next_metric_update = Instant::now();
        // inbuxa: #437: whether this node calculated the cluster-wide gauges
        // since it last took on the metrics role, so a node that just took
        // over doesn't evaluate alerts against gauges it never set
        let mut calculated = false;

        loop {
            tokio::time::sleep(queue.wake_up_time()).await;

            let server = inner.build_server();
            let roles = &server.core.network.roles;
            // inbuxa: #437: in a cluster, only the node holding the role's
            // lease queues the scheduled tasks and does the metrics work
            let mut batch = server
                .runs_singleton(SingletonRole::TaskScheduler)
                .then(BatchBuilder::new);
            let calculates = server.runs_singleton(SingletonRole::Metrics);
            if !calculates {
                // In a cluster the holder's gauges are the queue's: this
                // node's would be stale from when it last held the role
                if server.core.storage.has_coordinator() {
                    common::manager::singleton_lease::clear_cluster_gauges();
                }
                calculated = false;
                // Counted again at once if this node takes the role on
                next_metric_update = Instant::now();
            }

            while let Some(event) = queue.pop() {
                match event.event {
                    Event::PurgeAccount => {
                        queue.schedule(
                            Instant::now()
                                + server.core.email.account_purge_frequency.time_to_next(),
                            Event::PurgeAccount,
                        );

                        if let Some(batch) = batch.as_mut() {
                            trc::event!(
                                TaskManager(TaskManagerEvent::TaskQueued),
                                Type = TaskStoreMaintenanceType::PurgeAccounts.as_str()
                            );

                            batch.schedule_task(Task::StoreMaintenance(TaskStoreMaintenance {
                                maintenance_type: TaskStoreMaintenanceType::PurgeAccounts,
                                status: TaskStatus::now(),
                                shard_index: None,
                            }));
                        }
                    }
                    Event::PurgeDataStore => {
                        queue.schedule(
                            Instant::now() + server.core.email.data_purge_frequency.time_to_next(),
                            Event::PurgeDataStore,
                        );

                        if let Some(batch) = batch.as_mut() {
                            trc::event!(
                                TaskManager(TaskManagerEvent::TaskQueued),
                                Type = TaskStoreMaintenanceType::PurgeData.as_str()
                            );

                            batch.schedule_task(Task::StoreMaintenance(TaskStoreMaintenance {
                                maintenance_type: TaskStoreMaintenanceType::PurgeData,
                                status: TaskStatus::now(),
                                shard_index: None,
                            }));
                        }
                    }
                    Event::PurgeBlobStore => {
                        queue.schedule(
                            Instant::now() + server.core.email.blob_purge_frequency.time_to_next(),
                            Event::PurgeBlobStore,
                        );

                        if let Some(batch) = batch.as_mut() {
                            trc::event!(
                                TaskManager(TaskManagerEvent::TaskQueued),
                                Type = TaskStoreMaintenanceType::PurgeBlob.as_str()
                            );

                            batch.schedule_task(Task::StoreMaintenance(TaskStoreMaintenance {
                                maintenance_type: TaskStoreMaintenanceType::PurgeBlob,
                                status: TaskStatus::now(),
                                shard_index: None,
                            }));
                        }
                    }
                    Event::RenewNodeIdLease => {
                        queue.schedule(
                            Instant::now() + server.registry().refresh_node_id_interval(),
                            Event::RenewNodeIdLease,
                        );

                        trc::event!(
                            Cluster(ClusterEvent::NodeIdRenewed),
                            Id = server.registry().node_id()
                        );

                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Err(err) = server.registry().refresh_node_id_lease().await {
                                trc::error!(err.details("Failed to renew node ID lease"));
                            }
                        });
                    }
                    Event::ProbePeerPorts => {
                        queue.schedule(
                            Instant::now() + common::reachability::PROBE_INTERVAL,
                            Event::ProbePeerPorts,
                        );

                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Err(err) = common::reachability::probe_peers(&server).await {
                                trc::error!(err.details("Failed to probe the other nodes' ports"));
                            }
                        });
                    }
                    Event::OtelMetrics => {
                        if let Some(otel) = &server.core.metrics.otel {
                            queue.schedule(Instant::now() + otel.interval, Event::OtelMetrics);

                            if roles.metrics_push || otel.every_node {
                                let otel = otel.clone();

                                tokio::spawn(async move {
                                    let elapsed = Instant::now();
                                    otel.push_metrics(start_time).await;

                                    trc::event!(
                                        Telemetry(TelemetryEvent::MetricsPushed),
                                        Elapsed = elapsed.elapsed()
                                    );
                                });
                            }
                        }
                    }
                    Event::CalculateMetrics => {
                        // Calculate expensive metrics every 5 minutes
                        queue.schedule(
                            Instant::now() + Duration::from_secs(5 * 60),
                            Event::CalculateMetrics,
                        );

                        let update_other_metrics =
                            calculates && Instant::now() >= next_metric_update;
                        if update_other_metrics {
                            next_metric_update = Instant::now() + Duration::from_secs(86400);
                        }
                        calculated |= calculates;

                        let server = server.clone();
                        tokio::spawn(async move {
                            let elapsed = Instant::now();
                            if calculates {
                                calculate_cluster_metrics(&server, update_other_metrics).await;
                            }

                            match tokio::task::spawn_blocking(memory_stats::memory_stats).await {
                                Ok(Some(stats)) => {
                                    Collector::update_gauge(
                                        MetricType::ServerMemory,
                                        stats.physical_mem as u64,
                                    );
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    trc::error!(
                                        trc::EventType::Server(trc::ServerEvent::ThreadError,)
                                            .reason(err)
                                            .caused_by(trc::location!())
                                            .details("Join Error")
                                    );
                                }
                            }

                            trc::event!(
                                Telemetry(TelemetryEvent::MetricsCollected),
                                Elapsed = elapsed.elapsed()
                            );
                        });
                    }
                    // inbuxa: MON-25 to MON-30: on the node that calculates metrics;
                    // a failure is logged and tried again next minute (MON-37)
                    Event::EvaluateAlerts => {
                        queue.schedule(
                            Instant::now() + Duration::from_secs(60),
                            Event::EvaluateAlerts,
                        );
                        if calculates {
                            // #437: a node that just took over sets the gauges
                            // first, so no alert reads one it never set
                            let first = !calculated;
                            if first {
                                calculated = true;
                                next_metric_update = Instant::now() + Duration::from_secs(86400);
                            }
                            let server = server.clone();
                            tokio::spawn(async move {
                                if first {
                                    calculate_cluster_metrics(&server, true).await;
                                }
                                match server.process_alerts().await {
                                    Ok(messages) => {
                                        use smtp::reporting::send::MtaReportSend;
                                        for message in messages {
                                            server
                                                .send_autogenerated(
                                                    message.from.clone(),
                                                    message.to.iter(),
                                                    message.body,
                                                    None,
                                                    0,
                                                )
                                                .await;
                                            trc::event!(
                                                Telemetry(TelemetryEvent::AlertMessage),
                                                From = message.from,
                                                To = message.to,
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        trc::error!(err.details("Failed to evaluate alerts"));
                                    }
                                }
                            });
                        }
                    }
                    // inbuxa: MON-4: every node writes its own samples
                    Event::StoreMetrics => {
                        queue.schedule(
                            Instant::now() + metrics_collection_delay(&server).await,
                            Event::StoreMetrics,
                        );
                        let server = server.clone();
                        tokio::spawn(async move {
                            server.store_metrics().await;
                        });
                    }
                    // inbuxa: on the task scheduler only, like the tasks it queues
                    Event::CheckDomainTasks => {
                        queue.schedule(
                            Instant::now() + DOMAIN_TASK_CHECK_INTERVAL,
                            Event::CheckDomainTasks,
                        );
                        if batch.is_some() {
                            let server = server.clone();
                            tokio::spawn(async move {
                                if let Err(err) =
                                    super::domain_check::check_domain_tasks(&server).await
                                {
                                    trc::error!(err.details("Failed to check domain tasks"));
                                }
                            });
                        }
                    }
                    Event::TrainSpamClassifier => {
                        if let Some(train_frequency) = server
                            .core
                            .spam
                            .classifier
                            .as_ref()
                            .and_then(|c| c.train_frequency)
                        {
                            // Schedule next training
                            queue.schedule(
                                Instant::now() + Duration::from_secs(train_frequency),
                                Event::TrainSpamClassifier,
                            );

                            if let Some(batch) = batch.as_mut() {
                                trc::event!(
                                    TaskManager(TaskManagerEvent::TaskQueued),
                                    Type = TaskType::SpamFilterMaintenance.as_str()
                                );

                                batch.schedule_task(Task::SpamFilterMaintenance(
                                    TaskSpamFilterMaintenance {
                                        maintenance_type: TaskSpamFilterMaintenanceType::Train,
                                        status: TaskStatus::now(),
                                    },
                                ));
                            }
                        }
                    }
                }
            }

            if let Some(mut batch) = batch
                && !batch.is_empty()
                && let Err(err) = server.store().write(batch.build_all()).await
            {
                trc::error!(err.details("Failed to write scheduled tasks"));
            }
        }
    });
}

impl Queue {
    pub fn schedule(&mut self, due: Instant, event: Event) {
        trc::event!(
            TaskManager(TaskManagerEvent::TaskScheduled),
            Due = trc::Value::Timestamp(
                now() + due.saturating_duration_since(Instant::now()).as_secs()
            ),
            Id = event.name()
        );

        self.heap.push(Action { due, event });
    }

    pub fn wake_up_time(&self) -> Duration {
        self.heap
            .peek()
            .map(|e| e.due.saturating_duration_since(Instant::now()))
            .unwrap_or(LONG_1D_SLUMBER)
    }

    pub fn pop(&mut self) -> Option<Action> {
        if self.heap.peek()?.due <= Instant::now() {
            self.heap.pop()
        } else {
            None
        }
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.due.cmp(&other.due).reverse()
    }
}

impl PartialOrd for Action {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Event {
    fn name(&self) -> &'static str {
        match self {
            Event::PurgeAccount => "purgeAccount",
            Event::PurgeDataStore => "purgeDataStore",
            Event::PurgeBlobStore => "purgeBlobStore",
            Event::OtelMetrics => "otelMetrics",
            Event::CalculateMetrics => "calculateMetrics",
            Event::TrainSpamClassifier => "trainSpamClassifier",
            Event::RenewNodeIdLease => "renewNodeIdLease",
            Event::StoreMetrics => "storeMetrics",
            Event::EvaluateAlerts => "evaluateAlerts",
            Event::ProbePeerPorts => "probePeerPorts",
            Event::CheckDomainTasks => "checkDomainTasks",
        }
    }
}
