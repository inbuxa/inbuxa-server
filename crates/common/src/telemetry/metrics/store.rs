/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Metric history (monitoring spec MON-4 to MON-9, MON-17). Each sample is
//! stored under `TelemetryClass::Metric(id)`, as an `x:Metric` in the
//! registry's own encoding. The id is a snowflake of the tick's time, so key
//! order is time order and the timestamp is read from the id.

use crate::Server;
use ahash::AHashMap;
use registry::{
    pickle::PickledStream,
    schema::{
        prelude::{ObjectInner, ObjectType},
        structs::{DataRetention, Metric, MetricCount, MetricSum},
    },
};
use std::{future::Future, sync::Mutex, time::Duration};
use store::{
    IterateParams, Store, ValueKey,
    write::{BatchBuilder, TelemetryClass, ValueClass, key::DeserializeBigEndian, now},
};
use trc::{AddContext, Collector, MetricType, TelemetryEvent};
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

pub trait MetricsStore: Sync + Send {
    /// Writes one tick's samples, all at `timestamp`.
    fn write_metrics(
        &self,
        samples: Vec<Metric>,
        timestamp: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    /// Deletes samples older than `keep` (MON-17).
    fn purge_metrics(&self, keep: Duration) -> impl Future<Output = trc::Result<()>> + Send;
}

impl MetricsStore for Store {
    async fn write_metrics(&self, samples: Vec<Metric>, timestamp: u64) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        for sample in samples {
            let Some(id) = SnowflakeIdGenerator::global_id_from_timestamp(timestamp) else {
                continue;
            };
            batch.set(
                ValueClass::Telemetry(TelemetryClass::Metric(id)),
                ObjectInner::Metric(sample).to_pickled_vec(),
            );
            if batch.is_large_batch() {
                self.write(batch.build_all()).await?;
                batch = BatchBuilder::new();
            }
        }
        if !batch.is_empty() {
            self.write(batch.build_all()).await?;
        }
        Ok(())
    }

    async fn purge_metrics(&self, keep: Duration) -> trc::Result<()> {
        let Some(until) = SnowflakeIdGenerator::from_duration(keep) else {
            return Ok(());
        };
        self.delete_range(
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(0))),
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(until))),
        )
        .await
        .caused_by(trc::location!())
    }
}

/// Decodes a stored sample. Records in any other encoding (INBUXA's history
/// from before the fork) read as `None` and are skipped.
pub fn decode_metric(bytes: &[u8]) -> Option<Metric> {
    PickledStream::new(bytes)
        .and_then(|mut stream| ObjectInner::unpickle(ObjectType::Metric, &mut stream))
        .and_then(|inner| match inner {
            ObjectInner::Metric(metric) => Some(metric),
            _ => None,
        })
}

/// A stored sample as read by key: `None` when it can't be decoded.
pub struct MaybeMetric(pub Option<Metric>);

impl store::Deserialize for MaybeMetric {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(MaybeMetric(decode_metric(bytes)))
    }
}

/// A stored sample with its id.
pub struct StoredMetric {
    pub id: u64,
    pub metric: Metric,
}

impl StoredMetric {
    pub fn timestamp(&self) -> u64 {
        SnowflakeIdGenerator::to_timestamp(self.id)
    }

    /// The node that wrote the sample. Histogram totals are per node, so a
    /// reader diffs them per node.
    pub fn node_id(&self) -> u64 {
        SnowflakeIdGenerator::to_node_id(self.id)
    }
}

/// What the node wrote last, so counters and histograms are written as
/// changes (MON-4). Per process: a restart counts from the start.
static LAST: Mutex<Option<AHashMap<MetricType, (u64, u64)>>> = Mutex::new(None);

/// Gauges that count the whole cluster's data, not this node's. Only the node
/// that computes them (the metrics-calculation role) has a true reading; on
/// the others the queue gauge only moves with local queue events and drifts
/// below zero, and the account and domain counts stay at 0.
const CLUSTER_GAUGES: [MetricType; 3] = [
    MetricType::QueueCount,
    MetricType::UserCount,
    MetricType::DomainCount,
];

/// One tick's samples (MON-4 to MON-6). `calculates` is whether this node
/// computes the cluster-wide gauges; a node that doesn't leaves them out.
pub fn sample(calculates: bool) -> Vec<Metric> {
    let mut last_guard = LAST.lock().unwrap();
    let last = last_guard.get_or_insert_with(AHashMap::new);
    let mut samples = Vec::new();

    // Counters: the increase since the previous sample; none if unchanged
    for counter in Collector::collect_counters() {
        let Some(metric) = MetricType::parse(counter.id().as_str()) else {
            continue;
        };
        let total = counter.value();
        let previous = last.insert(metric, (total, 0)).map_or(0, |(count, _)| count);
        let increase = total.saturating_sub(previous);
        if increase > 0 {
            samples.push(Metric::Counter(MetricCount {
                count: increase,
                metric,
            }));
        }
    }

    // Gauges: the reading, always (MON-5)
    for gauge in Collector::collect_gauges() {
        if !calculates && CLUSTER_GAUGES.contains(&gauge.id()) {
            continue;
        }
        samples.push(Metric::Gauge(MetricCount {
            count: gauge.get(),
            metric: gauge.id(),
        }));
    }

    // Histograms: totals, when changed (MON-4 Decision)
    for histogram in Collector::collect_histograms() {
        let metric = histogram.id();
        let current = (histogram.count(), histogram.sum());
        if last.insert(metric, current) != Some(current) {
            samples.push(Metric::Histogram(MetricSum {
                count: current.0,
                sum: current.1,
                metric,
            }));
        }
    }

    samples
}

/// The retention settings in force now (MON-3 Decision: no reload needed).
pub async fn retention(server: &Server) -> DataRetention {
    server
        .registry()
        .object::<DataRetention>(Id::singleton())
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

impl Server {
    /// Writes one tick of metric history, if it's on (MON-4, MON-9). Never
    /// fails loudly: history is lost, mail isn't (MON-35).
    pub async fn store_metrics(&self) {
        let store = self.metrics_store();
        if store.is_none() {
            return;
        }
        let samples = sample(self.core.network.roles.metrics_calculate);
        let count = samples.len();
        let started = std::time::Instant::now();
        match store.write_metrics(samples, now()).await {
            Ok(()) => trc::event!(
                Telemetry(TelemetryEvent::MetricsStored),
                Total = count,
                Elapsed = started.elapsed(),
            ),
            Err(err) => {
                trc::error!(err.details("Failed to store metric history"));
            }
        }
    }

    /// The stored samples between two ids, in key order, skipping any that
    /// can't be decoded or are past `holdMetricsFor` (MON-17).
    pub async fn read_metrics(
        &self,
        from_id: u64,
        to_id: u64,
        ascending: bool,
        mut accept: impl FnMut(&StoredMetric) -> bool + Send + Sync,
    ) -> trc::Result<Vec<StoredMetric>> {
        let store = self.metrics_store();
        let mut out = Vec::new();
        if store.is_none() {
            return Ok(out);
        }
        let floor = match retention(self).await.hold_metrics_for {
            Some(keep) => SnowflakeIdGenerator::from_duration(keep.into_inner()).unwrap_or(0),
            None => 0,
        };
        let from_id = from_id.max(floor);
        if from_id > to_id {
            return Ok(out);
        }
        let params = IterateParams::new(
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(from_id))),
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(to_id))),
        );
        let params = if ascending {
            params.ascending()
        } else {
            params.descending()
        };
        store
            .iterate(params, |key, value| {
                let id = key.deserialize_be_u64(0)?;
                if let Some(metric) = decode_metric(value) {
                    let sample = StoredMetric { id, metric };
                    if accept(&sample) {
                        out.push(sample);
                    }
                }
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        Ok(out)
    }

    /// Test data for the shared metrics suite: 90 days of hourly ticks, a
    /// counter, a gauge and a histogram each.
    #[cfg(feature = "test_mode")]
    pub async fn insert_test_metrics(&self) {
        let now = now();
        for hour in (0..90 * 24u64).rev() {
            let samples = vec![
                Metric::Counter(MetricCount {
                    count: 1 + hour % 7,
                    metric: MetricType::AuthSuccess,
                }),
                Metric::Gauge(MetricCount {
                    count: 20 + hour % 11,
                    metric: MetricType::QueueCount,
                }),
                Metric::Histogram(MetricSum {
                    count: 100 + hour,
                    sum: 1000 + hour * 10,
                    metric: MetricType::DeliveryTotalTime,
                }),
            ];
            self.metrics_store()
                .write_metrics(samples, now - hour * 3600)
                .await
                .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gauges(samples: &[Metric]) -> Vec<MetricType> {
        samples
            .iter()
            .filter_map(|m| match m {
                Metric::Gauge(g) => Some(g.metric),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn only_the_calculating_node_stores_cluster_gauges() {
        let all = gauges(&sample(true));
        let local = gauges(&sample(false));
        for metric in CLUSTER_GAUGES {
            assert!(
                all.contains(&metric),
                "{metric:?} missing on the calculating node"
            );
            assert!(
                !local.contains(&metric),
                "{metric:?} stored by a node that doesn't compute it"
            );
        }
        // Per-node gauges are stored either way
        for metric in [MetricType::ServerMemory, MetricType::HttpActiveConnections] {
            assert!(
                all.contains(&metric) && local.contains(&metric),
                "{metric:?}"
            );
        }
    }
}
