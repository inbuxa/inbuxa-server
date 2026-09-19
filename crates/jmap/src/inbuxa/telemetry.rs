/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! `x:Metric/get` and `/query` over the stored history (monitoring spec,
//! "Interfaces"). Samples are server-level (MON-31) and read-only (MON-32).
//! A sample's `timestamp` comes from its id.

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse},
        query::RegistryQueryFilters,
    },
};
use common::telemetry::metrics::store::{MaybeMetric, StoredMetric};
use jmap_proto::types::state::State;
use registry::{
    jmap::{IntoValue, JmapValue},
    schema::{
        prelude::Property,
        structs::Metric,
    },
    types::datetime::UTCDateTime,
};
use store::{
    ValueKey,
    registry::RegistryFilterOp,
    write::{TelemetryClass, ValueClass},
};
use trc::MetricType;
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

/// Telemetry is server-level: nobody inside a tenant reads it (MON-31).
pub fn assert_server_level(access_token: &common::auth::AccessToken) -> trc::Result<()> {
    if access_token.tenant_id().is_some() {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Telemetry is server-level."))
    } else {
        Ok(())
    }
}

fn metric_type(metric: &Metric) -> MetricType {
    match metric {
        Metric::Counter(m) | Metric::Gauge(m) => m.metric,
        Metric::Histogram(m) => m.metric,
    }
}

fn to_value(sample: StoredMetric) -> JmapValue<'static> {
    let timestamp = sample.timestamp();
    let mut value = sample.metric.into_value();
    if let JmapValue::Object(obj) = &mut value {
        obj.insert_unchecked(
            Property::Timestamp,
            JmapValue::Str(UTCDateTime::from_timestamp(timestamp as i64).to_string().into()),
        );
    }
    value
}

/// `x:Metric/get`: by id, or every stored sample (up to the get limit).
pub(crate) async fn metric_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    assert_server_level(get.access_token)?;
    let server = get.server;
    match get.ids.take() {
        Some(ids) => {
            for id in ids {
                let sample = server
                    .metrics_store()
                    .get_value::<MaybeMetric>(ValueKey::from(ValueClass::Telemetry(
                        TelemetryClass::Metric(id.id()),
                    )))
                    .await
                    .ok()
                    .flatten()
                    .and_then(|MaybeMetric(metric)| metric)
                    .map(|metric| StoredMetric { id: id.id(), metric });
                match sample {
                    Some(sample) if !expired(server, sample.id).await => {
                        get.insert(id, to_value(sample))
                    }
                    _ => get.not_found(id),
                }
            }
        }
        None => {
            let max = server.core.jmap.get_max_objects;
            let mut n = 0;
            for sample in server
                .read_metrics(0, u64::MAX, true, |_| {
                    n += 1;
                    n <= max
                })
                .await?
            {
                get.insert(Id::from(sample.id), to_value(sample));
            }
        }
    }
    Ok(get)
}

async fn expired(server: &common::Server, id: u64) -> bool {
    match common::telemetry::metrics::store::retention(server)
        .await
        .hold_metrics_for
    {
        Some(keep) => {
            SnowflakeIdGenerator::from_duration(keep.into_inner()).is_some_and(|floor| id < floor)
        }
        None => false,
    }
}

fn timestamp_of(value: &serde_json::Value) -> Option<u64> {
    value
        .as_str()
        .and_then(|s| s.parse::<UTCDateTime>().ok())
        .map(|d| d.timestamp().max(0) as u64)
}

/// `x:Metric/query`: filters `metric` (a name or a list) and the timestamp
/// comparisons; a bare `timestamp` is `unsupportedFilter`. Sorted by
/// timestamp (the id), either way.
pub(crate) async fn metric_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    assert_server_level(req.access_token)?;
    let (mut from_id, mut to_id) = (0u64, u64::MAX);
    let mut metrics: Option<Vec<MetricType>> = None;
    let mut bad = false;
    req.request.extract_filters(|property, op, value| match property {
        Property::Timestamp => {
            let Some(ts) = timestamp_of(&value) else {
                return false;
            };
            // The ids of second `ts` run from `first_id_at(ts)` up to, not
            // including, `first_id_at(ts + 1)`
            let at = SnowflakeIdGenerator::first_id_at;
            match op {
                RegistryFilterOp::GreaterThan => from_id = from_id.max(at(ts + 1)),
                RegistryFilterOp::GreaterEqualThan => from_id = from_id.max(at(ts)),
                RegistryFilterOp::LowerThan => to_id = to_id.min(at(ts).saturating_sub(1)),
                RegistryFilterOp::LowerEqualThan => {
                    to_id = to_id.min(at(ts + 1).saturating_sub(1))
                }
                _ => return false,
            }
            true
        }
        Property::Metric => {
            let names = match &value {
                serde_json::Value::String(name) => vec![name.as_str()],
                serde_json::Value::Array(list) => {
                    list.iter().filter_map(|v| v.as_str()).collect()
                }
                _ => return false,
            };
            let mut parsed = Vec::with_capacity(names.len());
            for name in names {
                match MetricType::parse(name) {
                    Some(metric) => parsed.push(metric),
                    None => bad = true,
                }
            }
            metrics.get_or_insert_with(Vec::new).extend(parsed);
            true
        }
        _ => false,
    })?;
    if bad {
        return Err(trc::JmapEvent::UnsupportedFilter
            .into_err()
            .details("Unknown metric name"));
    }

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, None)?;
    if !matches!(params.sort_by, Property::Timestamp | Property::Id) {
        return Err(trc::JmapEvent::UnsupportedSort
            .into_err()
            .details("Metrics sort by timestamp only"));
    }
    let samples = req
        .server
        .read_metrics(from_id, to_id, params.sort_ascending, |sample| {
            metrics
                .as_ref()
                .is_none_or(|m| m.contains(&metric_type(&sample.metric)))
        })
        .await?;

    let mut response = QueryResponseBuilder::new(
        samples.len(),
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );
    for sample in samples {
        if !response.add_id(Id::from(sample.id)) {
            break;
        }
    }
    Ok(response)
}
