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

// ---- Traces (MON-10 to MON-17, MON-31, MON-32) ----

use common::telemetry::tracers::store::{MaybeTrace, decode_trace};
use registry::schema::structs::{Search, Trace, TraceValue};
use store::{
    IterateParams,
    search::{SearchFilter, SearchQuery, TracingSearchField},
    write::{BatchBuilder, SearchIndex, key::DeserializeBigEndian},
};
use trc::{AddContext, EventType, Key};

/// The trace's server-set fields (MON-14): the first event's time, the
/// first `from`, every distinct `to`, and the message size or 0.
fn trace_to_value(id: u64, trace: Trace) -> JmapValue<'static> {
    let mut from = None;
    let mut to: Vec<String> = Vec::new();
    let mut size = None;
    let mut first_timestamp = None;
    for event in trace.events.iter() {
        first_timestamp.get_or_insert(event.timestamp.timestamp());
        for kv in event.key_values.iter() {
            let mut texts = Vec::new();
            match &kv.value {
                TraceValue::String(v) => texts.push(v.value.clone()),
                TraceValue::List(list) => {
                    for item in list.value.iter() {
                        if let TraceValue::String(v) = item {
                            texts.push(v.value.clone());
                        }
                    }
                }
                TraceValue::UnsignedInt(v) if kv.key == Key::Size => {
                    size.get_or_insert(v.value);
                }
                _ => {}
            }
            match kv.key {
                Key::From => {
                    if from.is_none() {
                        from = texts.into_iter().next();
                    }
                }
                Key::To => {
                    for text in texts {
                        if !to.contains(&text) {
                            to.push(text);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let timestamp = first_timestamp
        .unwrap_or_else(|| SnowflakeIdGenerator::to_timestamp(id) as i64);
    let mut value = trace.into_value();
    if let JmapValue::Object(obj) = &mut value {
        obj.insert_unchecked(
            Property::Timestamp,
            JmapValue::Str(UTCDateTime::from_timestamp(timestamp).to_string().into()),
        );
        obj.insert_unchecked(
            Property::From,
            match from {
                Some(from) => JmapValue::Str(from.into()),
                None => JmapValue::Null,
            },
        );
        obj.insert_unchecked(Property::To, JmapValue::Str(to.join(", ").into()));
        obj.insert_unchecked(Property::Size, JmapValue::Number(size.unwrap_or(0).into()));
    }
    value
}

/// The oldest trace id still visible (MON-17).
async fn trace_floor(server: &common::Server) -> u64 {
    match common::telemetry::metrics::store::retention(server)
        .await
        .hold_traces_for
    {
        Some(keep) => SnowflakeIdGenerator::from_duration(keep.into_inner()).unwrap_or(0),
        None => 0,
    }
}

pub(crate) async fn read_trace(server: &common::Server, id: u64) -> trc::Result<Option<Trace>> {
    if id < trace_floor(server).await {
        return Ok(None);
    }
    Ok(server
        .tracing_store()
        .get_value::<MaybeTrace>(ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(id))))
        .await?
        .and_then(|MaybeTrace(trace)| trace))
}

/// `x:Trace/get`.
pub(crate) async fn trace_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    assert_server_level(get.access_token)?;
    let server = get.server;
    if server.tracing_store().is_none() {
        if let Some(ids) = get.ids.take() {
            for id in ids {
                get.not_found(id);
            }
        }
        return Ok(get);
    }
    let ids = match get.ids.take() {
        Some(ids) => ids,
        None => trace_ids(server, 0, u64::MAX, false, None)
            .await?
            .into_iter()
            .take(server.core.jmap.get_max_objects)
            .map(Id::from)
            .collect(),
    };
    for id in ids {
        match read_trace(server, id.id()).await? {
            Some(trace) => get.insert(id, trace_to_value(id.id(), trace)),
            None => get.not_found(id),
        }
    }
    Ok(get)
}

/// Trace ids in a range, newest first unless `ascending`, optionally only
/// those whose opening event is `event`.
async fn trace_ids(
    server: &common::Server,
    from_id: u64,
    to_id: u64,
    ascending: bool,
    event: Option<EventType>,
) -> trc::Result<Vec<u64>> {
    let from_id = from_id.max(trace_floor(server).await);
    let mut ids = Vec::new();
    if from_id > to_id || server.tracing_store().is_none() {
        return Ok(ids);
    }
    let params = IterateParams::new(
        ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(from_id))),
        ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(to_id))),
    );
    let params = if ascending {
        params.ascending()
    } else {
        params.descending()
    };
    server
        .tracing_store()
        .iterate(params, |key, value| {
            let id = key.deserialize_be_u64(0)?;
            if let Some(trace) = decode_trace(value)
                && event.is_none_or(|event| {
                    trace.events.iter().next().is_some_and(|first| first.event == event)
                })
            {
                ids.push(id);
            }
            Ok(true)
        })
        .await
        .caused_by(trc::location!())?;
    Ok(ids)
}

/// `x:Trace/query`: `event` (the opening event), `text` and `queueId`
/// (through the search index, refused when trace search is off), and the
/// timestamp comparisons.
pub(crate) async fn trace_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    assert_server_level(req.access_token)?;
    let (mut from_id, mut to_id) = (0u64, u64::MAX);
    let mut event = None;
    let mut search: Vec<SearchFilter> = Vec::new();
    req.request.extract_filters(|property, op, value| match property {
        Property::Timestamp => {
            let Some(ts) = timestamp_of(&value) else {
                return false;
            };
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
        Property::Event => match value.as_str().and_then(EventType::parse) {
            Some(parsed) => {
                event = Some(parsed);
                true
            }
            None => false,
        },
        Property::Text => match value.as_str() {
            Some(text) => {
                search.push(SearchFilter::has_text(
                    TracingSearchField::Keywords,
                    text.to_lowercase(),
                    nlp::language::Language::None,
                ));
                true
            }
            None => false,
        },
        // The queue id column is an integer on every search backend, and
        // holds a trace's first queue id; the keywords carry all of them
        Property::QueueId => match value
            .as_str()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .or_else(|| value.as_u64())
        {
            Some(queue_id) => {
                search.extend([
                    SearchFilter::Or,
                    SearchFilter::eq(TracingSearchField::QueueId, queue_id),
                    SearchFilter::has_text(
                        TracingSearchField::Keywords,
                        queue_id.to_string(),
                        nlp::language::Language::None,
                    ),
                    SearchFilter::End,
                ]);
                true
            }
            None => false,
        },
        _ => false,
    })?;

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, None)?;
    if !matches!(params.sort_by, Property::Timestamp | Property::Id) {
        return Err(trc::JmapEvent::UnsupportedSort
            .into_err()
            .details("Traces sort by timestamp only"));
    }

    let mut ids = trace_ids(req.server, from_id, to_id, params.sort_ascending, event).await?;
    if !search.is_empty() {
        let settings = req
            .server
            .registry()
            .object::<Search>(Id::singleton())
            .await?
            .unwrap_or_default();
        if !settings.index_telemetry {
            return Err(trc::JmapEvent::UnsupportedFilter
                .into_err()
                .details("Trace search is off (indexTelemetry)"));
        }
        let found = req
            .server
            .search_store()
            .query_global(SearchQuery::new(SearchIndex::Tracing).with_filters(search))
            .await?;
        let found = found.into_iter().collect::<std::collections::HashSet<_>>();
        ids.retain(|id| found.contains(id));
    }

    let mut response = QueryResponseBuilder::new(
        ids.len(),
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );
    for id in ids {
        if !response.add_id(Id::from(id)) {
            break;
        }
    }
    Ok(response)
}

/// `x:Trace/set`: create and update are refused; destroy removes the trace
/// and its search document (MON-32).
pub(crate) async fn trace_set(
    mut set: crate::registry::mapping::RegistrySetResponse<'_>,
) -> trc::Result<crate::registry::mapping::RegistrySetResponse<'_>> {
    assert_server_level(set.access_token)?;
    set.fail_all_create("Traces cannot be created");
    set.fail_all_update("Traces cannot be modified");
    let server = set.server;
    for id in std::mem::take(&mut set.destroy) {
        if read_trace(server, id.id()).await?.is_none() {
            set.response
                .not_destroyed
                .append(id, jmap_proto::error::set::SetError::not_found());
            continue;
        }
        let mut batch = BatchBuilder::new();
        batch.clear(ValueClass::Telemetry(TelemetryClass::Span(id.id())));
        server.tracing_store().write(batch.build_all()).await?;
        server
            .search_store()
            .unindex(
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(SearchFilter::eq(store::search::SearchField::Id, id.id())),
            )
            .await?;
        set.response.destroyed.push(id);
    }
    Ok(set)
}
