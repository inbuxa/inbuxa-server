/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Trace history (monitoring spec MON-10 to MON-17, MON-34). A lossy
//! collector subscriber gathers each inbound SMTP session and delivery
//! attempt, and writes it once, when the span closes, as an `x:Trace` in the
//! registry's own encoding under `TelemetryClass::Span(span_id)`.

use crate::telemetry::tracers::TraceEvents;
use ahash::AHashMap;
use registry::{
    pickle::PickledStream,
    schema::{
        prelude::{ObjectInner, ObjectType},
        structs::{
            Task, TaskIndexTrace, TaskStatus, Trace, TraceKeyValue, TraceValue,
            TraceValueString, TraceValueUnsignedInt,
        },
    },
};
use std::{future::Future, sync::Arc, time::Duration};
use store::{
    SearchStore, Store, ValueKey,
    search::{SearchFilter, SearchQuery},
    write::{BatchBuilder, SearchIndex, TelemetryClass, ValueClass, now},
};
use trc::{
    AddContext, DeliveryEvent, Event, EventDetails, EventType, Key, Level, SmtpEvent,
    ipc::subscriber::SubscriberBuilder,
};
use utils::snowflake::SnowflakeIdGenerator;

/// Events kept per trace (MON-15).
pub const MAX_EVENTS: usize = 1000;
/// The longest string value kept (MON-15).
pub const MAX_STRING: usize = 4096;
/// A span still open after this is dropped (MON-13).
const SPAN_MAX_HOLD: u64 = 86_400;

pub trait TracingStore: Sync + Send {
    /// Deletes traces older than `keep`, and their search documents
    /// (MON-17).
    fn purge_spans(
        &self,
        keep: Duration,
        search: Option<&SearchStore>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl TracingStore for Store {
    async fn purge_spans(&self, keep: Duration, search: Option<&SearchStore>) -> trc::Result<()> {
        let Some(until) = SnowflakeIdGenerator::from_duration(keep) else {
            return Ok(());
        };
        self.delete_range(
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(0))),
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(until))),
        )
        .await
        .caused_by(trc::location!())?;
        if let Some(search) = search {
            search
                .unindex(
                    SearchQuery::new(SearchIndex::Tracing)
                        .with_filter(SearchFilter::lt(store::search::SearchField::Id, until)),
                )
                .await
                .caused_by(trc::location!())?;
        }
        Ok(())
    }
}

/// Decodes a stored trace; `None` for records in any other encoding.
pub fn decode_trace(bytes: &[u8]) -> Option<Trace> {
    PickledStream::new(bytes)
        .and_then(|mut stream| ObjectInner::unpickle(ObjectType::Trace, &mut stream))
        .and_then(|inner| match inner {
            ObjectInner::Trace(trace) => Some(trace),
            _ => None,
        })
}

/// A stored trace as read by key: `None` when it can't be decoded.
pub struct MaybeTrace(pub Option<Trace>);

impl store::Deserialize for MaybeTrace {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(MaybeTrace(decode_trace(bytes)))
    }
}

fn is_stored_span(event: EventType) -> bool {
    matches!(
        event,
        EventType::Smtp(SmtpEvent::ConnectionStart) | EventType::Delivery(DeliveryEvent::AttemptStart)
    )
}

fn is_mail_from(event: EventType) -> bool {
    event.as_str().starts_with("smtp.mail-from") || event == EventType::Smtp(SmtpEvent::MultipleMailFrom)
}

struct Span {
    started: u64,
    is_smtp: bool,
    has_mail_from: bool,
    events: Vec<Arc<Event<EventDetails>>>,
    cut: usize,
}

fn truncate_values_list(values: &mut registry::types::list::List<TraceKeyValue>) {
    for kv in values.values_mut() {
        match &mut kv.value {
            TraceValue::String(TraceValueString { value }) if value.len() > MAX_STRING => {
                let mut end = MAX_STRING;
                while !value.is_char_boundary(end) {
                    end -= 1;
                }
                value.truncate(end);
            }
            TraceValue::Event(event) => truncate_values_list(&mut event.value),
            _ => {}
        }
    }
}

/// The trace a closed span leaves (MON-12, MON-15).
fn build_trace(span: &Span) -> Trace {
    let mut trace = Trace::from_events(span.events.iter().map(|e| e.as_ref()), span.events.len());
    for event in trace.events.values_mut() {
        truncate_values_list(&mut event.key_values);
    }
    if span.cut > 0
        && let Some(last) = trace.events.values_mut().last()
    {
        // The count of events cut rides on the closing event
        last.key_values.push(TraceKeyValue {
            key: Key::Total,
            value: TraceValue::UnsignedInt(TraceValueUnsignedInt {
                value: span.cut as u64,
            }),
        });
    }
    trace
}

/// Starts the subscriber that stores traces in `tracing`, scheduling their
/// indexing in `data` (MON-16). Lossy: a slow store loses history, never
/// delays mail (MON-34, MON-35).
pub(crate) fn spawn_store_tracer(builder: SubscriberBuilder, tracing: Store, data: Store) {
    let (_, mut rx) = builder.register();
    tokio::spawn(async move {
        let mut spans: AHashMap<u64, Span> = AHashMap::new();
        while let Some(events) = rx.recv().await {
            let mut closed = Vec::new();
            for event in events {
                let typ = event.inner.typ;
                let Some(span_id) = event.span_id() else {
                    continue;
                };
                if is_stored_span(typ) {
                    spans.insert(
                        span_id,
                        Span {
                            started: event.inner.timestamp,
                            is_smtp: matches!(typ, EventType::Smtp(_)),
                            has_mail_from: false,
                            events: vec![event],
                            cut: 0,
                        },
                    );
                    continue;
                }
                let Some(span) = spans.get_mut(&span_id) else {
                    continue;
                };
                if is_mail_from(typ) {
                    span.has_mail_from = true;
                }
                let is_end = typ.is_span_end();
                // MON-12: info and above, never raw I/O
                if !typ.is_raw_io() && (is_end || event.inner.level as usize >= Level::Info as usize) {
                    if span.events.len() < MAX_EVENTS - 1 || is_end {
                        span.events.push(event);
                    } else {
                        span.cut += 1;
                    }
                }
                if is_end && let Some(span) = spans.remove(&span_id) {
                    // MON-11: a session that never reached MAIL FROM isn't kept
                    if !span.is_smtp || span.has_mail_from {
                        closed.push((span_id, span));
                    }
                }
            }

            if !closed.is_empty() {
                let mut batch = BatchBuilder::new();
                let mut tasks = BatchBuilder::new();
                for (span_id, span) in &closed {
                    batch.set(
                        ValueClass::Telemetry(TelemetryClass::Span(*span_id)),
                        ObjectInner::Trace(build_trace(span)).to_pickled_vec(),
                    );
                    tasks.schedule_task(Task::IndexTrace(TaskIndexTrace {
                        trace_id: (*span_id).into(),
                        status: TaskStatus::now(),
                    }));
                }
                if let Err(err) = tracing.write(batch.build_all()).await {
                    trc::error!(err.details("Failed to store trace history"));
                } else if let Err(err) = data.write(tasks.build_all()).await {
                    trc::error!(err.details("Failed to schedule trace indexing"));
                }
            }

            // MON-13: spans open for over a day are dropped
            if spans.len() > 1000 {
                let now = now();
                spans.retain(|_, span| now.saturating_sub(span.started) < SPAN_MAX_HOLD);
            }
        }
    });
}
