/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod codec;
pub mod window;

use super::{
    AggregateTimestamp, dmarc::dmarc_report_descriptor, tls::tls_report_descriptor,
    tls::tls_report_policy,
};
use codec::{Detail, ReportRow, RowReader, RowWriter};
use common::{
    Server,
    config::smtp::report::AggregateFrequency,
    ipc::{ReportingEvent, ToHash},
};
use registry::{
    pickle::{Pickle, PickledStream},
    schema::{
        enums::TlsPolicyType,
        prelude::ObjectType,
        structs::{
            DmarcInternalReport, DmarcReportRecord, Task, TaskReportWindow, TaskStatus,
            TlsFailureDetails, TlsInternalReport, TlsReportPolicy,
        },
    },
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime},
};
use std::ops::Range;
use store::{
    IterateParams, Store, Subspace, U64_LEN,
    write::{
        AnyClass, AnyKey, BatchBuilder, ValueClass,
        key::{CounterKind, KeySerializer},
        now,
    },
    xxhash_rust::xxh3::Xxh3,
};
use trc::{AddContext, OutgoingReportEvent};

pub(crate) const REPORT_BURST: usize = 256;
const ROW_KEY_MAX_LEN: usize = 255;
const ROW_PREFIX_LEN: usize = 1 + U64_LEN;
const POLICY_KEY_LEN: usize = 1 + 2 + U64_LEN;
const POLICY_MARKER: u8 = u8::MAX;
const DESCRIPTOR_MARKER: u8 = u8::MAX - 1;
const DESCRIPTOR_PREFIX_LEN: usize = 1 + 2 + U64_LEN;
const DESCRIPTOR_KEY_LEN: usize = DESCRIPTOR_PREFIX_LEN + (U64_LEN * 2);
const ROW_PAYLOAD_MAX_LEN: usize = ROW_KEY_MAX_LEN - ROW_PREFIX_LEN;
const WINDOW_UNIT: u64 = 3600;
const ID_HASH_BITS: u32 = 41;
const ID_HASH_MASK: u64 = (1 << ID_HASH_BITS) - 1;
const ID_TLS_BIT: u64 = 1 << ID_HASH_BITS;
const ID_WINDOW_SHIFT: u32 = ID_HASH_BITS + 1;
const ID_WINDOW_BITS: u32 = 20;
const ID_WINDOW_MASK: u64 = (1 << ID_WINDOW_BITS) - 1;
const TLS_SUCCESS: u8 = 0;
const TLS_FAILURE: u8 = 1;
const SEND_DELAY: u64 = 300;
const SEND_JITTER: u64 = 600;
const DEFAULT_MAX_SIZE: usize = 5 * 1024 * 1024;

pub(crate) fn report_size_limit(max_size: Option<usize>) -> usize {
    match max_size.unwrap_or(DEFAULT_MAX_SIZE) {
        0 => usize::MAX,
        max_size => max_size,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReportWindow {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportItem {
    pub object: ObjectType,
    pub item_id: u64,
}

#[derive(Default)]
pub(crate) struct ReportScheduler {
    pending: Vec<PendingRow>,
    keys: Vec<u8>,
    windows: Vec<(ObjectType, u64)>,
}

struct PendingRow {
    object: ObjectType,
    slot: u64,
    window: ReportWindow,
    policy: u64,
    event: usize,
    key: Range<usize>,
}

impl ReportWindow {
    fn current(interval: &AggregateFrequency) -> Option<Self> {
        match interval.as_secs() {
            0 => None,
            secs => {
                let start = interval.to_timestamp();
                Some(ReportWindow {
                    start,
                    end: start + secs,
                })
            }
        }
    }

    fn slot(&self, object: ObjectType, domain: &str, policy: u64) -> u64 {
        let mut hasher = Xxh3::new();
        hasher.update(&object.to_id().to_be_bytes());
        hasher.update(domain.as_bytes());
        hasher.update(&[0]);
        hasher.update(&policy.to_be_bytes());
        hasher.update(&self.start.to_be_bytes());
        hasher.update(&self.end.to_be_bytes());
        hasher.digest()
    }

    fn item_id(&self, object: ObjectType, slot: u64) -> u64 {
        let object = match object {
            ObjectType::TlsInternalReport => ID_TLS_BIT,
            _ => 0,
        };
        (((self.end / WINDOW_UNIT) & ID_WINDOW_MASK) << ID_WINDOW_SHIFT)
            | object
            | (slot & ID_HASH_MASK)
    }

    fn task(&self, object: ObjectType) -> Option<Task> {
        let task = TaskReportWindow {
            window_end: UTCDateTime::from_timestamp(self.end.cast_signed()),
            status: TaskStatus::at(self.end.saturating_add(SEND_DELAY).cast_signed()),
        };
        match object {
            ObjectType::DmarcInternalReport => Some(Task::DmarcReportWindow(task)),
            ObjectType::TlsInternalReport => Some(Task::TlsReportWindow(task)),
            _ => None,
        }
    }
}

impl ReportItem {
    pub fn new(object: ObjectType, item_id: u64) -> Self {
        ReportItem { object, item_id }
    }

    pub(crate) fn deliver_at(&self, window: ReportWindow) -> u64 {
        window.end + SEND_DELAY + self.item_id % SEND_JITTER
    }

    fn push_row_prefix(&self, out: &mut Vec<u8>) {
        out.push(CounterKind::ReportRow.byte());
        out.extend_from_slice(&self.item_id.to_be_bytes());
    }

    fn row_bound(item_id: u64) -> AnyKey<Vec<u8>> {
        AnyKey {
            subspace: Subspace::Counter,
            key: KeySerializer::new(ROW_PREFIX_LEN)
                .write(CounterKind::ReportRow.byte())
                .write(item_id)
                .finalize(),
        }
    }

    fn policy_bound(&self, item_id: u64) -> AnyKey<Vec<u8>> {
        AnyKey {
            subspace: Subspace::ReportOut,
            key: KeySerializer::new(POLICY_KEY_LEN)
                .write(POLICY_MARKER)
                .write(self.object.to_id())
                .write(item_id)
                .finalize(),
        }
    }

    fn descriptor_key(&self, window_end: u64, slot: u64) -> Vec<u8> {
        KeySerializer::new(DESCRIPTOR_KEY_LEN)
            .write(DESCRIPTOR_MARKER)
            .write(self.object.to_id())
            .write(window_end)
            .write(self.item_id)
            .write(slot)
            .finalize()
    }

    fn descriptor_bound(object: ObjectType, window_end: u64) -> AnyKey<Vec<u8>> {
        AnyKey {
            subspace: Subspace::ReportOut,
            key: KeySerializer::new(DESCRIPTOR_PREFIX_LEN)
                .write(DESCRIPTOR_MARKER)
                .write(object.to_id())
                .write(window_end)
                .finalize(),
        }
    }

    fn policy_key(&self, policy: u64) -> Vec<u8> {
        KeySerializer::new(POLICY_KEY_LEN + U64_LEN)
            .write(POLICY_MARKER)
            .write(self.object.to_id())
            .write(self.item_id)
            .write(policy)
            .finalize()
    }

    async fn rows(
        &self,
        store: &Store,
        mut cb: impl FnMut(&[u8], u64) + Send + Sync,
    ) -> trc::Result<()> {
        store
            .iterate(
                IterateParams::new(
                    Self::row_bound(self.item_id),
                    Self::row_bound(self.item_id.saturating_add(1)),
                ),
                |key, value| {
                    let count = value
                        .first_chunk::<U64_LEN>()
                        .map(|count| i64::from_le_bytes(*count))
                        .ok_or_else(|| {
                            trc::Error::corrupted_key(key, value.into(), trc::location!())
                        })?;
                    if let (Some(row), Ok(count @ 1..)) =
                        (key.get(ROW_PREFIX_LEN..), u64::try_from(count))
                    {
                        cb(row, count);
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())
    }

    pub fn clear(&self, batch: &mut BatchBuilder) {
        batch.clear_range(
            Subspace::Counter,
            Self::row_bound(self.item_id).key,
            Self::row_bound(self.item_id.saturating_add(1)).key,
        );
        if self.object == ObjectType::TlsInternalReport {
            batch.clear_range(
                Subspace::ReportOut,
                self.policy_bound(self.item_id).key,
                self.policy_bound(self.item_id.saturating_add(1)).key,
            );
        }
    }

    pub async fn clear_orphans(&self, store: &Store) -> trc::Result<()> {
        let mut has_rows = false;
        store
            .iterate(
                IterateParams::new(
                    Self::row_bound(self.item_id),
                    Self::row_bound(self.item_id.saturating_add(1)),
                )
                .set_values(false),
                |_, _| {
                    has_rows = true;
                    Ok(false)
                },
            )
            .await
            .caused_by(trc::location!())?;
        if has_rows {
            let mut batch = BatchBuilder::new();
            self.clear(&mut batch);
            store
                .write_batch(&mut batch)
                .await
                .caused_by(trc::location!())?;
        }
        Ok(())
    }
}

pub async fn read_dmarc_records(
    store: &Store,
    item_id: u64,
    report: &mut DmarcInternalReport,
    max_size: usize,
) -> trc::Result<()> {
    let mut rows = TopRows::new(max_size, |record: &DmarcReportRecord| record.count);
    let domain = report.domain.as_str();
    ReportItem::new(ObjectType::DmarcInternalReport, item_id)
        .rows(store, |row, count| {
            match DmarcReportRecord::decode_row(domain, &mut RowReader::new(row)) {
                Some(mut record) => {
                    record.count = count;
                    rows.push(row.len(), record);
                }
                None => corrupted_row(item_id, row),
            }
        })
        .await?;

    let records = &mut report.report.records;
    for record in rows.into_rows() {
        records.push(record);
    }
    Ok(())
}

pub async fn read_tls_policies(
    store: &Store,
    item_id: u64,
    report: &mut TlsInternalReport,
    max_size: usize,
) -> trc::Result<()> {
    let item = ReportItem::new(ObjectType::TlsInternalReport, item_id);
    let mut policies: Vec<(u64, TlsReportPolicy)> = Vec::new();
    store
        .iterate(
            IterateParams::new(
                item.policy_bound(item_id),
                item.policy_bound(item_id.saturating_add(1)),
            ),
            |key, value| {
                if let Some(policy_hash) = key.last_chunk::<U64_LEN>() {
                    match PickledStream::new(value)
                        .and_then(|mut stream| TlsReportPolicy::unpickle(&mut stream))
                    {
                        Some(policy) => policies.push((u64::from_be_bytes(*policy_hash), policy)),
                        None => corrupted_row(item_id, key),
                    }
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let mut failures = TopRows::new(max_size, |(_, failure): &(u64, TlsFailureDetails)| {
        failure.failed_session_count
    });
    let domain = report.domain.as_str();
    item.rows(store, |row, count| {
        let Some((policy_hash, row)) = row.split_first_chunk::<U64_LEN>() else {
            corrupted_row(item_id, row);
            return;
        };
        let policy_hash = u64::from_be_bytes(*policy_hash);
        let index = match policies.binary_search_by_key(&policy_hash, |(hash, _)| *hash) {
            Ok(index) => index,
            Err(index) => {
                policies.insert(
                    index,
                    (
                        policy_hash,
                        TlsReportPolicy {
                            policy_type: TlsPolicyType::NoPolicyFound,
                            policy_domain: domain.to_string(),
                            ..Default::default()
                        },
                    ),
                );
                index
            }
        };
        let Some((_, policy)) = policies.get_mut(index) else {
            return;
        };
        match row.split_first() {
            Some((&TLS_SUCCESS, [])) => {
                policy.total_successful_sessions += count;
            }
            Some((&TLS_FAILURE, details)) => {
                policy.total_failed_sessions += count;
                match TlsFailureDetails::decode_row(domain, &mut RowReader::new(details)) {
                    Some(mut failure) => {
                        failure.failed_session_count = count;
                        failures.push(details.len(), (policy_hash, failure));
                    }
                    None => corrupted_row(item_id, row),
                }
            }
            _ => corrupted_row(item_id, row),
        }
    })
    .await?;

    for (policy_hash, failure) in failures.into_rows() {
        if let Ok(index) = policies.binary_search_by_key(&policy_hash, |(hash, _)| *hash)
            && let Some((_, policy)) = policies.get_mut(index)
        {
            policy.failure_details.push(failure);
        }
    }
    for (policy_hash, policy) in policies {
        report.policy_identifiers.push(policy_hash);
        report.report.policies.push(policy);
    }
    Ok(())
}

struct TopRows<T, F> {
    rows: Vec<(usize, T)>,
    size: usize,
    max_size: usize,
    count: F,
}

impl<T, F: Fn(&T) -> u64> TopRows<T, F> {
    fn new(max_size: usize, count: F) -> Self {
        TopRows {
            rows: Vec::new(),
            size: 0,
            max_size,
            count,
        }
    }

    fn push(&mut self, len: usize, row: T) {
        self.size = self.size.saturating_add(len);
        self.rows.push((len, row));
        if self.size > self.max_size.saturating_mul(2) {
            self.trim();
        }
    }

    fn trim(&mut self) {
        if self.size > self.max_size {
            let count = &self.count;
            self.rows
                .sort_unstable_by_key(|(_, row)| std::cmp::Reverse(count(row)));
            let max_size = self.max_size;
            let mut size = 0usize;
            self.rows.retain(|(len, _)| {
                size = size.saturating_add(*len);
                size <= max_size
            });
            self.size = self.rows.iter().map(|(len, _)| *len).sum();
        }
    }

    fn into_rows(mut self) -> impl Iterator<Item = T> {
        self.trim();
        self.rows.into_iter().map(|(_, row)| row)
    }
}

#[cold]
fn corrupted_row(item_id: u64, row: &[u8]) {
    trc::error!(
        trc::Error::corrupted_key(row, None, trc::location!())
            .id(item_id)
            .details("Undecodable aggregate report row")
    );
}

impl ReportScheduler {
    pub(crate) async fn process(
        &mut self,
        server: &Server,
        events: &mut Vec<ReportingEvent>,
    ) -> bool {
        let mut stop = false;
        self.pending.clear();
        self.keys.clear();
        for (index, event) in events.iter_mut().enumerate() {
            match event {
                ReportingEvent::Dmarc(event) => {
                    let Some(window) = ReportWindow::current(&event.interval) else {
                        continue;
                    };
                    let object = ObjectType::DmarcInternalReport;
                    let policy = event.dmarc_record.to_hash();
                    let record = DmarcReportRecord::from(std::mem::take(&mut event.report_record));
                    let start = self.keys.len();
                    if encode_row(&record, &event.domain, &mut self.keys, start) {
                        self.pending.push(PendingRow {
                            object,
                            slot: window.slot(object, &event.domain, policy),
                            window,
                            policy,
                            event: index,
                            key: start..self.keys.len(),
                        });
                    } else {
                        oversized_row(&event.domain, event.span_id);
                    }
                }
                ReportingEvent::Tls(event) => {
                    let Some(window) = ReportWindow::current(&event.interval) else {
                        continue;
                    };
                    let object = ObjectType::TlsInternalReport;
                    let policy = event.policy.to_hash();
                    let start = self.keys.len();
                    self.keys.extend_from_slice(&policy.to_be_bytes());
                    let is_encoded = match event.failure.take() {
                        Some(failure) => {
                            self.keys.push(TLS_FAILURE);
                            encode_row(
                                &TlsFailureDetails::from(failure),
                                &event.domain,
                                &mut self.keys,
                                start,
                            )
                        }
                        None => {
                            self.keys.push(TLS_SUCCESS);
                            true
                        }
                    };
                    if is_encoded {
                        self.pending.push(PendingRow {
                            object,
                            slot: window.slot(object, &event.domain, 0),
                            window,
                            policy,
                            event: index,
                            key: start..self.keys.len(),
                        });
                    } else {
                        oversized_row(&event.domain, event.span_id);
                    }
                }
                ReportingEvent::Stop => {
                    stop = true;
                }
            }
        }

        if !self.pending.is_empty() {
            let keys = self.keys.as_slice();
            self.pending.sort_unstable_by(|a, b| {
                a.slot
                    .cmp(&b.slot)
                    .then_with(|| keys.get(a.key.clone()).cmp(&keys.get(b.key.clone())))
                    .then(a.event.cmp(&b.event))
            });
            self.write_rows(server, events).await;
        }
        events.clear();

        stop
    }

    async fn write_rows(&mut self, server: &Server, events: &[ReportingEvent]) {
        let ReportScheduler {
            pending,
            keys,
            windows,
        } = self;
        let mut batch = BatchBuilder::new();
        let mut new_windows: Vec<(ObjectType, u64)> = Vec::new();

        for rows in pending.chunk_by(|a, b| a.slot == b.slot) {
            let Some(first) = rows.first() else {
                continue;
            };
            let item =
                ReportItem::new(first.object, first.window.item_id(first.object, first.slot));
            let descriptor = match events.get(first.event) {
                Some(ReportingEvent::Dmarc(event)) => {
                    dmarc_report_descriptor(event, first.window, item, first.policy)
                        .to_pickled_vec()
                }
                Some(ReportingEvent::Tls(event)) => {
                    tls_report_descriptor(event, first.window, item).to_pickled_vec()
                }
                Some(ReportingEvent::Stop) | None => continue,
            };

            let window = (first.object, first.window.end);
            if !windows.contains(&window)
                && !new_windows.contains(&window)
                && let Some(task) = first.window.task(first.object)
            {
                batch.schedule_task(task);
                new_windows.push(window);
            }

            batch.set(
                ValueClass::Any(AnyClass {
                    subspace: Subspace::ReportOut,
                    key: item.descriptor_key(first.window.end, first.slot),
                }),
                descriptor,
            );
            add_rows(item, events, rows, keys, &mut batch);
            batch.commit_point();
        }

        match server.store().write_batch(&mut batch).await {
            Ok(_) => {
                if !new_windows.is_empty() {
                    let now = now();
                    windows.retain(|(_, end)| end.saturating_add(SEND_DELAY) > now);
                    windows.extend(new_windows);
                }
            }
            Err(err) => {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to write aggregate report rows")
                );
            }
        }
    }
}

fn add_rows(
    item: ReportItem,
    events: &[ReportingEvent],
    rows: &[PendingRow],
    keys: &[u8],
    batch: &mut BatchBuilder,
) {
    let mut last_policy = None;
    for rows in rows.chunk_by(|a, b| keys.get(a.key.clone()) == keys.get(b.key.clone())) {
        let Some(row) = rows.first() else {
            continue;
        };
        let Some(payload) = keys.get(row.key.clone()) else {
            continue;
        };

        if let Some(ReportingEvent::Tls(event)) = events.get(row.event)
            && last_policy != Some(row.policy)
        {
            last_policy = Some(row.policy);
            let mut value = Vec::with_capacity(64);
            value.push(TlsInternalReport::VERSION);
            tls_report_policy(event).pickle(&mut value);
            batch.set(
                ValueClass::Any(AnyClass {
                    subspace: Subspace::ReportOut,
                    key: item.policy_key(row.policy),
                }),
                value,
            );
        }

        let mut key = Vec::with_capacity(ROW_PREFIX_LEN + payload.len());
        item.push_row_prefix(&mut key);
        key.extend_from_slice(payload);
        batch.add(
            ValueClass::Any(AnyClass {
                subspace: Subspace::Counter,
                key,
            }),
            i64::try_from(rows.len()).unwrap_or(i64::MAX),
        );
    }
}

fn encode_row(row: &impl ReportRow, context: &str, out: &mut Vec<u8>, start: usize) -> bool {
    let payload = out.len();
    row.encode_row(context, &mut RowWriter::new(out, Detail::Full));
    if out.len() - start <= ROW_PAYLOAD_MAX_LEN {
        return true;
    }
    out.truncate(payload);
    row.encode_row(context, &mut RowWriter::new(out, Detail::Compact));
    if out.len() - start <= ROW_PAYLOAD_MAX_LEN {
        true
    } else {
        out.truncate(start);
        false
    }
}

#[cold]
fn oversized_row(domain: &str, span_id: u64) {
    trc::event!(
        OutgoingReport(OutgoingReportEvent::MaxSizeExceeded),
        SpanId = span_id,
        Domain = domain.to_string(),
        Limit = ROW_KEY_MAX_LEN,
    );
}

