/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use registry::{
    pickle::Pickle,
    schema::{
        enums::{DmarcActionDisposition, TaskType},
        prelude::{ObjectType, Property},
        structs::{
            ArfExternalReport, DmarcExternalReport, DmarcInternalReport, Task, TaskDmarcReport,
            TaskStatus, TaskTlsReport, TlsExternalReport, TlsInternalReport,
        },
    },
    types::{
        EnumImpl, ObjectImpl,
        datetime::UTCDateTime,
        id::ObjectId,
        index::{IndexBuilder, IndexValue},
    },
};
use store::{
    SerializeInfallible, U64_LEN,
    registry::ObjectIdVersioned,
    write::{
        BatchBuilder, RegistryClass, TaskId, TaskQueueClass, ValueClass, assert::AssertValue,
        key::KeySerializer,
    },
    xxhash_rust::xxh3::Xxh3,
};
use types::id::Id;

pub trait InternalReportIndex: ObjectImpl + Pickle {
    const TASK_TYPE: TaskType;

    fn deliver_at(&self) -> UTCDateTime;

    fn set_deliver_at(&mut self, at: UTCDateTime);

    fn task(&self, item_id: u64) -> Task;

    fn primary_key(&self) -> ValueClass;

    /// Moves the report's delivery, and its queued task, to `at`.
    ///
    /// inbuxa: `queued` is the task as stored: its due, not the report's
    /// `deliverAt`, is the queue row that exists (they differ once the task
    /// has been retried), so that row goes too.
    fn reschedule_ops(
        &mut self,
        batch: &mut BatchBuilder,
        item_id: u64,
        revision: u64,
        at: UTCDateTime,
        queued: Option<&Task>,
    ) {
        let current_deliver_at = self.deliver_at();
        let current_due = current_deliver_at.timestamp() as u64;
        let queued_due = queued.map_or(current_due, |task| task.due_timestamp());
        let new_due = at.timestamp() as u64;

        if current_deliver_at != at || queued_due != new_due {
            let object = Self::OBJECT;
            let object_id = object.to_id();
            let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });

            self.set_deliver_at(at);

            batch.assert_value(key.clone(), AssertValue::Hash(revision));
            let mut stale = vec![current_due, u64::MAX];
            if !stale.contains(&queued_due) {
                stale.push(queued_due);
            }
            for due in stale.into_iter().filter(|due| *due != new_due) {
                batch.clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                    id: TaskId::Assigned(item_id),
                    typ: Self::TASK_TYPE,
                    due,
                }));
            }
            batch
                .schedule_task_with_id(item_id, self.task(item_id))
                .set(key, self.to_pickled_vec());
        }
    }

    fn write_header(&self, batch: &mut BatchBuilder, item_id: u64) -> usize {
        let object = Self::OBJECT;
        let value = self.to_pickled_vec();
        let len = value.len();

        batch
            .set(
                self.primary_key(),
                ObjectIdVersioned {
                    object_id: ObjectId::new(object, item_id.into()),
                    version: 0,
                }
                .serialize(),
            )
            .schedule_task_with_id(item_id, self.task(item_id))
            .set(
                ValueClass::Registry(RegistryClass::Item {
                    object_id: object.to_id(),
                    item_id,
                }),
                value,
            );

        len
    }

    fn write_ops(&self, batch: &mut BatchBuilder, item_id: u64, is_set: bool) {
        let object = Self::OBJECT;
        let object_id = object.to_id();
        let pk = self.primary_key();

        if is_set {
            batch
                .assert_value(pk.clone(), ())
                .set(
                    pk,
                    ObjectIdVersioned {
                        object_id: ObjectId::new(object, item_id.into()),
                        version: 0,
                    }
                    .serialize(),
                )
                .schedule_task_with_id(item_id, self.task(item_id));
        } else {
            batch
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id,
                }))
                .clear(pk)
                .clear(ValueClass::TaskQueue(TaskQueueClass::Task {
                    id: TaskId::Assigned(item_id),
                }))
                .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                    id: TaskId::Assigned(item_id),
                    typ: Self::TASK_TYPE,
                    due: self.deliver_at().timestamp() as u64,
                }))
                .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                    id: TaskId::Assigned(item_id),
                    typ: Self::TASK_TYPE,
                    due: u64::MAX,
                }));
        }
    }
}

pub trait ExternalReportIndex: ObjectImpl + Pickle {
    fn text(&self) -> impl Iterator<Item = &str>;

    // inbuxa: MT
    fn tenant_id(&self) -> Option<Id>;

    fn expires_at(&self) -> u64;

    fn domains(&self) -> impl Iterator<Item = &str>;

    fn success_fail_count(&self) -> (u64, u64);

    fn unique_key(&self) -> Option<[u8; 16]>;

    fn write_ops(&self, batch: &mut BatchBuilder, item_id: u64, is_set: bool) {
        let object_id = Self::OBJECT.to_id();
        let mut index_builder = IndexBuilder::default();
        for text in self.text() {
            index_builder.text(Property::Text, text);
        }

        // inbuxa: MT: tenant admins list their own reports
        if let Some(tenant_id) = self.tenant_id() {
            index_builder.search(Property::MemberTenantId, tenant_id.id());
        }

        let (success_count, fail_count) = self.success_fail_count();
        index_builder.search(Property::TotalSuccessfulSessions, success_count);
        index_builder.search(Property::TotalFailedSessions, fail_count);

        index_builder.search(Property::ExpiresAt, self.expires_at());

        if let Some(unique_key) = self.unique_key() {
            index_builder.unique(Property::ReportId, IndexValue::Bytes(unique_key.to_vec()));
        }

        batch.registry_index(object_id, item_id, index_builder.keys.iter(), is_set);

        let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });
        if is_set {
            batch.set(key, self.to_pickled_vec());
        } else {
            batch.clear(key);
        }
    }
}

pub(crate) fn internal_report_key(
    object: ObjectType,
    domain: &str,
    policy: Option<u64>,
    window_end: u64,
) -> ValueClass {
    let mut key = KeySerializer::new(domain.len() + 1 + (U64_LEN * 2));
    key.write(domain).write(0u8);
    if let Some(policy) = policy {
        key.write(policy);
    }
    ValueClass::Registry(RegistryClass::PrimaryKey {
        object_id: object.to_id().into(),
        index_id: Property::Domain.to_id(),
        key: key.write(window_end).finalize(),
    })
}

impl InternalReportIndex for DmarcInternalReport {
    const TASK_TYPE: TaskType = TaskType::DmarcReport;

    fn deliver_at(&self) -> UTCDateTime {
        self.deliver_at
    }

    fn set_deliver_at(&mut self, at: UTCDateTime) {
        self.deliver_at = at;
    }

    fn task(&self, item_id: u64) -> Task {
        Task::DmarcReport(TaskDmarcReport {
            report_id: item_id.into(),
            status: TaskStatus::at(self.deliver_at.timestamp()),
        })
    }

    fn primary_key(&self) -> ValueClass {
        internal_report_key(
            ObjectType::DmarcInternalReport,
            &self.domain,
            Some(self.policy_identifier),
            self.report.date_range_end.timestamp().cast_unsigned(),
        )
    }
}

impl InternalReportIndex for TlsInternalReport {
    const TASK_TYPE: TaskType = TaskType::TlsReport;

    fn deliver_at(&self) -> UTCDateTime {
        self.deliver_at
    }

    fn set_deliver_at(&mut self, at: UTCDateTime) {
        self.deliver_at = at;
    }

    fn task(&self, item_id: u64) -> Task {
        Task::TlsReport(TaskTlsReport {
            report_id: item_id.into(),
            status: TaskStatus::at(self.deliver_at.timestamp()),
        })
    }

    fn primary_key(&self) -> ValueClass {
        internal_report_key(
            ObjectType::TlsInternalReport,
            &self.domain,
            None,
            self.report.date_range_end.timestamp().cast_unsigned(),
        )
    }
}

impl ExternalReportIndex for ArfExternalReport {
    fn domains(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        report
            .reported_domains
            .iter()
            .filter_map(|s| non_empty(s))
            .chain(
                [report.dkim_domain.as_deref()]
                    .into_iter()
                    .flatten()
                    .filter_map(non_empty),
            )
    }

    fn text(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        report
            .reported_domains
            .iter()
            .filter_map(|s| non_empty(s))
            .chain(
                [
                    report.dkim_domain.as_deref(),
                    report.reporting_mta.as_deref(),
                    report.original_mail_from.as_deref(),
                    report.original_rcpt_to.as_deref(),
                ]
                .into_iter()
                .flatten()
                .filter_map(non_empty),
            )
            .chain(non_empty(&self.from))
    }

    // inbuxa: MT
    fn tenant_id(&self) -> Option<Id> {
        self.member_tenant_id
    }

    fn expires_at(&self) -> u64 {
        self.expires_at.timestamp() as u64
    }

    fn success_fail_count(&self) -> (u64, u64) {
        (self.report.incidents, 0)
    }

    fn unique_key(&self) -> Option<[u8; 16]> {
        None
    }
}

impl ExternalReportIndex for DmarcExternalReport {
    fn domains(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        non_empty(&report.policy_domain)
            .into_iter()
            .filter_map(non_empty)
    }

    fn text(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        non_empty(&report.email)
            .into_iter()
            .filter_map(non_empty)
            .chain(non_empty(&report.policy_domain))
            .chain(report.records.iter().flat_map(|r| {
                r.envelope_to
                    .as_deref()
                    .into_iter()
                    .filter_map(non_empty)
                    .chain(non_empty(&r.envelope_from))
                    .chain(non_empty(&r.header_from))
                    .chain(r.dkim_results.iter().filter_map(|d| non_empty(&d.domain)))
                    .chain(r.spf_results.iter().filter_map(|s| non_empty(&s.domain)))
            }))
            .chain(non_empty(&self.from))
    }

    // inbuxa: MT
    fn tenant_id(&self) -> Option<Id> {
        self.member_tenant_id
    }

    fn expires_at(&self) -> u64 {
        self.expires_at.timestamp() as u64
    }

    fn success_fail_count(&self) -> (u64, u64) {
        let mut success_count = 0;
        let mut fail_count = 0;

        for record in self.report.records.iter() {
            if record.evaluated_disposition == DmarcActionDisposition::Pass {
                success_count += std::cmp::min(record.count, 1);
            } else {
                fail_count += std::cmp::min(record.count, 1);
            }
        }

        (success_count, fail_count)
    }

    fn unique_key(&self) -> Option<[u8; 16]> {
        let report = &self.report;

        Some(report_key(
            [
                report.org_name.as_str(),
                report.policy_domain.as_str(),
                report.report_id.as_str(),
            ],
            report.date_range_start,
            report.date_range_end,
        ))
    }
}

impl ExternalReportIndex for TlsExternalReport {
    fn domains(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        report
            .policies
            .iter()
            .flat_map(|p| non_empty(&p.policy_domain).into_iter())
    }

    fn text(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        report
            .policies
            .iter()
            .flat_map(|p| {
                non_empty(&p.policy_domain)
                    .into_iter()
                    .chain(p.mx_hosts.iter().filter_map(|s| non_empty(s)))
                    .chain(p.failure_details.iter().flat_map(|fd| {
                        non_empty_opt(&fd.receiving_mx_hostname)
                            .into_iter()
                            .chain(non_empty_opt(&fd.receiving_mx_helo))
                    }))
            })
            .chain(non_empty(&self.from))
    }

    // inbuxa: MT
    fn tenant_id(&self) -> Option<Id> {
        self.member_tenant_id
    }

    fn expires_at(&self) -> u64 {
        self.expires_at.timestamp() as u64
    }

    fn success_fail_count(&self) -> (u64, u64) {
        let mut success_count = 0;
        let mut fail_count = 0;

        for policy in self.report.policies.iter() {
            success_count += std::cmp::min(policy.total_successful_sessions, 1);
            fail_count += std::cmp::min(policy.total_failed_sessions, 1);
        }

        (success_count, fail_count)
    }

    fn unique_key(&self) -> Option<[u8; 16]> {
        let report = &self.report;

        Some(report_key(
            [
                report.organization_name.as_deref().unwrap_or_default(),
                report.report_id.as_str(),
            ],
            report.date_range_start,
            report.date_range_end,
        ))
    }
}

fn report_key<const N: usize>(fields: [&str; N], from: UTCDateTime, to: UTCDateTime) -> [u8; 16] {
    let mut hasher = Xxh3::new();

    for field in fields {
        hasher.update(field.as_bytes());
        hasher.update(&[0u8]);
    }
    hasher.update(&(from.timestamp() as u64).to_be_bytes());
    hasher.update(&(to.timestamp() as u64).to_be_bytes());

    hasher.digest128().to_be_bytes()
}

#[inline(always)]
fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

#[inline(always)]
fn non_empty_opt(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}
